package heea8l

import "math/bits"

// SelectLehmer is a Lehmer-accelerated modulo-8L selector. It computes the
// same principal Euclidean sequence as SelectEuclidPrincipal and stops at the
// same row, but replaces most full-width steps with single-word arithmetic.
//
// Why: profiling the exact selector put roughly 40% of its time in one
// 256-bit division per iteration and another 40% in one 320-bit signed
// coefficient update per iteration, across about 65 iterations. Lehmer's
// method runs many Euclidean steps on the leading 64-bit words of the pair,
// accumulating a small 2x2 integer matrix, and touches the wide values only
// once per batch. The wide work is then amortized over every step the batch
// covered instead of paid per step.
//
// This remains research code. It is variable-time, is not wired into any
// verifier, and makes no side-channel claim.
func SelectLehmer(kBytes [32]byte, limit WidthLimit) FixedSelection {
	if limit != Width128 && limit != Width132 && limit != Width136 {
		return FixedSelection{Fallback: FallbackInvalidWidth}
	}
	k := uint256FromBytesLE(kBytes)
	if k.cmp(fixedOrder) >= 0 {
		return FixedSelection{Fallback: FallbackInvalidChallenge}
	}
	selection, _ := selectLehmer(k, limit)
	return selection
}

// lehmerGuardBits is how far above the width limit the wide values must stay
// before a batched step is allowed.
//
// A batch advances several rows at once, so it can only be used where it
// cannot step past the row the exact selector would have stopped on. Both rho
// and tau change by at most the batch's matrix norm, and the guard is chosen
// so a batch can never carry rho from above the limit to below it. Near the
// threshold the selector falls back to exact single steps, which is also where
// the values are smallest and single steps are cheapest.
const lehmerGuardBits = 32

// lehmerCoefficientCap bounds the 2x2 matrix entries so every product with a
// leading word stays inside int64. Continued-fraction convergents grow quickly,
// so this is reached long before anything can overflow.
const lehmerCoefficientCap = 1 << 31

type lehmerStats struct {
	Iterations   int
	BatchedSteps int
	Batches      int
	Exact        int
}

func selectLehmer(k uint256, limit WidthLimit) (FixedSelection, lehmerStats) {
	var stats lehmerStats
	if k.isZero() {
		return FixedSelection{
			Candidate: FixedCandidate{
				Tau:     SignedCoefficient{Limbs: [4]uint64{1}},
				Epsilon: 1,
			},
			UseCandidate: true,
			Fallback:     NoFallback,
		}, stats
	}

	rows := [2]principalEuclidRow{
		{rho: fixedModulus},
		{rho: k, tau: signed320FromUint64(1)},
	}
	if candidate, ok := principalEuclidCandidate(rows[1], int(limit)); ok {
		return FixedSelection{Candidate: candidate, UseCandidate: true}, stats
	}

	for !rows[1].rho.isZero() && stats.Iterations < principalEuclidIterationCap {
		// Batch only while comfortably clear of the stopping width, so a batch
		// cannot skip the row the exact sequence would have selected.
		if rows[1].rho.bitLen() > int(limit)+lehmerGuardBits {
			a, b, c, d, steps := lehmerMatrix(rows[0].rho, rows[1].rho)
			if steps > 0 {
				next, ok := applyLehmerMatrix(rows, a, b, c, d)
				if !ok {
					return FixedSelection{Fallback: FallbackWidthExceeded}, stats
				}
				rows = next
				stats.Iterations += steps
				stats.BatchedSteps += steps
				stats.Batches++
				// A batch stops short of the threshold by construction, so no
				// candidate can have been passed over inside it. Still check
				// the row it lands on.
				if candidate, ok := principalEuclidCandidate(rows[1], int(limit)); ok {
					return FixedSelection{Candidate: candidate, UseCandidate: true}, stats
				}
				continue
			}
		}

		quotient, remainder := divMod256(rows[0].rho, rows[1].rho)
		stats.Iterations++
		stats.Exact++
		if quotient[1]|quotient[2]|quotient[3] != 0 {
			return FixedSelection{Fallback: FallbackWidthExceeded}, stats
		}
		tau, ok := subMulUint64Signed320(rows[0].tau, rows[1].tau, quotient[0])
		if !ok || tau.mag[4] != 0 {
			return FixedSelection{Fallback: FallbackWidthExceeded}, stats
		}
		rows[0], rows[1] = rows[1], principalEuclidRow{rho: remainder, tau: tau}
		if candidate, ok := principalEuclidCandidate(rows[1], int(limit)); ok {
			return FixedSelection{Candidate: candidate, UseCandidate: true}, stats
		}
	}
	return FixedSelection{Fallback: FallbackWidthExceeded}, stats
}

// lehmerMatrix runs the Euclidean recurrence on the aligned leading words of
// the pair and returns the accumulated transformation
//
//	rho0' = a*rho0 + b*rho1
//	rho1' = c*rho0 + d*rho1
//
// together with the number of steps it represents. It returns steps == 0 when
// the leading words cannot determine even one quotient, in which case the
// caller must take an exact step.
func lehmerMatrix(rho0, rho1 uint256) (a, b, c, d int64, steps int) {
	shift := uint(256 - rho0.bitLen())
	u := int64(shl256(rho0, shift)[3] >> 1)
	v := int64(shl256(rho1, shift)[3] >> 1)

	a, b, c, d = 1, 0, 0, 1
	for {
		// The two denominators bracket the true value of the trailing row.
		lowDen, highDen := v+c, v+d
		if lowDen <= 0 || highDen <= 0 {
			break
		}
		q := (u + a) / lowDen
		if q != (u+b)/highDen {
			break
		}
		a, b, c, d = c, d, a-q*c, b-q*d
		u, v = v, u-q*v
		steps++
		if absInt64(c) >= lehmerCoefficientCap || absInt64(d) >= lehmerCoefficientCap {
			break
		}
	}
	return a, b, c, d, steps
}

// applyLehmerMatrix applies one batch's transformation to the full-width rows.
// The rho row stays non-negative by construction; a negative result means the
// batch was not a valid Euclidean transformation and is reported as a failure
// rather than silently accepted.
func applyLehmerMatrix(rows [2]principalEuclidRow, a, b, c, d int64) ([2]principalEuclidRow, bool) {
	// Apply all eight small-coefficient products in one limb pass. The matrix
	// entries are capped below 2^31 and every reachable rho/tau magnitude fits
	// four limbs, so the fifth limb is an explicit checked carry boundary.
	// Keeping the products together removes eight repeated multiply-helper
	// traversals from every Lehmer batch without changing sign-and-magnitude
	// semantics.
	coeffA, negA := lehmerCoefficientMagnitude(a)
	coeffB, negB := lehmerCoefficientMagnitude(b)
	coeffC, negC := lehmerCoefficientMagnitude(c)
	coeffD, negD := lehmerCoefficientMagnitude(d)

	var products [8][5]uint64
	var carry [8]uint64
	for limb := 0; limb < 5; limb++ {
		var rho0Word, rho1Word uint64
		if limb < 4 {
			rho0Word = rows[0].rho[limb]
			rho1Word = rows[1].rho[limb]
		}
		var ok bool
		products[0][limb], carry[0], ok = mulLehmerWord(rho0Word, coeffA, carry[0])
		if !ok {
			return rows, false
		}
		products[1][limb], carry[1], ok = mulLehmerWord(rho1Word, coeffB, carry[1])
		if !ok {
			return rows, false
		}
		products[2][limb], carry[2], ok = mulLehmerWord(rho0Word, coeffC, carry[2])
		if !ok {
			return rows, false
		}
		products[3][limb], carry[3], ok = mulLehmerWord(rho1Word, coeffD, carry[3])
		if !ok {
			return rows, false
		}
		products[4][limb], carry[4], ok = mulLehmerWord(rows[0].tau.mag[limb], coeffA, carry[4])
		if !ok {
			return rows, false
		}
		products[5][limb], carry[5], ok = mulLehmerWord(rows[1].tau.mag[limb], coeffB, carry[5])
		if !ok {
			return rows, false
		}
		products[6][limb], carry[6], ok = mulLehmerWord(rows[0].tau.mag[limb], coeffC, carry[6])
		if !ok {
			return rows, false
		}
		products[7][limb], carry[7], ok = mulLehmerWord(rows[1].tau.mag[limb], coeffD, carry[7])
		if !ok {
			return rows, false
		}
	}
	for _, high := range carry {
		if high != 0 {
			return rows, false
		}
	}

	rho0, ok := addSigned320(
		lehmerProduct(products[0], false, negA, coeffA),
		lehmerProduct(products[1], false, negB, coeffB),
	)
	if !ok || rho0.neg {
		return rows, false
	}
	rho1, ok := addSigned320(
		lehmerProduct(products[2], false, negC, coeffC),
		lehmerProduct(products[3], false, negD, coeffD),
	)
	if !ok || rho1.neg {
		return rows, false
	}
	tau0, ok := addSigned320(
		lehmerProduct(products[4], rows[0].tau.neg, negA, coeffA),
		lehmerProduct(products[5], rows[1].tau.neg, negB, coeffB),
	)
	if !ok || tau0.mag[4] != 0 {
		return rows, false
	}
	tau1, ok := addSigned320(
		lehmerProduct(products[6], rows[0].tau.neg, negC, coeffC),
		lehmerProduct(products[7], rows[1].tau.neg, negD, coeffD),
	)
	if !ok || tau1.mag[4] != 0 {
		return rows, false
	}
	if rho0.mag[4] != 0 || rho1.mag[4] != 0 {
		return rows, false
	}
	return [2]principalEuclidRow{
		{rho: uint256{rho0.mag[0], rho0.mag[1], rho0.mag[2], rho0.mag[3]}, tau: tau0},
		{rho: uint256{rho1.mag[0], rho1.mag[1], rho1.mag[2], rho1.mag[3]}, tau: tau1},
	}, true
}

func lehmerCoefficientMagnitude(coefficient int64) (uint64, bool) {
	if coefficient < 0 {
		return uint64(-coefficient), true
	}
	return uint64(coefficient), false
}

func mulLehmerWord(word, coefficient, carry uint64) (low, high uint64, ok bool) {
	high, low = bits.Mul64(word, coefficient)
	low, addCarry := bits.Add64(low, carry, 0)
	high, overflow := bits.Add64(high, 0, addCarry)
	return low, high, overflow == 0
}

func lehmerProduct(magnitude [5]uint64, inputNegative, coefficientNegative bool, coefficient uint64) signed320 {
	product := signed320{mag: magnitude}
	if coefficient != 0 && !product.isZero() {
		product.neg = inputNegative != coefficientNegative
	}
	return product
}

// applyLehmerMatrixReference retains the straightforward four-combine form as
// an independent test oracle for the fused limb schedule above.
func applyLehmerMatrixReference(rows [2]principalEuclidRow, a, b, c, d int64) ([2]principalEuclidRow, bool) {
	rho0, ok := combine320(signed320FromUint256(rows[0].rho), a, signed320FromUint256(rows[1].rho), b)
	if !ok || rho0.neg {
		return rows, false
	}
	rho1, ok := combine320(signed320FromUint256(rows[0].rho), c, signed320FromUint256(rows[1].rho), d)
	if !ok || rho1.neg {
		return rows, false
	}
	tau0, ok := combine320(rows[0].tau, a, rows[1].tau, b)
	if !ok || tau0.mag[4] != 0 {
		return rows, false
	}
	tau1, ok := combine320(rows[0].tau, c, rows[1].tau, d)
	if !ok || tau1.mag[4] != 0 {
		return rows, false
	}
	if rho0.mag[4] != 0 || rho1.mag[4] != 0 {
		return rows, false
	}
	return [2]principalEuclidRow{
		{rho: uint256{rho0.mag[0], rho0.mag[1], rho0.mag[2], rho0.mag[3]}, tau: tau0},
		{rho: uint256{rho1.mag[0], rho1.mag[1], rho1.mag[2], rho1.mag[3]}, tau: tau1},
	}, true
}

// combine320 returns x*m + y*n.
func combine320(x signed320, m int64, y signed320, n int64) (signed320, bool) {
	left, ok := mulSigned320Int64(x, m)
	if !ok {
		return signed320{}, false
	}
	right, ok := mulSigned320Int64(y, n)
	if !ok {
		return signed320{}, false
	}
	return addSigned320(left, right)
}

func mulSigned320Int64(x signed320, m int64) (signed320, bool) {
	if m == 0 {
		return signed320{}, true
	}
	magnitude := uint64(m)
	negate := false
	if m < 0 {
		magnitude = uint64(-m)
		negate = true
	}
	out, ok := mulSigned320Uint64(x, magnitude)
	if !ok {
		return signed320{}, false
	}
	if negate {
		out = negateSigned320(out)
	}
	return out, true
}

func addSigned320(x, y signed320) (signed320, bool) {
	return subSigned320(x, negateSigned320(y))
}

func absInt64(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}
