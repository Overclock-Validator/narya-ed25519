package heea8l

import "math/bits"

// SelectEuclidPrincipal is an experimental, allocation-free modulo-8L
// selector. It considers only principal Euclidean rows and stops at the first
// exact width-admissible unit multiplier. This deliberately trades some of
// SelectFixed's semiconvergent coverage for a much smaller selector cost.
//
// Every admitted result satisfies
//
//	Rho = Tau*k (mod 8L), and gcd(Tau, 8L) = 1.
//
// A miss is never a verification verdict: callers must route that signature
// through the ordinary verifier. This remains variable-time experimental
// code and is not wired to production backend selection.
func SelectEuclidPrincipal(kBytes [32]byte, limit WidthLimit) FixedSelection {
	if limit != Width128 && limit != Width132 && limit != Width136 {
		return FixedSelection{Fallback: FallbackInvalidWidth}
	}
	k := uint256FromBytesLE(kBytes)
	if k.cmp(fixedOrder) >= 0 {
		return FixedSelection{Fallback: FallbackInvalidChallenge}
	}
	selection, _ := selectEuclidPrincipal(k, limit)
	return selection
}

// principalEuclidIterationCap follows the classical worst-case bound for
// Euclid on 256-bit positive integers with margin. Reaching it is a defensive
// ordinary-verifier fallback, never an accept/reject result.
const principalEuclidIterationCap = 384

type principalEuclidStats struct {
	Iterations   int
	WideQuotient bool
	HitCap       bool
}

type principalEuclidRow struct {
	rho uint256
	tau signed320
}

func selectEuclidPrincipal(k uint256, limit WidthLimit) (FixedSelection, principalEuclidStats) {
	return selectEuclidPrincipalMode(k, limit, false)
}

func selectEuclidPrincipalLookahead(k uint256, limit WidthLimit) (FixedSelection, principalEuclidStats) {
	return selectEuclidPrincipalMode(k, limit, true)
}

func selectEuclidPrincipalMode(k uint256, limit WidthLimit, batched bool) (FixedSelection, principalEuclidStats) {
	if k.isZero() {
		return FixedSelection{
			Candidate: FixedCandidate{
				Tau:     SignedCoefficient{Limbs: [4]uint64{1}},
				Epsilon: 1,
			},
			UseCandidate: true,
			Fallback:     NoFallback,
		}, principalEuclidStats{}
	}

	rows := [2]principalEuclidRow{
		{rho: fixedModulus},
		{rho: k, tau: signed320FromUint64(1)},
	}
	if candidate, ok := principalEuclidCandidate(rows[1], int(limit)); ok {
		return FixedSelection{Candidate: candidate, UseCandidate: true}, principalEuclidStats{}
	}

	var stats principalEuclidStats
	var lookahead quotientLookahead
	for !rows[1].rho.isZero() && stats.Iterations < principalEuclidIterationCap {
		var quotient, remainder uint256
		if batched {
			quotient, remainder = lookahead.next(rows[0].rho, rows[1].rho, divMod256)
		} else {
			quotient, remainder = divMod256(rows[0].rho, rows[1].rho)
		}
		stats.Iterations++
		if quotient[1]|quotient[2]|quotient[3] != 0 {
			stats.WideQuotient = true
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
	if stats.Iterations == principalEuclidIterationCap && !rows[1].rho.isZero() {
		stats.HitCap = true
	}
	return FixedSelection{Fallback: FallbackWidthExceeded}, stats
}

func principalEuclidCandidate(row principalEuclidRow, limit int) (FixedCandidate, bool) {
	if row.rho.bitLen() > limit || row.tau.bitLen() > limit || !unitMultiplier320(row.tau) {
		return FixedCandidate{}, false
	}
	tau, ok := row.tau.external()
	if !ok {
		return FixedCandidate{}, false
	}
	return FixedCandidate{
		Rho:     SignedCoefficient{Limbs: row.rho},
		Tau:     tau,
		Epsilon: 1,
	}, true
}

// unitMultiplier320 enforces the actual injectivity condition from the
// transformed-equation theorem. Oddness alone is insufficient in general:
// Tau=L is odd but annihilates the prime-order subgroup. Configured fast
// widths are below L, yet retaining the complete check makes that invariant
// executable rather than dependent on call ordering or a comment.
func unitMultiplier320(x signed320) bool {
	if x.isZero() || !x.odd() || x.mag[4] != 0 {
		return false
	}
	return coprimeToModulus(uint256{x.mag[0], x.mag[1], x.mag[2], x.mag[3]}, fixedModulus)
}

func mulSigned320Uint64(x signed320, multiplier uint64) (signed320, bool) {
	if multiplier == 0 || x.isZero() {
		return signed320{}, true
	}
	var out signed320
	out.neg = x.neg
	var carry uint64
	for i := range x.mag {
		hi, lo := bits.Mul64(x.mag[i], multiplier)
		lo, addCarry := bits.Add64(lo, carry, 0)
		out.mag[i] = lo
		carry, addCarry = bits.Add64(hi, 0, addCarry)
		if addCarry != 0 {
			return signed320{}, false
		}
	}
	return out, carry == 0
}

func subSigned320(x, y signed320) (signed320, bool) {
	if x.neg != y.neg {
		mag, overflow := add320(x.mag, y.mag)
		if overflow {
			return signed320{}, false
		}
		return signed320{mag: mag, neg: x.neg}, true
	}
	switch cmp320(x.mag, y.mag) {
	case -1:
		mag, underflow := sub320(y.mag, x.mag)
		if underflow {
			return signed320{}, false
		}
		return signed320{mag: mag, neg: !x.neg}, true
	case 0:
		return signed320{}, true
	default:
		mag, underflow := sub320(x.mag, y.mag)
		if underflow {
			return signed320{}, false
		}
		return signed320{mag: mag, neg: x.neg}, true
	}
}

func subMulUint64Signed320(x, y signed320, multiplier uint64) (signed320, bool) {
	if multiplier == 0 || y.isZero() {
		return x, true
	}
	var product [5]uint64
	var carry uint64
	for i := range y.mag {
		high, low := bits.Mul64(y.mag[i], multiplier)
		low, addCarry := bits.Add64(low, carry, 0)
		product[i] = low
		carry, addCarry = bits.Add64(high, 0, addCarry)
		if addCarry != 0 {
			return signed320{}, false
		}
	}
	if carry != 0 {
		return signed320{}, false
	}

	// Compute x-(y*multiplier) directly from the product magnitude. This is
	// the same sign-and-magnitude rule as subSigned320, but avoids building a
	// temporary signed320 and rescanning y through the generic multiply path.
	if x.neg != y.neg {
		magnitude, overflow := add320(x.mag, product)
		if overflow {
			return signed320{}, false
		}
		return signed320{mag: magnitude, neg: x.neg}, true
	}
	switch cmp320(x.mag, product) {
	case -1:
		magnitude, underflow := sub320(product, x.mag)
		return signed320{mag: magnitude, neg: !x.neg}, !underflow
	case 0:
		return signed320{}, true
	default:
		magnitude, underflow := sub320(x.mag, product)
		return signed320{mag: magnitude, neg: x.neg}, !underflow
	}
}

// subMulUint64Signed320Reference retains the compositional form as an
// independent oracle for the fused exact-step helper.
func subMulUint64Signed320Reference(x, y signed320, multiplier uint64) (signed320, bool) {
	product, ok := mulSigned320Uint64(y, multiplier)
	if !ok {
		return signed320{}, false
	}
	return subSigned320(x, product)
}
