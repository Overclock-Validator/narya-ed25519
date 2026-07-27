package heea8l

import "math/big"

// exactGaussStepCap is a defensive bound for the direct two-dimensional
// Lagrange reduction below. Reaching it is an oracle failure, never a
// signature verdict. The production-shaped selectors retain their own
// independently bounded loops.
const exactGaussStepCap = 512

type exactLatticeVector struct {
	rho big.Int
	tau big.Int
}

type exactGaussStats struct {
	Steps      int
	Candidates int
}

// SelectExactGauss is an independently derived exact math/big oracle for the
// constrained modulo-8L decomposition. Unlike the production-shaped
// selectors, it never misses an available candidate because of enumeration:
// a width fallback means the globally minimum odd-unit pair itself is wider
// than limit.
//
// It allocates, is variable-time, and is not connected to verification or
// backend selection.
func SelectExactGauss(k *big.Int, limit WidthLimit) Selection {
	if limit != Width128 && limit != Width132 && limit != Width136 {
		return Selection{Fallback: FallbackInvalidWidth}
	}
	if k == nil || k.Sign() < 0 || k.Cmp(ed25519Order) >= 0 {
		return Selection{Fallback: FallbackInvalidChallenge}
	}
	candidate, _, ok := bestOddLInfForModulus(ed25519Exponent, k)
	if !ok {
		return Selection{Fallback: FallbackWidthExceeded}
	}
	selection := Selection{Candidate: candidate}
	if candidate.BitLen() > int(limit) {
		selection.Fallback = FallbackWidthExceeded
		return selection
	}
	selection.UseCandidate = true
	selection.Fallback = NoFallback
	return selection
}

// bestOddLInfForModulus finds the exact minimum-L-infinity vector in
//
//	{(rho,tau): rho = tau*k (mod n), tau odd}.
//
// Its domain is the Ed25519-shaped case n=8*l and 0<=k<l. In that domain the
// trivial (k,1) vector proves the optimum is below l, so an odd optimum cannot
// be a non-unit multiple of the odd prime l. The explicit GCD check below is
// retained as a defensive assertion.
//
// It is a proof and differential-testing oracle. It deliberately uses
// math/big and is not connected to verification or backend selection.
//
// After exact Gauss reduction, an optimum needs coefficient y only in
// {-1,0,1} in v=x*b1+y*b2. Negation makes y=-1 redundant. The y=1 family is
// a one-dimensional convex minimax problem whose only real breakpoints are
// rho=0, tau=0, rho=tau, and rho=-tau. Testing the nearest parity-valid
// integers on both sides of those breakpoints, plus b1 when it is feasible,
// is therefore exact.
func bestOddLInfForModulus(n, k *big.Int) (Candidate, exactGaussStats, bool) {
	var stats exactGaussStats
	if n == nil || n.Sign() <= 0 || n.Bit(0) != 0 || n.Bit(1) != 0 || n.Bit(2) != 0 ||
		k == nil || k.Sign() < 0 || k.Cmp(new(big.Int).Rsh(new(big.Int).Set(n), 3)) >= 0 {
		return Candidate{}, stats, false
	}
	if k.Sign() == 0 {
		var candidate Candidate
		candidate.Tau.SetInt64(1)
		candidate.Epsilon = 1
		stats.Candidates = 1
		return candidate, stats, true
	}

	b1 := exactLatticeVector{}
	b1.rho.Set(n)
	b2 := exactLatticeVector{}
	b2.rho.Set(k)
	b2.tau.SetInt64(1)

	var ok bool
	b1, b2, stats.Steps, ok = gaussReduceExact(b1, b2, exactGaussStepCap)
	if !ok || !validReducedBasis(n, k, &b1, &b2) {
		return Candidate{}, stats, false
	}

	var best Candidate
	found := false
	seen := make(map[string]struct{}, 10)
	considerVector := func(vector *exactLatticeVector) {
		if vector.tau.Sign() == 0 || vector.tau.Bit(0) == 0 {
			return
		}
		// v and -v have the same norm and preserve the exact relation. Keep a
		// positive Tau so tie-breaking agrees with the older EEA oracle and the
		// signed point layer has one deterministic representation.
		if vector.tau.Sign() < 0 {
			var normalized exactLatticeVector
			normalized.rho.Neg(&vector.rho)
			normalized.tau.Neg(&vector.tau)
			vector = &normalized
		}
		if new(big.Int).GCD(nil, nil, abs(&vector.tau), n).Cmp(big.NewInt(1)) != 0 {
			return
		}
		key := vector.rho.String() + "/" + vector.tau.String()
		if _, duplicate := seen[key]; duplicate {
			return
		}
		seen[key] = struct{}{}
		stats.Candidates++
		candidate := Candidate{Epsilon: 1}
		candidate.Rho.Set(&vector.rho)
		candidate.Tau.Set(&vector.tau)
		if !found || better(&candidate, &best) {
			best = candidate
			found = true
		}
	}

	if b1.tau.Bit(0) == 1 {
		considerVector(&b1)
	}

	// If t1 is odd, x must have parity 1-t2. If t1 is even, basis
	// unimodularity implies t2 is odd and every x is allowed.
	parity := -1
	if b1.tau.Bit(0) == 1 {
		parity = 1 - int(b2.tau.Bit(0))
	} else if b2.tau.Bit(0) != 1 {
		return Candidate{}, stats, false
	}

	type breakpoint struct {
		numerator   big.Int
		denominator big.Int
	}
	breakpoints := make([]breakpoint, 0, 4)
	addBreakpoint := func(numerator, denominator *big.Int) {
		if denominator.Sign() == 0 {
			return
		}
		var point breakpoint
		point.numerator.Neg(numerator)
		point.denominator.Set(denominator)
		breakpoints = append(breakpoints, point)
	}
	addBreakpoint(&b2.rho, &b1.rho)
	addBreakpoint(&b2.tau, &b1.tau)
	var numerator, denominator big.Int
	numerator.Sub(&b2.rho, &b2.tau)
	denominator.Sub(&b1.rho, &b1.tau)
	addBreakpoint(&numerator, &denominator)
	numerator.Add(&b2.rho, &b2.tau)
	denominator.Add(&b1.rho, &b1.tau)
	addBreakpoint(&numerator, &denominator)

	for index := range breakpoints {
		below, above := nearestAllowedIntegers(
			&breakpoints[index].numerator,
			&breakpoints[index].denominator,
			parity,
		)
		for _, x := range []*big.Int{below, above} {
			vector := combineExactVector(&b1, x, &b2)
			considerVector(&vector)
		}
	}

	// Redundant for non-degenerate bases, but useful as a defensive candidate
	// when several breakpoint denominators vanish or deduplicate.
	zero := new(big.Int)
	vector := combineExactVector(&b1, zero, &b2)
	considerVector(&vector)

	return best, stats, found
}

func gaussReduceExact(b1, b2 exactLatticeVector, cap int) (exactLatticeVector, exactLatticeVector, int, bool) {
	for step := 0; step < cap; step++ {
		norm1 := exactNorm2(&b1)
		norm2 := exactNorm2(&b2)
		if norm2.Cmp(norm1) < 0 {
			b1, b2 = b2, b1
			norm1, norm2 = norm2, norm1
		}
		dot := exactDot(&b1, &b2)
		twiceAbsDot := new(big.Int).Lsh(abs(dot), 1)
		if twiceAbsDot.Cmp(norm1) <= 0 {
			return b1, b2, step, true
		}
		quotient := nearestIntegerQuotient(dot, norm1)
		if quotient.Sign() == 0 {
			return b1, b2, step, false
		}
		product := scaleExactVector(&b1, quotient)
		b2.rho.Sub(&b2.rho, &product.rho)
		b2.tau.Sub(&b2.tau, &product.tau)
	}
	return b1, b2, cap, false
}

func exactNorm2(vector *exactLatticeVector) *big.Int {
	rho2 := new(big.Int).Mul(&vector.rho, &vector.rho)
	tau2 := new(big.Int).Mul(&vector.tau, &vector.tau)
	return rho2.Add(rho2, tau2)
}

func exactDot(left, right *exactLatticeVector) *big.Int {
	rho := new(big.Int).Mul(&left.rho, &right.rho)
	tau := new(big.Int).Mul(&left.tau, &right.tau)
	return rho.Add(rho, tau)
}

// nearestIntegerQuotient rounds numerator/positiveDenominator to the nearest
// integer, with exact half ties away from zero. Either tie choice is valid for
// Gauss reduction; choosing one explicitly keeps the oracle deterministic.
func nearestIntegerQuotient(numerator, positiveDenominator *big.Int) *big.Int {
	quotient := new(big.Int)
	remainder := new(big.Int)
	quotient.QuoRem(numerator, positiveDenominator, remainder)
	twiceRemainder := new(big.Int).Lsh(abs(remainder), 1)
	if twiceRemainder.Cmp(positiveDenominator) >= 0 {
		if numerator.Sign() < 0 {
			quotient.Sub(quotient, big.NewInt(1))
		} else {
			quotient.Add(quotient, big.NewInt(1))
		}
	}
	return quotient
}

func nearestAllowedIntegers(numerator, denominator *big.Int, parity int) (*big.Int, *big.Int) {
	if denominator.Sign() < 0 {
		numerator = new(big.Int).Neg(numerator)
		denominator = new(big.Int).Neg(denominator)
	}
	floor := new(big.Int)
	remainder := new(big.Int)
	floor.QuoRem(numerator, denominator, remainder)
	if remainder.Sign() < 0 {
		floor.Sub(floor, big.NewInt(1))
	}
	ceil := new(big.Int).Set(floor)
	if remainder.Sign() != 0 {
		ceil.Add(ceil, big.NewInt(1))
	}
	if parity >= 0 {
		if int(floor.Bit(0)) != parity {
			floor.Sub(floor, big.NewInt(1))
		}
		if int(ceil.Bit(0)) != parity {
			ceil.Add(ceil, big.NewInt(1))
		}
	}
	return floor, ceil
}

func scaleExactVector(vector *exactLatticeVector, scalar *big.Int) exactLatticeVector {
	var out exactLatticeVector
	out.rho.Mul(&vector.rho, scalar)
	out.tau.Mul(&vector.tau, scalar)
	return out
}

func combineExactVector(b1 *exactLatticeVector, x *big.Int, b2 *exactLatticeVector) exactLatticeVector {
	out := scaleExactVector(b1, x)
	out.rho.Add(&out.rho, &b2.rho)
	out.tau.Add(&out.tau, &b2.tau)
	return out
}

func validReducedBasis(n, k *big.Int, b1, b2 *exactLatticeVector) bool {
	determinant := new(big.Int).Mul(&b1.rho, &b2.tau)
	determinant.Sub(determinant, new(big.Int).Mul(&b2.rho, &b1.tau))
	if abs(determinant).Cmp(n) != 0 {
		return false
	}
	for _, vector := range []*exactLatticeVector{b1, b2} {
		delta := new(big.Int).Mul(&vector.tau, k)
		delta.Sub(&vector.rho, delta)
		delta.Mod(delta, n)
		if delta.Sign() != 0 {
			return false
		}
	}
	norm1 := exactNorm2(b1)
	if norm1.Cmp(exactNorm2(b2)) > 0 {
		return false
	}
	twiceAbsDot := new(big.Int).Lsh(abs(exactDot(b1, b2)), 1)
	return twiceAbsDot.Cmp(norm1) <= 0
}
