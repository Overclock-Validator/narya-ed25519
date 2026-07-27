package heea8l

import "math/bits"

// SelectExactGaussFixed is the allocation-free counterpart of
// SelectExactGauss. It uses Lehmer-batched EEA rows to reach the norm
// crossover, an exact fixed-width Gauss finish, and the same constant-size
// parity-aware breakpoint finalizer as the math/big oracle.
//
// It remains variable-time research code and is not wired to verification or
// backend selection. A rejected arithmetic invariant is an ordinary-verifier
// fallback, never a signature verdict.
func SelectExactGaussFixed(kBytes [32]byte, limit WidthLimit) FixedSelection {
	if limit != Width128 && limit != Width132 && limit != Width136 {
		return FixedSelection{Fallback: FallbackInvalidWidth}
	}
	k := uint256FromBytesLE(kBytes)
	if k.cmp(fixedOrder) >= 0 {
		return FixedSelection{Fallback: FallbackInvalidChallenge}
	}
	candidate, _, ok := bestOddLInfFixed(k)
	if !ok {
		return FixedSelection{Fallback: FallbackWidthExceeded}
	}
	selection := FixedSelection{Candidate: candidate.external()}
	if candidate.bitLen() > int(limit) {
		selection.Fallback = FallbackWidthExceeded
		return selection
	}
	selection.UseCandidate = true
	selection.Fallback = NoFallback
	return selection
}

type exactGaussFixedStats struct {
	EuclidSteps int
	Batches     int
	GaussSteps  int
	Candidates  int
}

type fixedExactVector struct {
	rho signed256
	tau signed256
}

type uint512 [8]uint64

type signed512 struct {
	mag uint512
	neg bool
}

func bestOddLInfFixed(k uint256) (fixedCandidate, exactGaussFixedStats, bool) {
	var stats exactGaussFixedStats
	if k.isZero() {
		return fixedCandidate{tau: newSigned256(uint256{1}, false), epsilon: 1}, stats, true
	}
	rows := [2]principalEuclidRow{
		{rho: fixedModulus},
		{rho: k, tau: signed320FromUint64(1)},
	}

	for stats.EuclidSteps < principalEuclidIterationCap {
		crossed, ok := fixedRowNormAtLeast(rows[1], rows[0])
		if !ok {
			return fixedCandidate{}, stats, false
		}
		if crossed {
			break
		}
		if rows[1].rho.isZero() {
			return fixedCandidate{}, stats, false
		}

		// Batch ordinary quotient steps while they stay on the descending side
		// of the norm crossover. If one batch crosses, replay only that batch as
		// exact steps so the precise adjacent pair is retained.
		a, b, c, d, steps := lehmerMatrix(rows[0].rho, rows[1].rho)
		if steps > 0 && stats.EuclidSteps+steps < principalEuclidIterationCap {
			next, matrixOK := applyLehmerMatrix(rows, a, b, c, d)
			if matrixOK {
				nextCrossed, normOK := fixedRowNormAtLeast(next[1], next[0])
				if !normOK {
					return fixedCandidate{}, stats, false
				}
				if !nextCrossed {
					rows = next
					stats.EuclidSteps += steps
					stats.Batches++
					continue
				}
			}
		}

		quotient, remainder := divMod256(rows[0].rho, rows[1].rho)
		tau, ok := subMulUint256Signed320(rows[0].tau, rows[1].tau, quotient)
		if !ok || tau.mag[4] != 0 {
			return fixedCandidate{}, stats, false
		}
		rows[0], rows[1] = rows[1], principalEuclidRow{rho: remainder, tau: tau}
		stats.EuclidSteps++
	}
	if stats.EuclidSteps >= principalEuclidIterationCap {
		return fixedCandidate{}, stats, false
	}

	b1, ok := fixedVectorFromRow(rows[0])
	if !ok {
		return fixedCandidate{}, stats, false
	}
	b2, ok := fixedVectorFromRow(rows[1])
	if !ok {
		return fixedCandidate{}, stats, false
	}
	b1, b2, stats.GaussSteps, ok = gaussFinishFixed(b1, b2)
	if !ok || !validReducedBasisFixed(k, b1, b2) {
		return fixedCandidate{}, stats, false
	}

	best, candidates, ok := bestFromReducedBasisFixed(b1, b2)
	stats.Candidates = candidates
	if !ok || !fixedVectorRelation(k, fixedExactVector{rho: best.rho, tau: best.tau}) {
		return fixedCandidate{}, stats, false
	}
	return best, stats, true
}

func fixedVectorFromRow(row principalEuclidRow) (fixedExactVector, bool) {
	if row.tau.mag[4] != 0 {
		return fixedExactVector{}, false
	}
	return fixedExactVector{
		rho: newSigned256(row.rho, false),
		tau: newSigned256(uint256{row.tau.mag[0], row.tau.mag[1], row.tau.mag[2], row.tau.mag[3]}, row.tau.neg),
	}, true
}

func fixedRowNormAtLeast(left, right principalEuclidRow) (bool, bool) {
	leftVector, ok := fixedVectorFromRow(left)
	if !ok {
		return false, false
	}
	rightVector, ok := fixedVectorFromRow(right)
	if !ok {
		return false, false
	}
	// If the largest coordinate widths differ by at least two bits, their
	// Euclidean norms cannot overlap: a vector with m-bit coordinates has
	// squared norm below 2^(2m+1), while one (m+2)-bit coordinate alone is at
	// least 2^(2m+2). Avoid four 256x256 products on almost every early EEA
	// row; use exact norms only in the two-bit crossover band.
	leftWidth := leftVector.rho.mag.bitLen()
	if tauWidth := leftVector.tau.mag.bitLen(); tauWidth > leftWidth {
		leftWidth = tauWidth
	}
	rightWidth := rightVector.rho.mag.bitLen()
	if tauWidth := rightVector.tau.mag.bitLen(); tauWidth > rightWidth {
		rightWidth = tauWidth
	}
	if leftWidth >= rightWidth+2 {
		return true, true
	}
	if rightWidth >= leftWidth+2 {
		return false, true
	}
	return norm2Fixed(leftVector).cmp(norm2Fixed(rightVector)) >= 0, true
}

func gaussFinishFixed(b1, b2 fixedExactVector) (fixedExactVector, fixedExactVector, int, bool) {
	for step := 0; step < 16; step++ {
		norm1 := norm2Fixed(b1)
		norm2 := norm2Fixed(b2)
		if norm2.cmp(norm1) < 0 {
			b1, b2 = b2, b1
			norm1, norm2 = norm2, norm1
		}
		dot := dotFixed(b1, b2)
		twiceDot, overflow := shl1_512(dot.mag)
		if overflow {
			return b1, b2, step, false
		}
		if twiceDot.cmp(norm1) <= 0 {
			return b1, b2, step, true
		}
		quotient, remainder, ok := divMod512To256(dot.mag, norm1)
		if !ok {
			return b1, b2, step, false
		}
		twiceRemainder, overflow := shl1_512(remainder)
		if overflow {
			return b1, b2, step, false
		}
		if twiceRemainder.cmp(norm1) >= 0 {
			var carry uint64
			quotient, carry = add256(quotient, uint256{1})
			if carry != 0 {
				return b1, b2, step, false
			}
		}
		if quotient.isZero() {
			return b1, b2, step, false
		}
		if dot.neg {
			quotientVector, ok := scaleFixedVector(b1, quotient)
			if !ok {
				return b1, b2, step, false
			}
			b2, ok = addFixedVector(b2, quotientVector)
			if !ok {
				return b1, b2, step, false
			}
		} else {
			quotientVector, ok := scaleFixedVector(b1, quotient)
			if !ok {
				return b1, b2, step, false
			}
			quotientVector.rho = quotientVector.rho.negate()
			quotientVector.tau = quotientVector.tau.negate()
			b2, ok = addFixedVector(b2, quotientVector)
			if !ok {
				return b1, b2, step, false
			}
		}
	}
	return b1, b2, 16, false
}

func bestFromReducedBasisFixed(b1, b2 fixedExactVector) (fixedCandidate, int, bool) {
	var candidates [10]fixedCandidate
	count := 0
	add := func(vector fixedExactVector) {
		if vector.tau.mag.isZero() || vector.tau.mag[0]&1 == 0 {
			return
		}
		if vector.tau.neg {
			vector.rho = vector.rho.negate()
			vector.tau = vector.tau.negate()
		}
		if !coprimeToModulus(vector.tau.mag, fixedModulus) {
			return
		}
		candidate := fixedCandidate{rho: vector.rho, tau: vector.tau, epsilon: 1}
		for index := 0; index < count; index++ {
			if candidates[index] == candidate {
				return
			}
		}
		if count < len(candidates) {
			candidates[count] = candidate
			count++
		}
	}

	if b1.tau.mag[0]&1 == 1 {
		add(b1)
	}
	parity := -1
	if b1.tau.mag[0]&1 == 1 {
		parity = 1 - int(b2.tau.mag[0]&1)
	} else if b2.tau.mag[0]&1 != 1 {
		return fixedCandidate{}, count, false
	}

	type fixedBreakpoint struct {
		numerator   signed256
		denominator signed256
	}
	var breakpoints [4]fixedBreakpoint
	breakpointCount := 0
	addBreakpoint := func(numerator, denominator signed256) {
		if denominator.mag.isZero() {
			return
		}
		breakpoints[breakpointCount] = fixedBreakpoint{
			numerator:   numerator.negate(),
			denominator: denominator,
		}
		breakpointCount++
	}
	addBreakpoint(b2.rho, b1.rho)
	addBreakpoint(b2.tau, b1.tau)
	rhoMinusTau2, ok := addSigned256Checked(b2.rho, b2.tau.negate())
	if !ok {
		return fixedCandidate{}, count, false
	}
	rhoMinusTau1, ok := addSigned256Checked(b1.rho, b1.tau.negate())
	if !ok {
		return fixedCandidate{}, count, false
	}
	addBreakpoint(rhoMinusTau2, rhoMinusTau1)
	rhoPlusTau2, ok := addSigned256Checked(b2.rho, b2.tau)
	if !ok {
		return fixedCandidate{}, count, false
	}
	rhoPlusTau1, ok := addSigned256Checked(b1.rho, b1.tau)
	if !ok {
		return fixedCandidate{}, count, false
	}
	addBreakpoint(rhoPlusTau2, rhoPlusTau1)

	for index := 0; index < breakpointCount; index++ {
		below, above, ok := nearestAllowedIntegersFixed(
			breakpoints[index].numerator,
			breakpoints[index].denominator,
			parity,
		)
		if !ok {
			return fixedCandidate{}, count, false
		}
		for _, x := range [2]signed256{below, above} {
			vector, ok := combineFixedVector(b1, x, b2)
			if ok {
				add(vector)
			}
		}
	}
	add(b2)
	if count == 0 {
		return fixedCandidate{}, count, false
	}
	best := candidates[0]
	for index := 1; index < count; index++ {
		if betterFixed(candidates[index], best) {
			best = candidates[index]
		}
	}
	return best, count, true
}

func nearestAllowedIntegersFixed(numerator, denominator signed256, parity int) (signed256, signed256, bool) {
	if denominator.neg {
		numerator = numerator.negate()
		denominator = denominator.negate()
	}
	quotient, remainder := divMod256(numerator.mag, denominator.mag)
	truncated := newSigned256(quotient, numerator.neg)
	floor := truncated
	ceil := truncated
	if !remainder.isZero() {
		one := newSigned256(uint256{1}, false)
		var ok bool
		if numerator.neg {
			floor, ok = addSigned256Checked(floor, one.negate())
		} else {
			ceil, ok = addSigned256Checked(ceil, one)
		}
		if !ok {
			return signed256{}, signed256{}, false
		}
	}
	if parity >= 0 {
		one := newSigned256(uint256{1}, false)
		var ok bool
		if int(floor.mag[0]&1) != parity {
			floor, ok = addSigned256Checked(floor, one.negate())
			if !ok {
				return signed256{}, signed256{}, false
			}
		}
		if int(ceil.mag[0]&1) != parity {
			ceil, ok = addSigned256Checked(ceil, one)
			if !ok {
				return signed256{}, signed256{}, false
			}
		}
	}
	return floor, ceil, true
}

func combineFixedVector(b1 fixedExactVector, x signed256, b2 fixedExactVector) (fixedExactVector, bool) {
	scaled, ok := scaleFixedVector(b1, x.mag)
	if !ok {
		return fixedExactVector{}, false
	}
	if x.neg {
		scaled.rho = scaled.rho.negate()
		scaled.tau = scaled.tau.negate()
	}
	return addFixedVector(scaled, b2)
}

func scaleFixedVector(vector fixedExactVector, scalar uint256) (fixedExactVector, bool) {
	rhoMagnitude, rhoOverflow := mul256(vector.rho.mag, scalar)
	tauMagnitude, tauOverflow := mul256(vector.tau.mag, scalar)
	if rhoOverflow || tauOverflow {
		return fixedExactVector{}, false
	}
	return fixedExactVector{
		rho: newSigned256(rhoMagnitude, vector.rho.neg),
		tau: newSigned256(tauMagnitude, vector.tau.neg),
	}, true
}

func addFixedVector(left, right fixedExactVector) (fixedExactVector, bool) {
	rho, ok := addSigned256Checked(left.rho, right.rho)
	if !ok {
		return fixedExactVector{}, false
	}
	tau, ok := addSigned256Checked(left.tau, right.tau)
	if !ok {
		return fixedExactVector{}, false
	}
	return fixedExactVector{rho: rho, tau: tau}, true
}

func addSigned256Checked(left, right signed256) (signed256, bool) {
	if left.neg == right.neg {
		magnitude, carry := add256(left.mag, right.mag)
		if carry != 0 {
			return signed256{}, false
		}
		return newSigned256(magnitude, left.neg), true
	}
	switch left.mag.cmp(right.mag) {
	case -1:
		magnitude, _ := sub256(right.mag, left.mag)
		return newSigned256(magnitude, right.neg), true
	case 0:
		return signed256{}, true
	default:
		magnitude, _ := sub256(left.mag, right.mag)
		return newSigned256(magnitude, left.neg), true
	}
}

func validReducedBasisFixed(k uint256, b1, b2 fixedExactVector) bool {
	norm1 := norm2Fixed(b1)
	if norm1.cmp(norm2Fixed(b2)) > 0 {
		return false
	}
	twiceDot, overflow := shl1_512(dotFixed(b1, b2).mag)
	if overflow || twiceDot.cmp(norm1) > 0 {
		return false
	}
	if !fixedVectorRelation(k, b1) || !fixedVectorRelation(k, b2) {
		return false
	}
	// A pair of lattice vectors with the right determinant is a complete basis
	// rather than a proper sublattice.
	determinantLeft := mulWide256(b1.rho.mag, b2.tau.mag)
	determinantRight := mulWide256(b2.rho.mag, b1.tau.mag)
	leftNegative := b1.rho.neg != b2.tau.neg
	rightNegative := b2.rho.neg != b1.tau.neg
	determinant := addSigned512(
		signed512{mag: determinantLeft, neg: leftNegative},
		signed512{mag: determinantRight, neg: !rightNegative},
	)
	want := uint512{fixedModulus[0], fixedModulus[1], fixedModulus[2], fixedModulus[3]}
	return determinant.mag == want
}

func fixedVectorRelation(k uint256, vector fixedExactVector) bool {
	product := signed512{mag: mulWide256(vector.tau.mag, k), neg: vector.tau.neg}
	rho := signed512{
		mag: uint512{vector.rho.mag[0], vector.rho.mag[1], vector.rho.mag[2], vector.rho.mag[3]},
		neg: vector.rho.neg,
	}
	delta := addSigned512(rho, signed512{mag: product.mag, neg: !product.neg})
	modulus := uint512{fixedModulus[0], fixedModulus[1], fixedModulus[2], fixedModulus[3]}
	_, remainder, ok := divMod512To256(delta.mag, modulus)
	return ok && remainder == (uint512{})
}

func norm2Fixed(vector fixedExactVector) uint512 {
	return add512(mulWide256(vector.rho.mag, vector.rho.mag), mulWide256(vector.tau.mag, vector.tau.mag))
}

func dotFixed(left, right fixedExactVector) signed512 {
	rho := signed512{mag: mulWide256(left.rho.mag, right.rho.mag), neg: left.rho.neg != right.rho.neg}
	tau := signed512{mag: mulWide256(left.tau.mag, right.tau.mag), neg: left.tau.neg != right.tau.neg}
	return addSigned512(rho, tau)
}

func addSigned512(left, right signed512) signed512 {
	if left.neg == right.neg {
		return signed512{mag: add512(left.mag, right.mag), neg: left.neg}
	}
	switch left.mag.cmp(right.mag) {
	case -1:
		return signed512{mag: sub512(right.mag, left.mag), neg: right.neg}
	case 0:
		return signed512{}
	default:
		return signed512{mag: sub512(left.mag, right.mag), neg: left.neg}
	}
}

func mulWide256(left, right uint256) (out uint512) {
	for i := 0; i < significantLimbs(left); i++ {
		for j := 0; j < significantLimbs(right); j++ {
			high, low := bits.Mul64(left[i], right[j])
			index := i + j
			var carry uint64
			out[index], carry = bits.Add64(out[index], low, 0)
			out[index+1], carry = bits.Add64(out[index+1], high, carry)
			for index += 2; carry != 0 && index < len(out); index++ {
				out[index], carry = bits.Add64(out[index], 0, carry)
			}
			if carry != 0 {
				panic("heea8l: impossible 512-bit product overflow")
			}
		}
	}
	return out
}

func (x uint512) cmp(y uint512) int {
	for index := len(x) - 1; index >= 0; index-- {
		if x[index] < y[index] {
			return -1
		}
		if x[index] > y[index] {
			return 1
		}
	}
	return 0
}

func (x uint512) bitLen() int {
	for index := len(x) - 1; index >= 0; index-- {
		if x[index] != 0 {
			return index*64 + bits.Len64(x[index])
		}
	}
	return 0
}

func add512(left, right uint512) (sum uint512) {
	var carry uint64
	for index := range sum {
		sum[index], carry = bits.Add64(left[index], right[index], carry)
	}
	if carry != 0 {
		panic("heea8l: impossible uint512 addition overflow")
	}
	return sum
}

func sub512(left, right uint512) (difference uint512) {
	var borrow uint64
	for index := range difference {
		difference[index], borrow = bits.Sub64(left[index], right[index], borrow)
	}
	if borrow != 0 {
		panic("heea8l: uint512 subtraction underflow")
	}
	return difference
}

func shl1_512(x uint512) (uint512, bool) {
	var out uint512
	var carry uint64
	for index := range out {
		next := x[index] >> 63
		out[index] = x[index]<<1 | carry
		carry = next
	}
	return out, carry != 0
}

func shl512(x uint512, shift uint) (out uint512, overflow bool) {
	if shift >= 512 {
		return out, x != (uint512{})
	}
	wordShift := int(shift / 64)
	bitShift := shift % 64
	for source := range x {
		if x[source] == 0 {
			continue
		}
		destination := source + wordShift
		if destination >= len(out) {
			overflow = true
			continue
		}
		out[destination] |= x[source] << bitShift
		if bitShift != 0 {
			if destination+1 >= len(out) {
				overflow = overflow || x[source]>>(64-bitShift) != 0
			} else {
				out[destination+1] |= x[source] >> (64 - bitShift)
			}
		}
	}
	return out, overflow
}

func shr1_512(x uint512) uint512 {
	var out uint512
	for index := range out {
		out[index] = x[index] >> 1
		if index+1 < len(out) {
			out[index] |= x[index+1] << 63
		}
	}
	return out
}

func divMod512To256(numerator, denominator uint512) (uint256, uint512, bool) {
	if denominator == (uint512{}) {
		return uint256{}, uint512{}, false
	}
	if numerator.cmp(denominator) < 0 {
		return uint256{}, numerator, true
	}
	shift := numerator.bitLen() - denominator.bitLen()
	if shift > 256 {
		return uint256{}, uint512{}, false
	}
	shifted, overflow := shl512(denominator, uint(shift))
	if overflow {
		return uint256{}, uint512{}, false
	}
	remainder := numerator
	var quotient uint256
	for {
		if remainder.cmp(shifted) >= 0 {
			if shift >= 256 {
				return uint256{}, uint512{}, false
			}
			remainder = sub512(remainder, shifted)
			quotient.setBit(uint(shift))
		}
		if shift == 0 {
			break
		}
		shifted = shr1_512(shifted)
		shift--
	}
	return quotient, remainder, true
}

func subMulUint256Signed320(left, right signed320, multiplier uint256) (signed320, bool) {
	product, ok := mulSigned320Uint256(right, multiplier)
	if !ok {
		return signed320{}, false
	}
	return subSigned320(left, product)
}

func mulSigned320Uint256(value signed320, multiplier uint256) (signed320, bool) {
	var wide [9]uint64
	for i := 0; i < len(value.mag); i++ {
		for j := 0; j < significantLimbs(multiplier); j++ {
			high, low := bits.Mul64(value.mag[i], multiplier[j])
			index := i + j
			var carry uint64
			wide[index], carry = bits.Add64(wide[index], low, 0)
			wide[index+1], carry = bits.Add64(wide[index+1], high, carry)
			for index += 2; carry != 0 && index < len(wide); index++ {
				wide[index], carry = bits.Add64(wide[index], 0, carry)
			}
			if carry != 0 {
				return signed320{}, false
			}
		}
	}
	if wide[5]|wide[6]|wide[7]|wide[8] != 0 {
		return signed320{}, false
	}
	return signed320{mag: [5]uint64{wide[0], wide[1], wide[2], wide[3], wide[4]}, neg: value.neg}, true
}
