package heea8l

import "math/bits"

// SelectShiftSubtract is an experimental, allocation-free HEEA candidate
// selector modulo 8L. It deliberately has a weaker contract than SelectFixed:
// it returns any exact width-admissible odd-tau relation that its
// division-free schedule encounters, rather than preserving the globally best
// candidate chosen by the semiconvergent oracle.
//
// The candidate loop uses only comparisons, bit lengths, shifts, additions,
// and subtractions. A miss is an explicit width fallback; callers must use the
// ordinary verifier rather than invoking the exact selector in a hot path.
// SelectFixed remains the independent research oracle for tests and coverage
// measurements.
//
// This is variable-time experimental code. It is not wired to verification or
// production backend selection.
func SelectShiftSubtract(kBytes [32]byte, limit WidthLimit) FixedSelection {
	if limit != Width128 && limit != Width132 && limit != Width136 {
		return FixedSelection{Fallback: FallbackInvalidWidth}
	}
	k := uint256FromBytesLE(kBytes)
	if k.cmp(fixedOrder) >= 0 {
		return FixedSelection{Fallback: FallbackInvalidChallenge}
	}
	return selectShiftSubtract(k, limit)
}

// signed320 is a sign-and-magnitude integer with five little-endian limbs.
// The extra limb is intentional even though the determinant proof below keeps
// every valid coefficient below N=8L<2^256. It makes all shifted intermediate
// operations explicit and gives the implementation a defensive overflow
// boundary instead of relying on four-limb wraparound.
type signed320 struct {
	mag [5]uint64
	neg bool
}

func signed320FromUint64(x uint64) signed320 {
	return signed320{mag: [5]uint64{x}}
}

func (x signed320) isZero() bool {
	return x.mag[0]|x.mag[1]|x.mag[2]|x.mag[3]|x.mag[4] == 0
}

func (x signed320) bitLen() int {
	for i := len(x.mag) - 1; i >= 0; i-- {
		if x.mag[i] != 0 {
			return i*64 + bits.Len64(x.mag[i])
		}
	}
	return 0
}

func (x signed320) odd() bool { return x.mag[0]&1 != 0 }

func (x signed320) external() (SignedCoefficient, bool) {
	if x.mag[4] != 0 {
		return SignedCoefficient{}, false
	}
	return SignedCoefficient{
		Limbs:    [4]uint64{x.mag[0], x.mag[1], x.mag[2], x.mag[3]},
		Negative: x.neg && !x.isZero(),
	}, true
}

func cmp320(x, y [5]uint64) int {
	for i := len(x) - 1; i >= 0; i-- {
		if x[i] < y[i] {
			return -1
		}
		if x[i] > y[i] {
			return 1
		}
	}
	return 0
}

func add320(x, y [5]uint64) (out [5]uint64, overflow bool) {
	var carry uint64
	for i := range out {
		out[i], carry = bits.Add64(x[i], y[i], carry)
	}
	return out, carry != 0
}

func sub320(x, y [5]uint64) (out [5]uint64, underflow bool) {
	var borrow uint64
	for i := range out {
		out[i], borrow = bits.Sub64(x[i], y[i], borrow)
	}
	return out, borrow != 0
}

func shl320(x [5]uint64, shift uint) (out [5]uint64, overflow bool) {
	if shift >= 320 {
		return out, x != [5]uint64{}
	}
	wordShift := int(shift / 64)
	bitShift := shift % 64
	for source := 0; source < len(x); source++ {
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
			high := x[source] >> (64 - bitShift)
			if destination+1 >= len(out) {
				overflow = overflow || high != 0
			} else {
				out[destination+1] |= high
			}
		}
	}
	return out, overflow
}

// subShifted320 computes x-(y*2^shift) exactly. HEEA rows have opposite
// coefficient signs after the initial zero row, but the generic signed helper
// also handles cancellation so the arithmetic invariant is locally testable.
func subShifted320(x, y signed320, shift uint) (signed320, bool) {
	shifted, overflow := shl320(y.mag, shift)
	if overflow {
		return signed320{}, false
	}
	if x.neg != y.neg {
		mag, carry := add320(x.mag, shifted)
		if carry {
			return signed320{}, false
		}
		return signed320{mag: mag, neg: x.neg}, true
	}
	switch cmp320(x.mag, shifted) {
	case -1:
		mag, underflow := sub320(shifted, x.mag)
		if underflow {
			return signed320{}, false
		}
		return signed320{mag: mag, neg: !x.neg}, true
	case 0:
		return signed320{}, true
	default:
		mag, underflow := sub320(x.mag, shifted)
		if underflow {
			return signed320{}, false
		}
		return signed320{mag: mag, neg: x.neg}, true
	}
}

type shiftSubtractRow struct {
	rho uint256
	tau signed320
}

func selectShiftSubtract(k uint256, limit WidthLimit) FixedSelection {
	if k.isZero() {
		return FixedSelection{
			Candidate: FixedCandidate{
				Tau:     SignedCoefficient{Limbs: [4]uint64{1}},
				Epsilon: 1,
			},
			UseCandidate: true,
			Fallback:     NoFallback,
		}
	}

	rows := [2]shiftSubtractRow{
		{rho: fixedModulus},
		{rho: k, tau: signed320FromUint64(1)},
	}
	var best fixedCandidate
	found := false
	considerShiftSubtractRow(&best, &found, rows[0], int(limit))
	considerShiftSubtractRow(&best, &found, rows[1], int(limit))
	if found {
		return FixedSelection{Candidate: best.external(), UseCandidate: true, Fallback: NoFallback}
	}

	// Each update cancels the current top bit of the larger remainder, so
	// that row loses at least one bit. Across the two rows there can be at
	// most 512 updates before a zero remainder is reached. The explicit cap
	// is a defensive guard around that proof, not an expected fallback.
	for step := 0; step < 512 && !rows[0].rho.isZero() && !rows[1].rho.isZero(); step++ {
		larger, smaller := 0, 1
		if rows[0].rho.cmp(rows[1].rho) < 0 {
			larger, smaller = 1, 0
		}

		shift := rows[larger].rho.bitLen() - rows[smaller].rho.bitLen()
		shifted := shl256(rows[smaller].rho, uint(shift))
		if shifted.cmp(rows[larger].rho) > 0 {
			if shift == 0 {
				return shiftSubtractFallback(best, found)
			}
			shift--
			shifted = shl256(rows[smaller].rho, uint(shift))
		}
		nextRho, borrow := sub256(rows[larger].rho, shifted)
		if borrow != 0 || nextRho.bitLen() >= rows[larger].rho.bitLen() {
			return shiftSubtractFallback(best, found)
		}
		nextTau, ok := subShifted320(rows[larger].tau, rows[smaller].tau, uint(shift))
		if !ok || nextTau.mag[4] != 0 {
			return shiftSubtractFallback(best, found)
		}
		rows[larger] = shiftSubtractRow{rho: nextRho, tau: nextTau}
		considerShiftSubtractRow(&best, &found, rows[larger], int(limit))
		if found {
			// The API asks for any exact candidate within the configured
			// width, not the shortest candidate. Stopping at the first
			// admissible row is both safe and the principal cost advantage
			// over the exhaustive semiconvergent oracle.
			return FixedSelection{Candidate: best.external(), UseCandidate: true, Fallback: NoFallback}
		}
	}

	if !found {
		return FixedSelection{Fallback: FallbackWidthExceeded}
	}
	return FixedSelection{Candidate: best.external(), UseCandidate: true, Fallback: NoFallback}
}

func shiftSubtractFallback(best fixedCandidate, found bool) FixedSelection {
	if !found {
		return FixedSelection{Fallback: FallbackWidthExceeded}
	}
	// Defensive arithmetic fallback. A retained candidate is still exact and
	// admissible, so it remains safe to use even if a later row violated an
	// internal bound.
	return FixedSelection{Candidate: best.external(), UseCandidate: true, Fallback: NoFallback}
}

func considerShiftSubtractRow(best *fixedCandidate, found *bool, row shiftSubtractRow, limit int) {
	if row.tau.isZero() || !row.tau.odd() || row.rho.bitLen() > limit || row.tau.bitLen() > limit {
		return
	}
	tau, ok := row.tau.external()
	if !ok {
		return
	}
	candidate := fixedCandidate{
		rho:     newSigned256(row.rho, false),
		tau:     newSigned256(uint256(tau.Limbs), tau.Negative),
		epsilon: 1,
	}
	if !*found || betterFixed(candidate, *best) {
		*best = candidate
		*found = true
	}
}
