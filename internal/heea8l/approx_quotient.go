package heea8l

// SelectApproxQuotient is an allocation-free implementation of the
// power-of-two approximate-quotient HEEA schedule from Algorithm 4 of
// "Accelerating EdDSA Signature Verification with Faster Scalar Size
// Halving" (TCHES 2025). The control-flow shape was cross-checked against
// Anza's solana-ed25519 0.2.2 curve25519_heea_vartime implementation.
//
// Narya's arithmetic and admission contract are deliberately different from
// that cofactored modulo-L implementation: rows are computed modulo 8L, all
// signed updates are checked rather than wrapping, and Tau must be a unit
// modulo 8L before a candidate can reach the strict QSM. A miss is an ordinary
// verifier fallback, never a verification verdict. This remains variable-time
// research code and is not wired to backend selection.
func SelectApproxQuotient(kBytes [32]byte, limit WidthLimit) FixedSelection {
	if limit != Width128 && limit != Width132 && limit != Width136 {
		return FixedSelection{Fallback: FallbackInvalidWidth}
	}
	k := uint256FromBytesLE(kBytes)
	if k.cmp(fixedOrder) >= 0 {
		return FixedSelection{Fallback: FallbackInvalidChallenge}
	}
	selection, _ := selectApproxQuotient(k, limit)
	return selection
}

const approxQuotientIterationCap = 384

type approxQuotientStats struct {
	Iterations int
	HitCap     bool
}

type approxQuotientRow struct {
	rho signed320
	tau signed320
}

func selectApproxQuotient(k uint256, limit WidthLimit) (FixedSelection, approxQuotientStats) {
	if k.isZero() {
		return FixedSelection{
			Candidate: FixedCandidate{
				Tau:     SignedCoefficient{Limbs: [4]uint64{1}},
				Epsilon: 1,
			},
			UseCandidate: true,
			Fallback:     NoFallback,
		}, approxQuotientStats{}
	}

	rows := [2]approxQuotientRow{
		{rho: signed320FromUint256(fixedModulus)},
		{rho: signed320FromUint256(k), tau: signed320FromUint64(1)},
	}
	bitLengths := [2]int{fixedModulus.bitLen(), k.bitLen()}
	if candidate, ok := approxQuotientCandidate(rows[1], int(limit)); ok {
		return FixedSelection{Candidate: candidate, UseCandidate: true}, approxQuotientStats{}
	}

	var stats approxQuotientStats
	for !rows[1].rho.isZero() && stats.Iterations < approxQuotientIterationCap {
		if bitLengths[0] < bitLengths[1] {
			rows[0], rows[1] = rows[1], rows[0]
			bitLengths[0], bitLengths[1] = bitLengths[1], bitLengths[0]
		}
		shift := uint(bitLengths[0] - bitLengths[1])
		sameSign := rows[0].rho.neg == rows[1].rho.neg

		var next approxQuotientRow
		var ok bool
		if sameSign {
			next.rho, ok = subShifted320(rows[0].rho, rows[1].rho, shift)
			if ok {
				next.tau, ok = subShifted320(rows[0].tau, rows[1].tau, shift)
			}
		} else {
			next.rho, ok = addShifted320(rows[0].rho, rows[1].rho, shift)
			if ok {
				next.tau, ok = addShifted320(rows[0].tau, rows[1].tau, shift)
			}
		}
		stats.Iterations++
		if !ok || next.rho.mag[4] != 0 || next.tau.mag[4] != 0 {
			return FixedSelection{Fallback: FallbackWidthExceeded}, stats
		}

		nextBits := next.rho.bitLen()
		if candidate, ok := approxQuotientCandidate(next, int(limit)); ok {
			return FixedSelection{Candidate: candidate, UseCandidate: true}, stats
		}
		if nextBits > bitLengths[1] {
			rows[0], bitLengths[0] = next, nextBits
		} else {
			rows[0], rows[1] = rows[1], next
			bitLengths[0], bitLengths[1] = bitLengths[1], nextBits
		}
	}
	if stats.Iterations == approxQuotientIterationCap && !rows[1].rho.isZero() {
		stats.HitCap = true
	}
	return FixedSelection{Fallback: FallbackWidthExceeded}, stats
}

func signed320FromUint256(x uint256) signed320 {
	return signed320{mag: [5]uint64{x[0], x[1], x[2], x[3]}}
}

func negateSigned320(x signed320) signed320 {
	if !x.isZero() {
		x.neg = !x.neg
	}
	return x
}

func addShifted320(x, y signed320, shift uint) (signed320, bool) {
	shifted, overflow := shl320(y.mag, shift)
	if overflow {
		return signed320{}, false
	}
	return subSigned320(x, negateSigned320(signed320{mag: shifted, neg: y.neg}))
}

func approxQuotientCandidate(row approxQuotientRow, limit int) (FixedCandidate, bool) {
	if row.rho.bitLen() > limit || row.tau.bitLen() > limit || !unitMultiplier320(row.tau) {
		return FixedCandidate{}, false
	}
	rho, rhoOK := row.rho.external()
	tau, tauOK := row.tau.external()
	if !rhoOK || !tauOK {
		return FixedCandidate{}, false
	}
	return FixedCandidate{Rho: rho, Tau: tau, Epsilon: 1}, true
}
