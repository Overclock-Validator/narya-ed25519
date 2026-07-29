package r51x5

import "crypto/sha512"

// quadPairedNAFTable5X8 stores two independent width-5 variable-base tables.
// Each ZMM value contains one packed [Y-X,Y+X,2dT,2Z] entry in each 256-bit
// half. The halves never exchange data: low is signature zero and high is
// signature one.
type quadPairedNAFTable5X8 struct {
	positive [8]IFMAElementX8
}

// quadPairedNAFTable8X8 is the corresponding process-wide generator table.
// Both halves contain the same generator multiple, but each half is selected
// and signed independently by its signature's scalar.
type quadPairedNAFTable8X8 struct {
	positive [64]IFMAElementX8
}

var quadTwoChainCachedScaleX8 = packQuadTwoChainElementsX8(&quadCachedScaleX4, &quadCachedScaleX4)

func packQuadTwoChainElementsX8(first, second *IFMAElementX4) IFMAElementX8 {
	var packed IFMAElementX8
	for limb := range packed.limbs {
		copy(packed.limbs[limb][:X4Lanes], first.limbs[limb][:])
		copy(packed.limbs[limb][X4Lanes:], second.limbs[limb][:])
	}
	return packed
}

func quadCacheTwoChainPointX8(out, point *IFMAElementX8) {
	var operand IFMAElementX8
	ifmaQuadTwoChainCachedAddFirstOperandUncheckedX8(&operand.limbs, &point.limbs)
	ifmaMulNormalizedUncheckedX8(&out.limbs, &operand.limbs, &quadTwoChainCachedScaleX8.limbs)
}

func buildQuadPairedNAFTable5X8(out *quadPairedNAFTable5X8, first, second *Point) error {
	firstPacked := new(quadPackedPointX4).setReduced(first)
	secondPacked := new(quadPackedPointX4).setReduced(second)
	current := packQuadTwoChainPointsX8(firstPacked, secondPacked)
	quadCacheTwoChainPointX8(&out.positive[0], &current)

	twice := current
	var doubleWorkspace quadTwoChainDoubleWorkspaceX8
	if err := quadTwoChainDoubleHardwareWorkspaceUncheckedX8(&twice, &twice, &doubleWorkspace); err != nil {
		return err
	}
	var twiceCached IFMAElementX8
	quadCacheTwoChainPointX8(&twiceCached, &twice)

	var addWorkspace quadTwoChainCachedAddWorkspaceX8
	for entry := 1; entry < len(out.positive); entry++ {
		if err := quadTwoChainCachedAddHardwareWorkspaceUncheckedX8(
			&current, &current, &twiceCached, &addWorkspace,
		); err != nil {
			return err
		}
		quadCacheTwoChainPointX8(&out.positive[entry], &current)
	}
	return nil
}

func packQuadPairedGeneratorTableX8(out *quadPairedNAFTable8X8, source *quadNAFTable8X4) {
	for entry := range out.positive {
		out.positive[entry] = packQuadTwoChainCachedX8(
			&source.positive[entry], &source.positive[entry],
		)
	}
}

func copyQuadCachedHalfX8(out, source *IFMAElementX8, half int) {
	base := half * X4Lanes
	for limb := range out.limbs {
		copy(out.limbs[limb][base:base+X4Lanes], source.limbs[limb][base:base+X4Lanes])
	}
}

// selectQuadPairedNAFEntryX8 independently selects one signed odd multiple
// for each half. A zero digit selects the cached identity in that half. The
// only cross-half operation is one lane-wise conditional-negate instruction;
// its mask has disjoint T lanes (2 and 6).
func selectQuadPairedNAFEntryX8(out *IFMAElementX8, positive []IFMAElementX8, digits [2]int8) {
	identity := quadPackedCachedIdentityValueX4()
	*out = packQuadTwoChainCachedX8(&identity, &identity)
	var negativeMask uint8
	for half, digit := range digits {
		if digit == 0 {
			continue
		}
		if digit&1 == 0 {
			panic("r51x5: invalid paired quad NAF digit")
		}
		magnitude := int(digit)
		if magnitude < 0 {
			magnitude = -magnitude
		}
		entry := magnitude / 2
		if entry >= len(positive) {
			panic("r51x5: paired quad NAF digit exceeds table")
		}
		copyQuadCachedHalfX8(out, &positive[entry], half)
		if digit < 0 {
			base := half * X4Lanes
			for limb := range out.limbs {
				out.limbs[limb][base], out.limbs[limb][base+1] =
					out.limbs[limb][base+1], out.limbs[limb][base]
			}
			negativeMask |= 1 << (base + 2)
		}
	}
	if negativeMask != 0 {
		conditionalNegateIFMAElementX8(out, negativeMask)
	}
}

// evaluateQuadPairedNAFVerifyX8 computes two independent equations
// [s_i]B-[k_i]A_i in one ZMM value. This differs from the older two-chain
// experiment, which split the two terms of one equation between halves and
// paid a final point addition. Here each half owns a complete equation and
// directly produces one verdict.
func evaluateQuadPairedNAFVerifyX8(
	out *IFMAElementX8,
	aTable *quadPairedNAFTable5X8,
	bTable *quadPairedNAFTable8X8,
	s, k *[2][32]byte,
	active uint8,
) (uint8, error) {
	active &= 0b11
	identity := quadPackedIdentityValueX4()
	acc := packQuadTwoChainPointsX8(&identity, &identity)
	if active == 0 {
		*out = acc
		return 0, nil
	}

	var aNAF, bNAF [2][256]int8
	for half := range aNAF {
		if active&(1<<half) == 0 {
			continue
		}
		if !recodeQuadCanonicalNAFX4(&aNAF[half], &k[half], 5) ||
			!recodeQuadCanonicalNAFX4(&bNAF[half], &s[half], 8) {
			active &^= 1 << half
		}
	}

	high := 255
	for ; high >= 0; high-- {
		if (active&1 != 0 && (aNAF[0][high] != 0 || bNAF[0][high] != 0)) ||
			(active&2 != 0 && (aNAF[1][high] != 0 || bNAF[1][high] != 0)) {
			break
		}
	}

	var doubleWorkspace quadTwoChainDoubleWorkspaceX8
	var addWorkspace quadTwoChainCachedAddWorkspaceX8
	for bit := high; bit >= 0; bit-- {
		if err := quadTwoChainDoubleHardwareWorkspaceUncheckedX8(&acc, &acc, &doubleWorkspace); err != nil {
			return 0, err
		}

		aDigits := [2]int8{-aNAF[0][bit], -aNAF[1][bit]}
		if active&1 == 0 {
			aDigits[0] = 0
		}
		if active&2 == 0 {
			aDigits[1] = 0
		}
		if aDigits != [2]int8{} {
			var selected IFMAElementX8
			selectQuadPairedNAFEntryX8(&selected, aTable.positive[:], aDigits)
			if err := quadTwoChainCachedAddHardwareWorkspaceUncheckedX8(
				&acc, &acc, &selected, &addWorkspace,
			); err != nil {
				return 0, err
			}
		}

		bDigits := [2]int8{bNAF[0][bit], bNAF[1][bit]}
		if active&1 == 0 {
			bDigits[0] = 0
		}
		if active&2 == 0 {
			bDigits[1] = 0
		}
		if bDigits != [2]int8{} {
			var selected IFMAElementX8
			selectQuadPairedNAFEntryX8(&selected, bTable.positive[:], bDigits)
			if err := quadTwoChainCachedAddHardwareWorkspaceUncheckedX8(
				&acc, &acc, &selected, &addWorkspace,
			); err != nil {
				return 0, err
			}
		}
	}
	*out = acc
	return active, nil
}

// quadPairedEqualDecodedAffineLanesX8 compares the low and high packed points
// with decoded R lanes 1 and 3 respectively. One x8 multiplication computes
// all four projective cross-products, and the returned bits remain in
// signature order.
func quadPairedEqualDecodedAffineLanesX8(q *IFMAElementX8, decoded *PointX8, active uint8) (uint8, error) {
	active &= 0b11
	if active == 0 {
		return 0, nil
	}
	if !isIFMAElementX8(q) {
		return 0, errIFMAComposableInputRange
	}

	qReduced := q.Reduced()
	for half := 0; half < 2; half++ {
		if active&(1<<half) == 0 {
			continue
		}
		qz := qReduced.Lane(half*X4Lanes + 3)
		if qz.IsZero() != 0 {
			active &^= 1 << half
		}
	}

	var affineXY, qZ IFMAElementX8
	for half := 0; half < 2; half++ {
		base := half * X4Lanes
		decodedLane := half*2 + 1
		for limb := range affineXY.limbs {
			affineXY.limbs[limb][base] = decoded.X.limbs[limb][decodedLane]
			affineXY.limbs[limb][base+1] = decoded.Y.limbs[limb][decodedLane]
			qZ.limbs[limb][base] = q.limbs[limb][base+3]
			qZ.limbs[limb][base+1] = q.limbs[limb][base+3]
		}
	}
	var cross IFMAElementX8
	if err := ifmaMultiplyComposableUncheckedX8(&cross, &affineXY, &qZ); err != nil {
		return 0, err
	}
	crossReduced := cross.Reduced()
	for half := 0; half < 2; half++ {
		if active&(1<<half) == 0 {
			continue
		}
		base := half * X4Lanes
		qx, qy := qReduced.Lane(base), qReduced.Lane(base+1)
		rxZ, ryZ := crossReduced.Lane(base), crossReduced.Lane(base+1)
		if qx.Equal(&rxZ)&qy.Equal(&ryZ) == 0 {
			active &^= 1 << half
		}
	}
	return active, nil
}

// VerifyPair verifies exactly two independent inputs under the Dalek strict
// predicate. The verdict slice is always fully initialized. Ordinary invalid
// inputs fail only their own lane; arithmetic/platform failures return an
// error so the public backend can recompute both inputs through its generic
// fault fallback.
func (verifier *ExperimentalPackedStrictVerifierX4) VerifyPair(
	pubs [2]*[32]byte,
	messages [2][]byte,
	signatures [2][]byte,
	verdicts *[2]bool,
) error {
	if verdicts == nil {
		panic("r51x5: nil paired verdict output")
	}
	*verdicts = [2]bool{}
	if verifier == nil || verifier.hash == nil || verifier.pairedBTable == nil {
		return errExperimentalPackedStrictVerifierUninitialized
	}

	var s [2][32]byte
	var live uint8
	for half := 0; half < 2; half++ {
		if packedStrictBytePrechecksX4(pubs[half], signatures[half], &s[half]) {
			live |= 1 << half
		}
	}
	if live == 0 {
		return nil
	}

	var encoded [X8Lanes][32]byte
	var decodeActive uint8
	for half := 0; half < 2; half++ {
		if live&(1<<half) == 0 {
			continue
		}
		encoded[half*2] = *pubs[half]
		copy(encoded[half*2+1][:], signatures[half][:32])
		decodeActive |= 0b11 << (half * 2)
	}
	var decoded PointX8
	decodedValid, err := ExperimentalIFMADecodeX8(&decoded, &encoded, decodeActive)
	if err != nil {
		return err
	}
	for half := 0; half < 2; half++ {
		pairMask := uint8(0b11 << (half * 2))
		if decodedValid&pairMask != pairMask {
			live &^= 1 << half
		}
	}
	if live == 0 {
		return nil
	}

	a := [2]Point{decoded.Lane(0), decoded.Lane(2)}
	var aTable quadPairedNAFTable5X8
	if err := buildQuadPairedNAFTable5X8(&aTable, &a[0], &a[1]); err != nil {
		return err
	}

	var wide [X8Lanes][sha512.Size]byte
	for half := 0; half < 2; half++ {
		if live&(1<<half) == 0 {
			continue
		}
		verifier.hash.Reset()
		_, _ = verifier.hash.Write(signatures[half][:32])
		_, _ = verifier.hash.Write(pubs[half][:])
		_, _ = verifier.hash.Write(messages[half])
		sum := verifier.hash.Sum(wide[half][:0])
		if len(sum) != sha512.Size {
			panic("r51x5: SHA-512 returned an invalid digest length")
		}
	}
	var reducedWide [X8Lanes][32]byte
	if ExperimentalReduceUniformScalarsX8(&reducedWide, &wide, live)&live != live {
		return nil
	}
	k := [2][32]byte{reducedWide[0], reducedWide[1]}

	var q IFMAElementX8
	live, err = evaluateQuadPairedNAFVerifyX8(&q, &aTable, verifier.pairedBTable, &s, &k, live)
	if err != nil || live == 0 {
		return err
	}
	live, err = quadPairedEqualDecodedAffineLanesX8(&q, &decoded, live)
	if err != nil {
		return err
	}
	for half := 0; half < 2; half++ {
		verdicts[half] = live&(1<<half) != 0
	}
	return nil
}
