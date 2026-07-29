package r51x5

// quadPackedCachedIdentityValueX4 returns the cached representation of the
// Edwards identity: [Y-X, Y+X, 2dT, 2Z] = [1, 1, 0, 2].
func quadPackedCachedIdentityValueX4() quadPackedCachedPointX4 {
	var identity quadPackedCachedPointX4
	identity.coordinates.limbs[0] = [X4Lanes]uint64{1, 1, 0, 2}
	return identity
}

// evaluateQuadTwoChainNAFVerifyX8Experiment computes [s]B-[k]A as two
// independent coordinate-parallel point chains packed into the low and high
// halves of one ZMM register. It is intentionally an experimental seam: the
// ordinary verifier supplies two chains without changing the verification
// equation, letting hardware measurements isolate whether the orientation is
// useful before HEEA or any other scalar transformation is considered.
//
// The low half evaluates -[k]A and the high half evaluates [s]B. A zero digit
// in one half selects the cached identity while the other half advances. The
// two completed terms are combined with the existing x4 cached-add oracle.
func evaluateQuadTwoChainNAFVerifyX8Experiment(
	out *quadPackedPointX4,
	aTable *quadNAFTable5X4,
	bTable *quadNAFTable8X4,
	s, k *[32]byte,
) (bool, error) {
	identity := quadPackedIdentityValueX4()
	if !ExperimentalIFMAAvailable() {
		*out = identity
		return false, ErrIFMAUnavailable
	}

	var aNAF, bNAF [256]int8
	valid := recodeQuadCanonicalNAFX4(&aNAF, k, 5)
	valid = recodeQuadCanonicalNAFX4(&bNAF, s, 8) && valid
	if !valid {
		*out = identity
		return false, nil
	}

	packed := packQuadTwoChainPointsX8(&identity, &identity)
	high := 255
	for ; high >= 0 && aNAF[high] == 0 && bNAF[high] == 0; high-- {
	}

	cachedIdentity := quadPackedCachedIdentityValueX4()
	var doubleWorkspace quadTwoChainDoubleWorkspaceX8
	var addWorkspace quadTwoChainCachedAddWorkspaceX8
	for bit := high; bit >= 0; bit-- {
		if err := quadTwoChainDoubleHardwareWorkspaceUncheckedX8(&packed, &packed, &doubleWorkspace); err != nil {
			return false, err
		}

		aDigit := -aNAF[bit]
		bDigit := bNAF[bit]
		if aDigit == 0 && bDigit == 0 {
			continue
		}

		var aNegative, bNegative quadPackedCachedPointX4
		aSelected := &cachedIdentity
		bSelected := &cachedIdentity
		if aDigit != 0 {
			aSelected = selectQuadNAFEntryX4(&aNegative, aTable.positive[:], aDigit)
		}
		if bDigit != 0 {
			bSelected = selectQuadNAFEntryX4(&bNegative, bTable.positive[:], bDigit)
		}
		cached := packQuadTwoChainCachedX8(aSelected, bSelected)
		if err := quadTwoChainCachedAddHardwareWorkspaceUncheckedX8(&packed, &packed, &cached, &addWorkspace); err != nil {
			return false, err
		}
	}

	terms := unpackQuadTwoChainPointsX8(&packed)
	var highCached quadPackedCachedPointX4
	hardwareOps := quadDSMOperationsX4{hardware: true}
	if err := quadCachePackedPointX4(&highCached, &terms[1], hardwareOps); err != nil {
		return false, err
	}
	var combineWorkspace quadPointAddCachedWorkspaceX4
	if err := quadPointAddCachedHardwareWorkspaceUncheckedX4(
		out, &terms[0], &highCached, &combineWorkspace,
	); err != nil {
		return false, err
	}
	return true, nil
}
