package r51x5

// CompareCompressedYFirst compares the canonical compressed encoding of each
// active point with the corresponding caller-provided byte string. It first
// compares projective Y with the raw canonical compressed y-coordinate. Only
// lanes that survive that comparison participate in the cross-group
// inversion needed to recover affine X and compare its sign bit.
//
// Unlike a permissive point decoder, this helper rejects low-255-bit values at
// least p before the projective comparison. The final sign comparison also
// rejects the sign-bit-one encoding of x=0. Consequently, its result is the
// exact literal predicate Encode(point)==encoded for every 32-byte encoded
// value; encoded need not have been decoded first.
//
// The low four bits of active[group] select live lanes. Each active point must
// be a valid extended Edwards point with Z != 0. A violated zero-Z invariant
// always fails closed: it either fails the Y comparison or returns
// errIFMABatchEncodeZeroZ if it reaches inversion. All point coordinates,
// including inactive lanes in selected groups, must obey the composable u52
// range contract.
//
// Output is committed only after the complete schedule succeeds. Selected
// groups are zeroed on a successful no-match result; groups beyond groups are
// unchanged. The workspace is mutable and not safe for concurrent use.
func (w *ExperimentalIFMABatchEncodeWorkspaceX4) CompareCompressedYFirst(
	out *[ExperimentalIFMABatchEncodeMaxX4Groups]uint8,
	points *[ExperimentalIFMABatchEncodeMaxX4Groups]IFMAPointX4,
	active *[ExperimentalIFMABatchEncodeMaxX4Groups]uint8,
	encoded *[ExperimentalIFMABatchEncodeMaxX4Groups][X4Lanes][32]byte,
	groups int,
) error {
	if !ExperimentalIFMAAvailable() {
		return ErrIFMAUnavailable
	}
	ops := decode2IFMAOpsX4{hardware: true, uncheckedInputs: true}
	return compareCompressedYFirstIFMAX4(w, out, points, active, encoded, groups, &ops)
}

// compareCompressedYFirstIFMAModelX4 executes the same schedule through the
// reduced scalar-lane multiplication oracle. It keeps the comparator fully
// testable on machines without AVX-512 IFMA.
func compareCompressedYFirstIFMAModelX4(
	w *ExperimentalIFMABatchEncodeWorkspaceX4,
	out *[ExperimentalIFMABatchEncodeMaxX4Groups]uint8,
	points *[ExperimentalIFMABatchEncodeMaxX4Groups]IFMAPointX4,
	active *[ExperimentalIFMABatchEncodeMaxX4Groups]uint8,
	encoded *[ExperimentalIFMABatchEncodeMaxX4Groups][X4Lanes][32]byte,
	groups int,
) error {
	ops := decode2IFMAOpsX4{}
	return compareCompressedYFirstIFMAX4(w, out, points, active, encoded, groups, &ops)
}

func compareCompressedYFirstIFMAX4(
	w *ExperimentalIFMABatchEncodeWorkspaceX4,
	out *[ExperimentalIFMABatchEncodeMaxX4Groups]uint8,
	points *[ExperimentalIFMABatchEncodeMaxX4Groups]IFMAPointX4,
	active *[ExperimentalIFMABatchEncodeMaxX4Groups]uint8,
	encoded *[ExperimentalIFMABatchEncodeMaxX4Groups][X4Lanes][32]byte,
	groups int,
	ops *decode2IFMAOpsX4,
) error {
	if groups < 1 || groups > ExperimentalIFMABatchEncodeMaxX4Groups {
		return errIFMABatchEncodeGroupCount
	}

	// Validate the only external composable boundary before using unchecked
	// hardware products. Match the literal encoder's whole-point policy: even
	// inactive coordinates in selected groups must remain in the u52 domain.
	var anyActive uint8
	for group := 0; group < groups; group++ {
		if active[group]&^uint8(0x0f) != 0 {
			return errIFMABatchEncodeActiveMask
		}
		point := &points[group]
		if !isIFMAElementX4(&point.X) || !isIFMAElementX4(&point.Y) ||
			!isIFMAElementX4(&point.Z) || !isIFMAElementX4(&point.T) {
			return errIFMAComposableInputRange
		}
		anyActive |= active[group]
	}

	var staged, survivors, requestedSigns [ExperimentalIFMABatchEncodeMaxX4Groups]uint8
	if anyActive == 0 {
		for group := 0; group < groups; group++ {
			out[group] = 0
		}
		return nil
	}

	// Encode(Q) stores canonical affine y in the low 255 bits. Therefore the
	// equality can be tested without inversion as Y_Q == y_R*Z_Q. Subtract in
	// the composable domain and reduce the difference before the zero test;
	// redundant u52 limbs must never be compared directly.
	var anySurvivor uint8
	for group := 0; group < groups; group++ {
		mask := active[group] & 0x0f
		if mask == 0 {
			continue
		}
		y, canonical, signs := canonicalCompressedYX4(&encoded[group], mask)
		requestedSigns[group] = signs
		if canonical == 0 {
			continue
		}
		var yIFMA, scaledY, difference IFMAElementX4
		yIFMA.SetReduced(&y)
		if err := ops.mul(&scaledY, &yIFMA, &points[group].Z); err != nil {
			return err
		}
		difference.Subtract(&points[group].Y, &scaledY)
		reducedDifference := difference.Reduced()
		zero := ElementX4{}
		survivors[group] = canonical & equalMaskX4(&reducedDifference, &zero)
		anySurvivor |= survivors[group]
	}

	// Random malformed R values normally leave no survivors. Avoid the fixed
	// 254-square inversion chain entirely in that common invalid-batch case.
	if anySurvivor == 0 {
		for group := 0; group < groups; group++ {
			out[group] = 0
		}
		return nil
	}

	if err := batchInvertPointZX4(&w.inverseZ, &w.prefix, points, &survivors, groups, ops); err != nil {
		return err
	}
	for group := 0; group < groups; group++ {
		mask := survivors[group] & 0x0f
		if mask == 0 {
			continue
		}
		var affineX IFMAElementX4
		if err := ops.mul(&affineX, &points[group].X, &w.inverseZ[group]); err != nil {
			return err
		}
		x := affineX.Reduced()
		staged[group] = mask &^ (negativeMaskX4(&x) ^ requestedSigns[group])
	}

	for group := 0; group < groups; group++ {
		out[group] = staged[group]
	}
	return nil
}

// canonicalCompressedYX4 extracts four low-255-bit y-coordinates and their x
// sign bits. canonical is restricted to active lanes whose low 255 bits are
// strictly less than p. Inactive and noncanonical lanes import one so they
// remain harmless if a caller later widens a mask by mistake.
func canonicalCompressedYX4(in *[X4Lanes][32]byte, active uint8) (y ElementX4, canonical, signs uint8) {
	var values [X4Lanes]Element
	for lane := 0; lane < X4Lanes; lane++ {
		laneMask := uint8(1 << lane)
		values[lane].One()
		if active&laneMask == 0 {
			continue
		}
		signs |= (in[lane][31] >> 7) << lane
		candidate := in[lane]
		candidate[31] &= 0x7f
		if _, err := values[lane].SetCanonicalBytes(candidate[:]); err != nil {
			values[lane].One()
			continue
		}
		canonical |= laneMask
	}
	y.SetElements(&values)
	return y, canonical, signs
}
