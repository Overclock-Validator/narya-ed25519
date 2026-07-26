package r51x5

// ExperimentalIFMADecodeComposableX8 decodes eight compressed points directly
// into the u52 representation consumed by the x8 variable-base table builder.
// It preserves ExperimentalIFMADecodeX8's permissive decoding and inactive /
// invalid identity semantics, but avoids reducing T and then importing all four
// coordinates back into IFMA form at the next pipeline boundary. The receiver
// is unchanged on error.
//
// This remains an experiment until a complete decode-plus-table-build benchmark
// shows a gain over ExperimentalIFMADecodeX8 followed by SetReduced.
func ExperimentalIFMADecodeComposableX8(
	out *IFMAPointX8,
	encoded *[X8Lanes][32]byte,
	active uint8,
) (valid uint8, err error) {
	if !ExperimentalIFMAAvailable() {
		return 0, ErrIFMAUnavailable
	}
	ops := decode2IFMAOpsX8{hardware: true, uncheckedInputs: true}
	return decodeComposableIFMAX8(out, encoded, active, &ops)
}

func decodeComposableIFMAModelX8(
	out *IFMAPointX8,
	encoded *[X8Lanes][32]byte,
	active uint8,
) (valid uint8, err error) {
	ops := decode2IFMAOpsX8{}
	return decodeComposableIFMAX8(out, encoded, active, &ops)
}

func decodeComposableIFMAX8(
	out *IFMAPointX8,
	encoded *[X8Lanes][32]byte,
	active uint8,
	ops *decode2IFMAOpsX8,
) (valid uint8, err error) {
	yReduced := decodeY8(encoded, active)
	oneReduced := broadcastX8(new(Element).One())
	dReduced := broadcastX8(&curveD)
	var y, one, d, y2, u, v IFMAElementX8
	y.SetReduced(&yReduced)
	one.SetReduced(&oneReduced)
	d.SetReduced(&dReduced)
	if err = ops.validateOneImports(&y, &one, &d); err != nil {
		return 0, err
	}
	if err = ops.mul(&y2, &y, &y); err != nil {
		return 0, err
	}
	u.Subtract(&y2, &one)
	if err = ops.mul(&v, &y2, &d); err != nil {
		return 0, err
	}
	v.Add(&v, &one)

	var x IFMAElementX8
	requestedSigns := encodedSignMaskX8(encoded, active)
	if valid, err = sqrtRatioSignedComposableIFMAX8(&x, &u, &v, requestedSigns, ops); err != nil {
		return 0, err
	}
	valid &= active

	var t IFMAElementX8
	if err = ops.mul(&t, &x, &y); err != nil {
		return 0, err
	}

	var zero IFMAElementX8
	result := IFMAPointX8{Y: one, Z: one}
	decodeSelectIFMAX8(&result.X, &zero, &x, valid)
	decodeSelectIFMAX8(&result.Y, &one, &y, valid)
	decodeSelectIFMAX8(&result.T, &zero, &t, valid)
	*out = result
	return valid, nil
}

// sqrtRatioSignedComposableIFMAX8 is sqrtRatioIFMAX8 with an IFMA-domain
// result. Equality and parity still use canonical reductions, but the selected
// root never makes the redundant reduced -> IFMA round trip. requestedSigns
// contains the original public compressed-point sign bits.
func sqrtRatioSignedComposableIFMAX8(
	z, u, v *IFMAElementX8,
	requestedSigns uint8,
	ops *decode2IFMAOpsX8,
) (square uint8, err error) {
	var uv, pow, root IFMAElementX8
	if err = ops.mul(&uv, u, v); err != nil {
		return 0, err
	}
	if err = pow22523IFMAX8(&pow, &uv, ops); err != nil {
		return 0, err
	}
	if err = ops.mul(&root, u, &pow); err != nil {
		return 0, err
	}

	var root2, check, negU IFMAElementX8
	if err = ops.mul(&root2, &root, &root); err != nil {
		return 0, err
	}
	if err = ops.mul(&check, v, &root2); err != nil {
		return 0, err
	}
	negU.Negate(u)
	rootIReduced := broadcastX8(&sqrtM1)
	var rootI, negUI IFMAElementX8
	rootI.SetReduced(&rootIReduced)
	if err = ops.mul(&negUI, &negU, &rootI); err != nil {
		return 0, err
	}

	checkReduced, uReduced := check.Reduced(), u.Reduced()
	negUReduced, negUIReduced := negU.Reduced(), negUI.Reduced()
	correct := equalMaskX8(&checkReduced, &uReduced)
	flipped := equalMaskX8(&checkReduced, &negUReduced)
	flippedI := equalMaskX8(&checkReduced, &negUIReduced)

	var rootTimesI IFMAElementX8
	if err = ops.mul(&rootTimesI, &root, &rootI); err != nil {
		return 0, err
	}
	decodeSelectIFMAX8(&root, &root, &rootTimesI, flipped|flippedI)

	// Compressed Edwards points request the parity of canonical affine x. One
	// XOR combines the conventional "choose nonnegative root" and "apply the
	// encoded sign" stages into a single composable-domain negation.
	rootReduced := root.Reduced()
	conditionalNegateIFMAElementX8(&root, negativeMaskX8(&rootReduced)^requestedSigns)
	*z = root
	return correct | flipped, nil
}
