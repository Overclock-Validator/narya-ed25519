package r51x5

// ExperimentalIFMADecodeX4 permissively decodes four independent compressed
// Edwards25519 points into the full extended representation required by the
// variable-base DSM. active selects input lanes; invalid and inactive lanes
// are identities and valid is always a subset of active.
//
// This is the single-point control for measuring paired A/R decompression. It
// performs one square-root chain and never decodes a second point. The output
// is unchanged on error, including when IFMA is unavailable.
func ExperimentalIFMADecodeX4(out *PointX4, encoded *[X4Lanes][32]byte, active uint8) (valid uint8, err error) {
	if !ExperimentalIFMAAvailable() {
		return 0, ErrIFMAUnavailable
	}
	ops := decode2IFMAOpsX4{hardware: true, uncheckedInputs: true}
	return decodeIFMAX4(out, encoded, active, &ops)
}

// ExperimentalIFMADecodeX8 is the eight-lane counterpart of
// ExperimentalIFMADecodeX4.
func ExperimentalIFMADecodeX8(out *PointX8, encoded *[X8Lanes][32]byte, active uint8) (valid uint8, err error) {
	if !ExperimentalIFMAAvailable() {
		return 0, ErrIFMAUnavailable
	}
	ops := decode2IFMAOpsX8{hardware: true, uncheckedInputs: true}
	return decodeIFMAX8(out, encoded, active, &ops)
}

// decodeIFMAModelX4 executes the exact single-point schedule through the
// reduced-lane oracle. It exists so every target can test the hardware
// schedule without executing unsupported instructions.
func decodeIFMAModelX4(out *PointX4, encoded *[X4Lanes][32]byte, active uint8) (valid uint8, err error) {
	ops := decode2IFMAOpsX4{}
	return decodeIFMAX4(out, encoded, active, &ops)
}

// decodeIFMAModelX8 is the eight-lane schedule oracle.
func decodeIFMAModelX8(out *PointX8, encoded *[X8Lanes][32]byte, active uint8) (valid uint8, err error) {
	ops := decode2IFMAOpsX8{}
	return decodeIFMAX8(out, encoded, active, &ops)
}

func decodeIFMAX4(out *PointX4, encoded *[X4Lanes][32]byte, active uint8, ops *decode2IFMAOpsX4) (valid uint8, err error) {
	active &= 0x0f
	var x, y ElementX4
	if valid, err = decodeOneIFMAX4(&x, &y, encoded, active, ops); err != nil {
		return 0, err
	}

	// A DSM point needs T=x*y. Keep this multiply inside the atomic boundary:
	// no caller-visible coordinates are committed until every IFMA operation
	// has succeeded.
	var xIFMA, yIFMA, tIFMA IFMAElementX4
	xIFMA.SetReduced(&x)
	yIFMA.SetReduced(&y)
	if err = ops.mul(&tIFMA, &xIFMA, &yIFMA); err != nil {
		return 0, err
	}
	t := tIFMA.Reduced()

	one := broadcastX4(new(Element).One())
	zero := ElementX4{}
	result := PointX4{Y: one, Z: one}
	decodeSelectX4(&result.X, &zero, &x, valid)
	decodeSelectX4(&result.Y, &one, &y, valid)
	decodeSelectX4(&result.T, &zero, &t, valid)
	*out = result
	return valid, nil
}

func decodeIFMAX8(out *PointX8, encoded *[X8Lanes][32]byte, active uint8, ops *decode2IFMAOpsX8) (valid uint8, err error) {
	var x, y ElementX8
	if valid, err = decodeOneIFMAX8(&x, &y, encoded, active, ops); err != nil {
		return 0, err
	}

	var xIFMA, yIFMA, tIFMA IFMAElementX8
	xIFMA.SetReduced(&x)
	yIFMA.SetReduced(&y)
	if err = ops.mul(&tIFMA, &xIFMA, &yIFMA); err != nil {
		return 0, err
	}
	t := tIFMA.Reduced()

	one := broadcastX8(new(Element).One())
	zero := ElementX8{}
	result := PointX8{Y: one, Z: one}
	decodeSelectX8(&result.X, &zero, &x, valid)
	decodeSelectX8(&result.Y, &one, &y, valid)
	decodeSelectX8(&result.T, &zero, &t, valid)
	*out = result
	return valid, nil
}
