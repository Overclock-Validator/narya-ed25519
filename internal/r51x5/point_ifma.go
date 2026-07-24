package r51x5

// ExperimentalIFMAPointAddX8 sets out=a+b using the correctness-first x8
// IFMA field bridge. Field multiplication is vectorized, while additions,
// subtractions, negation, and canonicalization remain in Go. This function is
// not wired into PointX8.Add or any verification backend and makes no complete
// point-operation performance claim.
//
// Inputs and output may alias. On an unavailable CPU, an out-of-range input,
// or any field-kernel failure, out is unchanged.
func ExperimentalIFMAPointAddX8(out, a, b *PointX8) error {
	if err := checkExperimentalIFMAPointsX8(a, b); err != nil {
		return err
	}

	var yMinusX1, yPlusX1, yMinusX2, yPlusX2 ElementX8
	yMinusX1.Subtract(&a.Y, &a.X)
	yPlusX1.Add(&a.Y, &a.X)
	yMinusX2.Subtract(&b.Y, &b.X)
	yPlusX2.Add(&b.Y, &b.X)

	var A, B, C, D, E, F, G, H ElementX8
	if err := ExperimentalIFMAMultiplyX8(&A, &yMinusX1, &yMinusX2); err != nil {
		return err
	}
	if err := ExperimentalIFMAMultiplyX8(&B, &yPlusX1, &yPlusX2); err != nil {
		return err
	}
	if err := ExperimentalIFMAMultiplyX8(&C, &a.T, &b.T); err != nil {
		return err
	}
	twoD := broadcastX8(&curve2D)
	if err := ExperimentalIFMAMultiplyX8(&C, &C, &twoD); err != nil {
		return err
	}
	if err := ExperimentalIFMAMultiplyX8(&D, &a.Z, &b.Z); err != nil {
		return err
	}
	D.Add(&D, &D)
	E.Subtract(&B, &A)
	F.Subtract(&D, &C)
	G.Add(&D, &C)
	H.Add(&B, &A)

	var result PointX8
	if err := ExperimentalIFMAMultiplyX8(&result.X, &E, &F); err != nil {
		return err
	}
	if err := ExperimentalIFMAMultiplyX8(&result.Y, &G, &H); err != nil {
		return err
	}
	if err := ExperimentalIFMAMultiplyX8(&result.T, &E, &H); err != nil {
		return err
	}
	if err := ExperimentalIFMAMultiplyX8(&result.Z, &F, &G); err != nil {
		return err
	}
	*out = result
	return nil
}

// ExperimentalIFMAPointDoubleX8 sets out=2*q through the checked x8 IFMA
// field bridge. Inputs and output may alias; out is unchanged on error.
func ExperimentalIFMAPointDoubleX8(out, q *PointX8) error {
	if err := checkExperimentalIFMAPointsX8(q); err != nil {
		return err
	}

	var A, B, C, D, E, F, G, H, xPlusY ElementX8
	if err := ExperimentalIFMASquareX8(&A, &q.X); err != nil {
		return err
	}
	if err := ExperimentalIFMASquareX8(&B, &q.Y); err != nil {
		return err
	}
	if err := ExperimentalIFMASquareX8(&C, &q.Z); err != nil {
		return err
	}
	C.Add(&C, &C)
	D.Negate(&A)
	xPlusY.Add(&q.X, &q.Y)
	if err := ExperimentalIFMASquareX8(&E, &xPlusY); err != nil {
		return err
	}
	E.Subtract(&E, &A)
	E.Subtract(&E, &B)
	G.Add(&D, &B)
	F.Subtract(&G, &C)
	H.Subtract(&D, &B)

	var result PointX8
	if err := ExperimentalIFMAMultiplyX8(&result.X, &E, &F); err != nil {
		return err
	}
	if err := ExperimentalIFMAMultiplyX8(&result.Y, &G, &H); err != nil {
		return err
	}
	if err := ExperimentalIFMAMultiplyX8(&result.T, &E, &H); err != nil {
		return err
	}
	if err := ExperimentalIFMAMultiplyX8(&result.Z, &F, &G); err != nil {
		return err
	}
	*out = result
	return nil
}

// ExperimentalIFMAPointEqualAffineX8 compares projective p with affine q
// using both cross-products. All q.Z lanes are required by contract to equal
// one. It returns a zero mask on error.
func ExperimentalIFMAPointEqualAffineX8(p, q *PointX8) (uint8, error) {
	if err := checkExperimentalIFMAPointsX8(p, q); err != nil {
		return 0, err
	}
	var qxpz, qypz ElementX8
	if err := ExperimentalIFMAMultiplyX8(&qxpz, &q.X, &p.Z); err != nil {
		return 0, err
	}
	if err := ExperimentalIFMAMultiplyX8(&qypz, &q.Y, &p.Z); err != nil {
		return 0, err
	}
	var mask uint8
	for lane := 0; lane < X8Lanes; lane++ {
		px, py := p.X.Lane(lane), p.Y.Lane(lane)
		qx, qy := qxpz.Lane(lane), qypz.Lane(lane)
		if px.Equal(&qx)&py.Equal(&qy) != 0 {
			mask |= 1 << lane
		}
	}
	return mask, nil
}

// ExperimentalIFMAPointAddX4 is the AVX-512VL/YMM four-lane analogue of
// ExperimentalIFMAPointAddX8. Inputs and output may alias; out is unchanged
// on error.
func ExperimentalIFMAPointAddX4(out, a, b *PointX4) error {
	if err := checkExperimentalIFMAPointsX4(a, b); err != nil {
		return err
	}

	var yMinusX1, yPlusX1, yMinusX2, yPlusX2 ElementX4
	yMinusX1.Subtract(&a.Y, &a.X)
	yPlusX1.Add(&a.Y, &a.X)
	yMinusX2.Subtract(&b.Y, &b.X)
	yPlusX2.Add(&b.Y, &b.X)

	var A, B, C, D, E, F, G, H ElementX4
	if err := ExperimentalIFMAMultiplyX4(&A, &yMinusX1, &yMinusX2); err != nil {
		return err
	}
	if err := ExperimentalIFMAMultiplyX4(&B, &yPlusX1, &yPlusX2); err != nil {
		return err
	}
	if err := ExperimentalIFMAMultiplyX4(&C, &a.T, &b.T); err != nil {
		return err
	}
	twoD := broadcastX4(&curve2D)
	if err := ExperimentalIFMAMultiplyX4(&C, &C, &twoD); err != nil {
		return err
	}
	if err := ExperimentalIFMAMultiplyX4(&D, &a.Z, &b.Z); err != nil {
		return err
	}
	D.Add(&D, &D)
	E.Subtract(&B, &A)
	F.Subtract(&D, &C)
	G.Add(&D, &C)
	H.Add(&B, &A)

	var result PointX4
	if err := ExperimentalIFMAMultiplyX4(&result.X, &E, &F); err != nil {
		return err
	}
	if err := ExperimentalIFMAMultiplyX4(&result.Y, &G, &H); err != nil {
		return err
	}
	if err := ExperimentalIFMAMultiplyX4(&result.T, &E, &H); err != nil {
		return err
	}
	if err := ExperimentalIFMAMultiplyX4(&result.Z, &F, &G); err != nil {
		return err
	}
	*out = result
	return nil
}

// ExperimentalIFMAPointDoubleX4 sets out=2*q through the checked x4 IFMA
// field bridge. Inputs and output may alias; out is unchanged on error.
func ExperimentalIFMAPointDoubleX4(out, q *PointX4) error {
	if err := checkExperimentalIFMAPointsX4(q); err != nil {
		return err
	}

	var A, B, C, D, E, F, G, H, xPlusY ElementX4
	if err := ExperimentalIFMASquareX4(&A, &q.X); err != nil {
		return err
	}
	if err := ExperimentalIFMASquareX4(&B, &q.Y); err != nil {
		return err
	}
	if err := ExperimentalIFMASquareX4(&C, &q.Z); err != nil {
		return err
	}
	C.Add(&C, &C)
	D.Negate(&A)
	xPlusY.Add(&q.X, &q.Y)
	if err := ExperimentalIFMASquareX4(&E, &xPlusY); err != nil {
		return err
	}
	E.Subtract(&E, &A)
	E.Subtract(&E, &B)
	G.Add(&D, &B)
	F.Subtract(&G, &C)
	H.Subtract(&D, &B)

	var result PointX4
	if err := ExperimentalIFMAMultiplyX4(&result.X, &E, &F); err != nil {
		return err
	}
	if err := ExperimentalIFMAMultiplyX4(&result.Y, &G, &H); err != nil {
		return err
	}
	if err := ExperimentalIFMAMultiplyX4(&result.T, &E, &H); err != nil {
		return err
	}
	if err := ExperimentalIFMAMultiplyX4(&result.Z, &F, &G); err != nil {
		return err
	}
	*out = result
	return nil
}

// ExperimentalIFMAPointEqualAffineX4 is the AVX-512VL/YMM four-lane analogue
// of ExperimentalIFMAPointEqualAffineX8.
func ExperimentalIFMAPointEqualAffineX4(p, q *PointX4) (uint8, error) {
	if err := checkExperimentalIFMAPointsX4(p, q); err != nil {
		return 0, err
	}
	var qxpz, qypz ElementX4
	if err := ExperimentalIFMAMultiplyX4(&qxpz, &q.X, &p.Z); err != nil {
		return 0, err
	}
	if err := ExperimentalIFMAMultiplyX4(&qypz, &q.Y, &p.Z); err != nil {
		return 0, err
	}
	var mask uint8
	for lane := 0; lane < X4Lanes; lane++ {
		px, py := p.X.Lane(lane), p.Y.Lane(lane)
		qx, qy := qxpz.Lane(lane), qypz.Lane(lane)
		if px.Equal(&qx)&py.Equal(&qy) != 0 {
			mask |= 1 << lane
		}
	}
	return mask, nil
}

func checkExperimentalIFMAPointsX8(points ...*PointX8) error {
	if !ExperimentalIFMAAvailable() {
		return ErrIFMAUnavailable
	}
	for _, p := range points {
		if !IsReducedX8(p.X.limbs) || !IsReducedX8(p.Y.limbs) ||
			!IsReducedX8(p.Z.limbs) || !IsReducedX8(p.T.limbs) {
			return errIFMAInputRange
		}
	}
	return nil
}

func checkExperimentalIFMAPointsX4(points ...*PointX4) error {
	if !ExperimentalIFMAAvailable() {
		return ErrIFMAUnavailable
	}
	for _, p := range points {
		if !IsReducedX4(p.X.limbs) || !IsReducedX4(p.Y.limbs) ||
			!IsReducedX4(p.Z.limbs) || !IsReducedX4(p.T.limbs) {
			return errIFMAInputRange
		}
	}
	return nil
}
