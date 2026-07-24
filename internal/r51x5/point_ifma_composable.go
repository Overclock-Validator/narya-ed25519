package r51x5

// IFMAPointX4 stores four extended-coordinate points whose coordinates obey
// the composable u52 limb contract. It is an experimental arithmetic type;
// no verifier dispatch selects it.
type IFMAPointX4 struct {
	X IFMAElementX4
	Y IFMAElementX4
	Z IFMAElementX4
	T IFMAElementX4
}

// IFMAPointX8 is the eight-lane analogue of IFMAPointX4.
type IFMAPointX8 struct {
	X IFMAElementX8
	Y IFMAElementX8
	Z IFMAElementX8
	T IFMAElementX8
}

// The composable point-add formulas only read 2d. Keep the lane broadcasts in
// read-only package storage so the hot loop does not rebuild and re-import the
// same reduced constant for every selected digit.
var (
	ifmaCurve2DX4 = func() IFMAElementX4 {
		reduced := broadcastX4(&curve2D)
		var out IFMAElementX4
		out.SetReduced(&reduced)
		return out
	}()
	ifmaCurve2DX8 = func() IFMAElementX8 {
		reduced := broadcastX8(&curve2D)
		var out IFMAElementX8
		out.SetReduced(&reduced)
		return out
	}()
)

// SetReduced imports a reduced four-lane point.
func (p *IFMAPointX4) SetReduced(q *PointX4) *IFMAPointX4 {
	p.X.SetReduced(&q.X)
	p.Y.SetReduced(&q.Y)
	p.Z.SetReduced(&q.Z)
	p.T.SetReduced(&q.T)
	return p
}

// SetReduced imports a reduced eight-lane point.
func (p *IFMAPointX8) SetReduced(q *PointX8) *IFMAPointX8 {
	p.X.SetReduced(&q.X)
	p.Y.SetReduced(&q.Y)
	p.Z.SetReduced(&q.Z)
	p.T.SetReduced(&q.T)
	return p
}

// Reduced canonically reduces each coordinate at an explicit four-lane
// boundary. Add and Double never invoke this operation internally.
func (p *IFMAPointX4) Reduced() PointX4 {
	return PointX4{
		X: p.X.Reduced(),
		Y: p.Y.Reduced(),
		Z: p.Z.Reduced(),
		T: p.T.Reduced(),
	}
}

// Reduced is the eight-lane boundary analogue of IFMAPointX4.Reduced.
func (p *IFMAPointX8) Reduced() PointX8 {
	return PointX8{
		X: p.X.Reduced(),
		Y: p.Y.Reduced(),
		Z: p.Z.Reduced(),
		T: p.T.Reduced(),
	}
}

type ifmaComposableMulX4 func(out, x, y *IFMAElementX4) error
type ifmaComposableMulX8 func(out, x, y *IFMAElementX8) error

// ExperimentalIFMAPointAddComposableX4 computes a+b without canonicalizing
// any intermediate field product. Each multiply is followed only by the
// single carry/fold pass needed to re-establish the u52 input contract.
// Inputs and output may alias; out is unchanged on error.
func ExperimentalIFMAPointAddComposableX4(out, a, b *IFMAPointX4) error {
	if err := checkIFMAComposablePointsX4(a, b); err != nil {
		return err
	}
	return ifmaPointAddComposableStaticX4(out, a, b)
}

// ExperimentalIFMAPointAddComposableX8 is the eight-lane analogue.
func ExperimentalIFMAPointAddComposableX8(out, a, b *IFMAPointX8) error {
	if err := checkIFMAComposablePointsX8(a, b); err != nil {
		return err
	}
	return ifmaPointAddComposableStaticX8(out, a, b)
}

// ExperimentalIFMAPointDoubleComposableX4 computes 2q within the composable
// domain. Inputs and output may alias; out is unchanged on error.
func ExperimentalIFMAPointDoubleComposableX4(out, q *IFMAPointX4) error {
	if err := checkIFMAComposablePointsX4(q); err != nil {
		return err
	}
	return ifmaPointDoubleComposableStaticX4(out, q)
}

// ExperimentalIFMAPointDoubleComposableX8 is the eight-lane analogue.
func ExperimentalIFMAPointDoubleComposableX8(out, q *IFMAPointX8) error {
	if err := checkIFMAComposablePointsX8(q); err != nil {
		return err
	}
	return ifmaPointDoubleComposableStaticX8(out, q)
}

// These statically bound formula cores deliberately duplicate the small
// scheduling scaffold below. Passing multiplication as a function value makes
// the Go compiler conservatively move every point-formula temporary to the
// heap. CPU and u52 input checks are performed once by the public wrappers or
// a larger gated workspace; every product still performs carry/fold from its
// analytically bounded u61 form. The injected variants remain independent
// non-IFMA test oracles; the runtime experiment uses only these allocation-free
// call sites.
func ifmaPointAddComposableStaticX4(out, a, b *IFMAPointX4) error {
	aa, bb := *a, *b
	var yMinusX1, yPlusX1, yMinusX2, yPlusX2 IFMAElementX4
	yMinusX1.Subtract(&aa.Y, &aa.X)
	yPlusX1.Add(&aa.Y, &aa.X)
	yMinusX2.Subtract(&bb.Y, &bb.X)
	yPlusX2.Add(&bb.Y, &bb.X)

	var A, B, C, D, E, F, G, H IFMAElementX4
	if err := ifmaMultiplyComposableUncheckedX4(&A, &yMinusX1, &yMinusX2); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX4(&B, &yPlusX1, &yPlusX2); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX4(&C, &aa.T, &bb.T); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX4(&C, &C, &ifmaCurve2DX4); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX4(&D, &aa.Z, &bb.Z); err != nil {
		return err
	}
	D.Add(&D, &D)
	E.Subtract(&B, &A)
	F.Subtract(&D, &C)
	G.Add(&D, &C)
	H.Add(&B, &A)

	var result IFMAPointX4
	if err := ifmaMultiplyComposableUncheckedX4(&result.X, &E, &F); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX4(&result.Y, &G, &H); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX4(&result.T, &E, &H); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX4(&result.Z, &F, &G); err != nil {
		return err
	}
	*out = result
	return nil
}

func ifmaPointAddComposableStaticX8(out, a, b *IFMAPointX8) error {
	aa, bb := *a, *b
	var yMinusX1, yPlusX1, yMinusX2, yPlusX2 IFMAElementX8
	yMinusX1.Subtract(&aa.Y, &aa.X)
	yPlusX1.Add(&aa.Y, &aa.X)
	yMinusX2.Subtract(&bb.Y, &bb.X)
	yPlusX2.Add(&bb.Y, &bb.X)

	var A, B, C, D, E, F, G, H IFMAElementX8
	if err := ifmaMultiplyComposableUncheckedX8(&A, &yMinusX1, &yMinusX2); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX8(&B, &yPlusX1, &yPlusX2); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX8(&C, &aa.T, &bb.T); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX8(&C, &C, &ifmaCurve2DX8); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX8(&D, &aa.Z, &bb.Z); err != nil {
		return err
	}
	D.Add(&D, &D)
	E.Subtract(&B, &A)
	F.Subtract(&D, &C)
	G.Add(&D, &C)
	H.Add(&B, &A)

	var result IFMAPointX8
	if err := ifmaMultiplyComposableUncheckedX8(&result.X, &E, &F); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX8(&result.Y, &G, &H); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX8(&result.T, &E, &H); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX8(&result.Z, &F, &G); err != nil {
		return err
	}
	*out = result
	return nil
}

func ifmaPointDoubleComposableStaticX4(out, q *IFMAPointX4) error {
	qq := *q
	var A, B, C, D, E, F, G, H, xPlusY IFMAElementX4
	if err := ifmaMultiplyComposableUncheckedX4(&A, &qq.X, &qq.X); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX4(&B, &qq.Y, &qq.Y); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX4(&C, &qq.Z, &qq.Z); err != nil {
		return err
	}
	C.Add(&C, &C)
	D.Negate(&A)
	xPlusY.Add(&qq.X, &qq.Y)
	if err := ifmaMultiplyComposableUncheckedX4(&E, &xPlusY, &xPlusY); err != nil {
		return err
	}
	E.Subtract(&E, &A)
	E.Subtract(&E, &B)
	G.Add(&D, &B)
	F.Subtract(&G, &C)
	H.Subtract(&D, &B)

	var result IFMAPointX4
	if err := ifmaMultiplyComposableUncheckedX4(&result.X, &E, &F); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX4(&result.Y, &G, &H); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX4(&result.T, &E, &H); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX4(&result.Z, &F, &G); err != nil {
		return err
	}
	*out = result
	return nil
}

func ifmaPointDoubleComposableStaticX8(out, q *IFMAPointX8) error {
	qq := *q
	var A, B, C, D, E, F, G, H, xPlusY IFMAElementX8
	if err := ifmaMultiplyComposableUncheckedX8(&A, &qq.X, &qq.X); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX8(&B, &qq.Y, &qq.Y); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX8(&C, &qq.Z, &qq.Z); err != nil {
		return err
	}
	C.Add(&C, &C)
	D.Negate(&A)
	xPlusY.Add(&qq.X, &qq.Y)
	if err := ifmaMultiplyComposableUncheckedX8(&E, &xPlusY, &xPlusY); err != nil {
		return err
	}
	E.Subtract(&E, &A)
	E.Subtract(&E, &B)
	G.Add(&D, &B)
	F.Subtract(&G, &C)
	H.Subtract(&D, &B)

	var result IFMAPointX8
	if err := ifmaMultiplyComposableUncheckedX8(&result.X, &E, &F); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX8(&result.Y, &G, &H); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX8(&result.T, &E, &H); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX8(&result.Z, &F, &G); err != nil {
		return err
	}
	*out = result
	return nil
}

func checkIFMAComposablePointsX4(points ...*IFMAPointX4) error {
	if !ExperimentalIFMAAvailable() {
		return ErrIFMAUnavailable
	}
	for _, point := range points {
		if !isIFMAElementX4(&point.X) || !isIFMAElementX4(&point.Y) || !isIFMAElementX4(&point.Z) || !isIFMAElementX4(&point.T) {
			return errIFMAComposableInputRange
		}
	}
	return nil
}

func checkIFMAComposablePointsX8(points ...*IFMAPointX8) error {
	if !ExperimentalIFMAAvailable() {
		return ErrIFMAUnavailable
	}
	for _, point := range points {
		if !isIFMAElementX8(&point.X) || !isIFMAElementX8(&point.Y) || !isIFMAElementX8(&point.Z) || !isIFMAElementX8(&point.T) {
			return errIFMAComposableInputRange
		}
	}
	return nil
}

func ifmaPointAddComposableX4(out, a, b *IFMAPointX4, mul ifmaComposableMulX4) error {
	aa, bb := *a, *b
	var yMinusX1, yPlusX1, yMinusX2, yPlusX2 IFMAElementX4
	yMinusX1.Subtract(&aa.Y, &aa.X)
	yPlusX1.Add(&aa.Y, &aa.X)
	yMinusX2.Subtract(&bb.Y, &bb.X)
	yPlusX2.Add(&bb.Y, &bb.X)

	var A, B, C, D, E, F, G, H IFMAElementX4
	if err := mul(&A, &yMinusX1, &yMinusX2); err != nil {
		return err
	}
	if err := mul(&B, &yPlusX1, &yPlusX2); err != nil {
		return err
	}
	if err := mul(&C, &aa.T, &bb.T); err != nil {
		return err
	}
	var reducedTwoD ElementX4
	reducedTwoD = broadcastX4(&curve2D)
	var twoD IFMAElementX4
	twoD.SetReduced(&reducedTwoD)
	if err := mul(&C, &C, &twoD); err != nil {
		return err
	}
	if err := mul(&D, &aa.Z, &bb.Z); err != nil {
		return err
	}
	D.Add(&D, &D)
	E.Subtract(&B, &A)
	F.Subtract(&D, &C)
	G.Add(&D, &C)
	H.Add(&B, &A)

	var result IFMAPointX4
	if err := mul(&result.X, &E, &F); err != nil {
		return err
	}
	if err := mul(&result.Y, &G, &H); err != nil {
		return err
	}
	if err := mul(&result.T, &E, &H); err != nil {
		return err
	}
	if err := mul(&result.Z, &F, &G); err != nil {
		return err
	}
	*out = result
	return nil
}

func ifmaPointAddComposableX8(out, a, b *IFMAPointX8, mul ifmaComposableMulX8) error {
	aa, bb := *a, *b
	var yMinusX1, yPlusX1, yMinusX2, yPlusX2 IFMAElementX8
	yMinusX1.Subtract(&aa.Y, &aa.X)
	yPlusX1.Add(&aa.Y, &aa.X)
	yMinusX2.Subtract(&bb.Y, &bb.X)
	yPlusX2.Add(&bb.Y, &bb.X)

	var A, B, C, D, E, F, G, H IFMAElementX8
	if err := mul(&A, &yMinusX1, &yMinusX2); err != nil {
		return err
	}
	if err := mul(&B, &yPlusX1, &yPlusX2); err != nil {
		return err
	}
	if err := mul(&C, &aa.T, &bb.T); err != nil {
		return err
	}
	var reducedTwoD ElementX8
	reducedTwoD = broadcastX8(&curve2D)
	var twoD IFMAElementX8
	twoD.SetReduced(&reducedTwoD)
	if err := mul(&C, &C, &twoD); err != nil {
		return err
	}
	if err := mul(&D, &aa.Z, &bb.Z); err != nil {
		return err
	}
	D.Add(&D, &D)
	E.Subtract(&B, &A)
	F.Subtract(&D, &C)
	G.Add(&D, &C)
	H.Add(&B, &A)

	var result IFMAPointX8
	if err := mul(&result.X, &E, &F); err != nil {
		return err
	}
	if err := mul(&result.Y, &G, &H); err != nil {
		return err
	}
	if err := mul(&result.T, &E, &H); err != nil {
		return err
	}
	if err := mul(&result.Z, &F, &G); err != nil {
		return err
	}
	*out = result
	return nil
}

func ifmaPointDoubleComposableX4(out, q *IFMAPointX4, mul ifmaComposableMulX4) error {
	qq := *q
	var A, B, C, D, E, F, G, H, xPlusY IFMAElementX4
	if err := mul(&A, &qq.X, &qq.X); err != nil {
		return err
	}
	if err := mul(&B, &qq.Y, &qq.Y); err != nil {
		return err
	}
	if err := mul(&C, &qq.Z, &qq.Z); err != nil {
		return err
	}
	C.Add(&C, &C)
	D.Negate(&A)
	xPlusY.Add(&qq.X, &qq.Y)
	if err := mul(&E, &xPlusY, &xPlusY); err != nil {
		return err
	}
	E.Subtract(&E, &A)
	E.Subtract(&E, &B)
	G.Add(&D, &B)
	F.Subtract(&G, &C)
	H.Subtract(&D, &B)

	var result IFMAPointX4
	if err := mul(&result.X, &E, &F); err != nil {
		return err
	}
	if err := mul(&result.Y, &G, &H); err != nil {
		return err
	}
	if err := mul(&result.T, &E, &H); err != nil {
		return err
	}
	if err := mul(&result.Z, &F, &G); err != nil {
		return err
	}
	*out = result
	return nil
}

func ifmaPointDoubleComposableX8(out, q *IFMAPointX8, mul ifmaComposableMulX8) error {
	qq := *q
	var A, B, C, D, E, F, G, H, xPlusY IFMAElementX8
	if err := mul(&A, &qq.X, &qq.X); err != nil {
		return err
	}
	if err := mul(&B, &qq.Y, &qq.Y); err != nil {
		return err
	}
	if err := mul(&C, &qq.Z, &qq.Z); err != nil {
		return err
	}
	C.Add(&C, &C)
	D.Negate(&A)
	xPlusY.Add(&qq.X, &qq.Y)
	if err := mul(&E, &xPlusY, &xPlusY); err != nil {
		return err
	}
	E.Subtract(&E, &A)
	E.Subtract(&E, &B)
	G.Add(&D, &B)
	F.Subtract(&G, &C)
	H.Subtract(&D, &B)

	var result IFMAPointX8
	if err := mul(&result.X, &E, &F); err != nil {
		return err
	}
	if err := mul(&result.Y, &G, &H); err != nil {
		return err
	}
	if err := mul(&result.T, &E, &H); err != nil {
		return err
	}
	if err := mul(&result.Z, &F, &G); err != nil {
		return err
	}
	*out = result
	return nil
}
