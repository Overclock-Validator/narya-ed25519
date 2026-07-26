package r51x5

// IFMAPointX4 stores four extended-coordinate points whose coordinates obey
// the composable u52 limb contract. The explicitly forced r51 verifier uses
// this type; automatic backend selection does not.
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

// SplitX4 copies lanes 0..3 and 4..7 into two four-lane composable points.
// It performs no field arithmetic or normalization: every u52 limb is copied
// bit-for-bit, so the output has exactly the input range contract. This layout
// boundary lets an x8 evaluator reuse the independently audited x4 batch-Q
// encoder without converting through canonical field elements.
func (p *IFMAPointX8) SplitX4(out *[2]IFMAPointX4) {
	splitIFMAElementX8(&out[0].X, &out[1].X, &p.X)
	splitIFMAElementX8(&out[0].Y, &out[1].Y, &p.Y)
	splitIFMAElementX8(&out[0].Z, &out[1].Z, &p.Z)
	splitIFMAElementX8(&out[0].T, &out[1].T, &p.T)
}

func splitIFMAElementX8(low, high *IFMAElementX4, source *IFMAElementX8) {
	for limb := range source.limbs {
		for lane := 0; lane < X4Lanes; lane++ {
			low.limbs[limb][lane] = source.limbs[limb][lane]
			high.limbs[limb][lane] = source.limbs[limb][lane+X4Lanes]
		}
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
	var A, B, C, D, E, F, G, H IFMAElementX4
	// Every input read completes before result is assigned to out, so exact
	// out==q aliasing does not require a 640-byte defensive point copy.
	if err := ifmaMultiplyComposableUncheckedX4(&A, &q.X, &q.X); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX4(&B, &q.Y, &q.Y); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX4(&C, &q.Z, &q.Z); err != nil {
		return err
	}
	C.Add(&C, &C)
	// E=2XY avoids the normalized (X+Y), E-A, and E-B operations needed
	// by the classical square trick. Squaring currently uses this same general
	// IFMA multiply, so the direct form keeps the multiply count unchanged.
	if err := ifmaMultiplyComposableUncheckedX4(&E, &q.X, &q.Y); err != nil {
		return err
	}
	E.Add(&E, &E)
	D.Negate(&A)
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
	var workspace ifmaPointDoubleWorkspaceX8
	return ifmaPointDoubleComposableWorkspaceStaticX8(out, q, &workspace)
}

// ifmaPointDoubleWorkspaceX8 holds the eight formula intermediates whose
// storage is fully overwritten by every point doubling. Scalar loops keep one
// workspace for the whole loop so Go does not zero 2.5 KiB of dead scratch on
// every one of the 252 dependent doublings.
type ifmaPointDoubleWorkspaceX8 struct {
	A, B, C, D, E, F, G, H IFMAElementX8
}

func ifmaPointDoubleComposableWorkspaceStaticX8(out, q *IFMAPointX8, workspace *ifmaPointDoubleWorkspaceX8) error {
	A, B, C, D := &workspace.A, &workspace.B, &workspace.C, &workspace.D
	E, F, G, H := &workspace.E, &workspace.F, &workspace.G, &workspace.H
	// As in the x4 counterpart, every input read completes before result is
	// assigned to out. Exact out==q aliasing therefore does not require a
	// 1,280-byte defensive point copy.
	if err := ifmaMultiplyComposableUncheckedX8(A, &q.X, &q.X); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX8(B, &q.Y, &q.Y); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX8(C, &q.Z, &q.Z); err != nil {
		return err
	}
	C.Add(C, C)
	// See the x4 schedule above: direct E=2XY removes two carry boundaries.
	if err := ifmaMultiplyComposableUncheckedX8(E, &q.X, &q.Y); err != nil {
		return err
	}
	E.Add(E, E)
	D.Negate(A)
	G.Add(D, B)
	F.Subtract(G, C)
	H.Subtract(D, B)

	// q is dead after the four formula intermediates are formed. Writing the
	// result directly is therefore safe even when out==q, and avoids zeroing a
	// temporary 1,280-byte point followed by a full point copy. The unchecked
	// field kernels used here have no error path after the boundary gate.
	if err := ifmaMultiplyComposableUncheckedX8(&out.X, E, F); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX8(&out.Y, G, H); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX8(&out.T, E, H); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX8(&out.Z, F, G); err != nil {
		return err
	}
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
	var A, B, C, D, E, F, G, H IFMAElementX4
	// The result is committed only after the final multiply, so exact out==q
	// aliasing does not require copying the input point.
	if err := mul(&A, &q.X, &q.X); err != nil {
		return err
	}
	if err := mul(&B, &q.Y, &q.Y); err != nil {
		return err
	}
	if err := mul(&C, &q.Z, &q.Z); err != nil {
		return err
	}
	C.Add(&C, &C)
	// Keep the injected model on the same direct-XY formula as the static core.
	if err := mul(&E, &q.X, &q.Y); err != nil {
		return err
	}
	E.Add(&E, &E)
	D.Negate(&A)
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
	var A, B, C, D, E, F, G, H IFMAElementX8
	// The result is committed only after the final multiply, so exact out==q
	// aliasing does not require copying the input point.
	if err := mul(&A, &q.X, &q.X); err != nil {
		return err
	}
	if err := mul(&B, &q.Y, &q.Y); err != nil {
		return err
	}
	if err := mul(&C, &q.Z, &q.Z); err != nil {
		return err
	}
	C.Add(&C, &C)
	// Keep the injected model on the same direct-XY formula as the static core.
	if err := mul(&E, &q.X, &q.Y); err != nil {
		return err
	}
	E.Add(&E, &E)
	D.Negate(&A)
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
