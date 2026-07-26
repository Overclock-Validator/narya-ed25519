package r51x5

// IFMAProjectiveNielsX8 stores eight projective cached Edwards points as
// (Y+X, Y-X, Z, 2dT). It has the same four-coordinate footprint as an
// extended point, but removes two field multiplications from every mixed
// addition because the table-side linear terms and 2d factor are prepared
// once. The coordinates retain the composable u52 contract.
type IFMAProjectiveNielsX8 struct {
	YPlusX  IFMAElementX8
	YMinusX IFMAElementX8
	Z       IFMAElementX8
	T2D     IFMAElementX8
}

type ifmaProjectiveNielsTableX8 struct {
	points [16]IFMAProjectiveNielsX8
}

// ExperimentalIFMAProjectiveNielsVariableBaseWorkspaceX8 owns one radix-32
// arbitrary-point table in projective Niels form. The forced r51 x8 verifier
// uses it for cold [k]A evaluation; automatic backend selection cannot reach
// it. The workspace is caller-owned, reusable, and not concurrent-safe.
type ExperimentalIFMAProjectiveNielsVariableBaseWorkspaceX8 struct {
	table    ifmaProjectiveNielsTableX8
	digits   FixedRadixDigitsX8
	prepared bool
}

func ifmaProjectiveNielsFromPointX8(out *IFMAProjectiveNielsX8, point *IFMAPointX8) error {
	var result IFMAProjectiveNielsX8
	result.YPlusX.Add(&point.Y, &point.X)
	result.YMinusX.Subtract(&point.Y, &point.X)
	result.Z = point.Z
	if err := ifmaMultiplyComposableUncheckedX8(&result.T2D, &point.T, &ifmaCurve2DX8); err != nil {
		return err
	}
	*out = result
	return nil
}

// ifmaPointAddProjectiveNielsX8 computes point+cached with the standard
// projective-Niels mixed-add formula. It uses eight field multiplications,
// versus ten when both operands are stored as raw extended coordinates.
// Inputs may alias out; out is unchanged on error.
func ifmaPointAddProjectiveNielsX8(out, point *IFMAPointX8, cached *IFMAProjectiveNielsX8) error {
	var yMinusX, yPlusX IFMAElementX8
	yMinusX.Subtract(&point.Y, &point.X)
	yPlusX.Add(&point.Y, &point.X)

	var A, B, C, D, E, F, G, H IFMAElementX8
	if err := ifmaMultiplyComposableUncheckedX8(&A, &yMinusX, &cached.YMinusX); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX8(&B, &yPlusX, &cached.YPlusX); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX8(&C, &point.T, &cached.T2D); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX8(&D, &point.Z, &cached.Z); err != nil {
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

// Prepare replaces the cold arbitrary-point table. It builds [1]A through
// [16]A without inversion, using the same projective-Niels addition that the
// evaluation loop consumes.
func (workspace *ExperimentalIFMAProjectiveNielsVariableBaseWorkspaceX8) Prepare(base *PointX8, radixBits uint) error {
	fixedScalarRoundCount(radixBits)
	if radixBits != 5 {
		panic("r51x5: projective Niels x8 workspace requires radix 32")
	}
	if !ExperimentalIFMAAvailable() {
		return ErrIFMAUnavailable
	}
	workspace.prepared = false
	var current IFMAPointX8
	current.SetReduced(base)
	if err := ifmaProjectiveNielsFromPointX8(&workspace.table.points[0], &current); err != nil {
		return err
	}
	baseCached := &workspace.table.points[0]
	for entry := 1; entry < len(workspace.table.points); entry++ {
		if err := ifmaPointAddProjectiveNielsX8(&current, &current, baseCached); err != nil {
			return err
		}
		if err := ifmaProjectiveNielsFromPointX8(&workspace.table.points[entry], &current); err != nil {
			return err
		}
	}
	workspace.prepared = true
	return nil
}

// Evaluate computes an exact signed [scalar]A from the prepared table.
// scalar must be a canonical modulo-L encoding; negativeMask is an exact
// integer sign, not an L-scalar negation. Invalid and inactive lanes are
// identities, and out is unchanged on error.
func (workspace *ExperimentalIFMAProjectiveNielsVariableBaseWorkspaceX8) Evaluate(out *IFMAPointX8, scalar *[X8Lanes][32]byte, negativeMask, active uint8) (uint8, error) {
	if !workspace.prepared {
		panic("r51x5: projective Niels x8 workspace is not prepared")
	}
	if !ExperimentalIFMAAvailable() {
		return 0, ErrIFMAUnavailable
	}
	usable := RecodeCanonicalScalarsX8(&workspace.digits, scalar, negativeMask, active, 5)
	acc := identityIFMAPointX8Value()
	if usable == 0 {
		*out = acc
		return 0, nil
	}
	for round := workspace.digits.RoundCount() - 1; round >= 0; round-- {
		if round != workspace.digits.RoundCount()-1 {
			for doubling := 0; doubling < 5; doubling++ {
				if err := ifmaPointDoubleComposableStaticX8(&acc, &acc); err != nil {
					return 0, err
				}
			}
		}
		digit := workspace.digits.Round(round)
		if digit.NonzeroMask&usable == 0 {
			continue
		}
		var selected IFMAProjectiveNielsX8
		selectIFMAProjectiveNielsX8(&selected, &workspace.table, digit, usable)
		if err := ifmaPointAddProjectiveNielsX8(&acc, &acc, &selected); err != nil {
			return 0, err
		}
	}
	*out = acc
	return usable, nil
}

// selectIFMAProjectiveNielsX8 is variable-time in the public verification
// scalar. digit must come from RecodeCanonicalScalarsX8. Negation swaps Y+X
// and Y-X and negates 2dT; Z is unchanged.
func selectIFMAProjectiveNielsX8(out *IFMAProjectiveNielsX8, table *ifmaProjectiveNielsTableX8, round *RadixRoundX8, active uint8) {
	lookupMask := round.NonzeroMask & active
	negativeMask := round.NegativeMask & lookupMask
	for lane := 0; lane < X8Lanes; lane++ {
		laneMask := uint8(1 << lane)
		if lookupMask&laneMask == 0 {
			setIdentityIFMAProjectiveNielsLaneX8(out, lane)
			continue
		}
		source := &table.points[int(round.Magnitude[lane])-1]
		for limb := range modulusLimbs {
			out.YPlusX.limbs[limb][lane] = source.YPlusX.limbs[limb][lane]
			out.YMinusX.limbs[limb][lane] = source.YMinusX.limbs[limb][lane]
			out.Z.limbs[limb][lane] = source.Z.limbs[limb][lane]
			out.T2D.limbs[limb][lane] = source.T2D.limbs[limb][lane]
		}
	}
	for limb := range modulusLimbs {
		for lane := 0; lane < X8Lanes; lane++ {
			if negativeMask&(1<<lane) != 0 {
				out.YPlusX.limbs[limb][lane], out.YMinusX.limbs[limb][lane] =
					out.YMinusX.limbs[limb][lane], out.YPlusX.limbs[limb][lane]
			}
		}
	}
	conditionalNegateIFMAElementX8(&out.T2D, negativeMask)
}

func setIdentityIFMAProjectiveNielsLaneX8(out *IFMAProjectiveNielsX8, lane int) {
	for limb := range modulusLimbs {
		out.YPlusX.limbs[limb][lane] = 0
		out.YMinusX.limbs[limb][lane] = 0
		out.Z.limbs[limb][lane] = 0
		out.T2D.limbs[limb][lane] = 0
	}
	out.YPlusX.limbs[0][lane] = 1
	out.YMinusX.limbs[0][lane] = 1
	out.Z.limbs[0][lane] = 1
}
