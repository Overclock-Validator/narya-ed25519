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

// ExperimentalIFMAProjectiveNielsVariableBaseWorkspaceX8 owns one radix-32
// arbitrary-point table in projective Niels form. Its micro-AoS cold storage
// keeps each key's [Y+X,Y-X,Z,2dT] limb row contiguous, then transposes eight
// independently selected entries into the x8 SoA arithmetic layout. The
// forced r51 x8 verifier uses it for cold [k]A evaluation; automatic backend
// selection cannot reach it. The workspace is caller-owned, reusable, and
// not concurrent-safe.
type ExperimentalIFMAProjectiveNielsVariableBaseWorkspaceX8 struct {
	table    ifmaProjectiveNielsMicroAoSTableX8
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
	var baseCached IFMAProjectiveNielsX8
	if err := ifmaProjectiveNielsFromPointX8(&baseCached, &current); err != nil {
		return err
	}
	storeIFMAProjectiveNielsMicroAoSEntryX8(&workspace.table, 0, &baseCached)
	for entry := 1; entry < 16; entry++ {
		if err := ifmaPointAddProjectiveNielsX8(&current, &current, &baseCached); err != nil {
			return err
		}
		var cached IFMAProjectiveNielsX8
		if err := ifmaProjectiveNielsFromPointX8(&cached, &current); err != nil {
			return err
		}
		storeIFMAProjectiveNielsMicroAoSEntryX8(&workspace.table, entry, &cached)
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
		selectIFMAProjectiveNielsMicroAoSX8(&selected, &workspace.table, digit, usable)
		if err := ifmaPointAddProjectiveNielsX8(&acc, &acc, &selected); err != nil {
			return 0, err
		}
	}
	*out = acc
	return usable, nil
}
