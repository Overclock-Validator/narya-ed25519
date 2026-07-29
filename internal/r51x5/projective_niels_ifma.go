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
	// Callers have already gated IFMA and keep point in the composable u52
	// domain. Write every coordinate through to out: a temporary result made
	// the compiler clear and then copy 1,280 bytes for each of the sixteen
	// entries built by a cold variable-base table.
	ifmaAddComposableUncheckedX8(&out.YPlusX, &point.Y, &point.X)
	ifmaSubtractComposableUncheckedX8(&out.YMinusX, &point.Y, &point.X)
	out.Z = point.Z
	if err := ifmaMultiplyComposableUncheckedX8(&out.T2D, &point.T, &ifmaCurve2DX8); err != nil {
		return err
	}
	return nil
}

// ifmaPointAddProjectiveNielsX8 computes point+cached with the standard
// projective-Niels mixed-add formula. It uses eight field multiplications,
// versus ten when both operands are stored as raw extended coordinates.
// Inputs may alias out; out is unchanged on error.
func ifmaPointAddProjectiveNielsX8(out, point *IFMAPointX8, cached *IFMAProjectiveNielsX8) error {
	var workspace ifmaPointAddProjectiveNielsScratchX8
	return ifmaPointAddProjectiveNielsWorkspaceX8(out, point, cached, &workspace)
}

// ifmaPointAddProjectiveNielsScratchX8 owns the fully overwritten scratch for
// one mixed addition. Stage 1 keeps only the two normalized point-side linear
// terms plus four exact raw products. The dedicated Stage-2 transition forms
// and carries E/F/G/H together, instead of normalizing A/B/C/D separately and
// then making five more element calls. Evaluation loops reuse the workspace so
// Go does not zero it for every selected digit.
type ifmaPointAddProjectiveNielsScratchX8 struct {
	yMinusX, yPlusX IFMAElementX8
	stage2          ifmaNielsStage2WorkspaceX8
}

func ifmaPointAddProjectiveNielsWorkspaceX8(
	out, point *IFMAPointX8,
	cached *IFMAProjectiveNielsX8,
	workspace *ifmaPointAddProjectiveNielsScratchX8,
) error {
	yMinusX, yPlusX := &workspace.yMinusX, &workspace.yPlusX
	ifmaSubtractComposableUncheckedX8(yMinusX, &point.Y, &point.X)
	ifmaAddComposableUncheckedX8(yPlusX, &point.Y, &point.X)

	stage2 := &workspace.stage2
	// A/B/C/D are four independent exact raw products. Compute them through
	// one assembly leaf so the hot Niels loop pays one Go/assembly transition
	// and one VZEROUPPER, while expanding the same source-level multiply body
	// as four standalone ifmaMulRawX8 calls.
	ifmaFourRawProductsNielsStage2UncheckedX8(
		&stage2[0],
		&yMinusX.limbs, &cached.YMinusX.limbs,
		&yPlusX.limbs, &cached.YPlusX.limbs,
		&point.T.limbs, &cached.T2D.limbs,
		&point.Z.limbs, &cached.Z.limbs,
	)

	// point and cached are both dead after A/B/C/D have been formed, so
	// direct output remains safe for exact out==point aliasing.
	ifmaPointFinalProductsUncheckedX8(out, &stage2[0])
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
	var addWorkspace ifmaPointAddProjectiveNielsScratchX8
	current.SetReduced(base)
	if err := ifmaProjectiveNielsFromPointX8(&workspace.table.points[0], &current); err != nil {
		return err
	}
	baseCached := &workspace.table.points[0]
	for entry := 1; entry < len(workspace.table.points); entry++ {
		if err := ifmaPointAddProjectiveNielsWorkspaceX8(&current, &current, baseCached, &addWorkspace); err != nil {
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
	var doubleWorkspace ifmaPointDoubleWorkspaceX8
	var addWorkspace ifmaPointAddProjectiveNielsScratchX8
	if usable == 0 {
		*out = acc
		return 0, nil
	}
	for round := workspace.digits.RoundCount() - 1; round >= 0; round-- {
		if round != workspace.digits.RoundCount()-1 {
			for doubling := 0; doubling < 5; doubling++ {
				if err := ifmaPointDoubleComposableWorkspaceStaticX8(&acc, &acc, &doubleWorkspace); err != nil {
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
		if err := ifmaPointAddProjectiveNielsWorkspaceX8(&acc, &acc, &selected, &addWorkspace); err != nil {
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
