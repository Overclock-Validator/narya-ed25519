package r51x5

// The grouped-SoA workspace is retained only as an independent test oracle
// for the selected cold micro-AoS layout. Keeping it in a _test.go file avoids
// carrying both full evaluators in the forced verifier binary.
type ifmaProjectiveNielsGroupedTableX8 struct {
	points [16]IFMAProjectiveNielsX8
}

type ifmaProjectiveNielsGroupedReferenceWorkspaceX8 struct {
	table    ifmaProjectiveNielsGroupedTableX8
	digits   FixedRadixDigitsX8
	prepared bool
}

func (workspace *ifmaProjectiveNielsGroupedReferenceWorkspaceX8) Prepare(base *PointX8) error {
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

func (workspace *ifmaProjectiveNielsGroupedReferenceWorkspaceX8) Evaluate(
	out *IFMAPointX8,
	scalar *[X8Lanes][32]byte,
	negativeMask, active uint8,
) (uint8, error) {
	if !workspace.prepared {
		panic("r51x5: grouped projective Niels reference is not prepared")
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
		selectIFMAProjectiveNielsGroupedReferenceX8(&selected, &workspace.table, digit, usable)
		if err := ifmaPointAddProjectiveNielsX8(&acc, &acc, &selected); err != nil {
			return 0, err
		}
	}
	*out = acc
	return usable, nil
}

func selectIFMAProjectiveNielsGroupedReferenceX8(
	out *IFMAProjectiveNielsX8,
	table *ifmaProjectiveNielsGroupedTableX8,
	round *RadixRoundX8,
	active uint8,
) {
	lookupMask := round.NonzeroMask & active
	negativeMask := round.NegativeMask & lookupMask
	for lane := 0; lane < X8Lanes; lane++ {
		laneMask := uint8(1 << lane)
		if lookupMask&laneMask == 0 {
			setIdentityIFMAProjectiveNielsGroupedReferenceLaneX8(out, lane)
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

func setIdentityIFMAProjectiveNielsGroupedReferenceLaneX8(out *IFMAProjectiveNielsX8, lane int) {
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
