package r51x5

// These three leaves use the same direct-XY, dedicated-raw-square Stage-2
// schedule as ifmaPointDoubleRawSquareStage2ExperimentX8. Their only new idea
// is representing the first four outputs in a five-doubling radix-32 run as P2
// (X,Y,Z) and computing extended T only on the fifth output, immediately before
// a possible Niels addition.

func ifmaPointDoubleRawSquareP3ToP2ExperimentX8(
	out *ifmaProjectivePointX8,
	q *IFMAPointX8,
	workspace *ifmaPointDoubleWorkspaceX8,
) {
	stage2 := &workspace.stage2
	ifmaSquareRawExperimentX8(&stage2[0], &q.X.limbs)
	ifmaSquareRawExperimentX8(&stage2[1], &q.Y.limbs)
	ifmaSquareRawExperimentX8(&stage2[2], &q.Z.limbs)
	ifmaMulRawX8(&stage2[3], &q.X.limbs, &q.Y.limbs)
	ifmaDoubleStage2ProjectiveFinalX8(out, stage2)
}

func ifmaPointDoubleRawSquareP2ToP2ExperimentX8(
	out, q *ifmaProjectivePointX8,
	workspace *ifmaPointDoubleWorkspaceX8,
) {
	stage2 := &workspace.stage2
	ifmaSquareRawExperimentX8(&stage2[0], &q.X.limbs)
	ifmaSquareRawExperimentX8(&stage2[1], &q.Y.limbs)
	ifmaSquareRawExperimentX8(&stage2[2], &q.Z.limbs)
	ifmaMulRawX8(&stage2[3], &q.X.limbs, &q.Y.limbs)

	// Stage 1 has consumed q completely, so in-place P2 doubling is safe.
	ifmaDoubleStage2ProjectiveFinalX8(out, stage2)
}

func ifmaPointDoubleRawSquareP2ToP3ExperimentX8(
	out *IFMAPointX8,
	q *ifmaProjectivePointX8,
	workspace *ifmaPointDoubleWorkspaceX8,
) {
	stage2 := &workspace.stage2
	ifmaSquareRawExperimentX8(&stage2[0], &q.X.limbs)
	ifmaSquareRawExperimentX8(&stage2[1], &q.Y.limbs)
	ifmaSquareRawExperimentX8(&stage2[2], &q.Z.limbs)
	ifmaMulRawX8(&stage2[3], &q.X.limbs, &q.Y.limbs)
	ifmaDoubleStage2PointFinalX8(out, stage2)
}

// EvaluateProjectiveDoubleExperiment preserves EvaluateRawSquareExperiment's
// exact radix-32 recoding, selection, and addition schedule. Every group of
// five doublings follows P3 -> P2 -> P2 -> P2 -> P2 -> P3, so the four
// intermediate states cannot be consumed by an extended-coordinate addition.
// The final P3 is formed even when the current digit is zero, keeping the loop
// state statically complete at every round boundary.
func (workspace *ExperimentalIFMAProjectiveNielsPreSignedMicroAoSVariableBaseWorkspaceX8) EvaluateProjectiveDoubleExperiment(
	out *IFMAPointX8,
	scalar *[X8Lanes][32]byte,
	negativeMask, active uint8,
) (uint8, error) {
	if !workspace.prepared {
		panic("r51x5: pre-signed projective Niels micro-AoS x8 workspace is not prepared")
	}
	if !ExperimentalIFMAAvailable() {
		return 0, ErrIFMAUnavailable
	}
	usable := recodeCanonicalScalarsRadix32X8(&workspace.digits, scalar, negativeMask, active)
	acc := identityIFMAPointX8Value()
	var projective ifmaProjectivePointX8
	var doubleWorkspace ifmaPointDoubleWorkspaceX8
	var addWorkspace ifmaPointAddProjectiveNielsScratchX8
	if usable == 0 {
		*out = acc
		return 0, nil
	}
	for round := workspace.digits.RoundCount() - 1; round >= 0; round-- {
		if round != workspace.digits.RoundCount()-1 {
			ifmaPointDoubleRawSquareP3ToP2ExperimentX8(&projective, &acc, &doubleWorkspace)
			for doubling := 1; doubling < 4; doubling++ {
				ifmaPointDoubleRawSquareP2ToP2ExperimentX8(&projective, &projective, &doubleWorkspace)
			}
			ifmaPointDoubleRawSquareP2ToP3ExperimentX8(&acc, &projective, &doubleWorkspace)
		}
		digit := workspace.digits.Round(round)
		if digit.NonzeroMask&usable == 0 {
			continue
		}
		var selected IFMAProjectiveNielsX8
		selectIFMAProjectiveNielsPreSignedMicroAoSX8(&selected, &workspace.table, digit, usable)
		if err := ifmaPointAddProjectiveNielsWorkspaceX8(&acc, &acc, &selected, &addWorkspace); err != nil {
			return 0, err
		}
	}
	*out = acc
	return usable, nil
}
