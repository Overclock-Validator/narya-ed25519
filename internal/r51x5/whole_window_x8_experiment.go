package r51x5

// ifmaCompletedPointX8 is the carried-u52 (E,F,G,H) state produced by the
// linear/carry stage of an Edwards doubling or Niels addition. Keeping this
// state distinct from IFMAPointX8 makes it impossible to consume an absent
// X/Y/Z/T coordinate accidentally.
//
// Regime tag: this state supports the bounded whole-window experiment derived
// for the r51/u52 arithmetic grammar. The registered path may use it only
// after complete-verifier native gates establish a win.
type ifmaCompletedPointX8 [4]IFMAProductX8

// ifmaCompletedLinearPointX8 stores the point-side multiplicands constructed
// directly from completed coordinates. Its fields are carried u52 values.
type ifmaCompletedLinearPointX8 struct {
	YMinusX IFMAElementX8
	YPlusX  IFMAElementX8
	Z       IFMAElementX8
	T       IFMAElementX8
}

// ifmaCompletedBoundaryScratchX8 is fully overwritten at every completed
// boundary. products temporarily holds exact raw [EF,GH,FG,EH]; linear then
// holds carried [Y-X,Y+X,Z,T]. Evaluation loops reuse one instance.
type ifmaCompletedBoundaryScratchX8 struct {
	products [4]IFMAProductX8
	linear   ifmaCompletedLinearPointX8
}

// ifmaCompletedProductsToLinearModelX8 is the portable oracle for the native
// boundary leaf. The constants and single-carry shape are intentionally
// literal so tests can compare the assembly against the independently
// generated range certificate without sharing its instruction schedule.
func ifmaCompletedProductsToLinearModelX8(out *ifmaCompletedLinearPointX8, inputs *[4]IFMAProductX8) {
	var yMinusX, yPlusX IFMAProductX8
	for limb := 0; limb < 5; limb++ {
		p := uint64(1)<<LimbBits - 1
		if limb == 0 {
			p -= 18
		}
		for lane := 0; lane < X8Lanes; lane++ {
			x := inputs[0][limb][lane]
			y := inputs[1][limb][lane]
			yMinusX[limb][lane] = y + 535*p - x
			yPlusX[limb][lane] = y + x
		}
	}
	out.YMinusX.limbs = mustNormalizeIFMAProductX8(&yMinusX)
	out.YPlusX.limbs = mustNormalizeIFMAProductX8(&yPlusX)
	out.Z.limbs = mustNormalizeIFMAProductX8(&inputs[2])
	out.T.limbs = mustNormalizeIFMAProductX8(&inputs[3])
}

func ifmaPointDoubleRawSquareP2ToCompletedExperimentX8(
	out *ifmaCompletedPointX8,
	q *ifmaProjectivePointX8,
) {
	stage2 := (*ifmaDoubleStage2WorkspaceX8)(out)
	ifmaSquareRawExperimentX8(&stage2[0], &q.X.limbs)
	ifmaSquareRawExperimentX8(&stage2[1], &q.Y.limbs)
	ifmaSquareRawExperimentX8(&stage2[2], &q.Z.limbs)
	ifmaMulRawX8(&stage2[3], &q.X.limbs, &q.Y.limbs)
	ifmaDoubleStage2X8(stage2)
}

func ifmaFiveDoublesP3ToCompletedExperimentX8(
	out *ifmaCompletedPointX8,
	q *IFMAPointX8,
	projective *ifmaProjectivePointX8,
	workspace *ifmaPointDoubleWorkspaceX8,
) {
	ifmaPointDoubleRawSquareP3ToP2ExperimentX8(projective, q, workspace)
	for doubling := 1; doubling < 4; doubling++ {
		ifmaPointDoubleRawSquareP2ToP2ExperimentX8(projective, projective, workspace)
	}
	ifmaPointDoubleRawSquareP2ToCompletedExperimentX8(out, projective)
}

func ifmaFiveDoublesP2ToCompletedExperimentX8(
	out *ifmaCompletedPointX8,
	q *ifmaProjectivePointX8,
	workspace *ifmaPointDoubleWorkspaceX8,
) {
	for doubling := 0; doubling < 4; doubling++ {
		ifmaPointDoubleRawSquareP2ToP2ExperimentX8(q, q, workspace)
	}
	ifmaPointDoubleRawSquareP2ToCompletedExperimentX8(out, q)
}

func ifmaCompletedToLinearExperimentX8(
	out *ifmaCompletedLinearPointX8,
	completed *ifmaCompletedPointX8,
	products *[4]IFMAProductX8,
) {
	e := (*LimbsX8)(&completed[0])
	f := (*LimbsX8)(&completed[1])
	g := (*LimbsX8)(&completed[2])
	h := (*LimbsX8)(&completed[3])
	ifmaFourRawProductsUncheckedX8(
		&products[0],
		e, f,
		g, h,
		f, g,
		e, h,
	)
	ifmaCompletedProductsToLinearUncheckedX8(out, products)
}

func ifmaCompletedToP2ExperimentX8(out *ifmaProjectivePointX8, completed *ifmaCompletedPointX8) {
	ifmaProjectiveFinalProductsUncheckedX8(out, &completed[0])
}

func ifmaCompletedToP3ExperimentX8(out *IFMAPointX8, completed *ifmaCompletedPointX8) {
	ifmaPointFinalProductsUncheckedX8(out, &completed[0])
}

func ifmaCompletedAddProjectiveNielsExperimentX8(
	out, completed *ifmaCompletedPointX8,
	cached *IFMAProjectiveNielsX8,
	scratch *ifmaCompletedBoundaryScratchX8,
) {
	ifmaCompletedToLinearExperimentX8(&scratch.linear, completed, &scratch.products)
	stage2 := (*ifmaNielsStage2WorkspaceX8)(out)
	ifmaFourRawProductsNielsStage2UncheckedX8(
		&stage2[0],
		&scratch.linear.YMinusX.limbs, &cached.YMinusX.limbs,
		&scratch.linear.YPlusX.limbs, &cached.YPlusX.limbs,
		&scratch.linear.T.limbs, &cached.T2D.limbs,
		&scratch.linear.Z.limbs, &cached.Z.limbs,
	)
}

func ifmaCompletedAddAffineNielsExperimentX8(
	out, completed *ifmaCompletedPointX8,
	cached *fixedBaseIFMACachedX8,
	scratch *ifmaCompletedBoundaryScratchX8,
) {
	ifmaCompletedToLinearExperimentX8(&scratch.linear, completed, &scratch.products)
	stage2 := (*ifmaNielsStage2WorkspaceX8)(out)
	ifmaThreeRawProductsNielsStage2UncheckedX8(
		&stage2[0],
		&scratch.linear.YMinusX.limbs, &cached.YMinusX.limbs,
		&scratch.linear.YPlusX.limbs, &cached.YPlusX.limbs,
		&scratch.linear.T.limbs, &cached.T2D.limbs,
		&scratch.linear.Z.limbs,
	)
}

// IFMAAsymmetricFixedB10EvaluateWholeWindowExperimentX8 preserves the exact
// B10/radix-32 scalar schedule of IFMAAsymmetricFixedB10EvaluateX8. It changes
// only the boundary around each five-doubling run:
//
//   - the fifth doubling stops at carried (E,F,G,H);
//   - raw EF/GH/FG/EH products are formed once at the next addition boundary;
//   - GH-EF uses the independently certified minimum 535*p bias;
//   - the final addition emits P2, omitting T that the following doubling
//     cannot read.
//
// The final block deliberately materializes P3 through the established path
// because the public evaluator still returns IFMAPointX8. That one-time cost
// keeps this experiment scoped to the hot repeated-window boundary.
func IFMAAsymmetricFixedB10EvaluateWholeWindowExperimentX8(
	out *IFMAPointX8,
	variable *ExperimentalIFMAProjectiveNielsPreSignedMicroAoSVariableBaseWorkspaceX8,
	fixed *IFMAAsymmetricFixedB10TableX8,
	s, k *[X8Lanes][32]byte,
	active uint8,
) (uint8, error) {
	if !ExperimentalIFMAAvailable() {
		return 0, ErrIFMAUnavailable
	}
	usable := recodeCanonicalScalarsRadix32X8(&variable.digits, k, active, active)
	var bDigits asymmetricFixedB10DigitsX8
	usable &= recodeAsymmetricFixedB10ScalarsX8(&bDigits, s, active)
	acc := identityIFMAPointX8Value()
	if usable == 0 {
		*out = acc
		return 0, nil
	}

	var projective ifmaProjectivePointX8
	var doubleWorkspace ifmaPointDoubleWorkspaceX8
	var completed [2]ifmaCompletedPointX8
	var boundaryScratch ifmaCompletedBoundaryScratchX8
	var aAddWorkspace ifmaPointAddProjectiveNielsScratchX8
	var bAddWorkspace fixedBaseIFMAAddScratchX8

	// The first block starts from P3. Preserve its established B-then-A order.
	bRound := &bDigits.rounds[25]
	if bRound.NonzeroMask&usable != 0 {
		var selected fixedBaseIFMACachedX8
		selectAsymmetricFixedB10SignedX8(&selected, fixed, bRound, usable)
		if err := addFixedBaseIFMACachedWorkspaceX8(&acc, &acc, &selected, &bAddWorkspace); err != nil {
			return 0, err
		}
	}
	aEven := variable.digits.Round(50)
	if aEven.NonzeroMask&usable != 0 {
		var selected IFMAProjectiveNielsX8
		selectIFMAProjectiveNielsPreSignedMicroAoSX8(&selected, &variable.table, aEven, usable)
		if err := ifmaPointAddProjectiveNielsWorkspaceX8(&acc, &acc, &selected, &aAddWorkspace); err != nil {
			return 0, err
		}
	}

	for block := 25; block > 0; block-- {
		if block == 25 {
			ifmaFiveDoublesP3ToCompletedExperimentX8(&completed[0], &acc, &projective, &doubleWorkspace)
		} else {
			ifmaFiveDoublesP2ToCompletedExperimentX8(&completed[0], &projective, &doubleWorkspace)
		}

		current, next := &completed[0], &completed[1]
		aOdd := variable.digits.Round(block*2 - 1)
		if aOdd.NonzeroMask&usable != 0 {
			var selected IFMAProjectiveNielsX8
			selectIFMAProjectiveNielsPreSignedMicroAoSX8(&selected, &variable.table, aOdd, usable)
			ifmaCompletedAddProjectiveNielsExperimentX8(next, current, &selected, &boundaryScratch)
			current, next = next, current
		}
		ifmaCompletedToP2ExperimentX8(&projective, current)

		ifmaFiveDoublesP2ToCompletedExperimentX8(&completed[0], &projective, &doubleWorkspace)
		current, next = &completed[0], &completed[1]
		nextBlock := block - 1
		if nextBlock == 0 {
			// Keep the terminal representation and public API unchanged.
			ifmaCompletedToP3ExperimentX8(&acc, current)
			bRound = &bDigits.rounds[0]
			if bRound.NonzeroMask&usable != 0 {
				var selected fixedBaseIFMACachedX8
				selectAsymmetricFixedB10SignedX8(&selected, fixed, bRound, usable)
				if err := addFixedBaseIFMACachedWorkspaceX8(&acc, &acc, &selected, &bAddWorkspace); err != nil {
					return 0, err
				}
			}
			aEven = variable.digits.Round(0)
			if aEven.NonzeroMask&usable != 0 {
				var selected IFMAProjectiveNielsX8
				selectIFMAProjectiveNielsPreSignedMicroAoSX8(&selected, &variable.table, aEven, usable)
				if err := ifmaPointAddProjectiveNielsWorkspaceX8(&acc, &acc, &selected, &aAddWorkspace); err != nil {
					return 0, err
				}
			}
			break
		}

		bRound = &bDigits.rounds[nextBlock]
		if bRound.NonzeroMask&usable != 0 {
			var selected fixedBaseIFMACachedX8
			selectAsymmetricFixedB10SignedX8(&selected, fixed, bRound, usable)
			ifmaCompletedAddAffineNielsExperimentX8(next, current, &selected, &boundaryScratch)
			current, next = next, current
		}
		aEven = variable.digits.Round(nextBlock * 2)
		if aEven.NonzeroMask&usable != 0 {
			var selected IFMAProjectiveNielsX8
			selectIFMAProjectiveNielsPreSignedMicroAoSX8(&selected, &variable.table, aEven, usable)
			ifmaCompletedAddProjectiveNielsExperimentX8(next, current, &selected, &boundaryScratch)
			current, next = next, current
		}
		ifmaCompletedToP2ExperimentX8(&projective, current)
	}

	*out = acc
	return usable, nil
}
