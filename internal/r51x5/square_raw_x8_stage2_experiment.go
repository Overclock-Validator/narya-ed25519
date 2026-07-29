package r51x5

// ifmaPointDoubleRawSquareStage2ExperimentX8 changes only the three square
// products in the current fused x8 doubling. The dedicated square returns the
// exact folded-u61 representation of ifmaMulRawX8(out, x, x), so the existing
// Stage-2 range proof and every downstream instruction remain unchanged.
//
// Regime tag: native-ZMM point doubling. This remains a measurement candidate
// until a complete cold-verifier A/B on Zen 5 demonstrates a retained gain.
func ifmaPointDoubleRawSquareStage2ExperimentX8(out, q *IFMAPointX8, workspace *ifmaPointDoubleWorkspaceX8) error {
	stage2 := &workspace.stage2
	ifmaSquareRawExperimentX8(&stage2[0], &q.X.limbs)
	ifmaSquareRawExperimentX8(&stage2[1], &q.Y.limbs)
	ifmaSquareRawExperimentX8(&stage2[2], &q.Z.limbs)
	ifmaMulRawX8(&stage2[3], &q.X.limbs, &q.Y.limbs)
	ifmaDoubleStage2X8(stage2)

	// Stage 1 consumed q completely, so writing through out is alias-safe.
	ifmaPointFinalProductsUncheckedX8(out, &stage2[0])
	return nil
}

// ifmaPointDoubleFourSquareStage2ExperimentX8 prices the classical
// (X+Y)^2-X^2-Y^2 formula in the current raw-square regime. X+Y is normalized
// before entering IFMA, so this experiment assumes no tighter undocumented
// point-coordinate bound. It is intentionally unwired until the primitive and
// complete-verifier gates show that the extra normalization pays for itself.
func ifmaPointDoubleFourSquareStage2ExperimentX8(out, q *IFMAPointX8, workspace *ifmaPointDoubleWorkspaceX8) error {
	stage2 := &workspace.stage2
	var xPlusY IFMAElementX8
	ifmaAddComposableUncheckedX8(&xPlusY, &q.X, &q.Y)
	ifmaSquareRawExperimentX8(&stage2[0], &q.X.limbs)
	ifmaSquareRawExperimentX8(&stage2[1], &q.Y.limbs)
	ifmaSquareRawExperimentX8(&stage2[2], &q.Z.limbs)
	ifmaSquareRawExperimentX8(&stage2[3], &xPlusY.limbs)
	ifmaDoubleStage2SquareTrickX8(stage2)

	ifmaPointFinalProductsUncheckedX8(out, &stage2[0])
	return nil
}
