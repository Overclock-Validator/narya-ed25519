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

	e := (*LimbsX8)(&stage2[0])
	f := (*LimbsX8)(&stage2[1])
	g := (*LimbsX8)(&stage2[2])
	h := (*LimbsX8)(&stage2[3])

	// Stage 1 consumed q completely, so writing through out is alias-safe.
	ifmaMulNormalizedUncheckedX8(&out.X.limbs, e, f)
	ifmaMulNormalizedUncheckedX8(&out.Y.limbs, g, h)
	ifmaMulNormalizedUncheckedX8(&out.T.limbs, e, h)
	ifmaMulNormalizedUncheckedX8(&out.Z.limbs, f, g)
	return nil
}
