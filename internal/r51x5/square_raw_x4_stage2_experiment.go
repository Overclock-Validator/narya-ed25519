package r51x5

// ifmaPointDoubleRawSquareStage2ExperimentX4 changes only the three square
// products in the fused x4 doubling. The dedicated square returns the exact
// folded-u61 representation of ifmaMulRawX4(out, x, x), so the existing
// Stage-2 range proof and every downstream instruction remain unchanged.
//
// Regime tag: four-signature/tail YMM point doubling. This remains a measured
// candidate until a complete public-verifier A/B selects it for a concrete CPU
// family; the normalized-square verdict does not transfer across this raw-u61
// Stage-2 boundary.
func ifmaPointDoubleRawSquareStage2ExperimentX4(out, q *IFMAPointX4) error {
	var workspace ifmaDoubleStage2WorkspaceX4
	ifmaSquareRawExperimentX4(&workspace[0], &q.X.limbs)
	ifmaSquareRawExperimentX4(&workspace[1], &q.Y.limbs)
	ifmaSquareRawExperimentX4(&workspace[2], &q.Z.limbs)
	ifmaMulRawX4(&workspace[3], &q.X.limbs, &q.Y.limbs)
	ifmaDoubleStage2X4(&workspace)

	e := (*LimbsX4)(&workspace[0])
	f := (*LimbsX4)(&workspace[1])
	g := (*LimbsX4)(&workspace[2])
	h := (*LimbsX4)(&workspace[3])

	// Stage 1 consumed q completely, so direct output is alias-safe.
	ifmaMulNormalizedUncheckedX4(&out.X.limbs, e, f)
	ifmaMulNormalizedUncheckedX4(&out.Y.limbs, g, h)
	ifmaMulNormalizedUncheckedX4(&out.T.limbs, e, h)
	ifmaMulNormalizedUncheckedX4(&out.Z.limbs, f, g)
	return nil
}
