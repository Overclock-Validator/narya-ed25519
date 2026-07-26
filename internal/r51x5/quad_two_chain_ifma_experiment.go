package r51x5

// quadTwoChainDoubleWorkspaceX8 is the reusable scratch for the experimental
// Zen 5 two-chain packed doubling gate. Each 256-bit half of every vector holds
// one point's [X,Y,T,Z] coordinates. This is a regime probe, not a production
// verifier path: widening the singleton only has value when an algorithm such
// as separate-term DSM or HEEA supplies two independent point chains.
type quadTwoChainDoubleWorkspaceX8 struct {
	u        IFMAElementX8
	v        IFMAElementX8
	products IFMAElementX8
}

// quadTwoChainCachedAddWorkspaceX8 is the corresponding scratch for adding
// one cached point to each independent packed chain. Each field is completely
// overwritten before use.
type quadTwoChainCachedAddWorkspaceX8 struct {
	pointOperand IFMAElementX8
	products     IFMAElementX8
	left         IFMAElementX8
	right        IFMAElementX8
}

func packQuadTwoChainPointsX8(first, second *quadPackedPointX4) IFMAElementX8 {
	var packed IFMAElementX8
	for limb := range packed.limbs {
		for lane := 0; lane < X4Lanes; lane++ {
			packed.limbs[limb][lane] = first.coordinates.limbs[limb][lane]
			packed.limbs[limb][lane+X4Lanes] = second.coordinates.limbs[limb][lane]
		}
	}
	return packed
}

func unpackQuadTwoChainPointsX8(packed *IFMAElementX8) [2]quadPackedPointX4 {
	var points [2]quadPackedPointX4
	for limb := range packed.limbs {
		for lane := 0; lane < X4Lanes; lane++ {
			points[0].coordinates.limbs[limb][lane] = packed.limbs[limb][lane]
			points[1].coordinates.limbs[limb][lane] = packed.limbs[limb][lane+X4Lanes]
		}
	}
	return points
}

func packQuadTwoChainCachedX8(first, second *quadPackedCachedPointX4) IFMAElementX8 {
	var packed IFMAElementX8
	for limb := range packed.limbs {
		for lane := 0; lane < X4Lanes; lane++ {
			packed.limbs[limb][lane] = first.coordinates.limbs[limb][lane]
			packed.limbs[limb][lane+X4Lanes] = second.coordinates.limbs[limb][lane]
		}
	}
	return packed
}

func quadTwoChainDoubleHardwareWorkspaceUncheckedX8(out, q *IFMAElementX8, workspace *quadTwoChainDoubleWorkspaceX8) error {
	ifmaQuadTwoChainDoubleFirstOperandsUncheckedX8(&workspace.u.limbs, &workspace.v.limbs, &q.limbs)
	if err := ifmaMultiplyComposableUncheckedX8(&workspace.products, &workspace.u, &workspace.v); err != nil {
		return err
	}
	ifmaQuadTwoChainDoubleFinalMultiplyUncheckedX8(&out.limbs, &workspace.products.limbs)
	return nil
}

func quadTwoChainCachedAddHardwareWorkspaceUncheckedX8(
	out, point, cached *IFMAElementX8,
	workspace *quadTwoChainCachedAddWorkspaceX8,
) error {
	ifmaQuadTwoChainCachedAddFirstOperandUncheckedX8(&workspace.pointOperand.limbs, &point.limbs)
	ifmaMulNormalizedUncheckedX8(&workspace.products.limbs, &workspace.pointOperand.limbs, &cached.limbs)
	ifmaQuadTwoChainCachedAddFinalOperandsUncheckedX8(
		&workspace.left.limbs,
		&workspace.right.limbs,
		&workspace.products.limbs,
	)
	ifmaMulNormalizedUncheckedX8(&out.limbs, &workspace.left.limbs, &workspace.right.limbs)
	return nil
}
