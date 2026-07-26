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

func quadTwoChainDoubleHardwareWorkspaceUncheckedX8(out, q *IFMAElementX8, workspace *quadTwoChainDoubleWorkspaceX8) error {
	ifmaQuadTwoChainDoubleFirstOperandsUncheckedX8(&workspace.u.limbs, &workspace.v.limbs, &q.limbs)
	if err := ifmaMultiplyComposableUncheckedX8(&workspace.products, &workspace.u, &workspace.v); err != nil {
		return err
	}
	ifmaQuadTwoChainDoubleFinalMultiplyUncheckedX8(&out.limbs, &workspace.products.limbs)
	return nil
}
