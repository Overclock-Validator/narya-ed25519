//go:build !amd64 || purego

package r51x5

// The non-amd64 implementation is an exact scalar model for exercising the
// layout and selector semantics in architecture-independent test runs.
func ifmaMicroAoSTransposeSelectExperimentX4(out *IFMAPointX4, p0, p1, p2, p3 *ifmaMicroAoSPointEntryExperiment) {
	// Snapshot all sources before the first output store to preserve the
	// assembly routine's exact-alias contract.
	a, b, c, d := *p0, *p1, *p2, *p3
	for limb := 0; limb < 5; limb++ {
		out.X.limbs[limb] = [X4Lanes]uint64{a[limb][0], b[limb][0], c[limb][0], d[limb][0]}
		out.Y.limbs[limb] = [X4Lanes]uint64{a[limb][1], b[limb][1], c[limb][1], d[limb][1]}
		out.Z.limbs[limb] = [X4Lanes]uint64{a[limb][2], b[limb][2], c[limb][2], d[limb][2]}
		out.T.limbs[limb] = [X4Lanes]uint64{a[limb][3], b[limb][3], c[limb][3], d[limb][3]}
	}
}
