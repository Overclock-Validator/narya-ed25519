//go:build amd64

package r51x5

// ifmaAffine3MicroAoSTransposeSelectExperimentX4 loads five dense
// [Y+X,Y-X,2dT] rows from each source and transposes them into three SoA
// IFMA elements. Masked loads make the 120-byte source boundary exact.
//
//go:noescape
func ifmaAffine3MicroAoSTransposeSelectExperimentX4(
	out *fixedBaseIFMACachedX4,
	p0, p1, p2, p3 *ifmaAffine3MicroAoSEntryExperiment,
)
