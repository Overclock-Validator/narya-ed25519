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

// ifmaAffine3MicroAoSTransposeSelectExperimentX8 is the native-wide version.
// Sources and out must not overlap; fixed-base selection always reads the
// immutable process-shared table and writes worker-local scratch.
//
//go:noescape
func ifmaAffine3MicroAoSTransposeSelectExperimentX8(
	out *fixedBaseIFMACachedX8,
	p0, p1, p2, p3, p4, p5, p6, p7 *ifmaAffine3MicroAoSEntryExperiment,
)
