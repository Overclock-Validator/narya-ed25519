//go:build !amd64

package r51x5

func ifmaAffine3MicroAoSTransposeSelectExperimentX4(
	out *fixedBaseIFMACachedX4,
	p0, p1, p2, p3 *ifmaAffine3MicroAoSEntryExperiment,
) {
	a, b, c, d := *p0, *p1, *p2, *p3
	for limb := 0; limb < 5; limb++ {
		out.YPlusX.limbs[limb] = [X4Lanes]uint64{a[limb][0], b[limb][0], c[limb][0], d[limb][0]}
		out.YMinusX.limbs[limb] = [X4Lanes]uint64{a[limb][1], b[limb][1], c[limb][1], d[limb][1]}
		out.T2D.limbs[limb] = [X4Lanes]uint64{a[limb][2], b[limb][2], c[limb][2], d[limb][2]}
	}
}

func ifmaAffine3MicroAoSTransposeSelectExperimentX8(
	out *fixedBaseIFMACachedX8,
	p0, p1, p2, p3, p4, p5, p6, p7 *ifmaAffine3MicroAoSEntryExperiment,
) {
	points := [X8Lanes]*ifmaAffine3MicroAoSEntryExperiment{p0, p1, p2, p3, p4, p5, p6, p7}
	for limb := 0; limb < 5; limb++ {
		for lane, point := range points {
			out.YPlusX.limbs[limb][lane] = point[limb][0]
			out.YMinusX.limbs[limb][lane] = point[limb][1]
			out.T2D.limbs[limb][lane] = point[limb][2]
		}
	}
}
