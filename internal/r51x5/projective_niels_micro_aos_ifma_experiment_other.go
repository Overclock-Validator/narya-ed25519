//go:build !amd64

package r51x5

func ifmaProjectiveNielsMicroAoSTransposeX8(
	out *IFMAProjectiveNielsX8,
	p0, p1, p2, p3, p4, p5, p6, p7 *ifmaProjectiveNielsMicroAoSEntryX8,
) {
	sources := [X8Lanes]ifmaProjectiveNielsMicroAoSEntryX8{*p0, *p1, *p2, *p3, *p4, *p5, *p6, *p7}
	for limb := range modulusLimbs {
		for lane := 0; lane < X8Lanes; lane++ {
			out.YPlusX.limbs[limb][lane] = sources[lane][limb][0]
			out.YMinusX.limbs[limb][lane] = sources[lane][limb][1]
			out.Z.limbs[limb][lane] = sources[lane][limb][2]
			out.T2D.limbs[limb][lane] = sources[lane][limb][3]
		}
	}
}
