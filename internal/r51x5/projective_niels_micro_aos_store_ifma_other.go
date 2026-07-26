//go:build !amd64

package r51x5

func ifmaProjectiveNielsPreSignedMicroAoSStoreTransposeX8(
	table *ifmaProjectiveNielsPreSignedMicroAoSTableX8,
	entry uint64,
	point *IFMAProjectiveNielsX8,
	negativeT2D *IFMAElementX8,
) {
	for lane := 0; lane < X8Lanes; lane++ {
		for limb := range modulusLimbs {
			table[lane][0][entry][limb] = [4]uint64{
				point.YPlusX.limbs[limb][lane],
				point.YMinusX.limbs[limb][lane],
				point.Z.limbs[limb][lane],
				point.T2D.limbs[limb][lane],
			}
			table[lane][1][entry][limb] = [4]uint64{
				point.YMinusX.limbs[limb][lane],
				point.YPlusX.limbs[limb][lane],
				point.Z.limbs[limb][lane],
				negativeT2D.limbs[limb][lane],
			}
		}
	}
}
