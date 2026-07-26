//go:build !amd64

package r51x5

type ifmaNielsStage2WorkspaceX8 [4]IFMAProductX8

// ifmaNielsStage2X8 is the scalar reference-shaped implementation of the
// amd64 stage. It assumes the same exact A/B/C raw-product and D raw-product
// or composable-u52 entry contract.
func ifmaNielsStage2X8(workspace *ifmaNielsStage2WorkspaceX8) {
	input := *workspace
	var wide [4]IFMAProductX8

	for limb := 0; limb < 5; limb++ {
		p := uint64(1)<<LimbBits - 1
		if limb == 0 {
			p -= 18
		}
		for lane := 0; lane < X8Lanes; lane++ {
			a := input[0][limb][lane]
			b := input[1][limb][lane]
			c := input[2][limb][lane]
			d := input[3][limb][lane]
			d2 := 2 * d

			wide[0][limb][lane] = b + 535*p - a
			wide[1][limb][lane] = d2 + 535*p - c
			wide[2][limb][lane] = d2 + c
			wide[3][limb][lane] = b + a
		}
	}

	for coordinate := 0; coordinate < 4; coordinate++ {
		for lane := 0; lane < X8Lanes; lane++ {
			var carry [5]uint64
			for limb := 0; limb < 5; limb++ {
				carry[limb] = wide[coordinate][limb][lane] >> LimbBits
				workspace[coordinate][limb][lane] = wide[coordinate][limb][lane] & limbMask
			}
			workspace[coordinate][0][lane] += 19 * carry[4]
			for limb := 1; limb < 5; limb++ {
				workspace[coordinate][limb][lane] += carry[limb-1]
			}
		}
	}
}
