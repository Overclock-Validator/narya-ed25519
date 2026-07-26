//go:build !amd64

package r51x5

// ifmaDoubleStage2WorkspaceX4 is the non-amd64 declaration of the private
// state-transition workspace described by the amd64 implementation. Its entry slots
// are exact folded raw [X^2, Y^2, Z^2, X*Y] products and its exit slots are
// normalized u52 [E, F, G, H] representatives.
type ifmaDoubleStage2WorkspaceX4 [4]IFMAProductX4

// ifmaDoubleStage2WorkspaceX8 is the scalar native-wide counterpart.
type ifmaDoubleStage2WorkspaceX8 [4]IFMAProductX8

// ifmaDoubleStage2X4 is the scalar non-amd64 implementation of the assembly
// schedule. It deliberately assumes the same exact raw-product bounds as the
// unchecked amd64 leaf.
func ifmaDoubleStage2X4(workspace *ifmaDoubleStage2WorkspaceX4) {
	input := *workspace
	var wide [4]IFMAProductX4

	for limb := 0; limb < 5; limb++ {
		p := uint64(1)<<LimbBits - 1
		if limb == 0 {
			p -= 18
		}
		for lane := 0; lane < X4Lanes; lane++ {
			a := input[0][limb][lane]
			b := input[1][limb][lane]
			c := input[2][limb][lane]
			e := input[3][limb][lane]

			g := b + 535*p - a
			wide[0][limb][lane] = 2 * e
			wide[1][limb][lane] = g + 1068*p - 2*c
			wide[2][limb][lane] = g
			wide[3][limb][lane] = 1069*p - a - b
		}
	}

	for coordinate := 0; coordinate < 4; coordinate++ {
		for lane := 0; lane < X4Lanes; lane++ {
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

func ifmaDoubleStage2X8(workspace *ifmaDoubleStage2WorkspaceX8) {
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
			e := input[3][limb][lane]

			g := b + 535*p - a
			wide[0][limb][lane] = 2 * e
			wide[1][limb][lane] = g + 1068*p - 2*c
			wide[2][limb][lane] = g
			wide[3][limb][lane] = 1069*p - a - b
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
