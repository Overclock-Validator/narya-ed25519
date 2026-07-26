//go:build amd64 && !purego

package r51x5

// ifmaProjectiveNielsMicroAoSTransposeX8 loads eight independently selected
// 160-byte [limb][Y+X,Y-X,Z,2dT] entries and transposes them into the x8 SoA
// projective-Niels layout. Sources and output must not overlap.
//
//go:noescape
func ifmaProjectiveNielsMicroAoSTransposeX8(
	out *IFMAProjectiveNielsX8,
	p0, p1, p2, p3, p4, p5, p6, p7 *ifmaProjectiveNielsMicroAoSEntryX8,
)
