package r51x5

// ifmaProjectiveNielsMicroAoSEntryX8 stores one lane's projective-Niels point
// as five contiguous [Y+X,Y-X,Z,2dT] limb rows. The experiment keeps the
// production table's exact 160-byte-per-key-entry payload, but changes the
// cold table layout so eight independently selected entries can be loaded in
// contiguous 256-bit rows and transposed into the x8 SoA arithmetic layout.
type ifmaProjectiveNielsMicroAoSEntryX8 [5][4]uint64

type ifmaProjectiveNielsMicroAoSTableX8 [X8Lanes][16]ifmaProjectiveNielsMicroAoSEntryX8

var ifmaProjectiveNielsMicroAoSIdentityX8 = func() ifmaProjectiveNielsMicroAoSEntryX8 {
	var identity ifmaProjectiveNielsMicroAoSEntryX8
	identity[0] = [4]uint64{1, 1, 1, 0}
	return identity
}()

func storeIFMAProjectiveNielsMicroAoSEntryX8(
	table *ifmaProjectiveNielsMicroAoSTableX8,
	entry int,
	point *IFMAProjectiveNielsX8,
) {
	for lane := 0; lane < X8Lanes; lane++ {
		for limb := range modulusLimbs {
			table[lane][entry][limb] = [4]uint64{
				point.YPlusX.limbs[limb][lane],
				point.YMinusX.limbs[limb][lane],
				point.Z.limbs[limb][lane],
				point.T2D.limbs[limb][lane],
			}
		}
	}
}

func selectIFMAProjectiveNielsMicroAoSX8(
	out *IFMAProjectiveNielsX8,
	table *ifmaProjectiveNielsMicroAoSTableX8,
	round *RadixRoundX8,
	active uint8,
) {
	lookupMask := round.NonzeroMask & active
	negativeMask := round.NegativeMask & lookupMask
	p0 := &ifmaProjectiveNielsMicroAoSIdentityX8
	p1, p2, p3, p4, p5, p6, p7 := p0, p0, p0, p0, p0, p0, p0
	if lookupMask == 0xff {
		p0 = &table[0][int(round.Magnitude[0])-1]
		p1 = &table[1][int(round.Magnitude[1])-1]
		p2 = &table[2][int(round.Magnitude[2])-1]
		p3 = &table[3][int(round.Magnitude[3])-1]
		p4 = &table[4][int(round.Magnitude[4])-1]
		p5 = &table[5][int(round.Magnitude[5])-1]
		p6 = &table[6][int(round.Magnitude[6])-1]
		p7 = &table[7][int(round.Magnitude[7])-1]
	} else {
		pointers := [X8Lanes]**ifmaProjectiveNielsMicroAoSEntryX8{&p0, &p1, &p2, &p3, &p4, &p5, &p6, &p7}
		for lane := 0; lane < X8Lanes; lane++ {
			if lookupMask&(1<<lane) != 0 {
				*pointers[lane] = &table[lane][int(round.Magnitude[lane])-1]
			}
		}
	}
	ifmaProjectiveNielsMicroAoSTransposeX8(out, p0, p1, p2, p3, p4, p5, p6, p7)
	for limb := range modulusLimbs {
		for lane := 0; lane < X8Lanes; lane++ {
			if negativeMask&(1<<lane) != 0 {
				out.YPlusX.limbs[limb][lane], out.YMinusX.limbs[limb][lane] =
					out.YMinusX.limbs[limb][lane], out.YPlusX.limbs[limb][lane]
			}
		}
	}
	conditionalNegateIFMAElementX8(&out.T2D, negativeMask)
}
