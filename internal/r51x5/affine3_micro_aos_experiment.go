package r51x5

// ifmaAffine3MicroAoSEntryExperiment is the dense three-coordinate per-key
// table layout for the C2 experiment. Each limb row stores
// [Y+X, Y-X, 2dT]. The point is affine, so the mixed-add consumer uses an
// implicit Z=1 and needs no fourth coordinate.
//
// This type and its selectors remain private and unreachable from production
// dispatch until table construction, cache admission, and complete verifier
// gates have passed.
type ifmaAffine3MicroAoSEntryExperiment [5][3]uint64

type ifmaAffine3MicroAoSPerKeyTableExperiment struct {
	points []ifmaAffine3MicroAoSEntryExperiment
}

var ifmaAffine3MicroAoSIdentityEntryExperiment = identityIFMAAffine3MicroAoSEntryExperiment()

func identityIFMAAffine3MicroAoSEntryExperiment() ifmaAffine3MicroAoSEntryExperiment {
	var identity ifmaAffine3MicroAoSEntryExperiment
	identity[0][0] = 1 // Y+X
	identity[0][1] = 1 // Y-X
	return identity
}

// selectIFMAAffine3MicroAoSCheckedExperimentX4 preserves the checked public
// selector's validation, identity, sign, and output-atomicity semantics while
// sourcing four independently cacheable per-key affine entries.
func selectIFMAAffine3MicroAoSCheckedExperimentX4(
	out *fixedBaseIFMACachedX4,
	tables *[X4Lanes]ifmaAffine3MicroAoSPerKeyTableExperiment,
	round *RadixRoundX4,
	active uint8,
) *fixedBaseIFMACachedX4 {
	active &= 0x0f
	lookupMask := round.NonzeroMask & active
	p0 := &ifmaAffine3MicroAoSIdentityEntryExperiment
	p1, p2, p3 := p0, p0, p0
	for lane := 0; lane < X4Lanes; lane++ {
		laneMask := uint8(1 << lane)
		magnitude := round.Magnitude[lane]
		validatePublicDigit(
			magnitude,
			round.NonzeroMask&laneMask != 0,
			round.NegativeMask&laneMask != 0,
			len(tables[lane].points),
			active&laneMask != 0,
		)
		if lookupMask&laneMask == 0 {
			continue
		}
		source := &tables[lane].points[int(magnitude)-1]
		switch lane {
		case 0:
			p0 = source
		case 1:
			p1 = source
		case 2:
			p2 = source
		case 3:
			p3 = source
		}
	}

	var selected fixedBaseIFMACachedX4
	ifmaAffine3MicroAoSTransposeSelectExperimentX4(&selected, p0, p1, p2, p3)
	conditionalNegateIFMAAffine3MicroAoSX4(&selected, round.NegativeMask&lookupMask)
	*out = selected
	return out
}

// selectIFMAAffine3MicroAoSUncheckedExperimentX4 is the validated hot-loop
// counterpart. The caller owns the IFMA CPU gate and guarantees that every
// referenced magnitude exists. Zero and inactive lanes select affine identity.
func selectIFMAAffine3MicroAoSUncheckedExperimentX4(
	out *fixedBaseIFMACachedX4,
	tables *[X4Lanes]ifmaAffine3MicroAoSPerKeyTableExperiment,
	round *RadixRoundX4,
	active uint8,
) *fixedBaseIFMACachedX4 {
	lookupMask := round.NonzeroMask & active & 0x0f
	p0 := &ifmaAffine3MicroAoSIdentityEntryExperiment
	p1, p2, p3 := p0, p0, p0
	if lookupMask == 0x0f {
		p0 = &tables[0].points[int(round.Magnitude[0])-1]
		p1 = &tables[1].points[int(round.Magnitude[1])-1]
		p2 = &tables[2].points[int(round.Magnitude[2])-1]
		p3 = &tables[3].points[int(round.Magnitude[3])-1]
	} else {
		if lookupMask&0x01 != 0 {
			p0 = &tables[0].points[int(round.Magnitude[0])-1]
		}
		if lookupMask&0x02 != 0 {
			p1 = &tables[1].points[int(round.Magnitude[1])-1]
		}
		if lookupMask&0x04 != 0 {
			p2 = &tables[2].points[int(round.Magnitude[2])-1]
		}
		if lookupMask&0x08 != 0 {
			p3 = &tables[3].points[int(round.Magnitude[3])-1]
		}
	}
	ifmaAffine3MicroAoSTransposeSelectExperimentX4(out, p0, p1, p2, p3)
	conditionalNegateIFMAAffine3MicroAoSX4(out, round.NegativeMask&lookupMask)
	return out
}

func conditionalNegateIFMAAffine3MicroAoSX4(point *fixedBaseIFMACachedX4, negativeMask uint8) {
	negativeMask &= 0x0f
	if negativeMask == 0 {
		return
	}
	for limb := range point.YPlusX.limbs {
		for lane := 0; lane < X4Lanes; lane++ {
			if negativeMask&(1<<lane) != 0 {
				point.YPlusX.limbs[limb][lane], point.YMinusX.limbs[limb][lane] =
					point.YMinusX.limbs[limb][lane], point.YPlusX.limbs[limb][lane]
			}
		}
	}
	conditionalNegateIFMAElementX4(&point.T2D, negativeMask)
}
