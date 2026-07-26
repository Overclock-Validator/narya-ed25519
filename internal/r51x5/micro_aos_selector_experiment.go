package r51x5

// ifmaMicroAoSPointEntryExperiment is the first C2 per-key cache-layout
// experiment. Each radix-51 limb is one contiguous 256-bit row in
// [X,Y,Z,T] order. Four independently selected rows can therefore be loaded
// and transposed into IFMAPointX4's [coordinate][limb][lane] layout.
//
// The type is deliberately private and is not reachable from verifier
// dispatch. In particular, this experiment does not yet choose a comb
// parameterization or a cache admission policy.
type ifmaMicroAoSPointEntryExperiment [5][4]uint64

// ifmaMicroAoSPerKeyTableExperiment owns one independent signer's entries.
// A slice keeps the experiment agnostic to the 32- versus 176-entry frontier
// points without embedding the larger table in every benchmark fixture.
type ifmaMicroAoSPerKeyTableExperiment struct {
	points []ifmaMicroAoSPointEntryExperiment
}

// ifmaMicroAoSTableRadix32X4 is the fixed, caller-owned cold-table layout used
// by the production x4 radix-32 workspace. Unlike the cache experiments above,
// it has no slices or heap-owned payload: every verification rebuilds these
// four independent 16-entry tables in place.
type ifmaMicroAoSTableRadix32X4 [X4Lanes][16]ifmaMicroAoSPointEntryExperiment

var ifmaMicroAoSIdentityEntryExperiment = identityIFMAMicroAoSEntryExperiment()

func identityIFMAMicroAoSEntryExperiment() ifmaMicroAoSPointEntryExperiment {
	var identity ifmaMicroAoSPointEntryExperiment
	identity[0][1] = 1 // Y
	identity[0][2] = 1 // Z
	return identity
}

// selectIFMAMicroAoSCheckedExperimentX4 matches the checked public selector's
// digit, mask, sign, identity, and output-atomicity semantics while sourcing
// each lane from an independent per-key table. It is public-data variable
// time and must not be used for secret scalars.
//
// The low-level transpose loads all four selected entries before its first
// store. The checked wrapper additionally writes into a local value before
// publishing the result, so out may alias table storage and remains unchanged
// if digit validation panics.
func selectIFMAMicroAoSCheckedExperimentX4(out *IFMAPointX4, tables *[X4Lanes]ifmaMicroAoSPerKeyTableExperiment, round *RadixRoundX4, active uint8) *IFMAPointX4 {
	active &= 0x0f
	lookupMask := round.NonzeroMask & active
	negativeMask := round.NegativeMask & lookupMask
	p0 := &ifmaMicroAoSIdentityEntryExperiment
	p1 := p0
	p2 := p0
	p3 := p0
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
		if lookupMask&laneMask != 0 {
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
	}

	var selected IFMAPointX4
	ifmaMicroAoSTransposeSelectExperimentX4(&selected, p0, p1, p2, p3)
	conditionalNegateIFMAPointX4(&selected, negativeMask)
	*out = selected
	return out
}

// selectIFMAMicroAoSUncheckedExperimentX4 is the hot-loop counterpart of the
// checked helper. round must come from a validated recoder, every per-key
// table must contain all referenced magnitudes, and the caller must enforce
// the IFMA backend CPU gate on amd64. Inactive and zero lanes are identities.
// The low-level transpose is exact-alias safe.
func selectIFMAMicroAoSUncheckedExperimentX4(out *IFMAPointX4, tables *[X4Lanes]ifmaMicroAoSPerKeyTableExperiment, round *RadixRoundX4, active uint8) *IFMAPointX4 {
	lookupMask := round.NonzeroMask & active & 0x0f
	negativeMask := round.NegativeMask & lookupMask
	// Dense verifier rounds dominate the intended use. Keep that case free of
	// identity construction and per-lane branches before entering assembly.
	if lookupMask == 0x0f {
		ifmaMicroAoSTransposeSelectExperimentX4(
			out,
			&tables[0].points[int(round.Magnitude[0])-1],
			&tables[1].points[int(round.Magnitude[1])-1],
			&tables[2].points[int(round.Magnitude[2])-1],
			&tables[3].points[int(round.Magnitude[3])-1],
		)
		conditionalNegateIFMAPointX4(out, negativeMask)
		return out
	}

	p0 := &ifmaMicroAoSIdentityEntryExperiment
	p1 := p0
	p2 := p0
	p3 := p0
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
	ifmaMicroAoSTransposeSelectExperimentX4(out, p0, p1, p2, p3)
	conditionalNegateIFMAPointX4(out, negativeMask)
	return out
}

// selectIFMAMicroAoSRadix32UncheckedX4 is the fixed-storage counterpart used
// by the cold x4 verifier. round comes from the radix-32 recoder. Zero and
// inactive lanes select identity, and every magnitude is in [1,16].
func selectIFMAMicroAoSRadix32UncheckedX4(out *IFMAPointX4, table *ifmaMicroAoSTableRadix32X4, round *RadixRoundX4, active uint8) *IFMAPointX4 {
	lookupMask := round.NonzeroMask & active & 0x0f
	p0 := &ifmaMicroAoSIdentityEntryExperiment
	p1, p2, p3 := p0, p0, p0
	if lookupMask == 0x0f {
		p0 = &table[0][int(round.Magnitude[0])-1]
		p1 = &table[1][int(round.Magnitude[1])-1]
		p2 = &table[2][int(round.Magnitude[2])-1]
		p3 = &table[3][int(round.Magnitude[3])-1]
	} else {
		if lookupMask&0x01 != 0 {
			p0 = &table[0][int(round.Magnitude[0])-1]
		}
		if lookupMask&0x02 != 0 {
			p1 = &table[1][int(round.Magnitude[1])-1]
		}
		if lookupMask&0x04 != 0 {
			p2 = &table[2][int(round.Magnitude[2])-1]
		}
		if lookupMask&0x08 != 0 {
			p3 = &table[3][int(round.Magnitude[3])-1]
		}
	}
	ifmaMicroAoSTransposeSelectExperimentX4(out, p0, p1, p2, p3)
	conditionalNegateIFMAPointX4(out, round.NegativeMask&lookupMask)
	return out
}

// importIFMAMicroAoSTablesExperimentX4 splits one grouped x4 table into four
// per-key micro-AoS tables. Promoted from micro_aos_selector_experiment_test.go
// because the warm-comb verifier needs it outside test builds.
func importIFMAMicroAoSTablesExperimentX4[Storage ifmaFullTableStorageX4](grouped *ifmaFullTableX4[Storage]) [X4Lanes]ifmaMicroAoSPerKeyTableExperiment {
	var perKey [X4Lanes]ifmaMicroAoSPerKeyTableExperiment
	for lane := 0; lane < X4Lanes; lane++ {
		perKey[lane].points = make([]ifmaMicroAoSPointEntryExperiment, grouped.entries)
	}
	for entry := 0; entry < grouped.entries; entry++ {
		for limb := 0; limb < 5; limb++ {
			for lane := 0; lane < X4Lanes; lane++ {
				perKey[lane].points[entry][limb] = [4]uint64{
					grouped.points[entry].X.limbs[limb][lane],
					grouped.points[entry].Y.limbs[limb][lane],
					grouped.points[entry].Z.limbs[limb][lane],
					grouped.points[entry].T.limbs[limb][lane],
				}
			}
		}
	}
	return perKey
}
