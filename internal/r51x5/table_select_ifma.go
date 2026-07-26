package r51x5

// The IFMA table storage types deliberately have different array lengths.
// A radix-16 or radix-32 verifier must not retain and clear the 32 entries
// needed only by radix-64. Keeping the storage in the type also preserves the
// caller-owned, allocation-free workspace contract without unsafe unions.
type ifmaFullTableStorageRadix16X4 [8]IFMAPointX4
type ifmaFullTableStorageRadix32X4 [16]IFMAPointX4
type ifmaFullTableStorageRadix64X4 [32]IFMAPointX4

type ifmaFullTableStorageX4 interface {
	ifmaFullTableStorageRadix16X4 | ifmaFullTableStorageRadix32X4 | ifmaFullTableStorageRadix64X4
}

type ifmaFullTableX4[Storage ifmaFullTableStorageX4] struct {
	points    Storage
	entries   int
	radixBits uint
}

type ifmaFullTableStorageRadix16X8 [8]IFMAPointX8
type ifmaFullTableStorageRadix32X8 [16]IFMAPointX8
type ifmaFullTableStorageRadix64X8 [32]IFMAPointX8

type ifmaFullTableStorageX8 interface {
	ifmaFullTableStorageRadix16X8 | ifmaFullTableStorageRadix32X8 | ifmaFullTableStorageRadix64X8
}

type ifmaFullTableX8[Storage ifmaFullTableStorageX8] struct {
	points    Storage
	entries   int
	radixBits uint
}

// IFMAFullTableRadix16X4 and IFMAFullTableRadix16X8 retain exactly the eight
// positive multiples used by radix-16.
type IFMAFullTableRadix16X4 = ifmaFullTableX4[ifmaFullTableStorageRadix16X4]
type IFMAFullTableRadix16X8 = ifmaFullTableX8[ifmaFullTableStorageRadix16X8]

// IFMAFullTableX4 and IFMAFullTableX8 are the primary radix-32 table types.
// Their four-coordinate payloads are respectively 10 and 20 KiB. The
// unsuffixed name intentionally denotes the current default experiment.
type IFMAFullTableX4 = ifmaFullTableX4[ifmaFullTableStorageRadix32X4]
type IFMAFullTableX8 = ifmaFullTableX8[ifmaFullTableStorageRadix32X8]

// IFMAFullTableRadix64X4 and IFMAFullTableRadix64X8 retain the 32 positive
// multiples used only by radix-64.
type IFMAFullTableRadix64X4 = ifmaFullTableX4[ifmaFullTableStorageRadix64X4]
type IFMAFullTableRadix64X8 = ifmaFullTableX8[ifmaFullTableStorageRadix64X8]

// ImportIFMAFullTableX4 imports a reduced reference table into the composable
// domain. It is a correctness/table-selection bridge, not optimized table
// generation.
func ImportIFMAFullTableX4(reduced *FullTableX4) IFMAFullTableX4 {
	return importIFMAFullTableX4[ifmaFullTableStorageRadix32X4](reduced)
}

// ImportIFMAFullTableX8 is the eight-lane counterpart of
// ImportIFMAFullTableX4.
func ImportIFMAFullTableX8(reduced *FullTableX8) IFMAFullTableX8 {
	return importIFMAFullTableX8[ifmaFullTableStorageRadix32X8](reduced)
}

func ImportIFMAFullTableRadix16X4(reduced *FullTableX4) IFMAFullTableRadix16X4 {
	return importIFMAFullTableX4[ifmaFullTableStorageRadix16X4](reduced)
}

func ImportIFMAFullTableRadix16X8(reduced *FullTableX8) IFMAFullTableRadix16X8 {
	return importIFMAFullTableX8[ifmaFullTableStorageRadix16X8](reduced)
}

func ImportIFMAFullTableRadix64X4(reduced *FullTableX4) IFMAFullTableRadix64X4 {
	return importIFMAFullTableX4[ifmaFullTableStorageRadix64X4](reduced)
}

func ImportIFMAFullTableRadix64X8(reduced *FullTableX8) IFMAFullTableRadix64X8 {
	return importIFMAFullTableX8[ifmaFullTableStorageRadix64X8](reduced)
}

func importIFMAFullTableX4[Storage ifmaFullTableStorageX4](reduced *FullTableX4) ifmaFullTableX4[Storage] {
	var result ifmaFullTableX4[Storage]
	validateIFMAFullTableStorage(len(result.points), reduced.radixBits)
	result.entries = reduced.entries
	result.radixBits = reduced.radixBits
	for entry := 0; entry < reduced.entries; entry++ {
		result.points[entry].SetReduced(&reduced.points[entry])
	}
	return result
}

func importIFMAFullTableX8[Storage ifmaFullTableStorageX8](reduced *FullTableX8) ifmaFullTableX8[Storage] {
	var result ifmaFullTableX8[Storage]
	validateIFMAFullTableStorage(len(result.points), reduced.radixBits)
	result.entries = reduced.entries
	result.radixBits = reduced.radixBits
	for entry := 0; entry < reduced.entries; entry++ {
		result.points[entry].SetReduced(&reduced.points[entry])
	}
	return result
}

// SelectIFMAFullTableX4Public selects one signed composable point per active
// lane. It is variable-time in public verification scalars and must not be
// used for secret scalars. The gather writes [coordinate][limb][lane]
// directly, without Point.Lane or SetLane extraction. Inputs and output may
// alias; inactive and zero-digit lanes are identities.
func SelectIFMAFullTableX4Public[Storage ifmaFullTableStorageX4](out *IFMAPointX4, table *ifmaFullTableX4[Storage], round *RadixRoundX4, active uint8) *IFMAPointX4 {
	active &= 0x0f
	selected := identityIFMAPointX4Value()
	lookupMask := round.NonzeroMask & active
	negativeMask := round.NegativeMask & lookupMask
	for lane := 0; lane < X4Lanes; lane++ {
		laneMask := uint8(1 << lane)
		magnitude := round.Magnitude[lane]
		validatePublicDigit(magnitude, round.NonzeroMask&laneMask != 0, round.NegativeMask&laneMask != 0, table.entries, active&laneMask != 0)
		if lookupMask&laneMask == 0 {
			continue
		}
		source := &table.points[int(magnitude)-1]
		gatherIFMAPointLaneX4(&selected, source, lane)
	}
	conditionalNegateIFMAPointX4(&selected, negativeMask)
	*out = selected
	return out
}

// selectIFMAFullTableX4PublicUncheckedNoAlias is the hot verifier counterpart
// of SelectIFMAFullTableX4Public. out must not alias table (its prior contents
// are ignored), and round must come from one of this package's validated x4
// recoders for this table's radix. Those invariants let the selector write
// gathered lanes directly and initialize only zero/inactive lanes instead of
// constructing and copying a full 640-byte identity point on every loop term.
//
// The checked, alias-safe exported helper remains the differential oracle.
func selectIFMAFullTableX4PublicUncheckedNoAlias[Storage ifmaFullTableStorageX4](out *IFMAPointX4, table *ifmaFullTableX4[Storage], round *RadixRoundX4, active uint8) *IFMAPointX4 {
	lookupMask := round.NonzeroMask & active & 0x0f
	negativeMask := round.NegativeMask & lookupMask
	for lane := 0; lane < X4Lanes; lane++ {
		laneMask := uint8(1 << lane)
		if lookupMask&laneMask == 0 {
			setIdentityIFMAPointLaneX4(out, lane)
			continue
		}
		source := &table.points[int(round.Magnitude[lane])-1]
		gatherIFMAPointLaneX4(out, source, lane)
	}
	conditionalNegateIFMAPointX4(out, negativeMask)
	return out
}

// SelectIFMAFullTableX8Public is the eight-lane counterpart of
// SelectIFMAFullTableX4Public.
func SelectIFMAFullTableX8Public[Storage ifmaFullTableStorageX8](out *IFMAPointX8, table *ifmaFullTableX8[Storage], round *RadixRoundX8, active uint8) *IFMAPointX8 {
	selected := identityIFMAPointX8Value()
	lookupMask := round.NonzeroMask & active
	negativeMask := round.NegativeMask & lookupMask
	for lane := 0; lane < X8Lanes; lane++ {
		laneMask := uint8(1 << lane)
		magnitude := round.Magnitude[lane]
		validatePublicDigit(magnitude, round.NonzeroMask&laneMask != 0, round.NegativeMask&laneMask != 0, table.entries, active&laneMask != 0)
		if lookupMask&laneMask == 0 {
			continue
		}
		source := &table.points[int(magnitude)-1]
		gatherIFMAPointLaneX8(&selected, source, lane)
	}
	conditionalNegateIFMAPointX8(&selected, negativeMask)
	*out = selected
	return out
}

// selectIFMAFullTableX8PublicUncheckedNoAlias is the x8 hot-verifier
// counterpart of SelectIFMAFullTableX8Public. out must not alias table (its
// prior contents are ignored), and round must come from one of this package's
// validated x8 recoders for this table's radix. It writes selected lanes
// directly and initializes only zero/inactive lanes instead of constructing
// and copying a complete 1,280-byte identity point on every loop term.
//
// The checked, alias-safe exported helper remains the differential oracle.
func selectIFMAFullTableX8PublicUncheckedNoAlias[Storage ifmaFullTableStorageX8](out *IFMAPointX8, table *ifmaFullTableX8[Storage], round *RadixRoundX8, active uint8) *IFMAPointX8 {
	lookupMask := round.NonzeroMask & active
	negativeMask := round.NegativeMask & lookupMask
	for lane := 0; lane < X8Lanes; lane++ {
		laneMask := uint8(1 << lane)
		if lookupMask&laneMask == 0 {
			setIdentityIFMAPointLaneX8(out, lane)
			continue
		}
		source := &table.points[int(round.Magnitude[lane])-1]
		gatherIFMAPointLaneX8(out, source, lane)
	}
	conditionalNegateIFMAPointX8(out, negativeMask)
	return out
}

func validateIFMAFullTableStorage(entries int, radixBits uint) {
	if entries < regularRadixEntries(radixBits) {
		panic("r51x5: IFMA table storage is too small for radix")
	}
}

func identityIFMAPointX4Value() IFMAPointX4 {
	var result IFMAPointX4
	for lane := 0; lane < X4Lanes; lane++ {
		result.Y.limbs[0][lane] = 1
		result.Z.limbs[0][lane] = 1
	}
	return result
}

func identityIFMAPointX8Value() IFMAPointX8 {
	var result IFMAPointX8
	for lane := 0; lane < X8Lanes; lane++ {
		result.Y.limbs[0][lane] = 1
		result.Z.limbs[0][lane] = 1
	}
	return result
}

func gatherIFMAPointLaneX4(out, source *IFMAPointX4, lane int) {
	for limb := range modulusLimbs {
		out.X.limbs[limb][lane] = source.X.limbs[limb][lane]
		out.Y.limbs[limb][lane] = source.Y.limbs[limb][lane]
		out.Z.limbs[limb][lane] = source.Z.limbs[limb][lane]
		out.T.limbs[limb][lane] = source.T.limbs[limb][lane]
	}
}

func setIdentityIFMAPointLaneX4(out *IFMAPointX4, lane int) {
	for limb := range modulusLimbs {
		out.X.limbs[limb][lane] = 0
		out.Y.limbs[limb][lane] = 0
		out.Z.limbs[limb][lane] = 0
		out.T.limbs[limb][lane] = 0
	}
	out.Y.limbs[0][lane] = 1
	out.Z.limbs[0][lane] = 1
}

func gatherIFMAPointLaneX8(out, source *IFMAPointX8, lane int) {
	for limb := range modulusLimbs {
		out.X.limbs[limb][lane] = source.X.limbs[limb][lane]
		out.Y.limbs[limb][lane] = source.Y.limbs[limb][lane]
		out.Z.limbs[limb][lane] = source.Z.limbs[limb][lane]
		out.T.limbs[limb][lane] = source.T.limbs[limb][lane]
	}
}

func setIdentityIFMAPointLaneX8(out *IFMAPointX8, lane int) {
	for limb := range modulusLimbs {
		out.X.limbs[limb][lane] = 0
		out.Y.limbs[limb][lane] = 0
		out.Z.limbs[limb][lane] = 0
		out.T.limbs[limb][lane] = 0
	}
	out.Y.limbs[0][lane] = 1
	out.Z.limbs[0][lane] = 1
}

func conditionalNegateIFMAPointX4(point *IFMAPointX4, negativeMask uint8) {
	if negativeMask == 0 {
		return
	}
	conditionalNegateIFMAElementX4(&point.X, negativeMask)
	conditionalNegateIFMAElementX4(&point.T, negativeMask)
}

func conditionalNegateIFMAPointX8(point *IFMAPointX8, negativeMask uint8) {
	if negativeMask == 0 {
		return
	}
	conditionalNegateIFMAElementX8(&point.X, negativeMask)
	conditionalNegateIFMAElementX8(&point.T, negativeMask)
}

// The composable table may contain bounded non-canonical representatives, so
// per-lane sign application uses the same biased subtraction and carry/fold
// normalization as IFMAElement.Negate. Unselected lanes are normalized copies
// of themselves. This keeps every output limb below 2^52.
func conditionalNegateIFMAElementX4(element *IFMAElementX4, negativeMask uint8) {
	if ExperimentalIFMAAvailable() {
		ifmaConditionalNegateNormalizedUncheckedX4(&element.limbs, &element.limbs, negativeMask)
		return
	}
	conditionalNegateIFMAElementPortableX4(element, negativeMask)
}

//go:noinline
func conditionalNegateIFMAElementPortableX4(element *IFMAElementX4, negativeMask uint8) {
	var raw IFMAProductX4
	for limb := range raw {
		bias := ifmaSubtractionBias(limb)
		for lane := range raw[limb] {
			if negativeMask&(1<<lane) != 0 {
				raw[limb][lane] = bias - element.limbs[limb][lane]
			} else {
				raw[limb][lane] = element.limbs[limb][lane]
			}
		}
	}
	element.limbs = mustNormalizeIFMAProductX4(&raw)
}

func conditionalNegateIFMAElementX8(element *IFMAElementX8, negativeMask uint8) {
	if ExperimentalIFMAAvailable() {
		ifmaConditionalNegateNormalizedUncheckedX8(&element.limbs, &element.limbs, negativeMask)
		return
	}
	conditionalNegateIFMAElementPortableX8(element, negativeMask)
}

//go:noinline
func conditionalNegateIFMAElementPortableX8(element *IFMAElementX8, negativeMask uint8) {
	var raw IFMAProductX8
	for limb := range raw {
		bias := ifmaSubtractionBias(limb)
		for lane := range raw[limb] {
			if negativeMask&(1<<lane) != 0 {
				raw[limb][lane] = bias - element.limbs[limb][lane]
			} else {
				raw[limb][lane] = element.limbs[limb][lane]
			}
		}
	}
	element.limbs = mustNormalizeIFMAProductX8(&raw)
}
