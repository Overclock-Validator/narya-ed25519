package r51x5

// SelectFullTableX4Public selects one signed multiple per active lane from a
// full positive table. The lookup is intentionally variable-time: Ed25519
// verification scalars and HEEA-derived coefficients are public. Do not use
// this helper with secret scalars.
//
// Selection writes the existing [coordinate][limb][lane] layout directly.
// It does not unpack a scalar Point with Lane or repack one with SetLane, so
// its output can feed the future x4 IFMA point-operation loop unchanged.
// Inactive and zero-digit lanes are identities. Inputs and output may alias.
func SelectFullTableX4Public(out *PointX4, table *FullTableX4, round *RadixRoundX4, active uint8) *PointX4 {
	active &= 0x0f
	selected := identityPointX4Value()
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
		gatherPointLaneX4(&selected, source, lane)
	}
	conditionalNegatePointX4(&selected, negativeMask)
	*out = selected
	return out
}

// SelectFullTableX8Public is the eight-lane counterpart of
// SelectFullTableX4Public. It is public-data variable-time and not suitable
// for secret scalars.
func SelectFullTableX8Public(out *PointX8, table *FullTableX8, round *RadixRoundX8, active uint8) *PointX8 {
	selected := identityPointX8Value()
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
		gatherPointLaneX8(&selected, source, lane)
	}
	conditionalNegatePointX8(&selected, negativeMask)
	*out = selected
	return out
}

func validatePublicDigit(magnitude uint8, markedNonzero, markedNegative bool, entries int, active bool) {
	if !active {
		return
	}
	if markedNonzero != (magnitude != 0) || markedNegative && magnitude == 0 {
		panic("r51x5: inconsistent round-major digit metadata")
	}
	if magnitude > uint8(entries) {
		panic("r51x5: digit outside full table")
	}
}

func identityPointX4Value() PointX4 {
	var result PointX4
	for lane := 0; lane < X4Lanes; lane++ {
		result.Y.limbs[0][lane] = 1
		result.Z.limbs[0][lane] = 1
	}
	return result
}

func identityPointX8Value() PointX8 {
	var result PointX8
	for lane := 0; lane < X8Lanes; lane++ {
		result.Y.limbs[0][lane] = 1
		result.Z.limbs[0][lane] = 1
	}
	return result
}

func gatherPointLaneX4(out, source *PointX4, lane int) {
	for limb := 0; limb < len(modulusLimbs); limb++ {
		out.X.limbs[limb][lane] = source.X.limbs[limb][lane]
		out.Y.limbs[limb][lane] = source.Y.limbs[limb][lane]
		out.Z.limbs[limb][lane] = source.Z.limbs[limb][lane]
		out.T.limbs[limb][lane] = source.T.limbs[limb][lane]
	}
}

func gatherPointLaneX8(out, source *PointX8, lane int) {
	for limb := 0; limb < len(modulusLimbs); limb++ {
		out.X.limbs[limb][lane] = source.X.limbs[limb][lane]
		out.Y.limbs[limb][lane] = source.Y.limbs[limb][lane]
		out.Z.limbs[limb][lane] = source.Z.limbs[limb][lane]
		out.T.limbs[limb][lane] = source.T.limbs[limb][lane]
	}
}

func conditionalNegatePointX4(point *PointX4, negativeMask uint8) {
	for lane := 0; lane < X4Lanes; lane++ {
		if negativeMask&(1<<lane) == 0 {
			continue
		}
		negateReducedLaneX4(&point.X, lane)
		negateReducedLaneX4(&point.T, lane)
	}
}

func conditionalNegatePointX8(point *PointX8, negativeMask uint8) {
	for lane := 0; lane < X8Lanes; lane++ {
		if negativeMask&(1<<lane) == 0 {
			continue
		}
		negateReducedLaneX8(&point.X, lane)
		negateReducedLaneX8(&point.T, lane)
	}
}

// negateReducedLaneX4 computes p-x in place without extracting an Element.
// The zero special case preserves Element's unique reduced representation.
func negateReducedLaneX4(element *ElementX4, lane int) {
	var aggregate uint64
	for limb := range modulusLimbs {
		aggregate |= element.limbs[limb][lane]
	}
	if aggregate == 0 {
		return
	}
	var borrow uint64
	for limb, modulus := range modulusLimbs {
		subtrahend := element.limbs[limb][lane] + borrow
		if modulus >= subtrahend {
			element.limbs[limb][lane] = modulus - subtrahend
			borrow = 0
		} else {
			element.limbs[limb][lane] = 1<<LimbBits + modulus - subtrahend
			borrow = 1
		}
	}
}

// negateReducedLaneX8 is the eight-lane counterpart of negateReducedLaneX4.
func negateReducedLaneX8(element *ElementX8, lane int) {
	var aggregate uint64
	for limb := range modulusLimbs {
		aggregate |= element.limbs[limb][lane]
	}
	if aggregate == 0 {
		return
	}
	var borrow uint64
	for limb, modulus := range modulusLimbs {
		subtrahend := element.limbs[limb][lane] + borrow
		if modulus >= subtrahend {
			element.limbs[limb][lane] = modulus - subtrahend
			borrow = 0
		} else {
			element.limbs[limb][lane] = 1<<LimbBits + modulus - subtrahend
			borrow = 1
		}
	}
}
