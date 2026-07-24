package r51x5

const DSMTerms = 2

// DSMScalarsX4 stores two exact signed coefficients for each of four lanes.
// Coefficients are integers, not scalars modulo L, so the helper also remains
// correct when a decoded point contains torsion.
type DSMScalarsX4 [DSMTerms][X4Lanes]SignedMagnitude

// DSMScalarsX8 is the eight-lane counterpart of DSMScalarsX4.
type DSMScalarsX8 [DSMTerms][X8Lanes]SignedMagnitude

// DSMX4 evaluates [c0]P0+[c1]P1 in four independent lanes. It shares one
// doubling chain between both terms and includes public-scalar recoding and
// table construction. This is a reduced scalar correctness scaffold; it is
// not connected to production dispatch or the composable IFMA loop.
func DSMX4(out *PointX4, bases *[DSMTerms]PointX4, coefficients *DSMScalarsX4, radixBits uint, active uint8) *PointX4 {
	var tables [DSMTerms]FullTableX4
	var recoded [DSMTerms]RadixDigitsX4
	for term := 0; term < DSMTerms; term++ {
		tables[term] = BuildFullTableX4(&bases[term], radixBits)
		recoded[term] = RecodeRegularRadixX4(&coefficients[term], radixBits)
	}

	active &= 0x0f
	if active == 0 {
		return out.Set(NewIdentityPointX4())
	}
	maxRounds := maxDSMRoundsX4(&recoded)
	acc := NewIdentityPointX4()
	for round := maxRounds - 1; round >= 0; round-- {
		if round != maxRounds-1 {
			for doubling := uint(0); doubling < radixBits; doubling++ {
				acc.Double(acc)
			}
		}
		for term := 0; term < DSMTerms; term++ {
			var selected PointX4
			if round < len(recoded[term].Rounds) {
				SelectFullTableX4Public(&selected, &tables[term], &recoded[term].Rounds[round], active)
			} else {
				selected.Set(NewIdentityPointX4())
			}
			acc.Add(acc, &selected)
		}
	}
	return out.Set(acc)
}

// DSMX8 is the eight-lane counterpart of DSMX4.
func DSMX8(out *PointX8, bases *[DSMTerms]PointX8, coefficients *DSMScalarsX8, radixBits uint, active uint8) *PointX8 {
	var tables [DSMTerms]FullTableX8
	var recoded [DSMTerms]RadixDigitsX8
	for term := 0; term < DSMTerms; term++ {
		tables[term] = BuildFullTableX8(&bases[term], radixBits)
		recoded[term] = RecodeRegularRadixX8(&coefficients[term], radixBits)
	}

	if active == 0 {
		return out.Set(NewIdentityPointX8())
	}
	maxRounds := maxDSMRoundsX8(&recoded)
	acc := NewIdentityPointX8()
	for round := maxRounds - 1; round >= 0; round-- {
		if round != maxRounds-1 {
			for doubling := uint(0); doubling < radixBits; doubling++ {
				acc.Double(acc)
			}
		}
		for term := 0; term < DSMTerms; term++ {
			var selected PointX8
			if round < len(recoded[term].Rounds) {
				SelectFullTableX8Public(&selected, &tables[term], &recoded[term].Rounds[round], active)
			} else {
				selected.Set(NewIdentityPointX8())
			}
			acc.Add(acc, &selected)
		}
	}
	return out.Set(acc)
}

func maxDSMRoundsX4(recoded *[DSMTerms]RadixDigitsX4) int {
	maxRounds := 0
	for term := range recoded {
		if len(recoded[term].Rounds) > maxRounds {
			maxRounds = len(recoded[term].Rounds)
		}
	}
	return maxRounds
}

func maxDSMRoundsX8(recoded *[DSMTerms]RadixDigitsX8) int {
	maxRounds := 0
	for term := range recoded {
		if len(recoded[term].Rounds) > maxRounds {
			maxRounds = len(recoded[term].Rounds)
		}
	}
	return maxRounds
}
