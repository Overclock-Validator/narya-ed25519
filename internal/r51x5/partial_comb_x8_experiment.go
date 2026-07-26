// Eight-lane heterogeneous partial-comb evaluation.
//
// The x4 evaluator in partial_comb.go is what the promoted warm-comb verifier
// runs today. Its scheduling unit can already be eight signatures, but only by
// consuming two aligned x4 groups back to back: the arithmetic is two YMM
// groups, not one ZMM group.
//
// This file is the eight-lane counterpart. It changes no table format, no
// recoding rule, no acceptance predicate and no schedule; the exponent loop,
// the pass ordering, and the balanced-digit semantics are the x4 ones with a
// wider lane count. Every kernel it calls already existed in an x8 form.
//
// The per-key table is unchanged and needs no rebuild: it is a scalar table, so
// an x4 group owns four instances and an x8 group owns eight. Keys already
// promoted for the x4 path are consumed here as they are.

package r51x5

// asymmetricFixedBRoundX8 is the eight-lane counterpart of
// asymmetricFixedBRoundX4. Like it, the digit is uint16 rather than the uint8
// of RadixRoundX8, because widths 9 and 10 must represent the balanced boundary
// magnitudes 256 and 512 without truncation.
type asymmetricFixedBRoundX8 struct {
	Magnitude    [X8Lanes]uint16
	NonzeroMask  uint8
	NegativeMask uint8
}

type asymmetricFixedBDigitsX8 struct {
	rounds    [maxFixedScalarRounds]asymmetricFixedBRoundX8
	count     uint8
	radixBits uint8
}

// buildHeterogeneousPartialCombATablesX8Experiment builds one scalar per-key
// table per lane, exactly as the x4 builder does. The table format is
// lane-count independent, so these are the same tables the x4 path consumes.
func buildHeterogeneousPartialCombATablesX8Experiment(
	bases *PointX8,
	spec heterogeneousPartialCombSpecExperiment,
) [X8Lanes]*heterogeneousPartialCombTableExperiment {
	var tables [X8Lanes]*heterogeneousPartialCombTableExperiment
	for lane := range tables {
		base := bases.Lane(lane)
		tables[lane] = buildHeterogeneousPartialCombTableExperiment(&base, spec)
	}
	return tables
}

func setAsymmetricFixedBRoundDigitX8(round *asymmetricFixedBRoundX8, lane int, digit int16) {
	if digit < -512 || digit > 512 {
		panic("r51x5: asymmetric fixed-B digit outside experiment ABI")
	}
	negative := digit < 0
	if negative {
		digit = -digit
	}
	round.Magnitude[lane] = uint16(digit)
	if digit != 0 {
		round.NonzeroMask |= 1 << lane
	}
	if negative {
		round.NegativeMask |= 1 << lane
	}
}

// recodeAsymmetricFixedBScalarsX8 mirrors the x4 recoder exactly, including its
// balanced-digit rule, its negation-before-storage order, and its refusal to
// silently absorb a final carry. out is cleared first, so the accumulating
// masks always start from zero.
func recodeAsymmetricFixedBScalarsX8(
	out *asymmetricFixedBDigitsX8,
	scalars *[X8Lanes][32]byte,
	negativeMask, active uint8,
	radixBits uint,
) uint8 {
	*out = asymmetricFixedBDigitsX8{}
	out.count = uint8(asymmetricFixedBRoundCount(radixBits))
	out.radixBits = uint8(radixBits)
	var valid uint8
	for lane := 0; lane < X8Lanes; lane++ {
		laneMask := uint8(1 << lane)
		if active&laneMask == 0 || !canonicalScalarBytes(&scalars[lane]) {
			continue
		}
		valid |= laneMask
		carry := int32(0)
		radix := int32(1) << radixBits
		half := radix >> 1
		for round := 0; round < int(out.count); round++ {
			digit := int32(asymmetricFixedBScalarBitsExperiment(&scalars[lane], round*int(radixBits), radixBits)) + carry
			carry = (digit + half) / radix
			digit -= carry * radix
			if negativeMask&laneMask != 0 {
				digit = -digit
			}
			setAsymmetricFixedBRoundDigitX8(&out.rounds[round], lane, int16(digit))
		}
		if carry != 0 {
			panic("r51x5: canonical scalar exceeded asymmetric fixed-B width")
		}
	}
	return valid
}

func conditionalNegateIFMAAffine3MicroAoSX8(point *fixedBaseIFMACachedX8, negativeMask uint8) {
	if negativeMask == 0 {
		return
	}
	for limb := range point.YPlusX.limbs {
		for lane := 0; lane < X8Lanes; lane++ {
			if negativeMask&(1<<lane) != 0 {
				point.YPlusX.limbs[limb][lane], point.YMinusX.limbs[limb][lane] =
					point.YMinusX.limbs[limb][lane], point.YPlusX.limbs[limb][lane]
			}
		}
	}
	conditionalNegateIFMAElementX8(&point.T2D, negativeMask)
}

// liveHeterogeneousPartialCombSpecX8 is the eight-lane form of the x4 helper.
// It exists for the same reason: a lane skipped by the caller's pre-checks
// keeps a nil table, and reading the group's spec from lane 0 unconditionally
// would dereference nil for a position an attacker chooses.
func liveHeterogeneousPartialCombSpecX8(
	tables *[X8Lanes]*heterogeneousPartialCombTableExperiment,
	active uint8,
) (heterogeneousPartialCombSpecExperiment, bool) {
	for lane := 0; lane < X8Lanes; lane++ {
		if active&(1<<lane) == 0 {
			continue
		}
		if table := tables[lane]; table != nil {
			return table.spec, true
		}
	}
	return heterogeneousPartialCombSpecExperiment{}, false
}

func selectHeterogeneousPartialCombPerKeyX8Experiment(
	out *fixedBaseIFMACachedX8,
	tables *[X8Lanes]*heterogeneousPartialCombTableExperiment,
	row int,
	round *asymmetricFixedBRoundX8,
	active uint8,
) {
	lookupMask := round.NonzeroMask & active
	identity := &ifmaAffine3MicroAoSIdentityEntryExperiment
	var operands [X8Lanes]*ifmaAffine3MicroAoSEntryExperiment
	for lane := range operands {
		operands[lane] = identity
	}
	if spec, ok := liveHeterogeneousPartialCombSpecX8(tables, lookupMask); ok {
		entries := spec.entriesPerRow()
		for lane := 0; lane < X8Lanes; lane++ {
			if lookupMask&(1<<lane) != 0 {
				operands[lane] = &tables[lane].points[row*entries+int(round.Magnitude[lane])-1]
			}
		}
	}
	ifmaAffine3MicroAoSTransposeSelectExperimentX8(
		out,
		operands[0], operands[1], operands[2], operands[3],
		operands[4], operands[5], operands[6], operands[7],
	)
	conditionalNegateIFMAAffine3MicroAoSX8(out, round.NegativeMask&lookupMask)
}

// selectHeterogeneousPartialCombPreSignedSharedX8Experiment selects from the
// process-wide fixed-B table, which stores both signs so the hot loop needs no
// post-selection negation. The table is shared across every lane, so unlike the
// per-key selector there is no nil case to guard.
func selectHeterogeneousPartialCombPreSignedSharedX8Experiment(
	out *fixedBaseIFMACachedX8,
	table *heterogeneousPartialCombPreSignedSharedTableExperiment,
	row int,
	round *asymmetricFixedBRoundX8,
	active uint8,
) {
	lookupMask := round.NonzeroMask & active
	identity := &ifmaAffine3MicroAoSIdentityEntryExperiment
	var operands [X8Lanes]*ifmaAffine3MicroAoSEntryExperiment
	for lane := range operands {
		operands[lane] = identity
	}
	rowOffset := row * table.spec.entriesPerRow()
	for lane := 0; lane < X8Lanes; lane++ {
		if lookupMask&(1<<lane) == 0 {
			continue
		}
		sign := heterogeneousPartialCombPositiveSignExperiment
		if round.NegativeMask&(1<<lane) != 0 {
			sign = heterogeneousPartialCombNegativeSignExperiment
		}
		operands[lane] = &table.points[sign][rowOffset+int(round.Magnitude[lane])-1]
	}
	ifmaAffine3MicroAoSTransposeSelectExperimentX8(
		out,
		operands[0], operands[1], operands[2], operands[3],
		operands[4], operands[5], operands[6], operands[7],
	)
}

func addHeterogeneousPartialCombAPassX8Experiment(
	acc *IFMAPointX8,
	tables *[X8Lanes]*heterogeneousPartialCombTableExperiment,
	digits *asymmetricFixedBDigitsX8,
	pass int,
	usable uint8,
) error {
	spec, ok := liveHeterogeneousPartialCombSpecX8(tables, usable)
	if !ok {
		return nil
	}
	for row := 0; row < spec.rowCount(); row++ {
		digitIndex := row*spec.passes + pass
		if digitIndex >= spec.digitCount() {
			continue
		}
		round := &digits.rounds[digitIndex]
		if round.NonzeroMask&usable == 0 {
			continue
		}
		var selected fixedBaseIFMACachedX8
		selectHeterogeneousPartialCombPerKeyX8Experiment(&selected, tables, row, round, usable)
		if err := addFixedBaseIFMACachedX8(acc, acc, &selected); err != nil {
			return err
		}
	}
	return nil
}

func addHeterogeneousPartialCombPreSignedBPassX8Experiment(
	acc *IFMAPointX8,
	table *heterogeneousPartialCombPreSignedSharedTableExperiment,
	digits *asymmetricFixedBDigitsX8,
	pass int,
	usable uint8,
) error {
	spec := table.spec
	for row := 0; row < spec.rowCount(); row++ {
		digitIndex := row*spec.passes + pass
		if digitIndex >= spec.digitCount() {
			continue
		}
		round := &digits.rounds[digitIndex]
		if round.NonzeroMask&usable == 0 {
			continue
		}
		var selected fixedBaseIFMACachedX8
		selectHeterogeneousPartialCombPreSignedSharedX8Experiment(&selected, table, row, round, usable)
		if err := addFixedBaseIFMACachedX8(acc, acc, &selected); err != nil {
			return err
		}
	}
	return nil
}

// evaluateHeterogeneousPartialCombPreSignedBDSMX8Experiment computes
// [s]B+[-k]A across eight lanes with the same merged exponent schedule as the
// x4 evaluator: additions at exponent e happen before the accumulator is
// lowered to e-1, and each term keeps its own (width, passes) pair.
func evaluateHeterogeneousPartialCombPreSignedBDSMX8Experiment(
	out *IFMAPointX8,
	aTables *[X8Lanes]*heterogeneousPartialCombTableExperiment,
	bTable *heterogeneousPartialCombPreSignedSharedTableExperiment,
	scalars *FixedDSMScalarsX8,
	negativeMasks *[DSMTerms]uint8,
	active uint8,
) (uint8, error) {
	if !ExperimentalIFMAAvailable() {
		return 0, ErrIFMAUnavailable
	}
	aSpec, ok := liveHeterogeneousPartialCombSpecX8(aTables, active)
	if !ok {
		*out = identityIFMAPointX8Value()
		return 0, nil
	}
	bSpec := bTable.spec
	var aDigits, bDigits asymmetricFixedBDigitsX8
	// Term 1 is A. Applying negativeMasks[1] to every balanced digit preserves
	// exact -k, rather than replacing it by L-k (which is wrong on torsion).
	usable := recodeAsymmetricFixedBScalarsX8(&aDigits, &scalars[1], negativeMasks[1], active, aSpec.width)
	usable &= recodeAsymmetricFixedBScalarsX8(&bDigits, &scalars[0], negativeMasks[0], active, bSpec.width)
	acc := identityIFMAPointX8Value()
	if usable == 0 {
		*out = acc
		return 0, nil
	}

	topExponent := aSpec.onlineDepth()
	if bSpec.onlineDepth() > topExponent {
		topExponent = bSpec.onlineDepth()
	}
	for exponent := topExponent; exponent >= 0; exponent-- {
		if exponent != topExponent {
			if err := ifmaPointDoubleComposableStaticX8(&acc, &acc); err != nil {
				return 0, err
			}
		}
		if exponent%int(bSpec.width) == 0 {
			pass := exponent / int(bSpec.width)
			if pass < bSpec.passes {
				if err := addHeterogeneousPartialCombPreSignedBPassX8Experiment(&acc, bTable, &bDigits, pass, usable); err != nil {
					return 0, err
				}
			}
		}
		if exponent%int(aSpec.width) == 0 {
			pass := exponent / int(aSpec.width)
			if pass < aSpec.passes {
				if err := addHeterogeneousPartialCombAPassX8Experiment(&acc, aTables, &aDigits, pass, usable); err != nil {
					return 0, err
				}
			}
		}
	}
	*out = acc
	return usable, nil
}
