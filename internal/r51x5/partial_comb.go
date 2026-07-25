// Heterogeneous partial-comb construction and evaluation.
//
// Promoted verbatim from heterogeneous_partial_comb_experiment_test.go so the
// registered r51 backend can build per-key tables. Symbol names are unchanged
// from the experiment so this move is provably behaviour-neutral; the trailing
// Experiment suffixes are dropped in a separate cosmetic change.

package r51x5

import "unsafe"

// heterogeneousPartialCombSpecExperiment describes one term in the test-only
// heterogeneous comb. A scalar has ceil(253/width) balanced digits. Consecutive
// blocks of passes digits share one table row; row j is based at
// [2^(width*passes*j)]P. Online evaluation therefore needs only
// width*(passes-1) doublings, independently of the number of rows.
type heterogeneousPartialCombSpecExperiment struct {
	width  uint
	passes int
}

func (s heterogeneousPartialCombSpecExperiment) digitCount() int {
	return (253 + int(s.width) - 1) / int(s.width)
}

func (s heterogeneousPartialCombSpecExperiment) rowCount() int {
	return (s.digitCount() + s.passes - 1) / s.passes
}

func (s heterogeneousPartialCombSpecExperiment) entriesPerRow() int {
	return 1 << (s.width - 1)
}

func (s heterogeneousPartialCombSpecExperiment) onlineDepth() int {
	return int(s.width) * (s.passes - 1)
}

func (s heterogeneousPartialCombSpecExperiment) validCellsForPass(pass int) int {
	valid := 0
	for row := 0; row < s.rowCount(); row++ {
		if row*s.passes+pass < s.digitCount() {
			valid++
		}
	}
	return valid
}

func (s heterogeneousPartialCombSpecExperiment) validate() {
	if s.width < 6 || s.width > 10 || s.passes < 1 {
		panic("r51x5: invalid heterogeneous partial-comb experiment shape")
	}
}

var (
	heterogeneousPartialCombA6R9Experiment  = heterogeneousPartialCombSpecExperiment{width: 6, passes: 9}
	heterogeneousPartialCombB8R3Experiment  = heterogeneousPartialCombSpecExperiment{width: 8, passes: 3}
	heterogeneousPartialCombB10R5Experiment = heterogeneousPartialCombSpecExperiment{width: 10, passes: 5}
)

// heterogeneousPartialCombTableExperiment stores positive affine-cached
// multiples in the committed dense [Y+X,Y-X,2dT] micro-AoS format. It is a
// scalar table: an A-side x4 group owns four instances, while fixed B shares
// one instance across all lanes.
type heterogeneousPartialCombTableExperiment struct {
	points []ifmaAffine3MicroAoSEntryExperiment
	spec   heterogeneousPartialCombSpecExperiment
}

const (
	heterogeneousPartialCombPositiveSignExperiment = 0
	heterogeneousPartialCombNegativeSignExperiment = 1
)

// heterogeneousPartialCombPreSignedSharedTableExperiment duplicates only the
// process-wide fixed-B payload. Each public digit selects a positive or
// negative affine-cached entry before the existing micro-AoS transpose, so the
// hot loop does not need to swap Y+X/Y-X or negate 2dT after selection.
// Per-key A tables deliberately retain their single-sign representation.
type heterogeneousPartialCombPreSignedSharedTableExperiment struct {
	points [2][]ifmaAffine3MicroAoSEntryExperiment
	spec   heterogeneousPartialCombSpecExperiment
}

func buildHeterogeneousPartialCombTableExperiment(
	base *Point,
	spec heterogeneousPartialCombSpecExperiment,
) *heterogeneousPartialCombTableExperiment {
	spec.validate()
	rows, entries := spec.rowCount(), spec.entriesPerRow()
	table := &heterogeneousPartialCombTableExperiment{
		points: make([]ifmaAffine3MicroAoSEntryExperiment, rows*entries),
		spec:   spec,
	}

	rowBase := *base
	for row := 0; row < rows; row++ {
		multiple := rowBase
		for entry := 0; entry < entries; entry++ {
			var cached fixedBaseAffineCached
			fixedBaseCacheAffine(&cached, &multiple)
			importAsymmetricFixedBDenseAffine3EntryExperiment(
				&table.points[row*entries+entry],
				&cached,
			)
			if entry+1 < entries {
				fixedBasePointAdd(&multiple, &multiple, &rowBase)
			}
		}
		if row+1 < rows {
			for doubling := 0; doubling < int(spec.width)*spec.passes; doubling++ {
				fixedBasePointDouble(&rowBase, &rowBase)
			}
		}
	}
	return table
}

func (t *heterogeneousPartialCombTableExperiment) nominalPayloadBytes() int {
	return len(t.points) * int(unsafe.Sizeof(ifmaAffine3MicroAoSEntryExperiment{}))
}

func buildHeterogeneousPartialCombPreSignedSharedTableExperiment(
	positive *heterogeneousPartialCombTableExperiment,
) *heterogeneousPartialCombPreSignedSharedTableExperiment {
	table := &heterogeneousPartialCombPreSignedSharedTableExperiment{spec: positive.spec}
	for sign := range table.points {
		table.points[sign] = make([]ifmaAffine3MicroAoSEntryExperiment, len(positive.points))
	}
	copy(table.points[heterogeneousPartialCombPositiveSignExperiment], positive.points)
	for index := range positive.points {
		entry := &positive.points[index]
		negative := &table.points[heterogeneousPartialCombNegativeSignExperiment][index]
		var t2D Element
		for limb := range modulusLimbs {
			negative[limb][0] = entry[limb][1]
			negative[limb][1] = entry[limb][0]
			t2D.limbs[limb] = entry[limb][2]
		}
		t2D.Negate(&t2D)
		for limb := range modulusLimbs {
			negative[limb][2] = t2D.limbs[limb]
		}
	}
	return table
}

func (t *heterogeneousPartialCombPreSignedSharedTableExperiment) nominalPayloadBytes() int {
	return (len(t.points[0]) + len(t.points[1])) * int(unsafe.Sizeof(ifmaAffine3MicroAoSEntryExperiment{}))
}

func buildHeterogeneousPartialCombATablesX4Experiment(
	bases *PointX4,
	spec heterogeneousPartialCombSpecExperiment,
) [X4Lanes]*heterogeneousPartialCombTableExperiment {
	var tables [X4Lanes]*heterogeneousPartialCombTableExperiment
	for lane := range tables {
		base := bases.Lane(lane)
		tables[lane] = buildHeterogeneousPartialCombTableExperiment(&base, spec)
	}
	return tables
}

func heterogeneousPartialCombAGroupPayloadBytesExperiment(
	tables *[X4Lanes]*heterogeneousPartialCombTableExperiment,
) int {
	bytes := 0
	for lane := range tables {
		bytes += tables[lane].nominalPayloadBytes()
	}
	return bytes
}

func selectHeterogeneousPartialCombPerKeyX4Experiment(
	out *fixedBaseIFMACachedX4,
	tables *[X4Lanes]*heterogeneousPartialCombTableExperiment,
	row int,
	round *asymmetricFixedBRoundX4,
	active uint8,
) {
	lookupMask := round.NonzeroMask & active & 0x0f
	p0 := &ifmaAffine3MicroAoSIdentityEntryExperiment
	p1, p2, p3 := p0, p0, p0
	entries := tables[0].spec.entriesPerRow()
	if lookupMask&0x01 != 0 {
		p0 = &tables[0].points[row*entries+int(round.Magnitude[0])-1]
	}
	if lookupMask&0x02 != 0 {
		p1 = &tables[1].points[row*entries+int(round.Magnitude[1])-1]
	}
	if lookupMask&0x04 != 0 {
		p2 = &tables[2].points[row*entries+int(round.Magnitude[2])-1]
	}
	if lookupMask&0x08 != 0 {
		p3 = &tables[3].points[row*entries+int(round.Magnitude[3])-1]
	}
	ifmaAffine3MicroAoSTransposeSelectExperimentX4(out, p0, p1, p2, p3)
	conditionalNegateIFMAAffine3MicroAoSX4(out, round.NegativeMask&lookupMask)
}

func selectHeterogeneousPartialCombSharedX4Experiment(
	out *fixedBaseIFMACachedX4,
	table *heterogeneousPartialCombTableExperiment,
	row int,
	round *asymmetricFixedBRoundX4,
	active uint8,
) {
	lookupMask := round.NonzeroMask & active & 0x0f
	p0 := &ifmaAffine3MicroAoSIdentityEntryExperiment
	p1, p2, p3 := p0, p0, p0
	rowOffset := row * table.spec.entriesPerRow()
	if lookupMask&0x01 != 0 {
		p0 = &table.points[rowOffset+int(round.Magnitude[0])-1]
	}
	if lookupMask&0x02 != 0 {
		p1 = &table.points[rowOffset+int(round.Magnitude[1])-1]
	}
	if lookupMask&0x04 != 0 {
		p2 = &table.points[rowOffset+int(round.Magnitude[2])-1]
	}
	if lookupMask&0x08 != 0 {
		p3 = &table.points[rowOffset+int(round.Magnitude[3])-1]
	}
	ifmaAffine3MicroAoSTransposeSelectExperimentX4(out, p0, p1, p2, p3)
	conditionalNegateIFMAAffine3MicroAoSX4(out, round.NegativeMask&lookupMask)
}

func selectHeterogeneousPartialCombPreSignedSharedX4Experiment(
	out *fixedBaseIFMACachedX4,
	table *heterogeneousPartialCombPreSignedSharedTableExperiment,
	row int,
	round *asymmetricFixedBRoundX4,
	active uint8,
) {
	// This is deliberately unchecked test-only machinery: row and every
	// nonzero magnitude come exclusively from the internal balanced recoder.
	// A promoted API must validate public metadata before indexing and retain
	// output atomicity on malformed input.
	lookupMask := round.NonzeroMask & active & 0x0f
	p0 := &ifmaAffine3MicroAoSIdentityEntryExperiment
	p1, p2, p3 := p0, p0, p0
	rowOffset := row * table.spec.entriesPerRow()
	if lookupMask&0x01 != 0 {
		sign := heterogeneousPartialCombPositiveSignExperiment
		if round.NegativeMask&0x01 != 0 {
			sign = heterogeneousPartialCombNegativeSignExperiment
		}
		p0 = &table.points[sign][rowOffset+int(round.Magnitude[0])-1]
	}
	if lookupMask&0x02 != 0 {
		sign := heterogeneousPartialCombPositiveSignExperiment
		if round.NegativeMask&0x02 != 0 {
			sign = heterogeneousPartialCombNegativeSignExperiment
		}
		p1 = &table.points[sign][rowOffset+int(round.Magnitude[1])-1]
	}
	if lookupMask&0x04 != 0 {
		sign := heterogeneousPartialCombPositiveSignExperiment
		if round.NegativeMask&0x04 != 0 {
			sign = heterogeneousPartialCombNegativeSignExperiment
		}
		p2 = &table.points[sign][rowOffset+int(round.Magnitude[2])-1]
	}
	if lookupMask&0x08 != 0 {
		sign := heterogeneousPartialCombPositiveSignExperiment
		if round.NegativeMask&0x08 != 0 {
			sign = heterogeneousPartialCombNegativeSignExperiment
		}
		p3 = &table.points[sign][rowOffset+int(round.Magnitude[3])-1]
	}
	ifmaAffine3MicroAoSTransposeSelectExperimentX4(out, p0, p1, p2, p3)
}

func addHeterogeneousPartialCombAPassX4Experiment(
	acc *IFMAPointX4,
	tables *[X4Lanes]*heterogeneousPartialCombTableExperiment,
	digits *asymmetricFixedBDigitsX4,
	pass int,
	usable uint8,
) error {
	spec := tables[0].spec
	for row := 0; row < spec.rowCount(); row++ {
		digitIndex := row*spec.passes + pass
		if digitIndex >= spec.digitCount() {
			continue
		}
		round := &digits.rounds[digitIndex]
		if round.NonzeroMask&usable == 0 {
			continue
		}
		var selected fixedBaseIFMACachedX4
		selectHeterogeneousPartialCombPerKeyX4Experiment(&selected, tables, row, round, usable)
		if err := addFixedBaseIFMACachedX4(acc, acc, &selected); err != nil {
			return err
		}
	}
	return nil
}

func addHeterogeneousPartialCombBPassX4Experiment(
	acc *IFMAPointX4,
	table *heterogeneousPartialCombTableExperiment,
	digits *asymmetricFixedBDigitsX4,
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
		var selected fixedBaseIFMACachedX4
		selectHeterogeneousPartialCombSharedX4Experiment(&selected, table, row, round, usable)
		if err := addFixedBaseIFMACachedX4(acc, acc, &selected); err != nil {
			return err
		}
	}
	return nil
}

func addHeterogeneousPartialCombPreSignedBPassX4Experiment(
	acc *IFMAPointX4,
	table *heterogeneousPartialCombPreSignedSharedTableExperiment,
	digits *asymmetricFixedBDigitsX4,
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
		var selected fixedBaseIFMACachedX4
		selectHeterogeneousPartialCombPreSignedSharedX4Experiment(&selected, table, row, round, usable)
		if err := addFixedBaseIFMACachedX4(acc, acc, &selected); err != nil {
			return err
		}
	}
	return nil
}

// evaluateHeterogeneousPartialCombDSMX4Experiment computes [s]B+[-k]A with
// exact signed-integer scalar semantics on one accumulator. Each term has its
// own (width,passes) pair. Events are merged by exponent, and additions at
// exponent e happen before lowering the accumulator to e-1.
func evaluateHeterogeneousPartialCombDSMX4Experiment(
	out *IFMAPointX4,
	aTables *[X4Lanes]*heterogeneousPartialCombTableExperiment,
	bTable *heterogeneousPartialCombTableExperiment,
	scalars *FixedDSMScalarsX4,
	negativeMasks *[DSMTerms]uint8,
	active uint8,
) (uint8, error) {
	if !ExperimentalIFMAAvailable() {
		return 0, ErrIFMAUnavailable
	}
	active &= 0x0f
	aSpec, bSpec := aTables[0].spec, bTable.spec
	var aDigits, bDigits asymmetricFixedBDigitsX4
	// Term 1 is A. Applying negativeMasks[1] to every balanced digit preserves
	// exact -k, rather than replacing it by L-k (which is wrong on torsion).
	usable := recodeAsymmetricFixedBScalarsX4(&aDigits, &scalars[1], negativeMasks[1], active, aSpec.width)
	usable &= recodeAsymmetricFixedBScalarsX4(&bDigits, &scalars[0], negativeMasks[0], active, bSpec.width)
	acc := identityIFMAPointX4Value()
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
			if err := ifmaPointDoubleComposableStaticX4(&acc, &acc); err != nil {
				return 0, err
			}
		}
		if exponent%int(bSpec.width) == 0 {
			pass := exponent / int(bSpec.width)
			if pass < bSpec.passes {
				if err := addHeterogeneousPartialCombBPassX4Experiment(&acc, bTable, &bDigits, pass, usable); err != nil {
					return 0, err
				}
			}
		}
		if exponent%int(aSpec.width) == 0 {
			pass := exponent / int(aSpec.width)
			if pass < aSpec.passes {
				if err := addHeterogeneousPartialCombAPassX4Experiment(&acc, aTables, &aDigits, pass, usable); err != nil {
					return 0, err
				}
			}
		}
	}
	*out = acc
	return usable, nil
}

// evaluateHeterogeneousPartialCombPreSignedBDSMX4Experiment is the same exact
// merged integer schedule as evaluateHeterogeneousPartialCombDSMX4Experiment.
// Only fixed-B selection differs: its signed affine entry is chosen before the
// transpose, eliminating the post-selection conditional negation.
func evaluateHeterogeneousPartialCombPreSignedBDSMX4Experiment(
	out *IFMAPointX4,
	aTables *[X4Lanes]*heterogeneousPartialCombTableExperiment,
	bTable *heterogeneousPartialCombPreSignedSharedTableExperiment,
	scalars *FixedDSMScalarsX4,
	negativeMasks *[DSMTerms]uint8,
	active uint8,
) (uint8, error) {
	if !ExperimentalIFMAAvailable() {
		return 0, ErrIFMAUnavailable
	}
	active &= 0x0f
	aSpec, bSpec := aTables[0].spec, bTable.spec
	var aDigits, bDigits asymmetricFixedBDigitsX4
	usable := recodeAsymmetricFixedBScalarsX4(&aDigits, &scalars[1], negativeMasks[1], active, aSpec.width)
	usable &= recodeAsymmetricFixedBScalarsX4(&bDigits, &scalars[0], negativeMasks[0], active, bSpec.width)
	acc := identityIFMAPointX4Value()
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
			if err := ifmaPointDoubleComposableStaticX4(&acc, &acc); err != nil {
				return 0, err
			}
		}
		if exponent%int(bSpec.width) == 0 {
			pass := exponent / int(bSpec.width)
			if pass < bSpec.passes {
				if err := addHeterogeneousPartialCombPreSignedBPassX4Experiment(&acc, bTable, &bDigits, pass, usable); err != nil {
					return 0, err
				}
			}
		}
		if exponent%int(aSpec.width) == 0 {
			pass := exponent / int(aSpec.width)
			if pass < aSpec.passes {
				if err := addHeterogeneousPartialCombAPassX4Experiment(&acc, aTables, &aDigits, pass, usable); err != nil {
					return 0, err
				}
			}
		}
	}
	*out = acc
	return usable, nil
}
