package r51x5

import (
	"fmt"
	"math/big"
	"math/rand"
	"testing"
	"unsafe"

	edwardsref "github.com/Overclock-Validator/narya/internal/edwards25519"
)

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

type heterogeneousPartialCombCorrectnessFixtureExperiment struct {
	workspace ExperimentalIFMAFixedDSMWorkspaceRadix64X4
	regularA  [X4Lanes]ifmaMicroAoSPerKeyTableExperiment
	regularB  *asymmetricFixedBTableExperiment
	aTables   [X4Lanes]*heterogeneousPartialCombTableExperiment
	b8Table   *heterogeneousPartialCombTableExperiment
	b10Table  *heterogeneousPartialCombTableExperiment
	refs      [QSMTerms][X8Lanes]*edwardsref.Point
}

func newHeterogeneousPartialCombCorrectnessFixtureExperiment(t *testing.T) heterogeneousPartialCombCorrectnessFixtureExperiment {
	t.Helper()
	rng := rand.New(rand.NewSource(0xc0b6_a8b3))
	torsion := referenceTorsionPoints(t)

	bRef := new(edwardsref.Point).Add(edwardsref.NewGeneratorPoint(), torsion[3])
	var bEncoded [32]byte
	copy(bEncoded[:], bRef.Bytes())
	var bPoint Point
	if _, err := bPoint.SetBytes(bEncoded[:]); err != nil {
		t.Fatal(err)
	}
	var bPoints [X4Lanes]Point
	for lane := range bPoints {
		bPoints[lane] = bPoint
	}
	var bX4 PointX4
	bX4.SetPoints(&bPoints)

	var aTorsion [X8Lanes]*edwardsref.Point
	for lane := range aTorsion {
		aTorsion[lane] = torsion[(lane+1)%X8Lanes]
	}
	aRefs, aX8 := scalarWindowMixedBasesX8(t, rng, &aTorsion)
	aX8 = randomProjectiveScaleX8(t, rng, &aX8)
	aX4 := pointX4Half(&aX8, 0)

	var fixture heterogeneousPartialCombCorrectnessFixtureExperiment
	if err := fixture.workspace.PrepareBoth(&[DSMTerms]PointX4{bX4, aX4}, 6); err != nil {
		t.Fatal(err)
	}
	fixture.regularA = importIFMAMicroAoSTablesExperimentX4(&fixture.workspace.tables[1])
	fixture.regularB = buildAsymmetricFixedBTableExperiment(&bPoint, 10)
	fixture.aTables = buildHeterogeneousPartialCombATablesX4Experiment(&aX4, heterogeneousPartialCombA6R9Experiment)
	fixture.b8Table = buildHeterogeneousPartialCombTableExperiment(&bPoint, heterogeneousPartialCombB8R3Experiment)
	fixture.b10Table = buildHeterogeneousPartialCombTableExperiment(&bPoint, heterogeneousPartialCombB10R5Experiment)
	for lane := 0; lane < X8Lanes; lane++ {
		fixture.refs[0][lane] = bRef
		fixture.refs[1][lane] = aRefs[lane]
	}
	return fixture
}

func TestHeterogeneousPartialCombTableShapesAndPayloadsExperiment(t *testing.T) {
	if got := int(unsafe.Sizeof(ifmaAffine3MicroAoSEntryExperiment{})); got != 120 {
		t.Fatalf("dense affine3 entry bytes=%d want=120", got)
	}
	tests := []struct {
		name         string
		spec         heterogeneousPartialCombSpecExperiment
		digits       int
		rows         int
		entries      int
		depth        int
		payloadBytes int
		validCells   []int
	}{
		{name: "A6/r9", spec: heterogeneousPartialCombA6R9Experiment, digits: 43, rows: 5, entries: 32, depth: 48, payloadBytes: 19_200, validCells: []int{5, 5, 5, 5, 5, 5, 5, 4, 4}},
		{name: "B8/r3", spec: heterogeneousPartialCombB8R3Experiment, digits: 32, rows: 11, entries: 128, depth: 16, payloadBytes: 168_960, validCells: []int{11, 11, 10}},
		{name: "B10/r5", spec: heterogeneousPartialCombB10R5Experiment, digits: 26, rows: 6, entries: 512, depth: 40, payloadBytes: 368_640, validCells: []int{6, 5, 5, 5, 5}},
	}
	baseEncoding := newGeneratorEncodingForTest(t)
	var base Point
	if _, err := base.SetBytes(baseEncoding[:]); err != nil {
		t.Fatal(err)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			table := buildHeterogeneousPartialCombTableExperiment(&base, test.spec)
			if test.spec.digitCount() != test.digits || test.spec.rowCount() != test.rows ||
				test.spec.entriesPerRow() != test.entries || test.spec.onlineDepth() != test.depth {
				t.Fatalf("shape digits=%d rows=%d entries=%d depth=%d", test.spec.digitCount(), test.spec.rowCount(), test.spec.entriesPerRow(), test.spec.onlineDepth())
			}
			if len(table.points) != test.rows*test.entries || table.nominalPayloadBytes() != test.payloadBytes {
				t.Fatalf("table entries=%d payload=%d want entries=%d payload=%d", len(table.points), table.nominalPayloadBytes(), test.rows*test.entries, test.payloadBytes)
			}
			for pass, want := range test.validCells {
				if got := test.spec.validCellsForPass(pass); got != want {
					t.Fatalf("pass=%d valid cells=%d want=%d", pass, got, want)
				}
			}
		})
	}
}

func reconstructHeterogeneousPartialCombScalarExperiment(
	digits *asymmetricFixedBDigitsX4,
	spec heterogeneousPartialCombSpecExperiment,
	lane int,
) *big.Int {
	acc := new(big.Int)
	for exponent := spec.onlineDepth(); exponent >= 0; exponent-- {
		if exponent != spec.onlineDepth() {
			acc.Lsh(acc, 1)
		}
		if exponent%int(spec.width) != 0 {
			continue
		}
		pass := exponent / int(spec.width)
		if pass >= spec.passes {
			continue
		}
		for row := 0; row < spec.rowCount(); row++ {
			digitIndex := row*spec.passes + pass
			if digitIndex >= spec.digitCount() {
				continue
			}
			round := &digits.rounds[digitIndex]
			digit := int64(round.Magnitude[lane])
			if round.NegativeMask&(1<<lane) != 0 {
				digit = -digit
			}
			term := new(big.Int).Lsh(big.NewInt(digit), uint(int(spec.width)*spec.passes*row))
			acc.Add(acc, term)
		}
	}
	return acc
}

func TestHeterogeneousPartialCombScheduleReconstructsExactSignedScalarsExperiment(t *testing.T) {
	specs := []heterogeneousPartialCombSpecExperiment{
		heterogeneousPartialCombA6R9Experiment,
		heterogeneousPartialCombB8R3Experiment,
		heterogeneousPartialCombB10R5Experiment,
	}
	edges := [][32]byte{{}, {1}, scalarOrderBytes}
	edges[2][0]-- // L-1.
	rng := rand.New(rand.NewSource(0xc0b6_5ca1))
	for iteration := 0; iteration < 24; iteration++ {
		var scalar [32]byte
		if iteration < len(edges) {
			scalar = edges[iteration]
		} else {
			for i := range scalar {
				scalar[i] = byte(rng.Uint32())
			}
			scalar[31] &= 0x0f // certainly canonical and still exercises dense digits.
		}
		for _, negative := range []bool{false, true} {
			var negativeMask uint8
			if negative {
				negativeMask = 1
			}
			for _, spec := range specs {
				var scalars [X4Lanes][32]byte
				scalars[0] = scalar
				var digits asymmetricFixedBDigitsX4
				if mask := recodeAsymmetricFixedBScalarsX4(&digits, &scalars, negativeMask, 1, spec.width); mask != 1 {
					t.Fatalf("iteration=%d negative=%v width=%d recode mask=%02x", iteration, negative, spec.width, mask)
				}
				got := reconstructHeterogeneousPartialCombScalarExperiment(&digits, spec, 0)
				want := signedMagnitudeToBig(NewSignedMagnitude(scalar[:], negative))
				if got.Cmp(want) != 0 {
					t.Fatalf("iteration=%d negative=%v width=%d passes=%d got=%s want=%s", iteration, negative, spec.width, spec.passes, got, want)
				}
			}
		}
	}
}

func TestHeterogeneousPartialCombExactMixedOrderTorsionAndAllMasksExperiment(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("requires AVX-512 IFMA target")
	}
	fixture := newHeterogeneousPartialCombCorrectnessFixtureExperiment(t)
	rng := rand.New(rand.NewSource(0xc0b6_d1ff))
	for iteration := 0; iteration < 10; iteration++ {
		scalars8, signs8, exact := randomIFMAFixedDSMScalars(rng)
		if iteration == 0 {
			// Exact -1 on mixed-order A is the discriminating torsion case.
			scalars8[1][0] = [32]byte{1}
			signs8[1] |= 0x01
			exact[1][0] = big.NewInt(-1)
			// Exercise the balanced boundaries of the two B candidates.
			scalars8[0][1] = [32]byte{0x80}
			signs8[0] &^= 0x02
			exact[0][1] = big.NewInt(128)
			scalars8[0][2] = [32]byte{0x00, 0x02}
			signs8[0] &^= 0x04
			exact[0][2] = big.NewInt(512)
			// Width-6's half-radix digit exercises A's last table entry.
			scalars8[1][3] = [32]byte{32}
			signs8[1] &^= 0x08
			exact[1][3] = big.NewInt(32)
		}
		want8 := exactIFMAFixedDSMWant(&fixture.refs, &exact)
		var want4 [X4Lanes]*edwardsref.Point
		copy(want4[:], want8[:X4Lanes])
		var scalars4 FixedDSMScalarsX4
		var signs4 [DSMTerms]uint8
		for term := 0; term < DSMTerms; term++ {
			copy(scalars4[term][:], scalars8[term][:X4Lanes])
			signs4[term] = signs8[term] & 0x0f
		}
		for active := uint8(0); active < 1<<X4Lanes; active++ {
			var currentLoose IFMAPointX4
			currentMask, currentErr := fixture.workspace.Evaluate(&currentLoose, &scalars4, &signs4, active)
			if currentErr != nil || currentMask != active {
				t.Fatalf("iteration=%d active=%02x current=(%02x,%v)", iteration, active, currentMask, currentErr)
			}
			current := currentLoose.Reduced()
			assertMaskedPointX4(t, "current exact DSM reference", &current, &want4, active)

			for _, candidate := range []struct {
				name string
				b    *heterogeneousPartialCombTableExperiment
			}{
				{name: "A6r9-B8r3", b: fixture.b8Table},
				{name: "A6r9-B10r5", b: fixture.b10Table},
			} {
				var gotLoose IFMAPointX4
				usable, err := evaluateHeterogeneousPartialCombDSMX4Experiment(&gotLoose, &fixture.aTables, candidate.b, &scalars4, &signs4, active)
				if err != nil || usable != active {
					t.Fatalf("iteration=%d candidate=%s active=%02x evaluate=(%02x,%v)", iteration, candidate.name, active, usable, err)
				}
				got := gotLoose.Reduced()
				if !asymmetricFixedBProjectivelyEqual(&got, &current, active) {
					t.Fatalf("iteration=%d candidate=%s active=%02x current mismatch", iteration, candidate.name, active)
				}
				assertMaskedPointX4(t, fmt.Sprintf("%s exact mixed-order DSM", candidate.name), &got, &want4, active)
			}
		}
	}
}

func encodeHeterogeneousPartialCombScalarExperiment(value *big.Int) [32]byte {
	if value.Sign() < 0 || value.BitLen() > 253 {
		panic("r51x5: heterogeneous partial-comb test scalar outside canonical edge range")
	}
	var out [32]byte
	encoded := value.Bytes()
	for index := range encoded {
		out[index] = encoded[len(encoded)-1-index]
	}
	return out
}

func TestHeterogeneousPartialCombDeterministicBoundaryEventsExperiment(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("requires AVX-512 IFMA target")
	}
	fixture := newHeterogeneousPartialCombCorrectnessFixtureExperiment(t)
	two252 := new(big.Int).Lsh(big.NewInt(1), 252)
	two252Minus1 := new(big.Int).Sub(new(big.Int).Set(two252), big.NewInt(1))
	tests := []struct {
		name string
		b    *heterogeneousPartialCombTableExperiment
		s    *big.Int
		a    *big.Int
	}{
		// Last valid scalar cells: A j=42, B8 j=31, and B10 j=25.
		{name: "A-last-j42", b: fixture.b8Table, s: big.NewInt(0), a: new(big.Int).Neg(new(big.Int).Set(two252))},
		{name: "B8-last-j31", b: fixture.b8Table, s: new(big.Int).Lsh(big.NewInt(1), 248), a: big.NewInt(0)},
		{name: "B10-last-j25", b: fixture.b10Table, s: new(big.Int).Lsh(big.NewInt(1), 250), a: big.NewInt(0)},
		// Canonical high edges exercise the final balanced-recoding carry.
		{name: "two252-minus1", b: fixture.b8Table, s: two252Minus1, a: big.NewInt(-1)},
		{name: "two252", b: fixture.b10Table, s: new(big.Int).Set(two252), a: new(big.Int).Neg(new(big.Int).Set(two252Minus1))},
		// Half-radix digits shifted away from window zero force a negative digit
		// plus a carry into the following digit, while selecting the final entry.
		{name: "shifted-half-B8-A6", b: fixture.b8Table, s: new(big.Int).Lsh(big.NewInt(128), 8), a: new(big.Int).Lsh(big.NewInt(32), 6)},
		{name: "shifted-half-B10-A6", b: fixture.b10Table, s: new(big.Int).Lsh(big.NewInt(512), 10), a: new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(32), 12))},
		// Both pass-zero events collide at exponent zero, after the last double.
		{name: "B8-A6-collision-e0", b: fixture.b8Table, s: big.NewInt(1), a: big.NewInt(-1)},
		// B10 pass 3 and A6 pass 5 both inject at exponent 30. The event must
		// contain both additions before the accumulator is doubled to e=29.
		{name: "B10-A6-collision-e30", b: fixture.b10Table, s: new(big.Int).Lsh(big.NewInt(1), 30), a: new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 30))},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var scalars FixedDSMScalarsX4
			scalars[0][0] = encodeHeterogeneousPartialCombScalarExperiment(new(big.Int).Abs(new(big.Int).Set(test.s)))
			scalars[1][0] = encodeHeterogeneousPartialCombScalarExperiment(new(big.Int).Abs(new(big.Int).Set(test.a)))
			var signs [DSMTerms]uint8
			if test.s.Sign() < 0 {
				signs[0] = 1
			}
			if test.a.Sign() < 0 {
				signs[1] = 1
			}

			var gotLoose IFMAPointX4
			usable, err := evaluateHeterogeneousPartialCombDSMX4Experiment(&gotLoose, &fixture.aTables, test.b, &scalars, &signs, 1)
			if err != nil || usable != 1 {
				t.Fatalf("evaluate=(%02x,%v)", usable, err)
			}
			gotReduced := gotLoose.Reduced()
			got := gotReduced.Lane(0)
			wantB := exactReferenceIntegerMult(fixture.refs[0][0], test.s)
			wantA := exactReferenceIntegerMult(fixture.refs[1][0], test.a)
			want := new(edwardsref.Point).Add(wantB, wantA)
			assertScalarPointMatchesReference(t, test.name, &got, want)

			var currentLoose IFMAPointX4
			currentMask, currentErr := fixture.workspace.Evaluate(&currentLoose, &scalars, &signs, 1)
			if currentErr != nil || currentMask != 1 {
				t.Fatalf("current=(%02x,%v)", currentMask, currentErr)
			}
			currentReduced := currentLoose.Reduced()
			current := currentReduced.Lane(0)
			assertScalarPointMatchesReference(t, test.name+" current", &current, want)
		})
	}
}

func TestHeterogeneousPartialCombInvalidTopCellsDoNotContributeExperiment(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("requires AVX-512 IFMA target")
	}
	fixture := newHeterogeneousPartialCombCorrectnessFixtureExperiment(t)
	tests := []struct {
		name       string
		pass       int
		digitIndex int
		add        func(*IFMAPointX4, *asymmetricFixedBDigitsX4, int) error
	}{
		{name: "A-pass7-row4-j43", pass: 7, digitIndex: 43, add: func(acc *IFMAPointX4, digits *asymmetricFixedBDigitsX4, pass int) error {
			return addHeterogeneousPartialCombAPassX4Experiment(acc, &fixture.aTables, digits, pass, 1)
		}},
		{name: "A-pass8-row4-j44", pass: 8, digitIndex: 44, add: func(acc *IFMAPointX4, digits *asymmetricFixedBDigitsX4, pass int) error {
			return addHeterogeneousPartialCombAPassX4Experiment(acc, &fixture.aTables, digits, pass, 1)
		}},
		{name: "B8-pass2-row10-j32", pass: 2, digitIndex: 32, add: func(acc *IFMAPointX4, digits *asymmetricFixedBDigitsX4, pass int) error {
			return addHeterogeneousPartialCombBPassX4Experiment(acc, fixture.b8Table, digits, pass, 1)
		}},
	}
	for pass := 1; pass < heterogeneousPartialCombB10R5Experiment.passes; pass++ {
		pass := pass
		tests = append(tests, struct {
			name       string
			pass       int
			digitIndex int
			add        func(*IFMAPointX4, *asymmetricFixedBDigitsX4, int) error
		}{
			name:       fmt.Sprintf("B10-pass%d-row5-j%d", pass, 25+pass),
			pass:       pass,
			digitIndex: 25 + pass,
			add: func(acc *IFMAPointX4, digits *asymmetricFixedBDigitsX4, pass int) error {
				return addHeterogeneousPartialCombBPassX4Experiment(acc, fixture.b10Table, digits, pass, 1)
			},
		})
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var digits asymmetricFixedBDigitsX4
			setAsymmetricFixedBRoundDigitX4(&digits.rounds[test.digitIndex], 0, 1)
			acc := identityIFMAPointX4Value()
			if err := test.add(&acc, &digits, test.pass); err != nil {
				t.Fatal(err)
			}
			reduced := acc.Reduced()
			lane := reduced.Lane(0)
			if lane.IsIdentity() != 1 {
				t.Fatal("invalid top cell changed the accumulator")
			}
		})
	}
}

func TestHeterogeneousPartialCombInvalidScalarFailClosedExperiment(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("requires AVX-512 IFMA target")
	}
	fixture := newHeterogeneousPartialCombCorrectnessFixtureExperiment(t)
	var scalars FixedDSMScalarsX4
	for term := range scalars {
		for lane := range scalars[term] {
			scalars[term][lane] = [32]byte{byte(1 + term*7 + lane)}
		}
	}
	signs := [DSMTerms]uint8{0, 0x0f}
	for _, bTable := range []*heterogeneousPartialCombTableExperiment{fixture.b8Table, fixture.b10Table} {
		for invalidLane := 0; invalidLane < X4Lanes; invalidLane++ {
			invalid := scalars
			invalid[invalidLane&1][invalidLane] = scalarOrderBytes
			var gotLoose IFMAPointX4
			usable, err := evaluateHeterogeneousPartialCombDSMX4Experiment(&gotLoose, &fixture.aTables, bTable, &invalid, &signs, 0x0f)
			wantMask := uint8(0x0f &^ (1 << invalidLane))
			if err != nil || usable != wantMask {
				t.Fatalf("B%d/r%d invalid lane=%d evaluate=(%02x,%v) want=%02x", bTable.spec.width, bTable.spec.passes, invalidLane, usable, err, wantMask)
			}
			got := gotLoose.Reduced()
			gotLane := got.Lane(invalidLane)
			if gotLane.IsIdentity() != 1 {
				t.Fatalf("B%d/r%d invalid lane=%d did not fail closed", bTable.spec.width, bTable.spec.passes, invalidLane)
			}
		}
	}
}

func TestHeterogeneousPartialCombEvaluationZeroAllocationsExperiment(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("requires AVX-512 IFMA target")
	}
	fixture, scalars, signs := newHeterogeneousPartialCombBenchmarkFixtureExperiment(t)
	for _, bTable := range []*heterogeneousPartialCombTableExperiment{fixture.b8Table, fixture.b10Table} {
		var out IFMAPointX4
		if allocs := testing.AllocsPerRun(20, func() {
			if _, err := evaluateHeterogeneousPartialCombDSMX4Experiment(&out, &fixture.aTables, bTable, &scalars, &signs, 0x0f); err != nil {
				panic(err)
			}
		}); allocs != 0 {
			t.Fatalf("A6/r9+B%d/r%d allocations=%v want=0", bTable.spec.width, bTable.spec.passes, allocs)
		}
	}
}

type heterogeneousPartialCombBenchmarkFixtureExperiment struct {
	workspace ExperimentalIFMAFixedDSMWorkspaceRadix64X4
	regularA  [X4Lanes]ifmaMicroAoSPerKeyTableExperiment
	regularB  *asymmetricFixedBTableExperiment
	aTables   [X4Lanes]*heterogeneousPartialCombTableExperiment
	b8Table   *heterogeneousPartialCombTableExperiment
	b10Table  *heterogeneousPartialCombTableExperiment
}

func newHeterogeneousPartialCombBenchmarkFixtureExperiment(tb testing.TB) (heterogeneousPartialCombBenchmarkFixtureExperiment, FixedDSMScalarsX4, [DSMTerms]uint8) {
	tb.Helper()
	bX8, aX8, s8, k8 := fixedBaseCombDSMFixtures(tb)
	bX4, aX4 := pointX4Half(&bX8, 0), pointX4Half(&aX8, 0)
	var fixture heterogeneousPartialCombBenchmarkFixtureExperiment
	if err := fixture.workspace.PrepareBoth(&[DSMTerms]PointX4{bX4, aX4}, 6); err != nil {
		tb.Fatal(err)
	}
	fixture.regularA = importIFMAMicroAoSTablesExperimentX4(&fixture.workspace.tables[1])
	bPoint := bX4.Lane(0)
	fixture.regularB = buildAsymmetricFixedBTableExperiment(&bPoint, 10)
	fixture.aTables = buildHeterogeneousPartialCombATablesX4Experiment(&aX4, heterogeneousPartialCombA6R9Experiment)
	fixture.b8Table = buildHeterogeneousPartialCombTableExperiment(&bPoint, heterogeneousPartialCombB8R3Experiment)
	fixture.b10Table = buildHeterogeneousPartialCombTableExperiment(&bPoint, heterogeneousPartialCombB10R5Experiment)
	var scalars FixedDSMScalarsX4
	copy(scalars[0][:], s8[:X4Lanes])
	copy(scalars[1][:], k8[:X4Lanes])
	return fixture, scalars, [DSMTerms]uint8{0, 0x0f}
}

var (
	benchmarkHeterogeneousPartialCombPointSink IFMAPointX4
	benchmarkHeterogeneousPartialCombMaskSink  uint8
)

func BenchmarkHeterogeneousPartialCombPreparedDSMX4Experiment(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skip("requires AVX-512 IFMA target")
	}
	fixture, scalars, signs := newHeterogeneousPartialCombBenchmarkFixtureExperiment(b)

	var controlLoose IFMAPointX4
	controlMask, err := evaluateAsymmetricFixedBDensePreparedRadix64DSMX4(&controlLoose, &fixture.regularA, fixture.regularB, &scalars, &signs, 0x0f)
	if err != nil || controlMask != 0x0f {
		b.Fatalf("regular A6+B10 control=(%02x,%v)", controlMask, err)
	}
	control := controlLoose.Reduced()
	for _, table := range []*heterogeneousPartialCombTableExperiment{fixture.b8Table, fixture.b10Table} {
		var candidateLoose IFMAPointX4
		mask, candidateErr := evaluateHeterogeneousPartialCombDSMX4Experiment(&candidateLoose, &fixture.aTables, table, &scalars, &signs, 0x0f)
		if candidateErr != nil || mask != controlMask {
			b.Fatalf("candidate B%d/r%d=(%02x,%v)", table.spec.width, table.spec.passes, mask, candidateErr)
		}
		candidate := candidateLoose.Reduced()
		if !asymmetricFixedBProjectivelyEqual(&candidate, &control, mask) {
			b.Fatalf("candidate B%d/r%d preflight mismatch", table.spec.width, table.spec.passes)
		}
	}

	b.Run("implementation=control-A6-regular-B10-dense", func(b *testing.B) {
		var out IFMAPointX4
		var mask uint8
		b.ReportAllocs()
		b.ResetTimer()
		for iteration := 0; iteration < b.N; iteration++ {
			var err error
			mask, err = evaluateAsymmetricFixedBDensePreparedRadix64DSMX4(&out, &fixture.regularA, fixture.regularB, &scalars, &signs, 0x0f)
			if err != nil {
				b.Fatal(err)
			}
		}
		benchmarkHeterogeneousPartialCombPointSink = out
		benchmarkHeterogeneousPartialCombMaskSink = mask
		b.ReportMetric(float64(len(fixture.regularA)*len(fixture.regularA[0].points)*int(unsafe.Sizeof(ifmaMicroAoSPointEntryExperiment{}))), "A-group-table-bytes")
		b.ReportMetric(float64(len(fixture.regularB.densePoints)*int(unsafe.Sizeof(ifmaAffine3MicroAoSEntryExperiment{}))), "B-table-bytes")
		b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*X4Lanes), "ns/signature")
	})

	aGroupBytes := heterogeneousPartialCombAGroupPayloadBytesExperiment(&fixture.aTables)
	for _, table := range []*heterogeneousPartialCombTableExperiment{fixture.b8Table, fixture.b10Table} {
		name := fmt.Sprintf("implementation=partial-A6r9-B%dr%d", table.spec.width, table.spec.passes)
		b.Run(name, func(b *testing.B) {
			var out IFMAPointX4
			var mask uint8
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				var err error
				mask, err = evaluateHeterogeneousPartialCombDSMX4Experiment(&out, &fixture.aTables, table, &scalars, &signs, 0x0f)
				if err != nil {
					b.Fatal(err)
				}
			}
			benchmarkHeterogeneousPartialCombPointSink = out
			benchmarkHeterogeneousPartialCombMaskSink = mask
			b.ReportMetric(float64(aGroupBytes), "A-group-table-bytes")
			b.ReportMetric(float64(aGroupBytes/X4Lanes), "A-table-bytes/key")
			b.ReportMetric(float64(table.nominalPayloadBytes()), "B-table-bytes")
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*X4Lanes), "ns/signature")
		})
	}
}
