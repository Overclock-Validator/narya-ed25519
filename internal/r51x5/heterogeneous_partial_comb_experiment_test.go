package r51x5

import (
	"fmt"
	"math/big"
	"math/rand"
	"runtime"
	"sync/atomic"
	"testing"
	"unsafe"

	edwardsref "github.com/Overclock-Validator/narya/internal/edwards25519"
)

type heterogeneousPartialCombCorrectnessFixtureExperiment struct {
	workspace ExperimentalIFMAFixedDSMWorkspaceRadix64X4
	regularA  [X4Lanes]ifmaMicroAoSPerKeyTableExperiment
	regularB  *asymmetricFixedBTableExperiment
	aTables   [X4Lanes]*heterogeneousPartialCombTableExperiment
	b8Table   *heterogeneousPartialCombTableExperiment
	b10Table  *heterogeneousPartialCombTableExperiment
	b8Signed  *heterogeneousPartialCombPreSignedSharedTableExperiment
	b10Signed *heterogeneousPartialCombPreSignedSharedTableExperiment
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
	fixture.b8Signed = buildHeterogeneousPartialCombPreSignedSharedTableExperiment(fixture.b8Table)
	fixture.b10Signed = buildHeterogeneousPartialCombPreSignedSharedTableExperiment(fixture.b10Table)
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
		signedBytes  int
		validCells   []int
	}{
		{name: "A6/r9", spec: heterogeneousPartialCombA6R9Experiment, digits: 43, rows: 5, entries: 32, depth: 48, payloadBytes: 19_200, validCells: []int{5, 5, 5, 5, 5, 5, 5, 4, 4}},
		{name: "B8/r3", spec: heterogeneousPartialCombB8R3Experiment, digits: 32, rows: 11, entries: 128, depth: 16, payloadBytes: 168_960, signedBytes: 337_920, validCells: []int{11, 11, 10}},
		{name: "B10/r5", spec: heterogeneousPartialCombB10R5Experiment, digits: 26, rows: 6, entries: 512, depth: 40, payloadBytes: 368_640, signedBytes: 737_280, validCells: []int{6, 5, 5, 5, 5}},
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
			if test.signedBytes != 0 {
				signed := buildHeterogeneousPartialCombPreSignedSharedTableExperiment(table)
				if len(signed.points[0]) != len(table.points) || len(signed.points[1]) != len(table.points) || signed.nominalPayloadBytes() != test.signedBytes {
					t.Fatalf("pre-signed entries=(%d,%d) payload=%d want entries=(%d,%d) payload=%d", len(signed.points[0]), len(signed.points[1]), signed.nominalPayloadBytes(), len(table.points), len(table.points), test.signedBytes)
				}
				for index := range table.points {
					source := &table.points[index]
					positive := &signed.points[heterogeneousPartialCombPositiveSignExperiment][index]
					negative := &signed.points[heterogeneousPartialCombNegativeSignExperiment][index]
					if *positive != *source {
						t.Fatalf("pre-signed positive entry=%d differs from source", index)
					}
					var sourceT, negativeT Element
					for limb := range modulusLimbs {
						if negative[limb][0] != source[limb][1] || negative[limb][1] != source[limb][0] {
							t.Fatalf("pre-signed negative entry=%d limb=%d did not swap Y+X/Y-X", index, limb)
						}
						sourceT.limbs[limb] = source[limb][2]
						negativeT.limbs[limb] = negative[limb][2]
					}
					var tSum Element
					if tSum.Add(&sourceT, &negativeT).IsZero() != 1 {
						t.Fatalf("pre-signed negative entry=%d did not negate 2dT", index)
					}
				}
			}
			for pass, want := range test.validCells {
				if got := test.spec.validCellsForPass(pass); got != want {
					t.Fatalf("pass=%d valid cells=%d want=%d", pass, got, want)
				}
			}
		})
	}
}

func heterogeneousPartialCombCachedEqualModuloPExperiment(a, b *fixedBaseIFMACachedX4) bool {
	return a.YPlusX.Reduced() == b.YPlusX.Reduced() &&
		a.YMinusX.Reduced() == b.YMinusX.Reduced() &&
		a.T2D.Reduced() == b.T2D.Reduced()
}

func TestHeterogeneousPartialCombPreSignedSharedSelectorAllMasksAndBoundarySignsExperiment(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("requires AVX-512 IFMA target")
	}
	fixture := newHeterogeneousPartialCombCorrectnessFixtureExperiment(t)
	for _, candidate := range []struct {
		name     string
		positive *heterogeneousPartialCombTableExperiment
		signed   *heterogeneousPartialCombPreSignedSharedTableExperiment
	}{
		{name: "B8r3", positive: fixture.b8Table, signed: fixture.b8Signed},
		{name: "B10r5", positive: fixture.b10Table, signed: fixture.b10Signed},
	} {
		entries := candidate.positive.spec.entriesPerRow()
		patterns := []asymmetricFixedBRoundX4{
			{
				Magnitude:   [X4Lanes]uint16{1, uint16(entries / 2), uint16(entries - 1), uint16(entries)},
				NonzeroMask: 0x0f,
			},
			{
				Magnitude:   [X4Lanes]uint16{0, 1, 0, uint16(entries)},
				NonzeroMask: 0x0a,
			},
		}
		for _, row := range []int{0, candidate.positive.spec.rowCount() - 1} {
			for patternIndex := range patterns {
				for signs := uint8(0); signs < 1<<X4Lanes; signs++ {
					round := patterns[patternIndex]
					round.NegativeMask = signs & round.NonzeroMask
					for active := uint8(0); active < 1<<X4Lanes; active++ {
						var want, got fixedBaseIFMACachedX4
						selectHeterogeneousPartialCombSharedX4Experiment(&want, candidate.positive, row, &round, active)
						selectHeterogeneousPartialCombPreSignedSharedX4Experiment(&got, candidate.signed, row, &round, active)
						if !heterogeneousPartialCombCachedEqualModuloPExperiment(&got, &want) {
							t.Fatalf("%s row=%d pattern=%d signs=%02x active=%02x mismatch", candidate.name, row, patternIndex, signs, active)
						}
					}
				}
			}
		}
	}
}

func TestHeterogeneousPartialCombPreSignedSharedSelectorEveryEntryExperiment(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("requires AVX-512 IFMA target")
	}
	fixture := newHeterogeneousPartialCombCorrectnessFixtureExperiment(t)
	for _, candidate := range []struct {
		name     string
		positive *heterogeneousPartialCombTableExperiment
		signed   *heterogeneousPartialCombPreSignedSharedTableExperiment
	}{
		{name: "B8r3", positive: fixture.b8Table, signed: fixture.b8Signed},
		{name: "B10r5", positive: fixture.b10Table, signed: fixture.b10Signed},
	} {
		entries := candidate.positive.spec.entriesPerRow()
		for row := 0; row < candidate.positive.spec.rowCount(); row++ {
			for magnitude := 1; magnitude <= entries; magnitude++ {
				var magnitudes [X4Lanes]uint16
				for lane := range magnitudes {
					magnitudes[lane] = uint16(1 + (magnitude-1+lane)%entries)
				}
				for _, negativeMask := range []uint8{0x05, 0x0a} {
					round := asymmetricFixedBRoundX4{
						Magnitude:    magnitudes,
						NonzeroMask:  0x0f,
						NegativeMask: negativeMask,
					}
					var want, got fixedBaseIFMACachedX4
					selectHeterogeneousPartialCombSharedX4Experiment(&want, candidate.positive, row, &round, 0x0f)
					selectHeterogeneousPartialCombPreSignedSharedX4Experiment(&got, candidate.signed, row, &round, 0x0f)
					if !heterogeneousPartialCombCachedEqualModuloPExperiment(&got, &want) {
						t.Fatalf("%s row=%d magnitude=%d negative-mask=%02x entry mismatch", candidate.name, row, magnitude, negativeMask)
					}
				}
			}
		}
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
				name   string
				b      *heterogeneousPartialCombTableExperiment
				signed *heterogeneousPartialCombPreSignedSharedTableExperiment
			}{
				{name: "A6r9-B8r3", b: fixture.b8Table, signed: fixture.b8Signed},
				{name: "A6r9-B10r5", b: fixture.b10Table, signed: fixture.b10Signed},
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

				var signedLoose IFMAPointX4
				signedUsable, signedErr := evaluateHeterogeneousPartialCombPreSignedBDSMX4Experiment(&signedLoose, &fixture.aTables, candidate.signed, &scalars4, &signs4, active)
				if signedErr != nil || signedUsable != active {
					t.Fatalf("iteration=%d candidate=%s/pre-signed active=%02x evaluate=(%02x,%v)", iteration, candidate.name, active, signedUsable, signedErr)
				}
				signed := signedLoose.Reduced()
				if !asymmetricFixedBProjectivelyEqual(&signed, &got, active) {
					t.Fatalf("iteration=%d candidate=%s/pre-signed active=%02x runtime-sign mismatch", iteration, candidate.name, active)
				}
				assertMaskedPointX4(t, fmt.Sprintf("%s pre-signed exact mixed-order DSM", candidate.name), &signed, &want4, active)
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

			signedTable := fixture.b10Signed
			if test.b == fixture.b8Table {
				signedTable = fixture.b8Signed
			}
			var signedLoose IFMAPointX4
			signedMask, signedErr := evaluateHeterogeneousPartialCombPreSignedBDSMX4Experiment(&signedLoose, &fixture.aTables, signedTable, &scalars, &signs, 1)
			if signedErr != nil || signedMask != 1 {
				t.Fatalf("pre-signed evaluate=(%02x,%v)", signedMask, signedErr)
			}
			signedReduced := signedLoose.Reduced()
			signed := signedReduced.Lane(0)
			assertScalarPointMatchesReference(t, test.name+" pre-signed", &signed, want)

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
	for _, candidate := range []struct {
		positive *heterogeneousPartialCombTableExperiment
		signed   *heterogeneousPartialCombPreSignedSharedTableExperiment
	}{
		{positive: fixture.b8Table, signed: fixture.b8Signed},
		{positive: fixture.b10Table, signed: fixture.b10Signed},
	} {
		bTable := candidate.positive
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

			var signedLoose IFMAPointX4
			signedUsable, signedErr := evaluateHeterogeneousPartialCombPreSignedBDSMX4Experiment(&signedLoose, &fixture.aTables, candidate.signed, &invalid, &signs, 0x0f)
			if signedErr != nil || signedUsable != wantMask {
				t.Fatalf("B%d/r%d pre-signed invalid lane=%d evaluate=(%02x,%v) want=%02x", bTable.spec.width, bTable.spec.passes, invalidLane, signedUsable, signedErr, wantMask)
			}
			signed := signedLoose.Reduced()
			signedLane := signed.Lane(invalidLane)
			if signedLane.IsIdentity() != 1 {
				t.Fatalf("B%d/r%d pre-signed invalid lane=%d did not fail closed", bTable.spec.width, bTable.spec.passes, invalidLane)
			}
		}
	}
}

func TestHeterogeneousPartialCombEvaluationZeroAllocationsExperiment(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("requires AVX-512 IFMA target")
	}
	fixture, scalars, signs := newHeterogeneousPartialCombBenchmarkFixtureExperiment(t)
	for _, candidate := range []struct {
		positive *heterogeneousPartialCombTableExperiment
		signed   *heterogeneousPartialCombPreSignedSharedTableExperiment
	}{
		{positive: fixture.b8Table, signed: fixture.b8Signed},
		{positive: fixture.b10Table, signed: fixture.b10Signed},
	} {
		bTable := candidate.positive
		var out IFMAPointX4
		if allocs := testing.AllocsPerRun(20, func() {
			if _, err := evaluateHeterogeneousPartialCombDSMX4Experiment(&out, &fixture.aTables, bTable, &scalars, &signs, 0x0f); err != nil {
				panic(err)
			}
		}); allocs != 0 {
			t.Fatalf("A6/r9+B%d/r%d allocations=%v want=0", bTable.spec.width, bTable.spec.passes, allocs)
		}
		if allocs := testing.AllocsPerRun(20, func() {
			if _, err := evaluateHeterogeneousPartialCombPreSignedBDSMX4Experiment(&out, &fixture.aTables, candidate.signed, &scalars, &signs, 0x0f); err != nil {
				panic(err)
			}
		}); allocs != 0 {
			t.Fatalf("A6/r9+B%d/r%d pre-signed allocations=%v want=0", bTable.spec.width, bTable.spec.passes, allocs)
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
	b8Signed  *heterogeneousPartialCombPreSignedSharedTableExperiment
	b10Signed *heterogeneousPartialCombPreSignedSharedTableExperiment
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
	fixture.b8Signed = buildHeterogeneousPartialCombPreSignedSharedTableExperiment(fixture.b8Table)
	fixture.b10Signed = buildHeterogeneousPartialCombPreSignedSharedTableExperiment(fixture.b10Table)
	var scalars FixedDSMScalarsX4
	copy(scalars[0][:], s8[:X4Lanes])
	copy(scalars[1][:], k8[:X4Lanes])
	return fixture, scalars, [DSMTerms]uint8{0, 0x0f}
}

var (
	benchmarkHeterogeneousPartialCombPointSink    IFMAPointX4
	benchmarkHeterogeneousPartialCombMaskSink     uint8
	benchmarkHeterogeneousPartialCombParallelSink uint64
)

const heterogeneousPartialCombBenchmarkCorpusSizeExperiment = 64

func heterogeneousPartialCombBenchmarkCorpusExperiment() [heterogeneousPartialCombBenchmarkCorpusSizeExperiment]FixedDSMScalarsX4 {
	rng := rand.New(rand.NewSource(0xc0b6_b5a1))
	var corpus [heterogeneousPartialCombBenchmarkCorpusSizeExperiment]FixedDSMScalarsX4
	for sample := range corpus {
		for term := range corpus[sample] {
			for lane := range corpus[sample][term] {
				for index := range corpus[sample][term][lane] {
					corpus[sample][term][lane][index] = byte(rng.Uint32())
				}
				// Values below 2^252 are canonical scalars while retaining dense,
				// varied balanced digits for every tested width.
				corpus[sample][term][lane][31] &= 0x0f
			}
		}
	}
	return corpus
}

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
	for _, candidate := range []struct {
		positive *heterogeneousPartialCombTableExperiment
		signed   *heterogeneousPartialCombPreSignedSharedTableExperiment
	}{
		{positive: fixture.b8Table, signed: fixture.b8Signed},
		{positive: fixture.b10Table, signed: fixture.b10Signed},
	} {
		table := candidate.positive
		var candidateLoose IFMAPointX4
		mask, candidateErr := evaluateHeterogeneousPartialCombDSMX4Experiment(&candidateLoose, &fixture.aTables, table, &scalars, &signs, 0x0f)
		if candidateErr != nil || mask != controlMask {
			b.Fatalf("candidate B%d/r%d=(%02x,%v)", table.spec.width, table.spec.passes, mask, candidateErr)
		}
		candidateReduced := candidateLoose.Reduced()
		if !asymmetricFixedBProjectivelyEqual(&candidateReduced, &control, mask) {
			b.Fatalf("candidate B%d/r%d preflight mismatch", table.spec.width, table.spec.passes)
		}
		var signedLoose IFMAPointX4
		signedMask, signedErr := evaluateHeterogeneousPartialCombPreSignedBDSMX4Experiment(&signedLoose, &fixture.aTables, candidate.signed, &scalars, &signs, 0x0f)
		if signedErr != nil || signedMask != mask {
			b.Fatalf("pre-signed candidate B%d/r%d=(%02x,%v) runtime-sign-mask=%02x", table.spec.width, table.spec.passes, signedMask, signedErr, mask)
		}
		signed := signedLoose.Reduced()
		if !asymmetricFixedBProjectivelyEqual(&signed, &candidateReduced, signedMask) {
			b.Fatalf("pre-signed candidate B%d/r%d preflight mismatch", table.spec.width, table.spec.passes)
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
	for _, candidate := range []struct {
		positive *heterogeneousPartialCombTableExperiment
		signed   *heterogeneousPartialCombPreSignedSharedTableExperiment
	}{
		{positive: fixture.b8Table, signed: fixture.b8Signed},
		{positive: fixture.b10Table, signed: fixture.b10Signed},
	} {
		table := candidate.positive
		name := fmt.Sprintf("implementation=partial-A6r9-B%dr%d-runtime-sign", table.spec.width, table.spec.passes)
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

		name = fmt.Sprintf("implementation=partial-A6r9-B%dr%d-pre-signed", table.spec.width, table.spec.passes)
		b.Run(name, func(b *testing.B) {
			var out IFMAPointX4
			var mask uint8
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				var err error
				mask, err = evaluateHeterogeneousPartialCombPreSignedBDSMX4Experiment(&out, &fixture.aTables, candidate.signed, &scalars, &signs, 0x0f)
				if err != nil {
					b.Fatal(err)
				}
			}
			benchmarkHeterogeneousPartialCombPointSink = out
			benchmarkHeterogeneousPartialCombMaskSink = mask
			b.ReportMetric(float64(aGroupBytes), "A-group-table-bytes")
			b.ReportMetric(float64(aGroupBytes/X4Lanes), "A-table-bytes/key")
			b.ReportMetric(float64(candidate.signed.nominalPayloadBytes()), "B-table-bytes")
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*X4Lanes), "ns/signature")
		})
	}
}

// BenchmarkHeterogeneousPartialCombPreSignedCorpusDSMX4Experiment prevents a
// single fixed scalar/sign trace from making pre-signed selection look better
// through perfect branch prediction or an unrealistically tiny hot-address
// set. Recoding remains inside both timed evaluators. The fixture owns every
// candidate so adjacent subbenchmarks have identical setup; B-table-bytes is
// the nominal steady-state payload of the selected replacement, not total live
// heap retained by this comparison fixture.
func BenchmarkHeterogeneousPartialCombPreSignedCorpusDSMX4Experiment(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skip("requires AVX-512 IFMA target")
	}
	fixture, _, signs := newHeterogeneousPartialCombBenchmarkFixtureExperiment(b)
	corpus := heterogeneousPartialCombBenchmarkCorpusExperiment()
	candidates := []struct {
		positive *heterogeneousPartialCombTableExperiment
		signed   *heterogeneousPartialCombPreSignedSharedTableExperiment
	}{
		{positive: fixture.b8Table, signed: fixture.b8Signed},
		{positive: fixture.b10Table, signed: fixture.b10Signed},
	}

	for sample := range corpus {
		var controlLoose IFMAPointX4
		controlMask, err := evaluateAsymmetricFixedBDensePreparedRadix64DSMX4(
			&controlLoose, &fixture.regularA, fixture.regularB,
			&corpus[sample], &signs, 0x0f,
		)
		if err != nil || controlMask != 0x0f {
			b.Fatalf("sample=%d control=(%02x,%v)", sample, controlMask, err)
		}
		control := controlLoose.Reduced()
		for _, candidate := range candidates {
			var runtimeLoose, signedLoose IFMAPointX4
			runtimeMask, runtimeErr := evaluateHeterogeneousPartialCombDSMX4Experiment(
				&runtimeLoose, &fixture.aTables, candidate.positive,
				&corpus[sample], &signs, 0x0f,
			)
			signedMask, signedErr := evaluateHeterogeneousPartialCombPreSignedBDSMX4Experiment(
				&signedLoose, &fixture.aTables, candidate.signed,
				&corpus[sample], &signs, 0x0f,
			)
			if runtimeErr != nil || signedErr != nil || runtimeMask != controlMask || signedMask != runtimeMask {
				b.Fatalf("sample=%d B%d/r%d control=%02x runtime=(%02x,%v) pre-signed=(%02x,%v)", sample, candidate.positive.spec.width, candidate.positive.spec.passes, controlMask, runtimeMask, runtimeErr, signedMask, signedErr)
			}
			runtimeReduced, signedReduced := runtimeLoose.Reduced(), signedLoose.Reduced()
			if !asymmetricFixedBProjectivelyEqual(&runtimeReduced, &control, runtimeMask) ||
				!asymmetricFixedBProjectivelyEqual(&signedReduced, &runtimeReduced, signedMask) {
				b.Fatalf("sample=%d B%d/r%d preflight mismatch", sample, candidate.positive.spec.width, candidate.positive.spec.passes)
			}
		}
	}

	aGroupBytes := heterogeneousPartialCombAGroupPayloadBytesExperiment(&fixture.aTables)
	for _, order := range []struct {
		name           string
		preSignedFirst bool
	}{
		{name: "runtime-first"},
		{name: "pre-signed-first", preSignedFirst: true},
	} {
		b.Run("order="+order.name, func(b *testing.B) {
			for _, candidate := range candidates {
				table := candidate.positive
				run := func(preSigned bool) {
					implementation := "runtime-sign"
					if preSigned {
						implementation = "pre-signed"
					}
					name := fmt.Sprintf("implementation=partial-A6r9-B%dr%d-%s", table.spec.width, table.spec.passes, implementation)
					b.Run(name, func(b *testing.B) {
						var out IFMAPointX4
						var mask uint8
						b.ReportAllocs()
						b.ResetTimer()
						if preSigned {
							for iteration := 0; iteration < b.N; iteration++ {
								var err error
								scalars := &corpus[iteration&(heterogeneousPartialCombBenchmarkCorpusSizeExperiment-1)]
								mask, err = evaluateHeterogeneousPartialCombPreSignedBDSMX4Experiment(&out, &fixture.aTables, candidate.signed, scalars, &signs, 0x0f)
								if err != nil {
									b.Fatal(err)
								}
							}
						} else {
							for iteration := 0; iteration < b.N; iteration++ {
								var err error
								scalars := &corpus[iteration&(heterogeneousPartialCombBenchmarkCorpusSizeExperiment-1)]
								mask, err = evaluateHeterogeneousPartialCombDSMX4Experiment(&out, &fixture.aTables, table, scalars, &signs, 0x0f)
								if err != nil {
									b.Fatal(err)
								}
							}
						}
						benchmarkHeterogeneousPartialCombPointSink = out
						benchmarkHeterogeneousPartialCombMaskSink = mask
						b.ReportMetric(float64(aGroupBytes), "A-group-table-bytes")
						b.ReportMetric(float64(aGroupBytes/X4Lanes), "A-table-bytes/key")
						bTableBytes := table.nominalPayloadBytes()
						if preSigned {
							bTableBytes = candidate.signed.nominalPayloadBytes()
						}
						b.ReportMetric(float64(bTableBytes), "B-table-bytes")
						b.ReportMetric(heterogeneousPartialCombBenchmarkCorpusSizeExperiment, "corpus-groups")
						b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*X4Lanes), "ns/signature")
					})
				}
				if order.preSignedFirst {
					run(true)
					run(false)
				} else {
					run(false)
					run(true)
				}
			}
		})
	}
}

const heterogeneousPartialCombPressureCorpusSizeExperiment = 256

func heterogeneousPartialCombSharedBPressureCorpusExperiment() [heterogeneousPartialCombPressureCorpusSizeExperiment]FixedDSMScalarsX4 {
	rng := rand.New(rand.NewSource(0xc0b6_5b1e))
	var corpus [heterogeneousPartialCombPressureCorpusSizeExperiment]FixedDSMScalarsX4
	for sample := range corpus {
		for lane := range corpus[sample][0] {
			for index := range corpus[sample][0][lane] {
				corpus[sample][0][lane][index] = byte(rng.Uint32())
			}
			corpus[sample][0][lane][31] &= 0x0f
		}
	}
	return corpus
}

// BenchmarkHeterogeneousPartialCombSharedBPressureX4Experiment isolates the
// cache/concurrency consequence of doubling the process-wide immutable B
// table. A is the zero scalar and its spec-only tables are never indexed, but
// its A6/r9 shape keeps the real 48-doubling merged timeline and B injection
// spacing. Every parallel worker shares exactly one selected B layout.
//
// This is a necessary shared-table pressure gate, not a complete-verifier or
// random-A working-set result. A production pre-signed builder should transfer
// ownership of the positive slice instead of retaining the temporary 3x peak
// used by the comparison builder.
func BenchmarkHeterogeneousPartialCombSharedBPressureX4Experiment(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skip("requires AVX-512 IFMA target")
	}
	baseEncoding := newGeneratorEncodingForTest(b)
	var base Point
	if _, err := base.SetBytes(baseEncoding[:]); err != nil {
		b.Fatal(err)
	}
	corpus := heterogeneousPartialCombSharedBPressureCorpusExperiment()
	signs := [DSMTerms]uint8{0, 0x0f}
	aSpecOnly := &heterogeneousPartialCombTableExperiment{spec: heterogeneousPartialCombA6R9Experiment}
	aTables := [X4Lanes]*heterogeneousPartialCombTableExperiment{aSpecOnly, aSpecOnly, aSpecOnly, aSpecOnly}

	for _, order := range []struct {
		name           string
		preSignedFirst bool
	}{
		{name: "runtime-first"},
		{name: "pre-signed-first", preSignedFirst: true},
	} {
		b.Run("order="+order.name, func(b *testing.B) {
			for _, spec := range []heterogeneousPartialCombSpecExperiment{
				heterogeneousPartialCombB8R3Experiment,
				heterogeneousPartialCombB10R5Experiment,
			} {
				run := func(preSigned bool) {
					implementation := "runtime-sign"
					if preSigned {
						implementation = "pre-signed"
					}
					name := fmt.Sprintf("B=%dr%d/layout=%s", spec.width, spec.passes, implementation)
					b.Run(name, func(b *testing.B) {
						var positive *heterogeneousPartialCombTableExperiment
						var signed *heterogeneousPartialCombPreSignedSharedTableExperiment
						if preSigned {
							source := buildHeterogeneousPartialCombTableExperiment(&base, spec)
							signed = buildHeterogeneousPartialCombPreSignedSharedTableExperiment(source)
							source = nil
						} else {
							positive = buildHeterogeneousPartialCombTableExperiment(&base, spec)
						}
						// Drop unreachable tables from preceding subbenchmarks before this
						// arm establishes its own steady-state working set.
						runtime.GC()

						var preflight IFMAPointX4
						var mask uint8
						var err error
						if preSigned {
							mask, err = evaluateHeterogeneousPartialCombPreSignedBDSMX4Experiment(&preflight, &aTables, signed, &corpus[0], &signs, 0x0f)
						} else {
							mask, err = evaluateHeterogeneousPartialCombDSMX4Experiment(&preflight, &aTables, positive, &corpus[0], &signs, 0x0f)
						}
						if err != nil || mask != 0x0f {
							b.Fatalf("preflight=(%02x,%v)", mask, err)
						}

						var workerSequence uint64
						b.ReportAllocs()
						b.SetParallelism(1)
						b.ResetTimer()
						b.RunParallel(func(pb *testing.PB) {
							worker := atomic.AddUint64(&workerSequence, 1) - 1
							cursor := int(worker*131) & (heterogeneousPartialCombPressureCorpusSizeExperiment - 1)
							var out IFMAPointX4
							var localMask uint8
							for pb.Next() {
								scalars := &corpus[cursor]
								cursor = (cursor + 1) & (heterogeneousPartialCombPressureCorpusSizeExperiment - 1)
								var localErr error
								if preSigned {
									localMask, localErr = evaluateHeterogeneousPartialCombPreSignedBDSMX4Experiment(&out, &aTables, signed, scalars, &signs, 0x0f)
								} else {
									localMask, localErr = evaluateHeterogeneousPartialCombDSMX4Experiment(&out, &aTables, positive, scalars, &signs, 0x0f)
								}
								if localErr != nil {
									panic(localErr)
								}
							}
							atomic.AddUint64(
								&benchmarkHeterogeneousPartialCombParallelSink,
								uint64(localMask)+out.X.limbs[0][0],
							)
						})
						b.StopTimer()

						var bTableBytes int
						if preSigned {
							bTableBytes = signed.nominalPayloadBytes()
						} else {
							bTableBytes = positive.nominalPayloadBytes()
						}
						b.ReportMetric(float64(bTableBytes), "B-table-bytes")
						b.ReportMetric(heterogeneousPartialCombPressureCorpusSizeExperiment, "corpus-groups")
						b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*X4Lanes), "ns/signature")
						b.ReportMetric(float64(b.N*X4Lanes)/b.Elapsed().Seconds(), "sig/s")
						b.ReportMetric(float64(runtime.GOMAXPROCS(0)), "workers")
					})
				}
				if order.preSignedFirst {
					run(true)
					run(false)
				} else {
					run(false)
					run(true)
				}
			}
		})
	}
}
