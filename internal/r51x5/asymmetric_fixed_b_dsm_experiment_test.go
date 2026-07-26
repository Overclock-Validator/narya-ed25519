package r51x5

import (
	"fmt"
	"math/big"
	"math/rand"
	"testing"
	"unsafe"

	edwardsref "github.com/Overclock-Validator/narya-ed25519/internal/edwards25519"
)

func TestAsymmetricFixedBThreeByteExtractorAndBoundaryDigits(t *testing.T) {
	for _, width := range []uint{6, 8, 9, 10} {
		for offset := 0; offset < 8; offset++ {
			var scalar [32]byte
			value := uint16((1 << width) - 1)
			bit := 80 + offset
			for sourceBit := uint(0); sourceBit < width; sourceBit++ {
				if value&(1<<sourceBit) != 0 {
					absolute := bit + int(sourceBit)
					scalar[absolute>>3] |= 1 << (absolute & 7)
				}
			}
			if got := asymmetricFixedBScalarBitsExperiment(&scalar, bit, width); got != value {
				t.Fatalf("width=%d offset=%d got=%d want=%d", width, offset, got, value)
			}
		}
	}

	for _, test := range []struct {
		width     uint
		scalar    uint16
		magnitude uint16
	}{
		{width: 8, scalar: 128, magnitude: 128},
		{width: 9, scalar: 256, magnitude: 256},
		{width: 10, scalar: 512, magnitude: 512},
	} {
		var scalars [X4Lanes][32]byte
		scalars[0][0] = byte(test.scalar)
		scalars[0][1] = byte(test.scalar >> 8)
		var digits asymmetricFixedBDigitsX4
		if mask := recodeAsymmetricFixedBScalarsX4(&digits, &scalars, 0, 1, test.width); mask != 1 {
			t.Fatalf("width=%d valid mask=%02x", test.width, mask)
		}
		first := &digits.rounds[0]
		if first.Magnitude[0] != test.magnitude || first.NegativeMask&1 == 0 || first.NonzeroMask&1 == 0 {
			t.Fatalf("width=%d boundary digit=(magnitude=%d nonzero=%02x negative=%02x)", test.width, first.Magnitude[0], first.NonzeroMask, first.NegativeMask)
		}
		if digits.rounds[1].Magnitude[0] != 1 || digits.rounds[1].NegativeMask&1 != 0 {
			t.Fatalf("width=%d carry digit=(magnitude=%d negative=%02x)", test.width, digits.rounds[1].Magnitude[0], digits.rounds[1].NegativeMask)
		}
	}
}

func TestAsymmetricFixedBRecodingReconstructsCanonicalEdges(t *testing.T) {
	edges := [][32]byte{{}, {1}, scalarOrderBytes}
	edges[2][0]-- // L-1.
	for _, width := range []uint{6, 8, 9, 10} {
		for edgeIndex, scalar := range edges {
			var scalars [X4Lanes][32]byte
			scalars[0] = scalar
			for _, negative := range []bool{false, true} {
				var digits asymmetricFixedBDigitsX4
				var negativeMask uint8
				if negative {
					negativeMask = 1
				}
				if mask := recodeAsymmetricFixedBScalarsX4(&digits, &scalars, negativeMask, 1, width); mask != 1 {
					t.Fatalf("width=%d edge=%d negative=%v mask=%02x", width, edgeIndex, negative, mask)
				}
				got := new(big.Int)
				place := big.NewInt(1)
				radix := new(big.Int).Lsh(big.NewInt(1), width)
				for round := 0; round < int(digits.count); round++ {
					record := &digits.rounds[round]
					digit := int64(record.Magnitude[0])
					if record.NegativeMask&1 != 0 {
						digit = -digit
					}
					got.Add(got, new(big.Int).Mul(big.NewInt(digit), place))
					place.Mul(place, radix)
				}
				want := signedMagnitudeToBig(NewSignedMagnitude(scalar[:], negative))
				if got.Cmp(want) != 0 {
					t.Fatalf("width=%d edge=%d negative=%v got=%s want=%s", width, edgeIndex, negative, got, want)
				}
			}
		}
	}
}

func TestAsymmetricFixedBDenseAffine3SelectorMatchesScalarAllMasksAndSigns(t *testing.T) {
	if !microAoSSelectorExperimentCanCall() {
		t.Skip("requires AVX-512 IFMA target on amd64")
	}
	baseEncoding := newGeneratorEncodingForTest(t)
	var base Point
	if _, err := base.SetBytes(baseEncoding[:]); err != nil {
		t.Fatal(err)
	}
	table := buildAsymmetricFixedBTableExperiment(&base, 10)
	patterns := []asymmetricFixedBRoundX4{
		{},
		{
			Magnitude:    [X4Lanes]uint16{1, 128, 256, 512},
			NonzeroMask:  0x0f,
			NegativeMask: 0x0a,
		},
		{
			Magnitude:    [X4Lanes]uint16{512, 0, 17, 0},
			NonzeroMask:  0x05,
			NegativeMask: 0x01,
		},
	}
	for patternIndex := range patterns {
		round := &patterns[patternIndex]
		for active := uint8(0); active < 1<<X4Lanes; active++ {
			var want fixedBaseIFMACachedX4
			selectAsymmetricFixedBIFMACachedX4(&want, table, round, active)
			var checked fixedBaseIFMACachedX4
			selectAsymmetricFixedBDenseAffine3CheckedX4(&checked, table, round, active)
			if checked != want {
				t.Fatalf("pattern=%d active=%02x checked mismatch", patternIndex, active)
			}
			var unchecked fixedBaseIFMACachedX4
			selectAsymmetricFixedBDenseAffine3UncheckedX4(&unchecked, table, round, active)
			if unchecked != want {
				t.Fatalf("pattern=%d active=%02x unchecked mismatch", patternIndex, active)
			}
		}
	}

	bad := asymmetricFixedBRoundX4{Magnitude: [X4Lanes]uint16{513}, NonzeroMask: 1}
	sentinel := fixedBaseIFMACachedX4{
		YPlusX:  patternedIFMAElementX4Garbage(),
		YMinusX: patternedIFMAElementX4Garbage(),
		T2D:     patternedIFMAElementX4Garbage(),
	}
	got := sentinel
	if !microAoSSelectorExperimentPanics(func() {
		selectAsymmetricFixedBDenseAffine3CheckedX4(&got, table, &bad, 1)
	}) {
		t.Fatal("invalid dense asymmetric metadata did not panic")
	}
	if got != sentinel {
		t.Fatal("invalid dense asymmetric metadata changed output")
	}
}

type asymmetricFixedBCorrectnessFixture struct {
	workspace ExperimentalIFMAFixedDSMWorkspaceRadix64X4
	aTables   [X4Lanes]ifmaMicroAoSPerKeyTableExperiment
	bTables   map[uint]*asymmetricFixedBTableExperiment
	refs      [QSMTerms][X8Lanes]*edwardsref.Point
}

func newAsymmetricFixedBCorrectnessFixture(t *testing.T) asymmetricFixedBCorrectnessFixture {
	t.Helper()
	rng := rand.New(rand.NewSource(0xa5b6_10d5))
	torsion := referenceTorsionPoints(t)

	// Give the shared B a torsion component too. This ensures the merged
	// schedule is tested as exact integer arithmetic, not merely modulo L.
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

	fixture := asymmetricFixedBCorrectnessFixture{bTables: make(map[uint]*asymmetricFixedBTableExperiment)}
	if err := fixture.workspace.PrepareBoth(&[DSMTerms]PointX4{bX4, aX4}, 6); err != nil {
		t.Fatal(err)
	}
	fixture.aTables = importIFMAMicroAoSTablesExperimentX4(&fixture.workspace.tables[1])
	for _, width := range []uint{6, 8, 9, 10} {
		fixture.bTables[width] = buildAsymmetricFixedBTableExperiment(&bPoint, width)
	}
	for lane := 0; lane < X8Lanes; lane++ {
		fixture.refs[0][lane] = bRef
		fixture.refs[1][lane] = aRefs[lane]
	}
	return fixture
}

func TestAsymmetricFixedBPreparedRadix64DSMX4ExactMixedOrderAllMasks(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("requires AVX-512 IFMA target")
	}
	fixture := newAsymmetricFixedBCorrectnessFixture(t)
	rng := rand.New(rand.NewSource(0xa5b6_d1ff))
	for iteration := 0; iteration < 12; iteration++ {
		scalars8, signs8, exact := randomIFMAFixedDSMScalars(rng)
		if iteration == 0 {
			// Exercise exact -1 on mixed-order A and the two widest balanced
			// boundary digits on B in separate lanes.
			scalars8[1][0] = [32]byte{1}
			exact[1][0] = big.NewInt(-1)
			scalars8[0][1] = [32]byte{0x80}
			exact[0][1] = big.NewInt(128)
			scalars8[0][2] = [32]byte{0x00, 0x02}
			exact[0][2] = big.NewInt(512)
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
		for _, width := range []uint{6, 8, 9, 10} {
			for active := uint8(0); active < 1<<X4Lanes; active++ {
				var gotLoose IFMAPointX4
				usable, err := evaluateAsymmetricFixedBPreparedRadix64DSMX4(&gotLoose, &fixture.aTables, fixture.bTables[width], &scalars4, &signs4, active)
				if err != nil || usable != active {
					t.Fatalf("iteration=%d width=%d active=%02x evaluate=(%02x,%v)", iteration, width, active, usable, err)
				}
				got := gotLoose.Reduced()
				assertMaskedPointX4(t, fmt.Sprintf("asymmetric B width=%d iteration=%d active=%02x", width, iteration, active), &got, &want4, active)

				var denseLoose IFMAPointX4
				denseUsable, denseErr := evaluateAsymmetricFixedBDensePreparedRadix64DSMX4(&denseLoose, &fixture.aTables, fixture.bTables[width], &scalars4, &signs4, active)
				if denseErr != nil || denseUsable != usable {
					t.Fatalf("iteration=%d width=%d active=%02x dense=(%02x,%v) scalar-mask=%02x", iteration, width, active, denseUsable, denseErr, usable)
				}
				dense := denseLoose.Reduced()
				if dense != got {
					t.Fatalf("iteration=%d width=%d active=%02x dense/scalar mismatch", iteration, width, active)
				}
				assertMaskedPointX4(t, fmt.Sprintf("dense asymmetric B width=%d iteration=%d active=%02x", width, iteration, active), &dense, &want4, active)
			}
		}
	}
}

func TestAsymmetricFixedBPreparedRadix64DSMX4InvalidFailClosed(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("requires AVX-512 IFMA target")
	}
	fixture := newAsymmetricFixedBCorrectnessFixture(t)
	var scalars FixedDSMScalarsX4
	for term := range scalars {
		for lane := range scalars[term] {
			scalars[term][lane] = [32]byte{byte(1 + term*7 + lane)}
		}
	}
	signs := [DSMTerms]uint8{0, 0x0f}
	for _, width := range []uint{6, 8, 9, 10} {
		for invalidLane := 0; invalidLane < X4Lanes; invalidLane++ {
			invalid := scalars
			invalid[invalidLane&1][invalidLane] = scalarOrderBytes
			var gotLoose IFMAPointX4
			usable, err := evaluateAsymmetricFixedBPreparedRadix64DSMX4(&gotLoose, &fixture.aTables, fixture.bTables[width], &invalid, &signs, 0x0f)
			wantMask := uint8(0x0f &^ (1 << invalidLane))
			if err != nil || usable != wantMask {
				t.Fatalf("width=%d invalid lane=%d evaluate=(%02x,%v) want=%02x", width, invalidLane, usable, err, wantMask)
			}
			got := gotLoose.Reduced()
			gotLane := got.Lane(invalidLane)
			if gotLane.IsIdentity() != 1 {
				t.Fatalf("width=%d invalid lane=%d did not fail closed", width, invalidLane)
			}

			var denseLoose IFMAPointX4
			denseUsable, denseErr := evaluateAsymmetricFixedBDensePreparedRadix64DSMX4(&denseLoose, &fixture.aTables, fixture.bTables[width], &invalid, &signs, 0x0f)
			if denseErr != nil || denseUsable != wantMask {
				t.Fatalf("dense width=%d invalid lane=%d evaluate=(%02x,%v) want=%02x", width, invalidLane, denseUsable, denseErr, wantMask)
			}
			dense := denseLoose.Reduced()
			denseLane := dense.Lane(invalidLane)
			if denseLane.IsIdentity() != 1 {
				t.Fatalf("dense width=%d invalid lane=%d did not fail closed", width, invalidLane)
			}
			if dense != got {
				t.Fatalf("dense width=%d invalid lane=%d scalar/dense mismatch", width, invalidLane)
			}
		}
	}
}

func TestAsymmetricFixedBPreparedRadix64DSMX4ZeroAllocations(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("requires AVX-512 IFMA target")
	}
	fixture, scalars, signs := newAsymmetricFixedBBenchmarkFixture(t)
	for _, width := range []uint{6, 8, 9, 10} {
		table := fixture.bTables[width]
		var out IFMAPointX4
		if allocs := testing.AllocsPerRun(20, func() {
			if _, err := evaluateAsymmetricFixedBPreparedRadix64DSMX4(&out, &fixture.aTables, table, &scalars, &signs, 0x0f); err != nil {
				panic(err)
			}
		}); allocs != 0 {
			t.Fatalf("scalar width=%d allocations=%v want=0", width, allocs)
		}
		if allocs := testing.AllocsPerRun(20, func() {
			if _, err := evaluateAsymmetricFixedBDensePreparedRadix64DSMX4(&out, &fixture.aTables, table, &scalars, &signs, 0x0f); err != nil {
				panic(err)
			}
		}); allocs != 0 {
			t.Fatalf("dense width=%d allocations=%v want=0", width, allocs)
		}
	}
}

func asymmetricFixedBProjectivelyEqual(x, y *PointX4, active uint8) bool {
	active &= 0x0f
	return x.Equal(y)&active == active
}

// The projective and affine-cached evaluators are free to return different
// projective scales. A benchmark preflight must compare Edwards points by
// cross multiplication, never by coordinate-array equality.
func TestAsymmetricFixedBBenchmarkFixtureProjectivePreflight(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("requires AVX-512 IFMA target")
	}
	fixture, scalars, signs := newAsymmetricFixedBBenchmarkFixture(t)
	var controlLoose IFMAPointX4
	controlMask, err := evaluateIFMAMicroAoSPreparedRadix64DSMX4(&controlLoose, &fixture.workspace, &fixture.microTables, &scalars, &signs, 0x0f)
	if err != nil || controlMask != 0x0f {
		t.Fatalf("control=(%02x,%v)", controlMask, err)
	}
	control := controlLoose.Reduced()
	for _, width := range []uint{6, 8, 9, 10} {
		var scalarLoose, denseLoose IFMAPointX4
		scalarMask, scalarErr := evaluateAsymmetricFixedBPreparedRadix64DSMX4(&scalarLoose, &fixture.aTables, fixture.bTables[width], &scalars, &signs, 0x0f)
		denseMask, denseErr := evaluateAsymmetricFixedBDensePreparedRadix64DSMX4(&denseLoose, &fixture.aTables, fixture.bTables[width], &scalars, &signs, 0x0f)
		if scalarErr != nil || denseErr != nil || scalarMask != controlMask || denseMask != controlMask {
			t.Fatalf("width=%d scalar=(%02x,%v) dense=(%02x,%v) control=%02x", width, scalarMask, scalarErr, denseMask, denseErr, controlMask)
		}
		scalar, dense := scalarLoose.Reduced(), denseLoose.Reduced()
		if !asymmetricFixedBProjectivelyEqual(&scalar, &control, controlMask) ||
			!asymmetricFixedBProjectivelyEqual(&dense, &control, controlMask) {
			t.Fatalf("width=%d projective preflight mismatch", width)
		}
	}
}

type asymmetricFixedBBenchmarkFixture struct {
	workspace   ExperimentalIFMAFixedDSMWorkspaceRadix64X4
	microTables [DSMTerms][X4Lanes]ifmaMicroAoSPerKeyTableExperiment
	aTables     [X4Lanes]ifmaMicroAoSPerKeyTableExperiment
	bTables     map[uint]*asymmetricFixedBTableExperiment
}

func newAsymmetricFixedBBenchmarkFixture(tb testing.TB) (asymmetricFixedBBenchmarkFixture, FixedDSMScalarsX4, [DSMTerms]uint8) {
	tb.Helper()
	bX8, aX8, s8, k8 := fixedBaseCombDSMFixtures(tb)
	bX4, aX4 := pointX4Half(&bX8, 0), pointX4Half(&aX8, 0)
	fixture := asymmetricFixedBBenchmarkFixture{bTables: make(map[uint]*asymmetricFixedBTableExperiment)}
	if err := fixture.workspace.PrepareBoth(&[DSMTerms]PointX4{bX4, aX4}, 6); err != nil {
		tb.Fatal(err)
	}
	fixture.microTables = importIFMAMicroAoSDSMTableExperimentX4(&fixture.workspace)
	fixture.aTables = fixture.microTables[1]
	bPoint := bX4.Lane(0)
	for _, width := range []uint{6, 8, 9, 10} {
		fixture.bTables[width] = buildAsymmetricFixedBTableExperiment(&bPoint, width)
	}
	var scalars FixedDSMScalarsX4
	copy(scalars[0][:], s8[:X4Lanes])
	copy(scalars[1][:], k8[:X4Lanes])
	return fixture, scalars, [DSMTerms]uint8{0, 0x0f}
}

var (
	benchmarkAsymmetricFixedBPointSink IFMAPointX4
	benchmarkAsymmetricFixedBMaskSink  uint8
)

func BenchmarkAsymmetricFixedBPreparedRadix64DSMX4(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skip("requires AVX-512 IFMA target")
	}
	fixture, scalars, signs := newAsymmetricFixedBBenchmarkFixture(b)
	var controlLoose IFMAPointX4
	controlMask, err := evaluateIFMAMicroAoSPreparedRadix64DSMX4(&controlLoose, &fixture.workspace, &fixture.microTables, &scalars, &signs, 0x0f)
	if err != nil || controlMask != 0x0f {
		b.Fatalf("current control evaluate=(%02x,%v)", controlMask, err)
	}
	control := controlLoose.Reduced()
	for _, width := range []uint{6, 8, 9, 10} {
		var candidateLoose IFMAPointX4
		mask, candidateErr := evaluateAsymmetricFixedBPreparedRadix64DSMX4(&candidateLoose, &fixture.aTables, fixture.bTables[width], &scalars, &signs, 0x0f)
		if candidateErr != nil || mask != 0x0f {
			b.Fatalf("shared affine B%d preflight=(%02x,%v)", width, mask, candidateErr)
		}
		if candidate := candidateLoose.Reduced(); !asymmetricFixedBProjectivelyEqual(&candidate, &control, mask) {
			b.Fatalf("shared affine B%d preflight=(%02x,%v) projectively matches-control=false", width, mask, candidateErr)
		}
		var denseLoose IFMAPointX4
		denseMask, denseErr := evaluateAsymmetricFixedBDensePreparedRadix64DSMX4(&denseLoose, &fixture.aTables, fixture.bTables[width], &scalars, &signs, 0x0f)
		if denseErr != nil || denseMask != mask {
			b.Fatalf("dense affine B%d preflight=(%02x,%v) scalar-mask=%02x", width, denseMask, denseErr, mask)
		}
		if dense := denseLoose.Reduced(); !asymmetricFixedBProjectivelyEqual(&dense, &control, denseMask) {
			b.Fatalf("dense affine B%d preflight=(%02x,%v) projectively matches-control=false", width, denseMask, denseErr)
		}
	}
	b.Run("implementation=current-micro-aos-B6-projective", func(b *testing.B) {
		var out IFMAPointX4
		var mask uint8
		b.ReportAllocs()
		b.ResetTimer()
		for iteration := 0; iteration < b.N; iteration++ {
			var err error
			mask, err = evaluateIFMAMicroAoSPreparedRadix64DSMX4(&out, &fixture.workspace, &fixture.microTables, &scalars, &signs, 0x0f)
			if err != nil {
				b.Fatal(err)
			}
		}
		benchmarkAsymmetricFixedBPointSink = out
		benchmarkAsymmetricFixedBMaskSink = mask
		b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*X4Lanes), "ns/signature")
	})
	for _, width := range []uint{6, 8, 9, 10} {
		width := width
		table := fixture.bTables[width]
		b.Run(fmt.Sprintf("implementation=shared-affine-B%d", width), func(b *testing.B) {
			var out IFMAPointX4
			var mask uint8
			b.ReportAllocs()
			b.ReportMetric(float64(len(table.points)*3*len(modulusLimbs)*8), "B-table-bytes")
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				var err error
				mask, err = evaluateAsymmetricFixedBPreparedRadix64DSMX4(&out, &fixture.aTables, table, &scalars, &signs, 0x0f)
				if err != nil {
					b.Fatal(err)
				}
			}
			benchmarkAsymmetricFixedBPointSink = out
			benchmarkAsymmetricFixedBMaskSink = mask
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*X4Lanes), "ns/signature")
		})
		b.Run(fmt.Sprintf("implementation=dense-affine-B%d", width), func(b *testing.B) {
			var out IFMAPointX4
			var mask uint8
			b.ReportAllocs()
			b.ReportMetric(float64(len(table.densePoints)*int(unsafe.Sizeof(ifmaAffine3MicroAoSEntryExperiment{}))), "B-table-bytes")
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				var err error
				mask, err = evaluateAsymmetricFixedBDensePreparedRadix64DSMX4(&out, &fixture.aTables, table, &scalars, &signs, 0x0f)
				if err != nil {
					b.Fatal(err)
				}
			}
			benchmarkAsymmetricFixedBPointSink = out
			benchmarkAsymmetricFixedBMaskSink = mask
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*X4Lanes), "ns/signature")
		})
	}
}
