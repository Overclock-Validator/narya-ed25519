package r51x5

import (
	"bytes"
	"fmt"
	"math/big"
	"math/rand"
	"testing"
	"unsafe"

	edwardsref "github.com/Overclock-Validator/narya-ed25519/internal/edwards25519"
)

// quadSignedCachedTableX4 is a test-only single-point table. Each entry is
// stored in both signs so the public-digit selector is only one indexed load;
// no field negation sits in the measured scalar loop. A packed cached point is
// 160 bytes, so the active payload is 5 KiB at radix 32 and 10 KiB at radix
// 64, per base. The fixed-size experimental container reserves the radix-64
// maximum even while a radix-32 gate uses only its first sixteen entries.
type quadSignedCachedTableX4 struct {
	positive  [32]quadPackedCachedPointX4
	negative  [32]quadPackedCachedPointX4
	entries   uint8
	radixBits uint8
}

func buildQuadSignedCachedTableX4(out *quadSignedCachedTableX4, base *Point, radixBits uint, ops quadDSMOperationsX4) error {
	entries := regularRadixEntries(radixBits)
	var table quadSignedCachedTableX4
	table.entries = uint8(entries)
	table.radixBits = uint8(radixBits)

	current := new(quadPackedPointX4).setReduced(base)
	if err := quadCachePackedPointX4(&table.positive[0], current, ops); err != nil {
		return err
	}
	quadNegateCachedPointX4(&table.negative[0], &table.positive[0])
	baseCached := table.positive[0]
	for entry := 1; entry < entries; entry++ {
		if err := ops.addCached(current, current, &baseCached); err != nil {
			return err
		}
		if err := quadCachePackedPointX4(&table.positive[entry], current, ops); err != nil {
			return err
		}
		quadNegateCachedPointX4(&table.negative[entry], &table.positive[entry])
	}
	*out = table
	return nil
}

func selectQuadSignedCachedPointX4(table *quadSignedCachedTableX4, digit int8) *quadPackedCachedPointX4 {
	if digit == 0 {
		panic("r51x5: zero quad digit has no table entry")
	}
	magnitude := int(digit)
	if magnitude < 0 {
		magnitude = -magnitude
	}
	if magnitude > int(table.entries) {
		panic("r51x5: quad digit exceeds table")
	}
	if digit < 0 {
		return &table.negative[magnitude-1]
	}
	return &table.positive[magnitude-1]
}

// evaluateQuadFixedDSMX4 computes [s]B+[-k]A with exact signed-integer
// semantics. It deliberately reuses the ordinary canonical scalar recoder;
// only lane zero is active because the four IFMA lanes hold X/Y/T/Z.
func evaluateQuadFixedDSMX4(
	out *quadPackedPointX4,
	tables *[DSMTerms]quadSignedCachedTableX4,
	scalars *FixedDSMScalarsX4,
	negativeMasks *[DSMTerms]uint8,
	radixBits uint,
	ops quadDSMOperationsX4,
) (uint8, error) {
	if tables[0].radixBits != uint8(radixBits) || tables[1].radixBits != uint8(radixBits) {
		panic("r51x5: quad DSM table radix mismatch")
	}
	var digits [DSMTerms]FixedRadixDigitsX4
	usable := uint8(1)
	for term := 0; term < DSMTerms; term++ {
		usable &= RecodeCanonicalScalarsX4(&digits[term], &scalars[term], negativeMasks[term]&1, 1, radixBits)
	}
	acc := quadPackedIdentityValueX4()
	if usable == 0 {
		*out = acc
		return 0, nil
	}

	rounds := digits[0].RoundCount()
	for round := rounds - 1; round >= 0; round-- {
		if round != rounds-1 {
			for doubling := uint(0); doubling < radixBits; doubling++ {
				if err := ops.double(&acc, &acc); err != nil {
					return 0, err
				}
			}
		}
		for term := 0; term < DSMTerms; term++ {
			digit := digits[term].Round(round).Digit(0)
			if digit == 0 {
				continue
			}
			selected := selectQuadSignedCachedPointX4(&tables[term], digit)
			if err := ops.addCached(&acc, &acc, selected); err != nil {
				return 0, err
			}
		}
	}
	*out = acc
	return usable, nil
}

type quadDSMFixtureX4 struct {
	b       Point
	a       Point
	bRef    *edwardsref.Point
	aRef    *edwardsref.Point
	scalars FixedDSMScalarsX4
	signs   [DSMTerms]uint8
}

func newQuadDSMFixtureX4(tb testing.TB) quadDSMFixtureX4 {
	tb.Helper()
	var generatorEncoding [32]byte
	generatorEncoding[0] = 0x58
	for index := 1; index < len(generatorEncoding); index++ {
		generatorEncoding[index] = 0x66
	}
	var fixture quadDSMFixtureX4
	if _, err := fixture.b.SetBytes(generatorEncoding[:]); err != nil {
		tb.Fatal(err)
	}

	// A = [3]B + T8 is mixed-order. In particular, replacing exact -k by
	// L-k changes the result by [L]A's nonzero torsion component.
	var twoB, threeB Point
	fixedBasePointDouble(&twoB, &fixture.b)
	fixedBasePointAdd(&threeB, &twoB, &fixture.b)
	torsion := quadLoopDecodePoint(tb, pointTestEncodings[10])
	fixedBasePointAdd(&fixture.a, &threeB, &torsion)

	fixture.bRef = edwardsref.NewGeneratorPoint()
	aEncoding := fixture.a.Bytes()
	var err error
	fixture.aRef, err = new(edwardsref.Point).SetBytes(aEncoding[:])
	if err != nil {
		tb.Fatal(err)
	}
	// Dense canonical scalars keep almost every radix-32/radix-64 round live,
	// so the benchmark charges realistic public table selection and addition
	// work instead of mostly measuring the doubling chain.
	rng := rand.New(rand.NewSource(0x514d5afe))
	_, _ = rng.Read(fixture.scalars[0][0][:])
	_, _ = rng.Read(fixture.scalars[1][0][:])
	fixture.scalars[0][0][31] &= 0x0f
	fixture.scalars[1][0][31] &= 0x0f
	fixture.signs = [DSMTerms]uint8{0, 1}
	return fixture
}

func quadDSMReferenceX4(fixture *quadDSMFixtureX4) *edwardsref.Point {
	return quadDSMReferenceScalarsX4(fixture, &fixture.scalars)
}

func quadDSMReferenceScalarsX4(fixture *quadDSMFixtureX4, scalars *FixedDSMScalarsX4) *edwardsref.Point {
	s := signedMagnitudeToBig(NewSignedMagnitude(scalars[0][0][:], false))
	minusK := signedMagnitudeToBig(NewSignedMagnitude(scalars[1][0][:], true))
	want := edwardsref.NewIdentityPoint()
	want.Add(want, exactReferenceIntegerMult(fixture.bRef, s))
	want.Add(want, exactReferenceIntegerMult(fixture.aRef, minusK))
	return want
}

func TestExperimentalCoordinateParallelFixedDSMX4(t *testing.T) {
	fixture := newQuadDSMFixtureX4(t)
	want := quadDSMReferenceX4(&fixture)
	modelOps := quadDSMOperationsX4{}
	for _, radixBits := range []uint{5, 6} {
		var modelTables [DSMTerms]quadSignedCachedTableX4
		if err := buildQuadSignedCachedTableX4(&modelTables[0], &fixture.b, radixBits, modelOps); err != nil {
			t.Fatal(err)
		}
		if err := buildQuadSignedCachedTableX4(&modelTables[1], &fixture.a, radixBits, modelOps); err != nil {
			t.Fatal(err)
		}
		var model quadPackedPointX4
		usable, err := evaluateQuadFixedDSMX4(&model, &modelTables, &fixture.scalars, &fixture.signs, radixBits, modelOps)
		if err != nil || usable != 1 {
			t.Fatalf("radix %d model evaluate=(%d,%v)", 1<<radixBits, usable, err)
		}
		modelPoint := model.reduced()
		modelEncoding := modelPoint.Bytes()
		if !bytes.Equal(modelEncoding[:], want.Bytes()) {
			t.Fatalf("radix %d model mismatch\ngot  %x\nwant %x", 1<<radixBits, modelEncoding, want.Bytes())
		}

		// Reuse the prepared tables across dense public scalar pairs. This
		// exercises carries, zero digits, both digit signs, and exact -k without
		// conflating scalar correctness with table construction. Keep the model
		// differential outside the IFMA gate so every architecture runs it.
		var randomScalars [16]FixedDSMScalarsX4
		var randomModelEncodings [len(randomScalars)][32]byte
		rng := rand.New(rand.NewSource(int64(0x514d5000 + radixBits)))
		for iteration := range randomScalars {
			randomScalars[iteration] = fixture.scalars
			_, _ = rng.Read(randomScalars[iteration][0][0][:])
			_, _ = rng.Read(randomScalars[iteration][1][0][:])
			randomScalars[iteration][0][0][31] &= 0x0f
			randomScalars[iteration][1][0][31] &= 0x0f
			randomWant := quadDSMReferenceScalarsX4(&fixture, &randomScalars[iteration])
			var randomModel quadPackedPointX4
			usable, err := evaluateQuadFixedDSMX4(&randomModel, &modelTables, &randomScalars[iteration], &fixture.signs, radixBits, modelOps)
			if err != nil || usable != 1 {
				t.Fatalf("radix %d iteration %d model=(%d,%v)", 1<<radixBits, iteration, usable, err)
			}
			randomModelPoint := randomModel.reduced()
			randomModelEncodings[iteration] = randomModelPoint.Bytes()
			if !bytes.Equal(randomModelEncodings[iteration][:], randomWant.Bytes()) {
				t.Fatalf("radix %d iteration %d model/reference mismatch", 1<<radixBits, iteration)
			}
		}

		if !ExperimentalIFMAAvailable() {
			continue
		}
		hardwareOps := quadDSMOperationsX4{hardware: true}
		var hardwareTables [DSMTerms]quadSignedCachedTableX4
		if err := buildQuadSignedCachedTableX4(&hardwareTables[0], &fixture.b, radixBits, hardwareOps); err != nil {
			t.Fatal(err)
		}
		if err := buildQuadSignedCachedTableX4(&hardwareTables[1], &fixture.a, radixBits, hardwareOps); err != nil {
			t.Fatal(err)
		}
		var hardware quadPackedPointX4
		usable, err = evaluateQuadFixedDSMX4(&hardware, &hardwareTables, &fixture.scalars, &fixture.signs, radixBits, hardwareOps)
		if err != nil || usable != 1 {
			t.Fatalf("radix %d hardware evaluate=(%d,%v)", 1<<radixBits, usable, err)
		}
		hardwarePoint := hardware.reduced()
		hardwareEncoding := hardwarePoint.Bytes()
		if hardwareEncoding != modelEncoding {
			t.Fatalf("radix %d hardware/model mismatch", 1<<radixBits)
		}

		// Compare with the existing one-active-signature-lane DSM using the
		// identical bases, scalars, exact negative mask, and radix.
		current := evaluateCurrentOneLaneDSMForQuadTest(t, &fixture, radixBits)
		currentEncoding := current.Bytes()
		if !bytes.Equal(currentEncoding[:], want.Bytes()) {
			t.Fatalf("radix %d current/reference mismatch", 1<<radixBits)
		}

		for iteration := range randomScalars {
			var randomHardware quadPackedPointX4
			usable, err = evaluateQuadFixedDSMX4(&randomHardware, &hardwareTables, &randomScalars[iteration], &fixture.signs, radixBits, hardwareOps)
			if err != nil || usable != 1 {
				t.Fatalf("radix %d iteration %d hardware=(%d,%v)", 1<<radixBits, iteration, usable, err)
			}
			randomHardwarePoint := randomHardware.reduced()
			if randomHardwarePoint.Bytes() != randomModelEncodings[iteration] {
				t.Fatalf("radix %d iteration %d hardware/model mismatch", 1<<radixBits, iteration)
			}
		}
	}

	// Make the torsion discriminator explicit: [L-k]A is not [-k]A for the
	// mixed-order A selected above.
	order := signedMagnitudeToBig(NewSignedMagnitude(scalarOrderBytes[:], false))
	k := signedMagnitudeToBig(NewSignedMagnitude(fixture.scalars[1][0][:], false))
	wrongCoefficient := new(big.Int).Sub(order, k)
	s := signedMagnitudeToBig(NewSignedMagnitude(fixture.scalars[0][0][:], false))
	wrong := edwardsref.NewIdentityPoint()
	wrong.Add(wrong, exactReferenceIntegerMult(fixture.bRef, s))
	wrong.Add(wrong, exactReferenceIntegerMult(fixture.aRef, wrongCoefficient))
	if bytes.Equal(wrong.Bytes(), want.Bytes()) {
		t.Fatal("mixed-order fixture failed to distinguish exact -k from L-k")
	}
}

func evaluateCurrentOneLaneDSMForQuadTest(t *testing.T, fixture *quadDSMFixtureX4, radixBits uint) Point {
	t.Helper()
	pointsB := [X4Lanes]Point{fixture.b, *NewIdentityPoint(), *NewIdentityPoint(), *NewIdentityPoint()}
	pointsA := [X4Lanes]Point{fixture.a, *NewIdentityPoint(), *NewIdentityPoint(), *NewIdentityPoint()}
	var baseB, baseA PointX4
	baseB.SetPoints(&pointsB)
	baseA.SetPoints(&pointsA)
	var loose IFMAPointX4
	switch radixBits {
	case 5:
		var workspace ExperimentalIFMAFixedDSMWorkspaceX4
		if err := workspace.PrepareFixedBase(&baseB, radixBits); err != nil {
			t.Fatal(err)
		}
		if err := workspace.PrepareVariableBase(&baseA); err != nil {
			t.Fatal(err)
		}
		if usable, err := workspace.Evaluate(&loose, &fixture.scalars, &fixture.signs, 1); err != nil || usable != 1 {
			t.Fatalf("current radix 32 evaluate=(%d,%v)", usable, err)
		}
	case 6:
		var workspace ExperimentalIFMAFixedDSMWorkspaceRadix64X4
		if err := workspace.PrepareFixedBase(&baseB, radixBits); err != nil {
			t.Fatal(err)
		}
		if err := workspace.PrepareVariableBase(&baseA); err != nil {
			t.Fatal(err)
		}
		if usable, err := workspace.Evaluate(&loose, &fixture.scalars, &fixture.signs, 1); err != nil || usable != 1 {
			t.Fatalf("current radix 64 evaluate=(%d,%v)", usable, err)
		}
	default:
		t.Fatalf("unsupported radix %d", radixBits)
	}
	reduced := loose.Reduced()
	return reduced.Lane(0)
}

func TestExperimentalCoordinateParallelFixedDSMX4ZeroAllocations(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("AVX-512 IFMA is unavailable")
	}
	fixture := newQuadDSMFixtureX4(t)
	ops := quadDSMOperationsX4{hardware: true}
	for _, radixBits := range []uint{5, 6} {
		var tables [DSMTerms]quadSignedCachedTableX4
		if err := buildQuadSignedCachedTableX4(&tables[0], &fixture.b, radixBits, ops); err != nil {
			t.Fatal(err)
		}
		if err := buildQuadSignedCachedTableX4(&tables[1], &fixture.a, radixBits, ops); err != nil {
			t.Fatal(err)
		}
		var out quadPackedPointX4
		if allocs := testing.AllocsPerRun(20, func() {
			if _, err := evaluateQuadFixedDSMX4(&out, &tables, &fixture.scalars, &fixture.signs, radixBits, ops); err != nil {
				panic(err)
			}
		}); allocs != 0 {
			t.Fatalf("radix %d prepared allocations=%v want 0", 1<<radixBits, allocs)
		}
		if allocs := testing.AllocsPerRun(20, func() {
			if err := buildQuadSignedCachedTableX4(&tables[1], &fixture.a, radixBits, ops); err != nil {
				panic(err)
			}
			if _, err := evaluateQuadFixedDSMX4(&out, &tables, &fixture.scalars, &fixture.signs, radixBits, ops); err != nil {
				panic(err)
			}
		}); allocs != 0 {
			t.Fatalf("radix %d cold allocations=%v want 0", 1<<radixBits, allocs)
		}
	}
}

var (
	benchmarkQuadDSMPointSink    quadPackedPointX4
	benchmarkCurrentDSMPointSink IFMAPointX4
	benchmarkQuadDSMTableSink    quadSignedCachedTableX4
)

func BenchmarkExperimentalCoordinateParallelFixedDSMX4(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skip("AVX-512 IFMA is unavailable")
	}
	fixture := newQuadDSMFixtureX4(b)
	ops := quadDSMOperationsX4{hardware: true}
	for _, radixBits := range []uint{5, 6} {
		entries := regularRadixEntries(radixBits)
		name := fmt.Sprintf("radix=%d", 1<<radixBits)
		var quadTables [DSMTerms]quadSignedCachedTableX4
		if err := buildQuadSignedCachedTableX4(&quadTables[0], &fixture.b, radixBits, ops); err != nil {
			b.Fatal(err)
		}
		if err := buildQuadSignedCachedTableX4(&quadTables[1], &fixture.a, radixBits, ops); err != nil {
			b.Fatal(err)
		}

		b.Run("stage=prepared/path=quad/"+name, func(b *testing.B) {
			var out quadPackedPointX4
			b.ReportAllocs()
			b.ReportMetric(float64(2*entries*int(unsafe.Sizeof(quadPackedCachedPointX4{}))), "logical-table-B/base")
			b.ReportMetric(float64(unsafe.Sizeof(quadSignedCachedTableX4{})), "physical-table-B/base")
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				if _, err := evaluateQuadFixedDSMX4(&out, &quadTables, &fixture.scalars, &fixture.signs, radixBits, ops); err != nil {
					b.Fatal(err)
				}
			}
			benchmarkQuadDSMPointSink = out
		})

		benchmarkCurrentOneLaneDSM(b, &fixture, radixBits, name)

		b.Run("stage=cold-A/path=quad/"+name, func(b *testing.B) {
			var out quadPackedPointX4
			var coldA quadSignedCachedTableX4
			tables := [DSMTerms]quadSignedCachedTableX4{quadTables[0], coldA}
			b.ReportAllocs()
			b.ReportMetric(float64(2*entries*int(unsafe.Sizeof(quadPackedCachedPointX4{}))), "logical-A-table-B")
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				if err := buildQuadSignedCachedTableX4(&tables[1], &fixture.a, radixBits, ops); err != nil {
					b.Fatal(err)
				}
				if _, err := evaluateQuadFixedDSMX4(&out, &tables, &fixture.scalars, &fixture.signs, radixBits, ops); err != nil {
					b.Fatal(err)
				}
			}
			benchmarkQuadDSMPointSink = out
			benchmarkQuadDSMTableSink = tables[1]
		})
	}
}

func benchmarkCurrentOneLaneDSM(b *testing.B, fixture *quadDSMFixtureX4, radixBits uint, name string) {
	b.Helper()
	pointsB := [X4Lanes]Point{fixture.b, *NewIdentityPoint(), *NewIdentityPoint(), *NewIdentityPoint()}
	pointsA := [X4Lanes]Point{fixture.a, *NewIdentityPoint(), *NewIdentityPoint(), *NewIdentityPoint()}
	var baseB, baseA PointX4
	baseB.SetPoints(&pointsB)
	baseA.SetPoints(&pointsA)
	b.Run("stage=prepared/path=current-one-active-lane/"+name, func(b *testing.B) {
		var out IFMAPointX4
		b.ReportAllocs()
		switch radixBits {
		case 5:
			var workspace ExperimentalIFMAFixedDSMWorkspaceX4
			if err := workspace.PrepareFixedBase(&baseB, radixBits); err != nil {
				b.Fatal(err)
			}
			if err := workspace.PrepareVariableBase(&baseA); err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				if _, err := workspace.Evaluate(&out, &fixture.scalars, &fixture.signs, 1); err != nil {
					b.Fatal(err)
				}
			}
		case 6:
			var workspace ExperimentalIFMAFixedDSMWorkspaceRadix64X4
			if err := workspace.PrepareFixedBase(&baseB, radixBits); err != nil {
				b.Fatal(err)
			}
			if err := workspace.PrepareVariableBase(&baseA); err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				if _, err := workspace.Evaluate(&out, &fixture.scalars, &fixture.signs, 1); err != nil {
					b.Fatal(err)
				}
			}
		default:
			b.Fatalf("unsupported radix %d", radixBits)
		}
		benchmarkCurrentDSMPointSink = out
	})
}
