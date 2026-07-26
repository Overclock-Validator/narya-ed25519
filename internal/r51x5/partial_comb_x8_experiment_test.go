package r51x5

import (
	"fmt"
	"math/rand"
	"testing"

	edwardsref "github.com/Overclock-Validator/narya-ed25519/internal/edwards25519"
)

// newPartialCombX8BasesExperiment returns eight distinct bases with mixed
// torsion, reusing the same construction the x4 correctness fixture uses so the
// two evaluators are compared over the same class of inputs.
func newPartialCombX8BasesExperiment(t *testing.T, rng *rand.Rand) (PointX8, Point) {
	t.Helper()
	torsion := referenceTorsionPoints(t)

	var aTorsion [X8Lanes]*edwardsref.Point
	for lane := range aTorsion {
		aTorsion[lane] = torsion[(lane+1)%X8Lanes]
	}
	_, aX8 := scalarWindowMixedBasesX8(t, rng, &aTorsion)
	aX8 = randomProjectiveScaleX8(t, rng, &aX8)

	bRef := new(edwardsref.Point).Add(edwardsref.NewGeneratorPoint(), torsion[3])
	var bEncoded [32]byte
	copy(bEncoded[:], bRef.Bytes())
	var bPoint Point
	if _, err := bPoint.SetBytes(bEncoded[:]); err != nil {
		t.Fatal(err)
	}
	return aX8, bPoint
}

func randomPartialCombScalarX8Experiment(rng *rand.Rand) [32]byte {
	for {
		var out [32]byte
		for i := 0; i < 32; i++ {
			out[i] = byte(rng.Intn(256))
		}
		out[31] &= 0x0f
		if canonicalScalarBytes(&out) {
			return out
		}
	}
}

// The eight-lane partial-comb evaluator must produce exactly what the shipping
// four-lane one produces. That is the whole claim: a warm group of eight is
// currently two sequential x4 groups, and replacing it with one x8 group must
// change throughput and nothing else.
//
// Comparing against the x4 evaluator rather than against a scalar reference is
// deliberate. The x4 path is what runs in production today, so an agreement
// failure here is exactly a behaviour change, whichever of the two is wrong.
func TestHeterogeneousPartialCombX8MatchesTwoX4Experiment(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("requires AVX-512 IFMA target")
	}

	rng := rand.New(rand.NewSource(20260726))
	for round := 0; round < 8; round++ {
		t.Run(fmt.Sprintf("round=%d", round), func(t *testing.T) {
			bases, bPoint := newPartialCombX8BasesExperiment(t, rng)

			aTablesX8 := buildHeterogeneousPartialCombATablesX8Experiment(&bases, heterogeneousPartialCombA6R9Experiment)
			var aTablesX4 [2][X4Lanes]*heterogeneousPartialCombTableExperiment
			for half := 0; half < 2; half++ {
				for lane := 0; lane < X4Lanes; lane++ {
					aTablesX4[half][lane] = aTablesX8[half*X4Lanes+lane]
				}
			}

			bTable := buildHeterogeneousPartialCombPreSignedSharedTableExperiment(
				buildHeterogeneousPartialCombTableExperiment(&bPoint, heterogeneousPartialCombB10R5Experiment),
			)

			var scalarsX8 FixedDSMScalarsX8
			for term := 0; term < DSMTerms; term++ {
				for lane := 0; lane < X8Lanes; lane++ {
					scalarsX8[term][lane] = randomPartialCombScalarX8Experiment(rng)
				}
			}
			// Term 1 carries the negation, matching the verifier's [s]B+[-k]A.
			negativeMasks := [DSMTerms]uint8{0, 0xff}

			// Sweep the active mask so partial groups and skipped lanes are
			// covered, not only the all-live case.
			for _, active := range []uint8{0xff, 0x0f, 0xf0, 0b10110101, 0b00000001, 0b10000000, 0} {
				var gotX8 IFMAPointX8
				usableX8, err := evaluateHeterogeneousPartialCombPreSignedBDSMX8Experiment(
					&gotX8, &aTablesX8, bTable, &scalarsX8, &negativeMasks, active,
				)
				if err != nil {
					t.Fatalf("active=%#x: x8 evaluate: %v", active, err)
				}

				var wantHalves [2]IFMAPointX4
				var usableX4 uint8
				for half := 0; half < 2; half++ {
					var scalarsX4 FixedDSMScalarsX4
					for term := 0; term < DSMTerms; term++ {
						for lane := 0; lane < X4Lanes; lane++ {
							scalarsX4[term][lane] = scalarsX8[term][half*X4Lanes+lane]
						}
					}
					halfActive := uint8(active>>(half*X4Lanes)) & 0x0f
					halfNegative := [DSMTerms]uint8{
						negativeMasks[0] >> (half * X4Lanes) & 0x0f,
						negativeMasks[1] >> (half * X4Lanes) & 0x0f,
					}
					usable, err := evaluateHeterogeneousPartialCombPreSignedBDSMX4Experiment(
						&wantHalves[half], &aTablesX4[half], bTable, &scalarsX4, &halfNegative, halfActive,
					)
					if err != nil {
						t.Fatalf("active=%#x half=%d: x4 evaluate: %v", active, half, err)
					}
					usableX4 |= usable << (half * X4Lanes)
				}

				if usableX8 != usableX4 {
					t.Fatalf("active=%#x: usable x8=%#x x4=%#x", active, usableX8, usableX4)
				}
				if usableX8 == 0 {
					continue
				}

				gotReduced := gotX8.Reduced()
				for half := 0; half < 2; half++ {
					wantReduced := wantHalves[half].Reduced()
					for lane := 0; lane < X4Lanes; lane++ {
						index := half*X4Lanes + lane
						if usableX8&(1<<index) == 0 {
							continue
						}
						got := gotReduced.Lane(index)
						want := wantReduced.Lane(lane)
						if got.Equal(&want) != 1 {
							t.Fatalf("active=%#x lane=%d: x8 result differs from the shipping x4 result", active, index)
						}
					}
				}
			}
		})
	}
}

// A lane skipped by the caller keeps a nil table. The x8 selector must survive
// that for the same reason the x4 one must: the position is the batch index
// modulo the group width, so an attacker chooses it.
func TestHeterogeneousPartialCombX8SurvivesNilLanesExperiment(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("requires AVX-512 IFMA target")
	}

	rng := rand.New(rand.NewSource(7))
	bases, bPoint := newPartialCombX8BasesExperiment(t, rng)
	full := buildHeterogeneousPartialCombATablesX8Experiment(&bases, heterogeneousPartialCombA6R9Experiment)
	bTable := buildHeterogeneousPartialCombPreSignedSharedTableExperiment(
		buildHeterogeneousPartialCombTableExperiment(&bPoint, heterogeneousPartialCombB10R5Experiment),
	)

	var scalars FixedDSMScalarsX8
	for term := 0; term < DSMTerms; term++ {
		for lane := 0; lane < X8Lanes; lane++ {
			scalars[term][lane] = randomPartialCombScalarX8Experiment(rng)
		}
	}
	negativeMasks := [DSMTerms]uint8{0, 0xff}

	for dead := 0; dead < X8Lanes; dead++ {
		tables := full
		tables[dead] = nil
		active := uint8(0xff) &^ (1 << dead)

		var out IFMAPointX8
		usable, err := evaluateHeterogeneousPartialCombPreSignedBDSMX8Experiment(
			&out, &tables, bTable, &scalars, &negativeMasks, active,
		)
		if err != nil {
			t.Fatalf("dead=%d: %v", dead, err)
		}
		if usable&(1<<dead) != 0 {
			t.Fatalf("dead=%d: skipped lane reported usable", dead)
		}
		if usable != active {
			t.Fatalf("dead=%d: usable=%#x want %#x", dead, usable, active)
		}
	}

	// Every lane dead is an empty group, not a fault.
	var none [X8Lanes]*heterogeneousPartialCombTableExperiment
	var out IFMAPointX8
	usable, err := evaluateHeterogeneousPartialCombPreSignedBDSMX8Experiment(
		&out, &none, bTable, &scalars, &negativeMasks, 0xff,
	)
	if err != nil {
		t.Fatalf("all-nil: %v", err)
	}
	if usable != 0 {
		t.Fatalf("all-nil: usable=%#x want 0", usable)
	}
}

// BenchmarkHeterogeneousPartialCombX8VersusTwoX4Experiment is the gate for
// replacing a paired warm x4 group with one x8 group.
//
// It measures the whole evaluator, not a single kernel: the exponent loop, all
// doublings, both comb passes and the recoding are inside. That makes it a much
// stronger signal than a component gate, and the two-chain ZMM result is the
// reason to care about the difference — there a positive component gate turned
// into a 66% loop regression.
//
// It is still an upper bound on the complete-verifier gain. Hashing, decoding,
// promotion and finalization are outside this loop and do not widen, so the
// end-to-end improvement will be smaller than whatever this shows.
func BenchmarkHeterogeneousPartialCombX8VersusTwoX4Experiment(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skip("requires AVX-512 IFMA target")
	}
	t := &testing.T{}
	rng := rand.New(rand.NewSource(20260726))
	bases, bPoint := newPartialCombX8BasesExperiment(t, rng)
	if t.Failed() {
		b.Fatal("fixture construction failed")
	}

	aTablesX8 := buildHeterogeneousPartialCombATablesX8Experiment(&bases, heterogeneousPartialCombA6R9Experiment)
	var aTablesX4 [2][X4Lanes]*heterogeneousPartialCombTableExperiment
	for half := 0; half < 2; half++ {
		for lane := 0; lane < X4Lanes; lane++ {
			aTablesX4[half][lane] = aTablesX8[half*X4Lanes+lane]
		}
	}
	bTable := buildHeterogeneousPartialCombPreSignedSharedTableExperiment(
		buildHeterogeneousPartialCombTableExperiment(&bPoint, heterogeneousPartialCombB10R5Experiment),
	)

	var scalarsX8 FixedDSMScalarsX8
	for term := 0; term < DSMTerms; term++ {
		for lane := 0; lane < X8Lanes; lane++ {
			scalarsX8[term][lane] = randomPartialCombScalarX8Experiment(rng)
		}
	}
	var scalarsX4 [2]FixedDSMScalarsX4
	for half := 0; half < 2; half++ {
		for term := 0; term < DSMTerms; term++ {
			for lane := 0; lane < X4Lanes; lane++ {
				scalarsX4[half][term][lane] = scalarsX8[term][half*X4Lanes+lane]
			}
		}
	}
	negativeX8 := [DSMTerms]uint8{0, 0xff}
	negativeX4 := [DSMTerms]uint8{0, 0x0f}

	// Both rows verify the same eight signatures, so ns/signature is directly
	// comparable and is the number the dispatch decision turns on.
	b.Run("one-x8-group", func(b *testing.B) {
		var out IFMAPointX8
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := evaluateHeterogeneousPartialCombPreSignedBDSMX8Experiment(
				&out, &aTablesX8, bTable, &scalarsX8, &negativeX8, 0xff,
			); err != nil {
				b.Fatal(err)
			}
		}
		b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*X8Lanes), "ns/signature")
	})

	b.Run("two-x4-groups", func(b *testing.B) {
		var out [2]IFMAPointX4
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for half := 0; half < 2; half++ {
				if _, err := evaluateHeterogeneousPartialCombPreSignedBDSMX4Experiment(
					&out[half], &aTablesX4[half], bTable, &scalarsX4[half], &negativeX4, 0x0f,
				); err != nil {
					b.Fatal(err)
				}
			}
		}
		b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*X8Lanes), "ns/signature")
	})
}
