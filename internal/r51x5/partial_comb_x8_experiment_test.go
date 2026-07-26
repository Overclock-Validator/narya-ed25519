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

// BenchmarkWarmCombX8ComponentsExperiment decomposes the x8 warm evaluator into
// the three operations its loop actually performs, so the gap between their sum
// and the complete evaluator is measured rather than assumed.
//
// The shape is fixed by the specs: A6/r9 contributes 43 digits over an online
// depth of 48, B10/r5 contributes 26 digits over a depth of 40, so one group is
// 47 doublings, 43 A selections and adds, and 26 B selections and adds.
func BenchmarkWarmCombX8ComponentsExperiment(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skip("requires AVX-512 IFMA target")
	}
	t := &testing.T{}
	rng := rand.New(rand.NewSource(20260726))
	bases, bPoint := newPartialCombX8BasesExperiment(t, rng)
	if t.Failed() {
		b.Fatal("fixture construction failed")
	}
	aTables := buildHeterogeneousPartialCombATablesX8Experiment(&bases, heterogeneousPartialCombA6R9Experiment)
	bTable := buildHeterogeneousPartialCombPreSignedSharedTableExperiment(
		buildHeterogeneousPartialCombTableExperiment(&bPoint, heterogeneousPartialCombB10R5Experiment),
	)

	// A round every lane contributes to, with magnitudes spread across the row
	// so the gather is not a single hot entry.
	makeRound := func(entries int) asymmetricFixedBRoundX8 {
		var round asymmetricFixedBRoundX8
		round.NonzeroMask = 0xff
		round.NegativeMask = 0b10101010
		for lane := 0; lane < X8Lanes; lane++ {
			round.Magnitude[lane] = uint16(1 + (lane*entries)/X8Lanes)
		}
		return round
	}
	aRound := makeRound(heterogeneousPartialCombA6R9Experiment.entriesPerRow())
	bRound := makeRound(heterogeneousPartialCombB10R5Experiment.entriesPerRow())

	acc := identityIFMAPointX8Value()
	var cached fixedBaseIFMACachedX8
	selectHeterogeneousPartialCombPerKeyX8Experiment(&cached, &aTables, 0, &aRound, 0xff)

	b.Run("double", func(b *testing.B) {
		point := acc
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := ifmaPointDoubleComposableStaticX8(&point, &point); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("cached-add", func(b *testing.B) {
		point := acc
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := addFixedBaseIFMACachedX8(&point, &point, &cached); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("select-A-perkey", func(b *testing.B) {
		var out fixedBaseIFMACachedX8
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			selectHeterogeneousPartialCombPerKeyX8Experiment(&out, &aTables, i%5, &aRound, 0xff)
		}
	})

	b.Run("select-B-shared", func(b *testing.B) {
		var out fixedBaseIFMACachedX8
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			selectHeterogeneousPartialCombPreSignedSharedX8Experiment(&out, bTable, i%6, &bRound, 0xff)
		}
	})

	b.Run("recode-only", func(b *testing.B) {
		var scalars [X8Lanes][32]byte
		for lane := range scalars {
			scalars[lane] = randomPartialCombScalarX8Experiment(rng)
		}
		var digits asymmetricFixedBDigitsX8
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			recodeAsymmetricFixedBScalarsX8(&digits, &scalars, 0xff, 0xff, 6)
		}
	})
}

// BenchmarkWarmCombX8ShapeSweepExperiment measures the speed/memory frontier of
// the comb shape.
//
// The passes count is a uniquely clean lever here. Digit count depends only on
// the window width, so changing passes leaves the number of additions untouched
// and moves only the online depth (width*(passes-1)) and the table size. Fewer
// passes therefore buys doublings with per-key bytes and nothing else, and
// per-key bytes are cache capacity.
//
// B is a single process-wide table, so its rows are far cheaper than A's. Both
// sides are swept because the loop runs to max(depthA, depthB): shrinking one
// alone stops helping as soon as the other dominates.
func BenchmarkWarmCombX8ShapeSweepExperiment(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skip("requires AVX-512 IFMA target")
	}
	t := &testing.T{}
	rng := rand.New(rand.NewSource(20260726))
	bases, bPoint := newPartialCombX8BasesExperiment(t, rng)
	if t.Failed() {
		b.Fatal("fixture construction failed")
	}

	var scalars FixedDSMScalarsX8
	for term := 0; term < DSMTerms; term++ {
		for lane := 0; lane < X8Lanes; lane++ {
			scalars[term][lane] = randomPartialCombScalarX8Experiment(rng)
		}
	}
	negative := [DSMTerms]uint8{0, 0xff}

	for _, shape := range []struct {
		aPasses, bPasses int
	}{
		{9, 5}, // current
		{7, 5},
		{5, 5},
		{5, 3},
		{4, 3},
		{3, 3},
		{3, 2},
		{2, 2},
		{2, 1},
		{1, 1},
	} {
		aSpec := heterogeneousPartialCombSpecExperiment{width: 6, passes: shape.aPasses}
		bSpec := heterogeneousPartialCombSpecExperiment{width: 10, passes: shape.bPasses}
		depth := aSpec.onlineDepth()
		if bSpec.onlineDepth() > depth {
			depth = bSpec.onlineDepth()
		}
		perKey := aSpec.rowCount() * aSpec.entriesPerRow() * 120

		name := fmt.Sprintf("A6r%d-B10r%d/depth=%d/keyKiB=%d", shape.aPasses, shape.bPasses, depth, perKey>>10)
		b.Run(name, func(b *testing.B) {
			aTables := buildHeterogeneousPartialCombATablesX8Experiment(&bases, aSpec)
			bTable := buildHeterogeneousPartialCombPreSignedSharedTableExperiment(
				buildHeterogeneousPartialCombTableExperiment(&bPoint, bSpec),
			)
			var out IFMAPointX8
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := evaluateHeterogeneousPartialCombPreSignedBDSMX8Experiment(
					&out, &aTables, bTable, &scalars, &negative, 0xff,
				); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*X8Lanes), "ns/signature")
			b.ReportMetric(float64(perKey), "B/key")
		})
	}
}

// BenchmarkWarmCombX8WorkingSetExperiment measures what a larger cache budget
// costs the hits it already had.
//
// Raising MaxTableBytes is usually discussed as buying hit rate. It also
// changes the cost of every hit, because the per-key tables stop fitting in
// cache. This sweeps the number of distinct promoted keys, cycling groups
// through the whole pool so each group touches tables the previous ones evicted,
// and reports nanoseconds per signature against the resident table bytes.
//
// The relevant boundaries on the measured host are 48 KiB of L1d and 1 MiB of
// L2 per core, and 32 MiB of shared L3. One group of eight A6/r9 tables is
// 150 KiB on its own.
func BenchmarkWarmCombX8WorkingSetExperiment(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skip("requires AVX-512 IFMA target")
	}
	t := &testing.T{}
	rng := rand.New(rand.NewSource(20260726))
	_, bPoint := newPartialCombX8BasesExperiment(t, rng)
	if t.Failed() {
		b.Fatal("fixture construction failed")
	}
	bTable := buildHeterogeneousPartialCombPreSignedSharedTableExperiment(
		buildHeterogeneousPartialCombTableExperiment(&bPoint, heterogeneousPartialCombB10R5Experiment),
	)

	var scalars FixedDSMScalarsX8
	for term := 0; term < DSMTerms; term++ {
		for lane := 0; lane < X8Lanes; lane++ {
			scalars[term][lane] = randomPartialCombScalarX8Experiment(rng)
		}
	}
	negative := [DSMTerms]uint8{0, 0xff}
	spec := heterogeneousPartialCombA6R9Experiment
	perKey := spec.rowCount() * spec.entriesPerRow() * 120

	for _, keys := range []int{8, 64, 256, 1024, 2048, 4096} {
		resident := keys * perKey
		name := fmt.Sprintf("keys=%d/MiB=%d", keys, resident>>20)
		b.Run(name, func(b *testing.B) {
			// Distinct bases so every key owns a genuinely different table
			// rather than a shared allocation the cache would keep hot.
			pool := make([]*heterogeneousPartialCombTableExperiment, keys)
			base := bPoint
			for i := range pool {
				pool[i] = buildHeterogeneousPartialCombTableExperiment(&base, spec)
				fixedBasePointAdd(&base, &base, &bPoint)
			}

			var group [X8Lanes]*heterogeneousPartialCombTableExperiment
			var out IFMAPointX8
			cursor := 0
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				for lane := 0; lane < X8Lanes; lane++ {
					group[lane] = pool[cursor]
					cursor++
					if cursor == len(pool) {
						cursor = 0
					}
				}
				if _, err := evaluateHeterogeneousPartialCombPreSignedBDSMX8Experiment(
					&out, &group, bTable, &scalars, &negative, 0xff,
				); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*X8Lanes), "ns/signature")
			b.ReportMetric(float64(resident)/(1<<20), "MiB-resident")
		})
	}
}
