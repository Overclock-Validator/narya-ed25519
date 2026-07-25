package r51x5

import (
	stded25519 "crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"
	"runtime"
	"sync/atomic"
	"testing"
)

// This file holds the fixtures, correctness gates and benchmarks for the
// heterogeneous warm-key comb. The verifier itself now lives in
// partial_comb_verify.go so the registered backend can reach it; automatic
// dispatch still does not select it.

// newHeterogeneousPartialCombCompleteVerifierExperiment adapts the production
// constructor to testing.TB, so the tests and benchmarks below keep their
// original call shape. Unavailable hardware skips; anything else is fatal.
func newHeterogeneousPartialCombCompleteVerifierExperiment(
	tb testing.TB,
	inputs []heterogeneousPartialCombCompleteInputExperiment,
) *heterogeneousPartialCombCompleteVerifierExperiment {
	tb.Helper()
	verifier, err := newHeterogeneousPartialCombCompleteVerifier(inputs)
	if errors.Is(err, errPartialCombUnavailable) {
		tb.Skip("requires AVX-512 IFMA target")
	}
	if err != nil {
		tb.Fatal(err)
	}
	return verifier
}

func makeHeterogeneousPartialCombCompleteInputsExperiment(
	tb testing.TB,
	count, messageSize int,
	shape heterogeneousPartialCombCompleteKeyShapeExperiment,
) []heterogeneousPartialCombCompleteInputExperiment {
	tb.Helper()
	keyCount := count
	switch shape {
	case heterogeneousPartialCombCompleteDistinctKeysExperiment:
	case heterogeneousPartialCombCompleteFourKeyCycleExperiment:
		keyCount = X4Lanes
	case heterogeneousPartialCombCompleteSameKeyExperiment:
		keyCount = 1
	default:
		panic("r51x5: unknown complete warm-comb key shape")
	}
	publicKeys := make([]stded25519.PublicKey, keyCount)
	privateKeys := make([]stded25519.PrivateKey, keyCount)
	for index := 0; index < keyCount; index++ {
		public, private, err := stded25519.GenerateKey(rand.Reader)
		if err != nil {
			tb.Fatal(err)
		}
		publicKeys[index], privateKeys[index] = public, private
	}
	inputs := make([]heterogeneousPartialCombCompleteInputExperiment, count)
	for index := range inputs {
		keyIndex := index % keyCount
		copy(inputs[index].pub[:], publicKeys[keyIndex])
		inputs[index].message = make([]byte, messageSize)
		if _, err := rand.Read(inputs[index].message); err != nil {
			tb.Fatal(err)
		}
		inputs[index].signature = stded25519.Sign(privateKeys[keyIndex], inputs[index].message)
	}
	return inputs
}

func assertHeterogeneousPartialCombCompleteMatchesPackedExperiment(
	t *testing.T,
	name string,
	inputs []heterogeneousPartialCombCompleteInputExperiment,
) {
	t.Helper()
	verifier := newHeterogeneousPartialCombCompleteVerifierExperiment(t, inputs)
	want := make([]bool, len(inputs))
	packed, err := NewExperimentalPackedStrictVerifierX4()
	if err != nil {
		t.Fatal(err)
	}
	for index := range inputs {
		want[index], err = packed.Verify(&inputs[index].pub, inputs[index].message, inputs[index].signature)
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, candidate := range []heterogeneousPartialCombCompleteCandidateExperiment{
		heterogeneousPartialCombCompleteRegularExperiment,
		heterogeneousPartialCombCompleteB8Experiment,
		heterogeneousPartialCombCompleteB10Experiment,
	} {
		got := make([]bool, len(inputs))
		all, err := verifier.Verify(candidate, inputs, got)
		if err != nil {
			t.Fatalf("%s/%s: %v", name, candidate, err)
		}
		wantAll := true
		for index := range want {
			wantAll = wantAll && want[index]
			if got[index] != want[index] {
				t.Fatalf("%s/%s input=%d got=%v want=%v", name, candidate, index, got[index], want[index])
			}
		}
		if all != wantAll {
			t.Fatalf("%s/%s all=%v want=%v", name, candidate, all, wantAll)
		}
	}
}

func TestHeterogeneousPartialCombCompleteStrictDifferentialExperiment(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("requires AVX-512 IFMA target")
	}

	honest := makeHeterogeneousPartialCombCompleteInputsExperiment(
		t, X4Lanes, 200, heterogeneousPartialCombCompleteDistinctKeysExperiment,
	)
	assertHeterogeneousPartialCombCompleteMatchesPackedExperiment(t, "honest", honest)

	mutated := append([]heterogeneousPartialCombCompleteInputExperiment(nil), honest...)
	mutated[1].message = append([]byte(nil), honest[1].message...)
	mutated[1].message[len(mutated[1].message)/2] ^= 1
	mutated[2].signature = append([]byte(nil), honest[2].signature...)
	mutated[2].signature[9] ^= 0x40
	assertHeterogeneousPartialCombCompleteMatchesPackedExperiment(t, "independent-invalid-lanes", mutated)

	malformedLengths := append([]heterogeneousPartialCombCompleteInputExperiment(nil), honest...)
	for lane, length := range []int{0, 31, 32, 63} {
		malformedLengths[lane].signature = append([]byte(nil), honest[lane].signature[:length]...)
	}
	assertHeterogeneousPartialCombCompleteMatchesPackedExperiment(t, "short-signatures", malformedLengths)
	longSignature := append([]heterogeneousPartialCombCompleteInputExperiment(nil), honest...)
	longSignature[0].signature = append(append([]byte(nil), honest[0].signature...), 0)
	assertHeterogeneousPartialCombCompleteMatchesPackedExperiment(t, "long-signature", longSignature)

	mixedPub, mixedMessage, mixedSignature := quadPairedRMixedOrderValidVectorX4(t)
	mixed := make([]heterogeneousPartialCombCompleteInputExperiment, X4Lanes)
	for lane := range mixed {
		mixed[lane] = heterogeneousPartialCombCompleteInputExperiment{
			pub: mixedPub, message: mixedMessage, signature: mixedSignature,
		}
	}
	assertHeterogeneousPartialCombCompleteMatchesPackedExperiment(t, "mixed-order-valid", mixed)

	// Dalek strict deliberately permits a noncanonical decodable A. The
	// signature belongs to another key, so the equation rejects, but successful
	// preparation proves the rejection is not an accidental canonical-A gate.
	noncanonical := append([]heterogeneousPartialCombCompleteInputExperiment(nil), honest...)
	noncanonical[0].pub = quadPairedRNoncanonicalDecodablePointX4(t)
	assertHeterogeneousPartialCombCompleteMatchesPackedExperiment(t, "noncanonical-decodable-A", noncanonical)
}

func TestHeterogeneousPartialCombCompletePreparedTableReuseExperiment(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("requires AVX-512 IFMA target")
	}
	for _, test := range []struct {
		shape      heterogeneousPartialCombCompleteKeyShapeExperiment
		uniqueKeys int
	}{
		{shape: heterogeneousPartialCombCompleteFourKeyCycleExperiment, uniqueKeys: X4Lanes},
		{shape: heterogeneousPartialCombCompleteSameKeyExperiment, uniqueKeys: 1},
	} {
		inputs := makeHeterogeneousPartialCombCompleteInputsExperiment(t, 8, 200, test.shape)
		verifier := newHeterogeneousPartialCombCompleteVerifierExperiment(t, inputs)
		seenPartial := make(map[*heterogeneousPartialCombTableExperiment]struct{})
		seenRegular := make(map[*ifmaMicroAoSPointEntryExperiment]struct{})
		for group := 0; group < verifier.groups; group++ {
			for lane := 0; lane < X4Lanes; lane++ {
				seenPartial[verifier.prepared[group].tables[lane]] = struct{}{}
				regular := verifier.prepared[group].regular[lane].points
				if len(regular) == 0 {
					t.Fatalf("shape=%s group=%d lane=%d has empty regular table", test.shape, group, lane)
				}
				seenRegular[&regular[0]] = struct{}{}
			}
		}
		if len(seenPartial) != test.uniqueKeys || len(seenRegular) != test.uniqueKeys {
			t.Fatalf("shape=%s unique partial=%d regular=%d want=%d", test.shape, len(seenPartial), len(seenRegular), test.uniqueKeys)
		}
	}
}

func TestHeterogeneousPartialCombCompleteStrictZeroAllocationsExperiment(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("requires AVX-512 IFMA target")
	}
	inputs := makeHeterogeneousPartialCombCompleteInputsExperiment(
		t, X4Lanes, 200, heterogeneousPartialCombCompleteDistinctKeysExperiment,
	)
	verifier := newHeterogeneousPartialCombCompleteVerifierExperiment(t, inputs)
	var ok [X4Lanes]bool
	for _, candidate := range []heterogeneousPartialCombCompleteCandidateExperiment{
		heterogeneousPartialCombCompleteRegularExperiment,
		heterogeneousPartialCombCompleteB8Experiment,
		heterogeneousPartialCombCompleteB10Experiment,
	} {
		allocations := testing.AllocsPerRun(10, func() {
			all, err := verifier.Verify(candidate, inputs, ok[:])
			if err != nil || !all {
				panic("r51x5: complete warm-comb verifier rejected honest signatures")
			}
		})
		if allocations != 0 {
			t.Fatalf("%s allocations=%v want 0", candidate, allocations)
		}
	}
}

var heterogeneousPartialCombCompleteResultSinkExperiment bool
var heterogeneousPartialCombCompleteParallelSinkExperiment uint64

func BenchmarkHeterogeneousPartialCombCompleteStrictExperiment(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skip("requires AVX-512 IFMA target")
	}
	for _, shape := range []heterogeneousPartialCombCompleteKeyShapeExperiment{
		heterogeneousPartialCombCompleteDistinctKeysExperiment,
		heterogeneousPartialCombCompleteFourKeyCycleExperiment,
		heterogeneousPartialCombCompleteSameKeyExperiment,
	} {
		for _, messageSize := range []int{200, 1232} {
			inputs := makeHeterogeneousPartialCombCompleteInputsExperiment(
				b, heterogeneousPartialCombCompleteMaxInputsExperiment, messageSize, shape,
			)
			for _, count := range []int{4, 8, 64} {
				batch := inputs[:count]
				verifier := newHeterogeneousPartialCombCompleteVerifierExperiment(b, batch)
				ok := make([]bool, count)
				for _, candidate := range []heterogeneousPartialCombCompleteCandidateExperiment{
					heterogeneousPartialCombCompleteRegularExperiment,
					heterogeneousPartialCombCompleteB8Experiment,
					heterogeneousPartialCombCompleteB10Experiment,
				} {
					name := fmt.Sprintf("keys=%s/implementation=%s/n=%d/msg=%d", shape, candidate, count, messageSize)
					b.Run(name, func(b *testing.B) {
						b.ReportAllocs()
						b.ResetTimer()
						var all bool
						var err error
						for iteration := 0; iteration < b.N; iteration++ {
							all, err = verifier.Verify(candidate, batch, ok)
							if err != nil || !all {
								b.Fatalf("complete verify=(%v,%v)", all, err)
							}
						}
						heterogeneousPartialCombCompleteResultSinkExperiment = all
						b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*count), "ns/signature")
					})
				}
			}
		}
	}
}

// BenchmarkHeterogeneousPartialCombCompleteStrictParallelExperiment models a
// process-wide immutable warm-key cache under production worker pressure. The
// prepared A tables, exact-key map, and fixed B table are shared; each parallel
// worker owns its hash state, scalar scratch, points, and batch encoder.
func BenchmarkHeterogeneousPartialCombCompleteStrictParallelExperiment(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skip("requires AVX-512 IFMA target")
	}
	const count = heterogeneousPartialCombCompleteMaxInputsExperiment
	for _, shape := range []heterogeneousPartialCombCompleteKeyShapeExperiment{
		heterogeneousPartialCombCompleteDistinctKeysExperiment,
		heterogeneousPartialCombCompleteFourKeyCycleExperiment,
		heterogeneousPartialCombCompleteSameKeyExperiment,
	} {
		inputs := makeHeterogeneousPartialCombCompleteInputsExperiment(b, count, 200, shape)
		prepared := newHeterogeneousPartialCombCompleteVerifierExperiment(b, inputs)
		for _, candidate := range []heterogeneousPartialCombCompleteCandidateExperiment{
			heterogeneousPartialCombCompleteB8Experiment,
			heterogeneousPartialCombCompleteB10Experiment,
		} {
			name := fmt.Sprintf("keys=%s/implementation=%s/n=%d/msg=200", shape, candidate, count)
			b.Run(name, func(b *testing.B) {
				workerCount := runtime.GOMAXPROCS(0)
				workers := make([]heterogeneousPartialCombCompleteVerifierExperiment, workerCount)
				verdicts := make([][]bool, workerCount)
				for index := range workers {
					workers[index] = *prepared
					workers[index].hash = sha512.New()
					workers[index].digest = [sha512.Size]byte{}
					workers[index].wide = [X4Lanes][sha512.Size]byte{}
					workers[index].encoder = ExperimentalIFMABatchEncodeWorkspaceX4{}
					workers[index].points = [ExperimentalIFMABatchEncodeMaxX4Groups]IFMAPointX4{}
					workers[index].active = [ExperimentalIFMABatchEncodeMaxX4Groups]uint8{}
					workers[index].encoded = [ExperimentalIFMABatchEncodeMaxX4Groups][X4Lanes][32]byte{}
					verdicts[index] = make([]bool, count)
				}

				var sequence uint64
				b.ReportAllocs()
				b.SetParallelism(1)
				b.ResetTimer()
				b.RunParallel(func(pb *testing.PB) {
					index := int(atomic.AddUint64(&sequence, 1) - 1)
					if index >= len(workers) {
						panic("r51x5: benchmark created more workers than GOMAXPROCS")
					}
					worker := &workers[index]
					ok := verdicts[index]
					var all bool
					for pb.Next() {
						var err error
						all, err = worker.Verify(candidate, inputs, ok)
						if err != nil || !all {
							panic("r51x5: parallel complete warm-comb verifier rejected honest signatures")
						}
					}
					if all {
						atomic.AddUint64(&heterogeneousPartialCombCompleteParallelSinkExperiment, 1)
					}
				})
				b.StopTimer()
				b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*count), "ns/signature")
				b.ReportMetric(float64(b.N*count)/b.Elapsed().Seconds(), "sig/s")
				b.ReportMetric(float64(workerCount), "workers")
			})
		}
	}
}
