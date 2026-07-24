package ed25519

import (
	"errors"
	"fmt"
	"runtime"
	"testing"
	"unsafe"
)

func requireR51IFMABatchQPipeline(t testing.TB) *r51IFMABatchQPipeline {
	t.Helper()
	if !r51IFMAPipelineAvailable(r51IFMATwoX4) {
		t.Skipf("forced two-x4 r51 IFMA batch-Q pipeline unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	pipeline, err := newR51IFMABatchQPipeline()
	if err != nil {
		t.Fatalf("new forced two-x4 radix-64 batch-Q pipeline: %v", err)
	}
	return pipeline
}

func assertR51IFMABatchQVectors(t *testing.T, batchQ, paired, literal *r51IFMABatchQPipelineSet, vectors []r51ReferenceVector, profile Profile) {
	t.Helper()
	pubs := make([]*[32]byte, len(vectors))
	msgs := make([][]byte, len(vectors))
	sigs := make([][]byte, len(vectors))
	want := make([]bool, len(vectors))
	wantAll := true
	for index := range vectors {
		pubs[index], msgs[index], sigs[index] = &vectors[index].pub, vectors[index].msg, vectors[index].sig
		want[index] = referenceVerifyProfile(profile, pubs[index], msgs[index], sigs[index])
		wantAll = wantAll && want[index]
	}

	sets := []*r51IFMABatchQPipelineSet{batchQ, paired, literal}
	for _, set := range sets {
		got := make([]bool, len(vectors))
		gotAll, err := set.verify(profile, pubs, msgs, sigs, got)
		if err != nil {
			t.Fatalf("%s: %v", set.name, err)
		}
		if gotAll != wantAll {
			t.Fatalf("%s aggregate=%v want=%v profile=%d count=%d", set.name, gotAll, wantAll, profile, len(vectors))
		}
		for index := range got {
			if got[index] != want[index] {
				t.Fatalf("%s lane=%d got=%v want=%v profile=%d\npub=%x\nmsg=%x\nsig=%x", set.name, index, got[index], want[index], profile, vectors[index].pub, vectors[index].msg, vectors[index].sig)
			}
		}
	}
}

// r51IFMABatchQPipelineSet gives one concrete call shape to the three complete
// verifier variants in differential tests without adding an interface to the
// timed implementation.
type r51IFMABatchQPipelineSet struct {
	name     string
	batchQ   *r51IFMABatchQPipeline
	ordinary *r51IFMAPipeline
}

func (set *r51IFMABatchQPipelineSet) verify(profile Profile, pubs []*[32]byte, msgs, sigs [][]byte, ok []bool) (bool, error) {
	if set.batchQ != nil {
		return set.batchQ.VerifyBatch(profile, pubs, msgs, sigs, ok)
	}
	return set.ordinary.VerifyBatch(profile, pubs, msgs, sigs, ok)
}

func newR51IFMABatchQPipelineSets(t testing.TB) (batchQ, paired, literal *r51IFMABatchQPipelineSet) {
	t.Helper()
	return &r51IFMABatchQPipelineSet{
			name:   "single-A/cross-group-batch-Q",
			batchQ: requireR51IFMABatchQPipeline(t),
		}, &r51IFMABatchQPipelineSet{
			name:     "paired-AR/projective",
			ordinary: requireR51IFMAPipeline(t, r51IFMATwoX4, 6),
		}, &r51IFMABatchQPipelineSet{
			name:     "single-A/per-x4-literal-Q",
			ordinary: requireR51IFMAEncodedQReferencePipeline(t, r51IFMATwoX4, 6),
		}
}

func TestR51IFMABatchQPipelineDifferential(t *testing.T) {
	batchQ, paired, literal := newR51IFMABatchQPipelineSets(t)

	mixture := makeR51HonestVectors(t, 67)
	for index := range mixture {
		switch index % 7 {
		case 1:
			mixture[index].msg[0] ^= 0x80
		case 2:
			mixture[index].sig[7] ^= 0x20
		case 3:
			mixture[index].sig[63] |= 0xe0
		case 4:
			mixture[index].pub[11] ^= 0x08
		}
	}
	mixture[63] = makeR51MixedOrderValidVector(t)

	for _, profile := range []Profile{DalekStrict, StdlibCompat} {
		t.Run(fmt.Sprintf("profile=%d/cctv", profile), func(t *testing.T) {
			assertR51IFMABatchQVectors(t, batchQ, paired, literal, r51CCTVVectors(t), profile)
		})
		t.Run(fmt.Sprintf("profile=%d/wycheproof", profile), func(t *testing.T) {
			assertR51IFMABatchQVectors(t, batchQ, paired, literal, r51WycheproofVectors(t), profile)
		})
		for _, count := range []int{1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 32, 63, 64, 65, 67} {
			count := count
			t.Run(fmt.Sprintf("profile=%d/mixture/n=%d", profile, count), func(t *testing.T) {
				assertR51IFMABatchQVectors(t, batchQ, paired, literal, mixture[:count], profile)
			})
		}
	}
}

func TestR51IFMABatchQPipelineFiredancerFuzzRegressions(t *testing.T) {
	batchQ, paired, literal := newR51IFMABatchQPipelineSets(t)
	vectors := repeatFiredancerFuzzRegressionVectors(t, 17)
	for _, profile := range []Profile{DalekStrict, StdlibCompat} {
		assertR51IFMABatchQVectors(t, batchQ, paired, literal, vectors, profile)
	}
}

func TestR51IFMABatchQPipelineEveryLaneAndTailMapping(t *testing.T) {
	batchQ, paired, literal := newR51IFMABatchQPipelineSets(t)
	honest := makeR51HonestVectors(t, 64)
	for _, count := range []int{1, 4, 8, 9, 16, 17, 32, 64} {
		for lane := 0; lane < count; lane++ {
			invalid := cloneR51Vectors(honest[:count])
			invalid[lane].msg[0] ^= 0x80
			t.Run(fmt.Sprintf("n=%d/lane=%d", count, lane), func(t *testing.T) {
				assertR51IFMABatchQVectors(t, batchQ, paired, literal, invalid, DalekStrict)
			})
		}
	}
}

func TestR51IFMABatchQPipelineKernelErrorClearsPriorChunkVerdicts(t *testing.T) {
	pipeline := requireR51IFMABatchQPipeline(t)
	failure := errors.New("injected second-chunk batch-encoding failure")
	encodeCalls := 0
	pipeline.beforeBatchEncode = func() error {
		encodeCalls++
		if encodeCalls == 2 {
			return failure
		}
		return nil
	}

	fixture := makeBatchFixture(t, 65, 200)
	for index := range fixture.ok {
		fixture.ok[index] = true
	}
	all, err := pipeline.VerifyBatch(DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok)
	if all || !errors.Is(err, failure) {
		t.Fatalf("verification=(%v,%v), want (false,injected failure)", all, err)
	}
	if encodeCalls != 2 {
		t.Fatalf("batch encodes=%d, want 2", encodeCalls)
	}
	for lane, accepted := range fixture.ok {
		if accepted {
			t.Fatalf("lane %d retained a verdict after later-chunk failure", lane)
		}
	}
}

func TestR51IFMABatchQPipelineZeroAllocations(t *testing.T) {
	pipeline := requireR51IFMABatchQPipeline(t)
	for _, count := range []int{1, 4, 8, 16, 32, 64, 65} {
		fixture := makeBatchFixture(t, count, 200)
		if allocs := testing.AllocsPerRun(10, func() {
			all, err := pipeline.VerifyBatch(DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok)
			if err != nil || !all {
				panic(fmt.Sprintf("verify=(%v,%v)", all, err))
			}
		}); allocs != 0 {
			t.Fatalf("count=%d allocations=%v", count, allocs)
		}
	}

	invalid := makeBatchFixture(t, 64, 200)
	for _, lane := range []int{0, 3, 4, 7, 8, 15, 16, 31, 32, 63} {
		invalid.sigs[lane] = append([]byte(nil), invalid.sigs[lane]...)
		invalid.sigs[lane][63] |= 0xe0
	}
	if allocs := testing.AllocsPerRun(10, func() {
		if _, err := pipeline.VerifyBatch(DalekStrict, invalid.pubs, invalid.msgs, invalid.sigs, invalid.ok); err != nil {
			panic(err)
		}
	}); allocs != 0 {
		t.Fatalf("sparse-invalid allocations=%v", allocs)
	}
}

// BenchmarkR51IFMABatchQGate measures the complete-path tradeoff at the
// actual candidate radix. The batch-Q row crosses all x4 groups in a chunk;
// the literal row encodes each x4 group independently and remains the byte-
// predicate oracle; the paired row is the current strict baseline.
func BenchmarkR51IFMABatchQGate(b *testing.B) {
	for _, messageSize := range []int{64, 200, 1232} {
		for _, count := range []int{1, 4, 8, 16, 32, 64} {
			fixture := makeBatchFixture(b, count, messageSize)
			b.Run(fmt.Sprintf("decode=paired-AR/final=projective/path=two-x4/radixA=64/n=%d/msg=%d", count, messageSize), func(b *testing.B) {
				benchmarkR51IFMABatchQOrdinary(b, requireR51IFMAPipeline(b, r51IFMATwoX4, 6), &fixture, count)
			})
			b.Run(fmt.Sprintf("decode=single-A/final=literal-per-x4/path=two-x4/radixA=64/n=%d/msg=%d", count, messageSize), func(b *testing.B) {
				benchmarkR51IFMABatchQOrdinary(b, requireR51IFMAEncodedQReferencePipeline(b, r51IFMATwoX4, 6), &fixture, count)
			})
			b.Run(fmt.Sprintf("decode=single-A/final=batch-Q/path=two-x4/radixA=64/n=%d/msg=%d", count, messageSize), func(b *testing.B) {
				pipeline := requireR51IFMABatchQPipeline(b)
				b.ReportAllocs()
				b.ResetTimer()
				var result bool
				for iteration := 0; iteration < b.N; iteration++ {
					var err error
					result, err = pipeline.VerifyBatch(DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok)
					if err != nil {
						b.Fatal(err)
					}
				}
				benchmarkR51IFMAPipelineResult = result
				b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*count)/1000, "µs/sig")
			})
		}
	}
}

func benchmarkR51IFMABatchQOrdinary(b *testing.B, pipeline *r51IFMAPipeline, fixture *batchFixture, count int) {
	b.Helper()
	b.ReportAllocs()
	b.ResetTimer()
	var result bool
	for iteration := 0; iteration < b.N; iteration++ {
		var err error
		result, err = pipeline.VerifyBatch(DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok)
		if err != nil {
			b.Fatal(err)
		}
	}
	benchmarkR51IFMAPipelineResult = result
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*count)/1000, "µs/sig")
}

// BenchmarkR51IFMABatchQParallel compares independent per-worker workspaces at
// the caller's GOMAXPROCS. Run it separately at 1/2/4/8/16 so each row sees
// the intended core and cache pressure. The read-only fixture is shared.
func BenchmarkR51IFMABatchQParallel(b *testing.B) {
	type workerState struct {
		batchQ *r51IFMABatchQPipeline
		paired *r51IFMAPipeline
		ok     []bool
		result bool
		err    error
		used   bool
	}

	const count = 64
	fixture := makeBatchFixture(b, count, 200)
	workers := runtime.GOMAXPROCS(0)
	for _, useBatchQ := range []bool{false, true} {
		final := "paired-AR-projective"
		if useBatchQ {
			final = "single-A-batch-Q"
		}
		b.Run(fmt.Sprintf("workers=%d/final=%s/n=64/msg=200", workers, final), func(b *testing.B) {
			states := make([]workerState, workers)
			available := make(chan *workerState, workers)
			for index := range states {
				if useBatchQ {
					states[index].batchQ = requireR51IFMABatchQPipeline(b)
				} else {
					states[index].paired = requireR51IFMAPipeline(b, r51IFMATwoX4, 6)
				}
				states[index].ok = make([]bool, count)
				available <- &states[index]
			}

			b.ReportAllocs()
			b.SetParallelism(1)
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				state := <-available
				for pb.Next() {
					state.used = true
					if useBatchQ {
						state.result, state.err = state.batchQ.VerifyBatch(DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, state.ok)
					} else {
						state.result, state.err = state.paired.VerifyBatch(DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, state.ok)
					}
					if state.err != nil {
						break
					}
				}
				available <- state
			})
			b.StopTimer()

			result := true
			for range states {
				state := <-available
				if state.err != nil {
					b.Fatal(state.err)
				}
				if state.used && !state.result {
					b.Fatal("parallel r51 batch-Q gate rejected a valid fixture")
				}
				result = result && (!state.used || state.result)
			}
			benchmarkR51IFMAPipelineResult = result
			elapsed := b.Elapsed()
			b.ReportMetric(float64(b.N*count)/elapsed.Seconds(), "sig/s")
			b.ReportMetric(float64(elapsed.Nanoseconds())/float64(b.N*count)/1000, "µs/sig")
			if useBatchQ {
				var pipeline r51IFMABatchQPipeline
				scratchBytes := unsafe.Sizeof(pipeline.encoder) + unsafe.Sizeof(pipeline.points) +
					unsafe.Sizeof(pipeline.active) + unsafe.Sizeof(pipeline.encoded)
				b.ReportMetric(float64(scratchBytes), "batch-scratch-B/worker")
			}
		})
	}
}
