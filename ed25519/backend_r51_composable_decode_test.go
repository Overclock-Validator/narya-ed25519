package ed25519

import (
	"fmt"
	"testing"
)

func requireR51IFMABatchQX8ComposableDecodePipeline(tb testing.TB) *r51IFMABatchQPipeline {
	tb.Helper()
	pipeline := requireR51IFMABatchQX8CombPipeline(tb)
	pipeline.experimentalComposableDecodeX8 = true
	return pipeline
}

func assertR51IFMAComposableDecodeVectors(t *testing.T, vectors []r51ReferenceVector, profile Profile) {
	t.Helper()
	pipeline := requireR51IFMABatchQX8ComposableDecodePipeline(t)
	baseline := requireR51IFMABatchQX8CombPipeline(t)
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

	for _, candidate := range []struct {
		name     string
		pipeline *r51IFMABatchQPipeline
	}{
		{name: "reduced-and-import", pipeline: baseline},
		{name: "composable", pipeline: pipeline},
	} {
		got := make([]bool, len(vectors))
		gotAll, err := candidate.pipeline.VerifyBatch(profile, pubs, msgs, sigs, got)
		if err != nil {
			t.Fatalf("%s: %v", candidate.name, err)
		}
		if gotAll != wantAll {
			t.Fatalf("%s aggregate=%v want=%v profile=%d count=%d", candidate.name, gotAll, wantAll, profile, len(vectors))
		}
		for lane := range got {
			if got[lane] != want[lane] {
				t.Fatalf("%s lane=%d got=%v want=%v profile=%d", candidate.name, lane, got[lane], want[lane], profile)
			}
		}
	}
}

func TestR51IFMAComposableDecodeCompletePipelineDifferential(t *testing.T) {
	mixture := makeR51HonestVectors(t, 65)
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
			assertR51IFMAComposableDecodeVectors(t, r51CCTVVectors(t), profile)
		})
		t.Run(fmt.Sprintf("profile=%d/wycheproof", profile), func(t *testing.T) {
			assertR51IFMAComposableDecodeVectors(t, r51WycheproofVectors(t), profile)
		})
		for _, count := range []int{8, 9, 16, 17, 64, 65} {
			count := count
			t.Run(fmt.Sprintf("profile=%d/mixture/n=%d", profile, count), func(t *testing.T) {
				assertR51IFMAComposableDecodeVectors(t, mixture[:count], profile)
			})
		}
	}
}

func TestR51IFMAComposableDecodeInvalidPublicKeyEveryX8Lane(t *testing.T) {
	vectors := makeR51HonestVectors(t, 8)
	invalid := findR51InvalidEncoding(t)
	for lane := range vectors {
		mutated := cloneR51Vectors(vectors)
		mutated[lane].pub = invalid
		t.Run(fmt.Sprintf("lane=%d", lane), func(t *testing.T) {
			assertR51IFMAComposableDecodeVectors(t, mutated, DalekStrict)
		})
	}
}

func TestR51IFMAComposableDecodeCompletePipelineZeroAllocations(t *testing.T) {
	pipeline := requireR51IFMABatchQX8ComposableDecodePipeline(t)
	for _, count := range []int{8, 64, 65} {
		fixture := makeBatchFixture(t, count, 1232)
		if allocs := testing.AllocsPerRun(10, func() {
			all, err := pipeline.VerifyBatch(DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok)
			if err != nil || !all {
				panic(fmt.Sprintf("verify=(%v,%v)", all, err))
			}
		}); allocs != 0 {
			t.Fatalf("count=%d allocations=%v", count, allocs)
		}
	}
}

// BenchmarkR51IFMAComposableDecodeCompletePipeline measures only the x8 cold
// representation handoff. The baseline reduces decoded A to scalar r51 limbs
// and imports it again during table preparation; the candidate retains the
// decoder's u52 IFMA form. Both use the same strict predicate, hash, DSM, and
// batch-Q finalizer. This is a regime-tagged experiment until Zen 5 shows a
// complete-verifier improvement with zero allocation or predicate changes.
func BenchmarkR51IFMAComposableDecodeCompletePipeline(b *testing.B) {
	for _, messageSize := range []int{200, 1232} {
		for _, count := range []int{8, 64} {
			fixture := makeBatchFixture(b, count, messageSize)
			for _, candidate := range []struct {
				name     string
				pipeline func(testing.TB) *r51IFMABatchQPipeline
			}{
				{name: "reduced-and-import", pipeline: requireR51IFMABatchQX8CombPipeline},
				{name: "composable", pipeline: requireR51IFMABatchQX8ComposableDecodePipeline},
			} {
				candidate := candidate
				b.Run(fmt.Sprintf("path=%s/n=%d/msg=%d", candidate.name, count, messageSize), func(b *testing.B) {
					pipeline := candidate.pipeline(b)
					all, err := pipeline.VerifyBatch(DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok)
					if err != nil || !all {
						b.Fatalf("preflight=(%v,%v)", all, err)
					}
					b.ReportAllocs()
					b.ResetTimer()
					for iteration := 0; iteration < b.N; iteration++ {
						all, err = pipeline.VerifyBatch(DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok)
						if err != nil {
							b.Fatal(err)
						}
					}
					benchmarkR51IFMAPipelineResult = all
					b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*count)/1000, "µs/sig")
				})
			}
		}
	}
}
