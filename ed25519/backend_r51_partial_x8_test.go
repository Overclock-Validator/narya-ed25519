package ed25519

import (
	"fmt"
	"testing"
)

func requireR51IFMAPartialX8TailPipeline(tb testing.TB) *r51IFMABatchQPipeline {
	tb.Helper()
	pipeline := requireR51IFMABatchQX4NielsPipeline(tb)
	pipeline.experimentalPartialX8Tail = true
	return pipeline
}

func requireR51IFMAWideHashX4TailPipeline(tb testing.TB) *r51IFMABatchQPipeline {
	tb.Helper()
	pipeline := requireR51IFMABatchQX4NielsPipeline(tb)
	pipeline.wideHashX4Tail = true
	return pipeline
}

func assertR51IFMATailCandidateVectors(t *testing.T, vectors []r51ReferenceVector, profile Profile, factory func(testing.TB) *r51IFMABatchQPipeline) {
	t.Helper()
	pipeline := factory(t)
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

	got := make([]bool, len(vectors))
	gotAll, err := pipeline.VerifyBatch(profile, pubs, msgs, sigs, got)
	if err != nil {
		t.Fatal(err)
	}
	if gotAll != wantAll {
		t.Fatalf("aggregate=%v want=%v profile=%d count=%d", gotAll, wantAll, profile, len(vectors))
	}
	for lane := range got {
		if got[lane] != want[lane] {
			t.Fatalf("lane=%d got=%v want=%v profile=%d count=%d", lane, got[lane], want[lane], profile, len(vectors))
		}
	}
}

func TestR51IFMAPartialX8TailCompletePipelineDifferential(t *testing.T) {
	mixture := makeR51HonestVectors(t, 17)
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
	mixture[16] = makeR51MixedOrderValidVector(t)

	for _, candidate := range []struct {
		name    string
		factory func(testing.TB) *r51IFMABatchQPipeline
	}{
		{name: "partial-x8", factory: requireR51IFMAPartialX8TailPipeline},
		{name: "x4-wide-hash", factory: requireR51IFMAWideHashX4TailPipeline},
	} {
		for _, profile := range []Profile{DalekStrict, StdlibCompat} {
			for _, count := range []int{4, 5, 6, 7, 12, 13, 14, 15, 17} {
				count := count
				t.Run(fmt.Sprintf("path=%s/profile=%d/mixture/n=%d", candidate.name, profile, count), func(t *testing.T) {
					assertR51IFMATailCandidateVectors(t, mixture[:count], profile, candidate.factory)
				})
			}
		}
	}
}

func TestR51IFMATailWidthCandidatesCompletePipelineZeroAllocations(t *testing.T) {
	for _, candidate := range []struct {
		name    string
		factory func(testing.TB) *r51IFMABatchQPipeline
	}{
		{name: "partial-x8", factory: requireR51IFMAPartialX8TailPipeline},
		{name: "x4-wide-hash", factory: requireR51IFMAWideHashX4TailPipeline},
	} {
		for _, count := range []int{4, 5, 7, 12, 15, 64} {
			pipeline := candidate.factory(t)
			fixture := makeBatchFixture(t, count, 1232)
			if allocs := testing.AllocsPerRun(10, func() {
				all, err := pipeline.VerifyBatch(DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok)
				if err != nil || !all {
					panic(fmt.Sprintf("verify=(%v,%v)", all, err))
				}
			}); allocs != 0 {
				t.Fatalf("path=%s count=%d allocations=%v", candidate.name, count, allocs)
			}
		}
	}
}

func BenchmarkR51IFMAPartialX8TailCompletePipeline(b *testing.B) {
	for _, messageSize := range []int{200, 1232, 4096} {
		for _, count := range []int{2, 4} {
			fixture := makeBatchFixture(b, count, messageSize)
			for _, candidate := range []struct {
				name     string
				pipeline func(testing.TB) *r51IFMABatchQPipeline
			}{
				{name: "x4", pipeline: requireR51IFMABatchQX4NielsPipeline},
				{name: "x4-wide-hash", pipeline: requireR51IFMAWideHashX4TailPipeline},
				{name: "partial-x8", pipeline: requireR51IFMAPartialX8TailPipeline},
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
					b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*count)/1000, "us/signature")
				})
			}
		}
	}
}
