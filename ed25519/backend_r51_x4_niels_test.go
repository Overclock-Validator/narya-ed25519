package ed25519

import (
	"fmt"
	"testing"
)

func requireR51IFMABatchQX4NielsPipeline(tb testing.TB) *r51IFMABatchQPipeline {
	tb.Helper()
	pipeline := requireR51IFMABatchQX8CombPipeline(tb)
	pipeline.experimentalProjectiveNielsX4 = true
	return pipeline
}

func assertR51IFMAX4NielsVectors(t *testing.T, vectors []r51ReferenceVector, profile Profile) {
	t.Helper()
	pipeline := requireR51IFMABatchQX4NielsPipeline(t)
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
			t.Fatalf("lane=%d got=%v want=%v profile=%d", lane, got[lane], want[lane], profile)
		}
	}
}

func TestR51IFMAX4NielsCompletePipelineDifferential(t *testing.T) {
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

	for _, profile := range []Profile{DalekStrict, StdlibCompat} {
		t.Run(fmt.Sprintf("profile=%d/cctv", profile), func(t *testing.T) {
			assertR51IFMAX4NielsVectors(t, r51CCTVVectors(t), profile)
		})
		t.Run(fmt.Sprintf("profile=%d/wycheproof", profile), func(t *testing.T) {
			assertR51IFMAX4NielsVectors(t, r51WycheproofVectors(t), profile)
		})
		for _, count := range []int{4, 5, 7, 12, 13, 17} {
			count := count
			t.Run(fmt.Sprintf("profile=%d/mixture/n=%d", profile, count), func(t *testing.T) {
				assertR51IFMAX4NielsVectors(t, mixture[:count], profile)
			})
		}
	}
}

func TestR51IFMAX4NielsCompletePipelineZeroAllocations(t *testing.T) {
	pipeline := requireR51IFMABatchQX4NielsPipeline(t)
	for _, count := range []int{4, 12, 64} {
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

// BenchmarkR51IFMAX4NielsCompletePipeline changes only the n=4 cold A table
// representation and mixed-add evaluator. The x8 path, fixed-base comb,
// hashing, decoding, and finalizer remain identical between both arms.
func BenchmarkR51IFMAX4NielsCompletePipeline(b *testing.B) {
	for _, messageSize := range []int{200, 1232, 4096} {
		fixture := makeBatchFixture(b, 4, messageSize)
		for _, candidate := range []struct {
			name     string
			pipeline func(testing.TB) *r51IFMABatchQPipeline
		}{
			{name: "extended", pipeline: requireR51IFMABatchQX8CombPipeline},
			{name: "projective-niels", pipeline: requireR51IFMABatchQX4NielsPipeline},
		} {
			candidate := candidate
			b.Run(fmt.Sprintf("path=%s/n=4/msg=%d", candidate.name, messageSize), func(b *testing.B) {
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
				b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*4)/1000, "µs/sig")
			})
		}
	}
}
