package ed25519

import (
	"fmt"
	"testing"
)

func requireR51IFMAX8BatchEncodePipeline(tb testing.TB) *r51IFMABatchQPipeline {
	tb.Helper()
	pipeline := requireR51IFMABatchQRawSquarePipeline(tb)
	pipeline.experimentalBatchEncodeX8 = true
	return pipeline
}

func assertR51IFMAX8BatchEncodeVectors(t *testing.T, vectors []r51ReferenceVector, profile Profile) {
	t.Helper()
	pipeline := requireR51IFMAX8BatchEncodePipeline(t)
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

func TestR51IFMAX8BatchEncodeCompletePipelineDifferential(t *testing.T) {
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
		for _, count := range []int{1, 2, 4, 8, 9, 16, 17, 64, 65} {
			count := count
			t.Run(fmt.Sprintf("profile=%d/n=%d", profile, count), func(t *testing.T) {
				assertR51IFMAX8BatchEncodeVectors(t, mixture[:count], profile)
			})
		}
	}
}

func TestR51IFMAX8BatchEncodeCompletePipelineZeroAllocations(t *testing.T) {
	pipeline := requireR51IFMAX8BatchEncodePipeline(t)
	for _, count := range []int{1, 4, 8, 9, 64, 65} {
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

func TestR51IFMAX8BatchEncodeDispatchThreshold(t *testing.T) {
	pipeline := requireR51IFMAX8BatchEncodePipeline(t)
	for _, test := range []struct {
		count      int
		wantDirect bool
	}{
		{count: r51BatchEncodeX8MinCount - 1, wantDirect: false},
		{count: r51BatchEncodeX8MinCount, wantDirect: true},
	} {
		fixture := makeBatchFixture(t, test.count, 1232)
		all, err := pipeline.VerifyBatch(DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok)
		if err != nil || !all {
			t.Fatalf("count=%d verify=(%v,%v)", test.count, all, err)
		}
		if got := pipeline.directX8 != 0; got != test.wantDirect {
			t.Fatalf("count=%d direct-x8=%v want=%v mask=%#x", test.count, got, test.wantDirect, pipeline.directX8)
		}
	}
}

func BenchmarkR51IFMAX8BatchEncodeCompletePipeline(b *testing.B) {
	for _, messageSize := range []int{200, 1232, 4096} {
		for _, count := range []int{8, 16, 32, 64} {
			fixture := makeBatchFixture(b, count, messageSize)
			for _, candidate := range []struct {
				name     string
				pipeline func(testing.TB) *r51IFMABatchQPipeline
			}{
				{name: "x4-encode", pipeline: requireR51IFMABatchQRawSquarePipeline},
				{name: "x8-encode", pipeline: requireR51IFMAX8BatchEncodePipeline},
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
					for range b.N {
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
