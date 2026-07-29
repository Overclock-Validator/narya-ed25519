package ed25519

import (
	"fmt"
	"testing"
)

func requireR51IFMAProjectiveDoubleX8Pipeline(tb testing.TB) *r51IFMABatchQPipeline {
	tb.Helper()
	pipeline := requireR51IFMABatchQRawSquarePipeline(tb)
	pipeline.experimentalProjectiveDoubleX8 = true
	return pipeline
}

func TestR51IFMAProjectiveDoubleX8CompletePipelineDifferential(t *testing.T) {
	vectors := makeR51HonestVectors(t, 65)
	for index := range vectors {
		switch index % 7 {
		case 1:
			vectors[index].msg[0] ^= 0x80
		case 2:
			vectors[index].sig[7] ^= 0x20
		case 3:
			vectors[index].sig[63] |= 0xe0
		case 4:
			vectors[index].pub[11] ^= 0x08
		}
	}
	vectors[63] = makeR51MixedOrderValidVector(t)

	for _, profile := range []Profile{DalekStrict, StdlibCompat} {
		for _, count := range []int{8, 9, 16, 64, 65} {
			count := count
			t.Run(fmt.Sprintf("profile=%d/n=%d", profile, count), func(t *testing.T) {
				pipeline := requireR51IFMAProjectiveDoubleX8Pipeline(t)
				pubs := make([]*[32]byte, count)
				msgs := make([][]byte, count)
				sigs := make([][]byte, count)
				got := make([]bool, count)
				wantAll := true
				for index := range count {
					pubs[index], msgs[index], sigs[index] = &vectors[index].pub, vectors[index].msg, vectors[index].sig
					wantAll = wantAll && referenceVerifyProfile(profile, pubs[index], msgs[index], sigs[index])
				}
				gotAll, err := pipeline.VerifyBatch(profile, pubs, msgs, sigs, got)
				if err != nil {
					t.Fatal(err)
				}
				if gotAll != wantAll {
					t.Fatalf("aggregate=%v want=%v", gotAll, wantAll)
				}
				for index := range count {
					want := referenceVerifyProfile(profile, pubs[index], msgs[index], sigs[index])
					if got[index] != want {
						t.Fatalf("lane=%d got=%v want=%v", index, got[index], want)
					}
				}
			})
		}
	}
}

func TestR51IFMAProjectiveDoubleX8CompletePipelineZeroAllocations(t *testing.T) {
	pipeline := requireR51IFMAProjectiveDoubleX8Pipeline(t)
	for _, count := range []int{8, 64, 65} {
		fixture := makeBatchFixture(t, count, 1232)
		if allocations := testing.AllocsPerRun(20, func() {
			all, err := pipeline.VerifyBatch(DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok)
			if err != nil || !all {
				panic(fmt.Sprintf("verify=(%v,%v)", all, err))
			}
		}); allocations != 0 {
			t.Fatalf("count=%d allocations=%v", count, allocations)
		}
	}
}

func BenchmarkR51IFMAProjectiveDoubleX8CompletePipeline(b *testing.B) {
	for _, messageSize := range []int{200, 1232, 4096} {
		for _, count := range []int{8, 64} {
			fixture := makeBatchFixture(b, count, messageSize)
			for _, candidate := range []struct {
				name     string
				pipeline func(testing.TB) *r51IFMABatchQPipeline
			}{
				{name: "complete-p3", pipeline: requireR51IFMABatchQRawSquarePipeline},
				{name: "intermediate-p2", pipeline: requireR51IFMAProjectiveDoubleX8Pipeline},
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
					b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*count)/1000, "us/signature")
				})
			}
		}
	}
}
