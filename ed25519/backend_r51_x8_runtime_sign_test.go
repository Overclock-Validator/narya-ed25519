package ed25519

import (
	"fmt"
	"testing"
)

func requireR51IFMABatchQX8RuntimeSignPipeline(tb testing.TB) *r51IFMABatchQPipeline {
	tb.Helper()
	if !r51IFMAPipelineAvailable(r51IFMAX8) {
		tb.Skip("forced x8 r51 IFMA batch-Q pipeline unavailable")
	}
	pipeline, err := newR51IFMABatchQX8RuntimeSignPipelineWithFinalizer(r51IFMABatchQFinalizerLiteral)
	if err != nil {
		tb.Fatalf("new x8 runtime-sign pipeline: %v", err)
	}
	return pipeline
}

func TestR51IFMAX8RuntimeSignDifferential(t *testing.T) {
	control := requireR51IFMABatchQX8CombPipeline(t)
	candidate := requireR51IFMABatchQX8RuntimeSignPipeline(t)
	vectors := makeR51HonestVectors(t, 64)
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
	for _, profile := range []Profile{DalekStrict, StdlibCompat} {
		for _, count := range []int{8, 16, 64} {
			pubs := make([]*[32]byte, count)
			msgs := make([][]byte, count)
			sigs := make([][]byte, count)
			for index := range count {
				pubs[index] = &vectors[index].pub
				msgs[index] = vectors[index].msg
				sigs[index] = vectors[index].sig
			}
			controlOK, candidateOK := make([]bool, count), make([]bool, count)
			controlAll, controlErr := control.VerifyBatch(profile, pubs, msgs, sigs, controlOK)
			candidateAll, candidateErr := candidate.VerifyBatch(profile, pubs, msgs, sigs, candidateOK)
			if controlErr != nil || candidateErr != nil || controlAll != candidateAll {
				t.Fatalf("profile=%d n=%d control=(%v,%v) candidate=(%v,%v)", profile, count, controlAll, controlErr, candidateAll, candidateErr)
			}
			for lane := range count {
				if controlOK[lane] != candidateOK[lane] {
					t.Fatalf("profile=%d n=%d lane=%d control=%v candidate=%v", profile, count, lane, controlOK[lane], candidateOK[lane])
				}
			}
		}
	}
}

func TestR51IFMAX8RuntimeSignZeroAllocations(t *testing.T) {
	fixture := makeBatchFixture(t, 64, 1232)
	pipeline := requireR51IFMABatchQX8RuntimeSignPipeline(t)
	if allocs := testing.AllocsPerRun(10, func() {
		all, err := pipeline.VerifyBatch(DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok)
		if err != nil || !all {
			panic(fmt.Sprintf("verify=(%v,%v)", all, err))
		}
	}); allocs != 0 {
		t.Fatalf("allocations=%v", allocs)
	}
}

func BenchmarkR51IFMAX8RuntimeSignExperiment(b *testing.B) {
	for _, count := range []int{8, 64} {
		fixture := makeBatchFixture(b, count, 1232)
		for _, implementation := range []struct {
			name string
			new  func(testing.TB) *r51IFMABatchQPipeline
		}{
			{name: "pre-signed", new: requireR51IFMABatchQX8CombPipeline},
			{name: "runtime-sign", new: requireR51IFMABatchQX8RuntimeSignPipeline},
		} {
			implementation := implementation
			b.Run(fmt.Sprintf("implementation=%s/n=%d/msg=1232", implementation.name, count), func(b *testing.B) {
				pipeline := implementation.new(b)
				b.ReportAllocs()
				b.ResetTimer()
				var result bool
				for range b.N {
					var err error
					result, err = pipeline.VerifyBatch(DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok)
					if err != nil || !result {
						b.Fatalf("verify=(%v,%v)", result, err)
					}
				}
				benchmarkR51IFMAPipelineResult = result
				b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*count)/1000, "us/signature")
			})
		}
	}
}
