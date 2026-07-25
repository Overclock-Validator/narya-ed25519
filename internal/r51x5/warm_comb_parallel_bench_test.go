package r51x5

import (
	"crypto/sha512"
	"fmt"
	"runtime"
	"sync/atomic"
	"testing"
)

var warmCombParallelMatrixSink uint64

// BenchmarkWarmCombParallelMatrix measures the warm-key partial comb across
// batch widths and message sizes under parallel worker pressure, so warm
// numbers can be compared directly against the cold pipeline at Solana's
// largest transaction size.
//
// The existing parallel warm benchmark pins itself to one batch width and
// msg=200, which cannot be lined up against cold-path measurements at 1232.
//
// Shape follows BenchmarkHeterogeneousPartialCombCompleteStrictParallelExperiment:
// the prepared A tables and shared fixed-B table are process-wide and immutable,
// while each worker owns its hash state, scalar scratch, points and encoder.
//
// Table preparation happens OUTSIDE the timed region, so these numbers are the
// 100%-cache-hit ceiling. They exclude the ~13.05us/key table build; a key must
// be seen about twice before caching beats verifying it cold.
//
// n=4 is the floor: the verifier requires a positive multiple of X4Lanes, so a
// warm n=1 does not exist.
func BenchmarkWarmCombParallelMatrix(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skip("requires AVX-512 IFMA target")
	}
	shape := heterogeneousPartialCombCompleteDistinctKeysExperiment
	candidate := heterogeneousPartialCombCompleteB10Experiment

	for _, messageSize := range []int{200, 1232} {
		for _, count := range []int{4, 8, 64} {
			inputs := makeHeterogeneousPartialCombCompleteInputsExperiment(b, count, messageSize, shape)
			prepared := newHeterogeneousPartialCombCompleteVerifierExperiment(b, inputs)

			name := fmt.Sprintf("warm-A6r9-B10r5/n=%d/msg=%d", count, messageSize)
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
							panic("r51x5: parallel warm comb rejected honest signatures")
						}
					}
					if all {
						atomic.AddUint64(&warmCombParallelMatrixSink, 1)
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
