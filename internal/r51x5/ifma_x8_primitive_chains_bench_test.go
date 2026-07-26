package r51x5

import (
	"runtime"
	"testing"
)

// benchmarkIFMAX8PrimitiveChainSink keeps every dependency-chain result
// observable without adding work to the timed loop.
var benchmarkIFMAX8PrimitiveChainSink [4]LimbsX8

// BenchmarkIFMAX8PrimitiveChains separates the latency of one dependent Zen 5
// ZMM multiply-normalize chain from the throughput of four independent chains.
// The complete verifier profile attributes roughly one third of its cycles to
// this exact fused primitive, so these two bounds decide whether rescheduling
// the kernel can help or whether the remaining cost is algorithmic.
func BenchmarkIFMAX8PrimitiveChains(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	b.Run("multiply-normalized/latency-dependent", benchmarkIFMAX8MultiplyNormalizedDependent)
	b.Run("multiply-normalized/throughput-independent-4", benchmarkIFMAX8MultiplyNormalizedIndependent4)
	b.Run("square-normalized-via-multiply/latency-dependent", benchmarkIFMAX8SquareNormalizedDependent)
	b.Run("square-normalized-via-multiply/throughput-independent-4", benchmarkIFMAX8SquareNormalizedIndependent4)
}

func benchmarkIFMAX8MultiplyNormalizedDependent(b *testing.B) {
	states := [4]LimbsX8{benchmarkIFMAX8ComposableInput(0x51_8101)}
	factor := benchmarkIFMAX8ComposableInput(0x51_8201)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ifmaMulNormalizedUncheckedX8(&states[0], &states[0], &factor)
	}
	benchmarkIFMAX8Finish(b, &states, 1)
}

func benchmarkIFMAX8MultiplyNormalizedIndependent4(b *testing.B) {
	states := [4]LimbsX8{
		benchmarkIFMAX8ComposableInput(0x51_8111),
		benchmarkIFMAX8ComposableInput(0x51_8112),
		benchmarkIFMAX8ComposableInput(0x51_8113),
		benchmarkIFMAX8ComposableInput(0x51_8114),
	}
	factors := [4]LimbsX8{
		benchmarkIFMAX8ComposableInput(0x51_8211),
		benchmarkIFMAX8ComposableInput(0x51_8212),
		benchmarkIFMAX8ComposableInput(0x51_8213),
		benchmarkIFMAX8ComposableInput(0x51_8214),
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ifmaMulNormalizedUncheckedX8(&states[0], &states[0], &factors[0])
		ifmaMulNormalizedUncheckedX8(&states[1], &states[1], &factors[1])
		ifmaMulNormalizedUncheckedX8(&states[2], &states[2], &factors[2])
		ifmaMulNormalizedUncheckedX8(&states[3], &states[3], &factors[3])
	}
	benchmarkIFMAX8Finish(b, &states, 4)
}

func benchmarkIFMAX8SquareNormalizedDependent(b *testing.B) {
	states := [4]LimbsX8{benchmarkIFMAX8ComposableInput(0x51_8301)}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ifmaMulNormalizedUncheckedX8(&states[0], &states[0], &states[0])
	}
	benchmarkIFMAX8Finish(b, &states, 1)
}

func benchmarkIFMAX8SquareNormalizedIndependent4(b *testing.B) {
	states := [4]LimbsX8{
		benchmarkIFMAX8ComposableInput(0x51_8311),
		benchmarkIFMAX8ComposableInput(0x51_8312),
		benchmarkIFMAX8ComposableInput(0x51_8313),
		benchmarkIFMAX8ComposableInput(0x51_8314),
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ifmaMulNormalizedUncheckedX8(&states[0], &states[0], &states[0])
		ifmaMulNormalizedUncheckedX8(&states[1], &states[1], &states[1])
		ifmaMulNormalizedUncheckedX8(&states[2], &states[2], &states[2])
		ifmaMulNormalizedUncheckedX8(&states[3], &states[3], &states[3])
	}
	benchmarkIFMAX8Finish(b, &states, 4)
}

func benchmarkIFMAX8Finish(b *testing.B, states *[4]LimbsX8, chains int) {
	b.StopTimer()
	benchmarkIFMAX8PrimitiveChainSink = *states
	if chains > 1 {
		b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*chains), "ns/primitive")
	}
}

func benchmarkIFMAX8ComposableInput(seed uint64) LimbsX8 {
	const inputMask = uint64(1)<<50 - 1
	var out LimbsX8
	for limb := range out {
		for lane := range out[limb] {
			value := seed + uint64(limb+1)*0x9e37_79b9 + uint64(lane+1)*0x7f4a_7c15
			value ^= value << 17
			value ^= value >> 23
			out[limb][lane] = value&inputMask | 1
		}
	}
	return out
}
