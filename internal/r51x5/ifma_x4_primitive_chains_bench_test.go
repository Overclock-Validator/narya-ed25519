package r51x5

import (
	"runtime"
	"testing"
)

// benchmarkIFMAX4PrimitiveChainSink keeps the final state of every dependency
// chain observable. The assembly calls are side effects in their own right,
// but retaining the states also protects these benchmarks if a Go
// implementation of one of the primitives is introduced later.
var benchmarkIFMAX4PrimitiveChainSink [4]LimbsX4

// BenchmarkIFMAX4PrimitiveChains separates the latency of one dependent x4
// chain from the throughput of four independent x4 chains. Each x4 primitive
// operates on four field elements; "independent-4" therefore keeps four YMM
// primitive calls (sixteen field elements) in flight per benchmark iteration.
//
// The current backend has no dedicated IFMA squaring kernel: its composable
// square is the multiply-and-normalize kernel with both inputs aliased. It also
// exposes addition only as add-and-normalize. The benchmark names make those
// fused costs explicit.
func BenchmarkIFMAX4PrimitiveChains(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	b.Run("multiply-normalized/latency-dependent", benchmarkIFMAX4MultiplyNormalizedDependent)
	b.Run("multiply-normalized/throughput-independent-4", benchmarkIFMAX4MultiplyNormalizedIndependent4)
	b.Run("square-normalized-via-multiply/latency-dependent", benchmarkIFMAX4SquareNormalizedDependent)
	b.Run("square-normalized-via-multiply/throughput-independent-4", benchmarkIFMAX4SquareNormalizedIndependent4)
	b.Run("normalize-u61-to-u52/latency-dependent", benchmarkIFMAX4NormalizeDependent)
	b.Run("normalize-u61-to-u52/throughput-independent-4", benchmarkIFMAX4NormalizeIndependent4)
	b.Run("add-normalized/latency-dependent", benchmarkIFMAX4AddNormalizedDependent)
	b.Run("add-normalized/throughput-independent-4", benchmarkIFMAX4AddNormalizedIndependent4)
}

func benchmarkIFMAX4MultiplyNormalizedDependent(b *testing.B) {
	states := [4]LimbsX4{benchmarkIFMAX4ComposableInput(0x51_1001)}
	factor := benchmarkIFMAX4ComposableInput(0x51_2001)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ifmaMulNormalizedUncheckedX4(&states[0], &states[0], &factor)
	}
	benchmarkIFMAX4Finish(b, &states, 1)
}

func benchmarkIFMAX4MultiplyNormalizedIndependent4(b *testing.B) {
	states := [4]LimbsX4{
		benchmarkIFMAX4ComposableInput(0x51_1101),
		benchmarkIFMAX4ComposableInput(0x51_1102),
		benchmarkIFMAX4ComposableInput(0x51_1103),
		benchmarkIFMAX4ComposableInput(0x51_1104),
	}
	factors := [4]LimbsX4{
		benchmarkIFMAX4ComposableInput(0x51_2101),
		benchmarkIFMAX4ComposableInput(0x51_2102),
		benchmarkIFMAX4ComposableInput(0x51_2103),
		benchmarkIFMAX4ComposableInput(0x51_2104),
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ifmaMulNormalizedUncheckedX4(&states[0], &states[0], &factors[0])
		ifmaMulNormalizedUncheckedX4(&states[1], &states[1], &factors[1])
		ifmaMulNormalizedUncheckedX4(&states[2], &states[2], &factors[2])
		ifmaMulNormalizedUncheckedX4(&states[3], &states[3], &factors[3])
	}
	benchmarkIFMAX4Finish(b, &states, 4)
}

func benchmarkIFMAX4SquareNormalizedDependent(b *testing.B) {
	states := [4]LimbsX4{benchmarkIFMAX4ComposableInput(0x51_3001)}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ifmaMulNormalizedUncheckedX4(&states[0], &states[0], &states[0])
	}
	benchmarkIFMAX4Finish(b, &states, 1)
}

func benchmarkIFMAX4SquareNormalizedIndependent4(b *testing.B) {
	states := [4]LimbsX4{
		benchmarkIFMAX4ComposableInput(0x51_3101),
		benchmarkIFMAX4ComposableInput(0x51_3102),
		benchmarkIFMAX4ComposableInput(0x51_3103),
		benchmarkIFMAX4ComposableInput(0x51_3104),
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ifmaMulNormalizedUncheckedX4(&states[0], &states[0], &states[0])
		ifmaMulNormalizedUncheckedX4(&states[1], &states[1], &states[1])
		ifmaMulNormalizedUncheckedX4(&states[2], &states[2], &states[2])
		ifmaMulNormalizedUncheckedX4(&states[3], &states[3], &states[3])
	}
	benchmarkIFMAX4Finish(b, &states, 4)
}

func benchmarkIFMAX4NormalizeDependent(b *testing.B) {
	states := [4]LimbsX4{LimbsX4(benchmarkIFMAX4RawInput(0x51_4001))}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// The amd64 normalizer loads all five vectors before its first store,
		// so exact overlap forms a dependency chain without a Go-side copy.
		ifmaNormalizeProductUncheckedX4(&states[0], (*IFMAProductX4)(&states[0]))
	}
	benchmarkIFMAX4Finish(b, &states, 1)
}

func benchmarkIFMAX4NormalizeIndependent4(b *testing.B) {
	states := [4]LimbsX4{
		LimbsX4(benchmarkIFMAX4RawInput(0x51_4101)),
		LimbsX4(benchmarkIFMAX4RawInput(0x51_4102)),
		LimbsX4(benchmarkIFMAX4RawInput(0x51_4103)),
		LimbsX4(benchmarkIFMAX4RawInput(0x51_4104)),
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ifmaNormalizeProductUncheckedX4(&states[0], (*IFMAProductX4)(&states[0]))
		ifmaNormalizeProductUncheckedX4(&states[1], (*IFMAProductX4)(&states[1]))
		ifmaNormalizeProductUncheckedX4(&states[2], (*IFMAProductX4)(&states[2]))
		ifmaNormalizeProductUncheckedX4(&states[3], (*IFMAProductX4)(&states[3]))
	}
	benchmarkIFMAX4Finish(b, &states, 4)
}

func benchmarkIFMAX4AddNormalizedDependent(b *testing.B) {
	states := [4]LimbsX4{benchmarkIFMAX4ComposableInput(0x51_5001)}
	addend := benchmarkIFMAX4ComposableInput(0x51_6001)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ifmaAddNormalizedUncheckedX4(&states[0], &states[0], &addend)
	}
	benchmarkIFMAX4Finish(b, &states, 1)
}

func benchmarkIFMAX4AddNormalizedIndependent4(b *testing.B) {
	states := [4]LimbsX4{
		benchmarkIFMAX4ComposableInput(0x51_5101),
		benchmarkIFMAX4ComposableInput(0x51_5102),
		benchmarkIFMAX4ComposableInput(0x51_5103),
		benchmarkIFMAX4ComposableInput(0x51_5104),
	}
	addends := [4]LimbsX4{
		benchmarkIFMAX4ComposableInput(0x51_6101),
		benchmarkIFMAX4ComposableInput(0x51_6102),
		benchmarkIFMAX4ComposableInput(0x51_6103),
		benchmarkIFMAX4ComposableInput(0x51_6104),
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ifmaAddNormalizedUncheckedX4(&states[0], &states[0], &addends[0])
		ifmaAddNormalizedUncheckedX4(&states[1], &states[1], &addends[1])
		ifmaAddNormalizedUncheckedX4(&states[2], &states[2], &addends[2])
		ifmaAddNormalizedUncheckedX4(&states[3], &states[3], &addends[3])
	}
	benchmarkIFMAX4Finish(b, &states, 4)
}

// benchmarkIFMAX4ComposableInput returns dense limbs below 2^50, leaving two
// bits of headroom beneath the IFMA u52 multiplicand limit.
func benchmarkIFMAX4ComposableInput(seed uint64) LimbsX4 {
	const inputMask = uint64(1)<<50 - 1
	var out LimbsX4
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

// benchmarkIFMAX4RawInput returns genuine non-negative u61 limbs and sets
// high carry bits in every lane. After one normalization the same storage is
// u52 and remains a legal input for every subsequent chain step.
func benchmarkIFMAX4RawInput(seed uint64) IFMAProductX4 {
	low := benchmarkIFMAX4ComposableInput(seed)
	var out IFMAProductX4
	for limb := range out {
		for lane := range out[limb] {
			carryPattern := uint64(1+limb*X4Lanes+lane) << 56
			out[limb][lane] = carryPattern | low[limb][lane]
		}
	}
	return out
}

func benchmarkIFMAX4Finish(b *testing.B, states *[4]LimbsX4, primitivesPerIteration int) {
	b.Helper()
	b.StopTimer()

	for chain := range states {
		for limb := range states[chain] {
			for lane, value := range states[chain][limb] {
				if value >= ifmaComposableLimbLimit {
					b.Fatalf("chain %d limb %d lane %d escaped u52: %#x", chain, limb, lane, value)
				}
			}
		}
	}
	benchmarkIFMAX4PrimitiveChainSink = *states

	primitiveCount := float64(b.N) * float64(primitivesPerIteration)
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/primitiveCount, "ns/primitive")
	b.ReportMetric(float64(primitivesPerIteration), "primitives/op")
}
