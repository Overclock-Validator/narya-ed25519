package r51x5

import (
	"math/rand"
	"runtime"
	"testing"
)

func TestIFMAFourRawProductsX8MatchesFourCalls(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	rng := rand.New(rand.NewSource(0x51_a4_b4_c4_d4))
	for iteration := 0; iteration < 10_000; iteration++ {
		var inputs [8]LimbsX8
		for input := range inputs {
			for limb := range inputs[input] {
				for lane := range inputs[input][limb] {
					switch iteration {
					case 0:
						inputs[input][limb][lane] = 0
					case 1:
						inputs[input][limb][lane] = ifmaComposableLimbLimit - 1
					default:
						inputs[input][limb][lane] = rng.Uint64() & (ifmaComposableLimbLimit - 1)
					}
				}
			}
		}
		before := inputs

		var want [4]IFMAProductX8
		fourRawProductsFourCallsX8(&want, &inputs)
		var got [4]IFMAProductX8
		ifmaFourRawProductsUncheckedX8(
			&got,
			&inputs[0], &inputs[1],
			&inputs[2], &inputs[3],
			&inputs[4], &inputs[5],
			&inputs[6], &inputs[7],
		)

		if got != want {
			t.Fatalf("iteration %d: compound raw products differ from four-call representation", iteration)
		}
		if inputs != before {
			t.Fatalf("iteration %d: compound raw products modified input workspace", iteration)
		}
	}
}

func TestIFMAFourRawProductsX8ZeroAllocations(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	inputs := benchmarkFourRawProductInputsX8()
	var out [4]IFMAProductX8
	allocations := testing.AllocsPerRun(1_000, func() {
		ifmaFourRawProductsUncheckedX8(
			&out,
			&inputs[0], &inputs[1],
			&inputs[2], &inputs[3],
			&inputs[4], &inputs[5],
			&inputs[6], &inputs[7],
		)
	})
	if allocations != 0 {
		t.Fatalf("allocations = %v, want 0", allocations)
	}
}

var benchmarkFourRawProductsSinkX8 [4]IFMAProductX8

func BenchmarkIFMAFourRawProductsX8(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	inputs := benchmarkFourRawProductInputsX8()
	b.Run("four-calls", func(b *testing.B) {
		var out [4]IFMAProductX8
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			fourRawProductsFourCallsX8(&out, &inputs)
		}
		benchmarkFourRawProductsSinkX8 = out
	})
	b.Run("one-leaf", func(b *testing.B) {
		var out [4]IFMAProductX8
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ifmaFourRawProductsUncheckedX8(
				&out,
				&inputs[0], &inputs[1],
				&inputs[2], &inputs[3],
				&inputs[4], &inputs[5],
				&inputs[6], &inputs[7],
			)
		}
		benchmarkFourRawProductsSinkX8 = out
	})
}

func fourRawProductsFourCallsX8(out *[4]IFMAProductX8, inputs *[8]LimbsX8) {
	ifmaMulRawX8(&out[0], &inputs[0], &inputs[1])
	ifmaMulRawX8(&out[1], &inputs[2], &inputs[3])
	ifmaMulRawX8(&out[2], &inputs[4], &inputs[5])
	ifmaMulRawX8(&out[3], &inputs[6], &inputs[7])
}

func benchmarkFourRawProductInputsX8() [8]LimbsX8 {
	var inputs [8]LimbsX8
	for input := range inputs {
		for limb := range inputs[input] {
			for lane := range inputs[input][limb] {
				value := uint64(input+1)*0x9e37_79b9 + uint64(limb+1)*0x7f4a_7c15 + uint64(lane+1)*0x51_8101
				inputs[input][limb][lane] = value & (ifmaComposableLimbLimit - 1)
			}
		}
	}
	return inputs
}
