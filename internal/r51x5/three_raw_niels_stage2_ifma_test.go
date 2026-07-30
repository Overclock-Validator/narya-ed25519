package r51x5

import (
	"math/rand"
	"runtime"
	"testing"
)

func TestIFMAThreeRawProductsNielsStage2X8MatchesSeparateLeaves(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	rng := rand.New(rand.NewSource(0x51_a3_d1_0008))
	for iteration := 0; iteration < 10_000; iteration++ {
		var inputs [7]LimbsX8
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

		var want ifmaNielsStage2WorkspaceX8
		ifmaMulRawX8(&want[0], &inputs[0], &inputs[1])
		ifmaMulRawX8(&want[1], &inputs[2], &inputs[3])
		ifmaMulRawX8(&want[2], &inputs[4], &inputs[5])
		want[3] = IFMAProductX8(inputs[6])
		ifmaNielsStage2X8(&want)

		var got ifmaNielsStage2WorkspaceX8
		ifmaThreeRawProductsNielsStage2UncheckedX8(
			&got,
			&inputs[0], &inputs[1],
			&inputs[2], &inputs[3],
			&inputs[4], &inputs[5],
			&inputs[6],
		)
		if got != want {
			t.Fatalf("iteration %d: affine Niels tail differs from separate exact leaves", iteration)
		}
		if inputs != before {
			t.Fatalf("iteration %d: affine Niels tail modified input workspace", iteration)
		}
	}
}

func TestIFMAThreeRawProductsNielsStage2X8ZeroAllocations(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	inputs := benchmarkThreeRawNielsInputsX8()
	var out ifmaNielsStage2WorkspaceX8
	allocations := testing.AllocsPerRun(1_000, func() {
		ifmaThreeRawProductsNielsStage2UncheckedX8(
			&out,
			&inputs[0], &inputs[1], &inputs[2], &inputs[3],
			&inputs[4], &inputs[5], &inputs[6],
		)
	})
	if allocations != 0 {
		t.Fatalf("allocations = %v, want 0", allocations)
	}
}

var benchmarkThreeRawNielsSinkX8 ifmaNielsStage2WorkspaceX8

func BenchmarkIFMAThreeRawProductsNielsStage2X8(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	inputs := benchmarkThreeRawNielsInputsX8()
	b.Run("separate", func(b *testing.B) {
		var out ifmaNielsStage2WorkspaceX8
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ifmaMulRawX8(&out[0], &inputs[0], &inputs[1])
			ifmaMulRawX8(&out[1], &inputs[2], &inputs[3])
			ifmaMulRawX8(&out[2], &inputs[4], &inputs[5])
			out[3] = IFMAProductX8(inputs[6])
			ifmaNielsStage2X8(&out)
		}
		benchmarkThreeRawNielsSinkX8 = out
	})
	b.Run("tail", func(b *testing.B) {
		var out ifmaNielsStage2WorkspaceX8
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ifmaThreeRawProductsNielsStage2UncheckedX8(
				&out,
				&inputs[0], &inputs[1], &inputs[2], &inputs[3],
				&inputs[4], &inputs[5], &inputs[6],
			)
		}
		benchmarkThreeRawNielsSinkX8 = out
	})
}

func benchmarkThreeRawNielsInputsX8() [7]LimbsX8 {
	all := benchmarkFourRawProductInputsX8()
	return [7]LimbsX8{all[0], all[1], all[2], all[3], all[4], all[5], all[6]}
}
