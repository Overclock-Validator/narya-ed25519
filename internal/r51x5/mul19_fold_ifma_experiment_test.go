package r51x5

import (
	"math/rand"
	"runtime"
	"testing"
)

var mul19FoldIFMAExperimentSink [4]LimbsX8

func TestIFMAMulNormalizedMul19ExperimentX8Differential(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	inputs := mul19FoldIFMAExperimentInputs()
	for index := range inputs {
		x := inputs[index]
		y := inputs[(index*17+3)%len(inputs)]
		var got, want LimbsX8
		ifmaMulNormalizedMul19ExperimentX8(&got, &x, &y)
		ifmaMulNormalizedUncheckedX8(&want, &x, &y)
		if got != want {
			t.Fatalf("input %d: mul19/general representation mismatch", index)
		}
	}
}

func TestIFMAMulNormalizedMul19ExperimentX8Aliasing(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	inputs := mul19FoldIFMAExperimentInputs()[:16]
	for index := range inputs {
		x := inputs[index]
		y := inputs[(index+5)%len(inputs)]
		var want LimbsX8
		ifmaMulNormalizedUncheckedX8(&want, &x, &y)

		aliasX := x
		ifmaMulNormalizedMul19ExperimentX8(&aliasX, &aliasX, &y)
		if aliasX != want {
			t.Fatalf("input %d: x alias mismatch", index)
		}
		aliasY := y
		ifmaMulNormalizedMul19ExperimentX8(&aliasY, &x, &aliasY)
		if aliasY != want {
			t.Fatalf("input %d: y alias mismatch", index)
		}
	}

	for index := range inputs {
		want := inputs[index]
		ifmaMulNormalizedUncheckedX8(&want, &want, &want)
		got := inputs[index]
		ifmaMulNormalizedMul19ExperimentX8(&got, &got, &got)
		if got != want {
			t.Fatalf("input %d: double alias mismatch", index)
		}
	}
}

func TestIFMAMulNormalizedMul19ExperimentX8ZeroAllocations(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	state := benchmarkIFMAX8ComposableInput(0x51_19_0001)
	factor := benchmarkIFMAX8ComposableInput(0x51_19_0002)
	if allocs := testing.AllocsPerRun(1000, func() {
		ifmaMulNormalizedMul19ExperimentX8(&state, &state, &factor)
	}); allocs != 0 {
		t.Fatalf("mul19 x8 allocations=%v", allocs)
	}
	mul19FoldIFMAExperimentSink[0] = state
}

func BenchmarkIFMAMulNormalizedMul19ExperimentX8(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	b.Run("kernel=shift-add/dependency=dependent", func(b *testing.B) {
		state := benchmarkIFMAX8ComposableInput(0x51_19_1001)
		factor := benchmarkIFMAX8ComposableInput(0x51_19_1002)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ifmaMulNormalizedUncheckedX8(&state, &state, &factor)
		}
		mul19FoldIFMAExperimentSink[0] = state
	})
	b.Run("kernel=vpmullq/dependency=dependent", func(b *testing.B) {
		state := benchmarkIFMAX8ComposableInput(0x51_19_1001)
		factor := benchmarkIFMAX8ComposableInput(0x51_19_1002)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ifmaMulNormalizedMul19ExperimentX8(&state, &state, &factor)
		}
		mul19FoldIFMAExperimentSink[0] = state
	})
	b.Run("kernel=shift-add/dependency=independent-4", func(b *testing.B) {
		states, factors := mul19FoldIFMAIndependentInputs()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for index := range states {
				ifmaMulNormalizedUncheckedX8(&states[index], &states[index], &factors[index])
			}
		}
		mul19FoldIFMAExperimentSink = states
	})
	b.Run("kernel=vpmullq/dependency=independent-4", func(b *testing.B) {
		states, factors := mul19FoldIFMAIndependentInputs()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for index := range states {
				ifmaMulNormalizedMul19ExperimentX8(&states[index], &states[index], &factors[index])
			}
		}
		mul19FoldIFMAExperimentSink = states
	})
}

func mul19FoldIFMAExperimentInputs() []LimbsX8 {
	inputs := squareIFMAX8ExperimentBoundaryInputs()
	rng := rand.New(rand.NewSource(0x51_19_2026))
	for round := 0; round < 4096; round++ {
		var input LimbsX8
		for limb := range input {
			for lane := range input[limb] {
				input[limb][lane] = rng.Uint64() & squareIFMAExperimentU52Mask
			}
		}
		inputs = append(inputs, input)
	}
	return inputs
}

func mul19FoldIFMAIndependentInputs() ([4]LimbsX8, [4]LimbsX8) {
	var states, factors [4]LimbsX8
	for index := range states {
		states[index] = benchmarkIFMAX8ComposableInput(0x51_19_3000 + uint64(index))
		factors[index] = benchmarkIFMAX8ComposableInput(0x51_19_4000 + uint64(index))
	}
	return states, factors
}
