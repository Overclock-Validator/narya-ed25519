package r51x5

import (
	"math/rand"
	"runtime"
	"testing"
)

var squareIFMAX8ExperimentSink [4]LimbsX8

func TestIFMASquareNormalizedExperimentX8Differential(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	for index, input := range squareIFMAX8ExperimentInputs() {
		var got, want LimbsX8
		ifmaSquareNormalizedExperimentX8(&got, &input)
		ifmaMulNormalizedUncheckedX8(&want, &input, &input)
		if got != want {
			t.Fatalf("input %d: dedicated/general representation mismatch", index)
		}
		if !squareIFMAX8ExperimentIsU52(&got) {
			t.Fatalf("input %d: output escaped u52", index)
		}

		composableInput := IFMAElementX8{limbs: input}
		reducedInput := composableInput.Reduced()
		var reducedWant ElementX8
		reducedWant.Square(&reducedInput)
		composableGot := IFMAElementX8{limbs: got}
		if reducedGot := composableGot.Reduced(); reducedGot != reducedWant {
			t.Fatalf("input %d: dedicated/scalar field mismatch", index)
		}
	}
}

func TestIFMASquareNormalizedExperimentX8Aliasing(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	for index, input := range squareIFMAX8ExperimentBoundaryInputs() {
		want := input
		ifmaMulNormalizedUncheckedX8(&want, &want, &want)
		got := input
		ifmaSquareNormalizedExperimentX8(&got, &got)
		if got != want {
			t.Fatalf("input %d: aliased representation mismatch", index)
		}
	}
}

func TestIFMASquareNormalizedExperimentX8ZeroAllocations(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	state := benchmarkIFMAX8ComposableInput(0x51_58_0001)
	if allocs := testing.AllocsPerRun(1000, func() {
		ifmaSquareNormalizedExperimentX8(&state, &state)
	}); allocs != 0 {
		t.Fatalf("dedicated x8 square allocations=%v", allocs)
	}
	squareIFMAX8ExperimentSink[0] = state
}

func BenchmarkIFMASquareNormalizedExperimentX8(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	b.Run("kernel=general-multiply/dependency=dependent", func(b *testing.B) {
		state := benchmarkIFMAX8ComposableInput(0x51_59_0001)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ifmaMulNormalizedUncheckedX8(&state, &state, &state)
		}
		squareIFMAX8ExperimentSink[0] = state
	})
	b.Run("kernel=dedicated-square/dependency=dependent", func(b *testing.B) {
		state := benchmarkIFMAX8ComposableInput(0x51_59_0001)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ifmaSquareNormalizedExperimentX8(&state, &state)
		}
		squareIFMAX8ExperimentSink[0] = state
	})
	b.Run("kernel=general-multiply/dependency=independent-4", func(b *testing.B) {
		states := squareIFMAX8IndependentInputs(0x51_5a_0001)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for index := range states {
				ifmaMulNormalizedUncheckedX8(&states[index], &states[index], &states[index])
			}
		}
		squareIFMAX8ExperimentSink = states
	})
	b.Run("kernel=dedicated-square/dependency=independent-4", func(b *testing.B) {
		states := squareIFMAX8IndependentInputs(0x51_5a_0001)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for index := range states {
				ifmaSquareNormalizedExperimentX8(&states[index], &states[index])
			}
		}
		squareIFMAX8ExperimentSink = states
	})
}

func squareIFMAX8ExperimentInputs() []LimbsX8 {
	inputs := squareIFMAX8ExperimentBoundaryInputs()
	rng := rand.New(rand.NewSource(0x51_8a7e_2026))
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

func squareIFMAX8ExperimentBoundaryInputs() []LimbsX8 {
	values := [...]uint64{
		0,
		1,
		uint64(1)<<LimbBits - 1,
		uint64(1) << LimbBits,
		uint64(1)<<LimbBits + 1919,
		squareIFMAExperimentU52Mask - 1,
		squareIFMAExperimentU52Mask,
	}
	inputs := make([]LimbsX8, 0, len(values)+2)
	for _, value := range values {
		var input LimbsX8
		for limb := range input {
			for lane := range input[limb] {
				input[limb][lane] = value
			}
		}
		inputs = append(inputs, input)
	}
	var mixed LimbsX8
	for limb := range mixed {
		for lane := range mixed[limb] {
			mixed[limb][lane] = values[(limb*X8Lanes+lane)%len(values)]
		}
	}
	return append(inputs, mixed, benchmarkIFMAX8ComposableInput(0x51_5b_0001))
}

func squareIFMAX8IndependentInputs(seed uint64) [4]LimbsX8 {
	return [4]LimbsX8{
		benchmarkIFMAX8ComposableInput(seed),
		benchmarkIFMAX8ComposableInput(seed + 1),
		benchmarkIFMAX8ComposableInput(seed + 2),
		benchmarkIFMAX8ComposableInput(seed + 3),
	}
}

func squareIFMAX8ExperimentIsU52(input *LimbsX8) bool {
	for limb := range input {
		for lane := range input[limb] {
			if input[limb][lane] >= uint64(1)<<IFMAComposableLimbBits {
				return false
			}
		}
	}
	return true
}
