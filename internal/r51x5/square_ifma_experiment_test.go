package r51x5

import (
	"math/bits"
	"math/rand"
	"runtime"
	"testing"
)

const squareIFMAExperimentU52Mask = uint64(1)<<IFMAComposableLimbBits - 1

var squareIFMAExperimentSink [4]LimbsX4

func TestIFMASquareNormalizedExperimentX4Model(t *testing.T) {
	for index, input := range squareIFMAExperimentInputs() {
		for lane := 0; lane < X4Lanes; lane++ {
			var scalar Limbs
			for limb := range scalar {
				scalar[limb] = input[limb][lane]
			}

			raw, got := squareIFMAExperimentLaneModel(t, scalar)
			wantRaw := ifmaLooseLaneModel(scalar, scalar)
			if raw != wantRaw {
				t.Fatalf("input %d lane %d: raw symmetry-model mismatch\n got=%#v\nwant=%#v", index, lane, raw, wantRaw)
			}
			for limb, value := range raw {
				if value >= ifmaProductLimbLimit {
					t.Fatalf("input %d lane %d limb %d: raw square escaped u61: %#x", index, lane, limb, value)
				}
			}
			want, ok := normalizeIFMAProductLane(wantRaw)
			if !ok {
				t.Fatalf("input %d lane %d: general model escaped normalizer contract", index, lane)
			}
			if got != want || !IsIFMAMultiplicand(got) {
				t.Fatalf("input %d lane %d: normalized model mismatch or non-u52 output", index, lane)
			}
		}
	}
}

func TestIFMASquareNormalizedExperimentX4Differential(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	for index, input := range squareIFMAExperimentInputs() {
		var got, want LimbsX4
		ifmaSquareNormalizedExperimentX4(&got, &input)
		ifmaMulNormalizedUncheckedX4(&want, &input, &input)

		// The symmetry schedule preserves the exact folded-and-carried
		// representation, not merely the field value.
		if got != want {
			t.Fatalf("input %d: representation mismatch\n got=%#v\nwant=%#v", index, got, want)
		}
		if !squareIFMAExperimentIsU52(&got) {
			t.Fatalf("input %d: output escaped u52: %#v", index, got)
		}

		// Also check against the scalar field oracle after independently
		// reducing the arbitrary u52 input representation.
		composableInput := IFMAElementX4{limbs: input}
		reducedInput := composableInput.Reduced()
		var reducedWant ElementX4
		reducedWant.Square(&reducedInput)
		composableGot := IFMAElementX4{limbs: got}
		reducedGot := composableGot.Reduced()
		if reducedGot != reducedWant {
			t.Fatalf("input %d: scalar field mismatch", index)
		}
	}
}

func TestIFMASquareNormalizedExperimentX4Aliasing(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	for index, input := range squareIFMAExperimentBoundaryInputs() {
		want := input
		ifmaMulNormalizedUncheckedX4(&want, &want, &want)

		got := input
		ifmaSquareNormalizedExperimentX4(&got, &got)
		if got != want {
			t.Fatalf("input %d: aliased representation mismatch", index)
		}
	}
}

func TestIFMASquareNormalizedExperimentX4ZeroAllocations(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	state := squareIFMAExperimentDenseInput(0x51_51_0001)
	if allocs := testing.AllocsPerRun(1000, func() {
		ifmaSquareNormalizedExperimentX4(&state, &state)
	}); allocs != 0 {
		t.Fatalf("dedicated x4 square allocations=%v", allocs)
	}
	squareIFMAExperimentSink[0] = state
}

func BenchmarkIFMASquareNormalizedExperimentX4(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	b.Run("kernel=general-multiply/dependency=dependent", func(b *testing.B) {
		state := squareIFMAExperimentDenseInput(0x51_52_0001)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ifmaMulNormalizedUncheckedX4(&state, &state, &state)
		}
		squareIFMAExperimentSink[0] = state
	})

	b.Run("kernel=dedicated-square/dependency=dependent", func(b *testing.B) {
		state := squareIFMAExperimentDenseInput(0x51_52_0001)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ifmaSquareNormalizedExperimentX4(&state, &state)
		}
		squareIFMAExperimentSink[0] = state
	})

	b.Run("kernel=general-multiply/dependency=independent-4", func(b *testing.B) {
		states := squareIFMAExperimentIndependentInputs(0x51_54_0001)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ifmaMulNormalizedUncheckedX4(&states[0], &states[0], &states[0])
			ifmaMulNormalizedUncheckedX4(&states[1], &states[1], &states[1])
			ifmaMulNormalizedUncheckedX4(&states[2], &states[2], &states[2])
			ifmaMulNormalizedUncheckedX4(&states[3], &states[3], &states[3])
		}
		squareIFMAExperimentSink = states
	})

	b.Run("kernel=dedicated-square/dependency=independent-4", func(b *testing.B) {
		states := squareIFMAExperimentIndependentInputs(0x51_54_0001)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ifmaSquareNormalizedExperimentX4(&states[0], &states[0])
			ifmaSquareNormalizedExperimentX4(&states[1], &states[1])
			ifmaSquareNormalizedExperimentX4(&states[2], &states[2])
			ifmaSquareNormalizedExperimentX4(&states[3], &states[3])
		}
		squareIFMAExperimentSink = states
	})
}

func squareIFMAExperimentBoundaryInputs() []LimbsX4 {
	values := [...]uint64{
		0,
		1,
		uint64(1)<<LimbBits - 1,
		uint64(1) << LimbBits,
		uint64(1)<<LimbBits + 1,
		uint64(1)<<LimbBits + 1919,
		squareIFMAExperimentU52Mask - 1,
		squareIFMAExperimentU52Mask,
	}

	inputs := make([]LimbsX4, 0, len(values)+3)
	for _, value := range values {
		var input LimbsX4
		for limb := range input {
			for lane := range input[limb] {
				input[limb][lane] = value
			}
		}
		inputs = append(inputs, input)
	}

	// Exercise different bounds simultaneously in every limb and lane.
	var ascending, descending LimbsX4
	for limb := range ascending {
		for lane := range ascending[limb] {
			index := (limb*X4Lanes + lane) % len(values)
			ascending[limb][lane] = values[index]
			descending[limb][lane] = values[len(values)-1-index]
		}
	}
	inputs = append(inputs, ascending, descending, squareIFMAExperimentDenseInput(0x51_b0_0001))
	return inputs
}

func squareIFMAExperimentInputs() []LimbsX4 {
	inputs := squareIFMAExperimentBoundaryInputs()
	rng := rand.New(rand.NewSource(0x51_5a7e_2026))
	for round := 0; round < 4096; round++ {
		var input LimbsX4
		for limb := range input {
			for lane := range input[limb] {
				input[limb][lane] = rng.Uint64() & squareIFMAExperimentU52Mask
			}
		}
		inputs = append(inputs, input)
	}
	return inputs
}

// squareIFMAExperimentLaneModel mirrors the 15-product assembly schedule.
// The off-diagonal halves are doubled after accumulation, then the diagonal
// halves are added. At most five product contributions reach any coefficient,
// so every low/high accumulator is below 5*2^52 and all uint64 arithmetic is
// exact. The returned raw limbs are the folded, not-yet-carried product.
func squareIFMAExperimentLaneModel(t *testing.T, x Limbs) (Limbs, Limbs) {
	t.Helper()
	var low, high [9]uint64
	for i := range x {
		for j := i; j < len(x); j++ {
			hi, lo := bits.Mul64(x[i], x[j])
			scale := uint64(1)
			if i != j {
				scale = 2
			}
			degree := i + j
			low[degree] += scale * (lo & squareIFMAExperimentU52Mask)
			high[degree] += scale * (lo>>IFMAComposableLimbBits | hi<<(64-IFMAComposableLimbBits))
		}
	}

	var coefficients [10]uint64
	for degree := range low {
		coefficients[degree] += low[degree]
		coefficients[degree+1] += 2 * high[degree]
	}
	raw := Limbs{
		coefficients[0] + 19*coefficients[5],
		coefficients[1] + 19*coefficients[6],
		coefficients[2] + 19*coefficients[7],
		coefficients[3] + 19*coefficients[8],
		coefficients[4] + 19*coefficients[9],
	}
	normalized, ok := normalizeIFMAProductLane(raw)
	if !ok {
		t.Fatalf("symmetry square model escaped u61 normalizer contract: %#v", raw)
	}
	return raw, normalized
}

func squareIFMAExperimentDenseInput(seed uint64) LimbsX4 {
	var out LimbsX4
	for limb := range out {
		for lane := range out[limb] {
			value := seed + uint64(limb+1)*0x9e37_79b9_7f4a_7c15 + uint64(lane+1)*0xbf58_476d_1ce4_e5b9
			value ^= value >> 30
			value *= 0xbf58_476d_1ce4_e5b9
			value ^= value >> 27
			out[limb][lane] = value & squareIFMAExperimentU52Mask
		}
	}
	return out
}

func squareIFMAExperimentIndependentInputs(seed uint64) [4]LimbsX4 {
	return [4]LimbsX4{
		squareIFMAExperimentDenseInput(seed),
		squareIFMAExperimentDenseInput(seed + 1),
		squareIFMAExperimentDenseInput(seed + 2),
		squareIFMAExperimentDenseInput(seed + 3),
	}
}

func squareIFMAExperimentIsU52(x *LimbsX4) bool {
	for limb := range x {
		for lane := range x[limb] {
			if x[limb][lane] >= uint64(1)<<IFMAComposableLimbBits {
				return false
			}
		}
	}
	return true
}
