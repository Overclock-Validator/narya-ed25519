package r51x5

import (
	"bytes"
	"encoding/binary"
	"math/bits"
	"math/rand"
	"testing"

	edwardsref "github.com/Overclock-Validator/narya-ed25519/internal/edwards25519"
)

func TestExperimentalUniformScalarReductionMatchesSetUniformBytes(t *testing.T) {
	inputs := scalarReductionEdgeCases()
	rng := rand.New(rand.NewSource(0x51ca1a2))
	for i := 0; i < 4096; i++ {
		var input [64]byte
		_, _ = rng.Read(input[:])
		inputs = append(inputs, input)
	}

	for i := range inputs {
		var got [32]byte
		reduceUniformScalar(&got, &inputs[i])
		want := referenceUniformScalar(t, &inputs[i])
		if got != want {
			t.Fatalf("case %d: radix-2^21 reduction differs from SetUniformBytes\n got %x\nwant %x", i, got, want)
		}
		oracle := bitwiseUniformScalarOracle(&inputs[i])
		if got != oracle {
			t.Fatalf("case %d: radix-2^21 reduction differs from bitwise oracle\n got %x\nwant %x", i, got, oracle)
		}
		var barrett [32]byte
		reduceUniformScalarBarrett(&barrett, &inputs[i])
		if barrett != oracle {
			t.Fatalf("case %d: Barrett oracle differs from bitwise oracle\n got %x\nwant %x", i, barrett, oracle)
		}
	}
}

func TestExperimentalUniformScalarReductionMasksTailsAndEveryLane(t *testing.T) {
	rng := rand.New(rand.NewSource(0x4a8ca1a2))
	var inputs [X8Lanes][64]byte
	var want [X8Lanes][32]byte
	for lane := 0; lane < X8Lanes; lane++ {
		_, _ = rng.Read(inputs[lane][:])
		// Make the lane identity visible in deterministic failure output.
		binary.LittleEndian.PutUint64(inputs[lane][:8], uint64(lane+1)*0x0102030405060708)
		want[lane] = referenceUniformScalar(t, &inputs[lane])
	}

	// All 256 masks cover every tail and every independent lane position.
	for mask := 0; mask < 1<<X8Lanes; mask++ {
		var got [X8Lanes][32]byte
		for lane := range got {
			for i := range got[lane] {
				got[lane][i] = 0xa5
			}
		}
		if returned := ExperimentalReduceUniformScalarsX8(&got, &inputs, uint8(mask)); returned != uint8(mask) {
			t.Fatalf("mask %#02x: returned mask %#02x", mask, returned)
		}
		for lane := range got {
			if mask&(1<<lane) != 0 {
				if got[lane] != want[lane] {
					t.Fatalf("mask %#02x lane %d: active result differs", mask, lane)
				}
			} else if got[lane] != ([32]byte{}) {
				t.Fatalf("mask %#02x lane %d: inactive output was not zeroed", mask, lane)
			}
		}
	}

	for mask := 0; mask < 1<<X8Lanes; mask++ {
		var in4 [X4Lanes][64]byte
		copy(in4[:], inputs[:X4Lanes])
		var got [X4Lanes][32]byte
		for lane := range got {
			for i := range got[lane] {
				got[lane][i] = 0x5a
			}
		}
		wantMask := uint8(mask) & 0x0f
		if returned := ExperimentalReduceUniformScalarsX4(&got, &in4, uint8(mask)); returned != wantMask {
			t.Fatalf("x4 mask %#02x: returned mask %#02x, want %#02x", mask, returned, wantMask)
		}
		for lane := range got {
			if wantMask&(1<<lane) != 0 {
				if got[lane] != want[lane] {
					t.Fatalf("x4 mask %#02x lane %d: active result differs", mask, lane)
				}
			} else if got[lane] != ([32]byte{}) {
				t.Fatalf("x4 mask %#02x lane %d: inactive output was not zeroed", mask, lane)
			}
		}
	}
}

func TestExperimentalUniformScalarReductionX8EqualsTwoX4(t *testing.T) {
	rng := rand.New(rand.NewSource(0x8f04ca1a2))
	for sample := 0; sample < 256; sample++ {
		var input8 [X8Lanes][64]byte
		for lane := range input8 {
			_, _ = rng.Read(input8[lane][:])
		}
		active := uint8(rng.Uint32())
		var got8 [X8Lanes][32]byte
		ExperimentalReduceUniformScalarsX8(&got8, &input8, active)

		var gotTwo [X8Lanes][32]byte
		for half := 0; half < 2; half++ {
			var input4 [X4Lanes][64]byte
			copy(input4[:], input8[half*X4Lanes:(half+1)*X4Lanes])
			var got4 [X4Lanes][32]byte
			ExperimentalReduceUniformScalarsX4(&got4, &input4, active>>uint(half*X4Lanes))
			copy(gotTwo[half*X4Lanes:(half+1)*X4Lanes], got4[:])
		}
		if got8 != gotTwo {
			t.Fatalf("sample %d mask %#02x: x8 differs from two x4 groups", sample, active)
		}
	}
}

func TestExperimentalUniformScalarReductionAllocations(t *testing.T) {
	var input4 [X4Lanes][64]byte
	var input8 [X8Lanes][64]byte
	var out4 [X4Lanes][32]byte
	var out8 [X8Lanes][32]byte
	if allocs := testing.AllocsPerRun(1000, func() {
		ExperimentalReduceUniformScalarsX4(&out4, &input4, 0x0f)
	}); allocs != 0 {
		t.Fatalf("x4 reduction allocated %.2f objects per call", allocs)
	}
	if allocs := testing.AllocsPerRun(1000, func() {
		ExperimentalReduceUniformScalarsX8(&out8, &input8, 0xff)
	}); allocs != 0 {
		t.Fatalf("x8 reduction allocated %.2f objects per call", allocs)
	}
}

func FuzzExperimentalUniformScalarReduction(f *testing.F) {
	for _, input := range scalarReductionEdgeCases() {
		f.Add(input[:])
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 64 {
			return
		}
		var input [64]byte
		copy(input[:], raw)
		var got [32]byte
		reduceUniformScalar(&got, &input)
		want := referenceUniformScalar(t, &input)
		if got != want {
			t.Fatalf("reduction mismatch\n got %x\nwant %x", got, want)
		}
	})
}

func scalarReductionEdgeCases() [][64]byte {
	inputs := make([][64]byte, 0, 16)
	inputs = append(inputs, [64]byte{})
	var one [64]byte
	one[0] = 1
	inputs = append(inputs, one)
	var max [64]byte
	for i := range max {
		max[i] = 0xff
	}
	inputs = append(inputs, max)

	order := [32]byte{
		0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
		0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
	}
	var exactlyOrder [64]byte
	copy(exactlyOrder[:], order[:])
	inputs = append(inputs, exactlyOrder)
	orderMinusOne := exactlyOrder
	subOneLE(orderMinusOne[:])
	inputs = append(inputs, orderMinusOne)
	orderPlusOne := exactlyOrder
	addOneLE(orderPlusOne[:])
	inputs = append(inputs, orderPlusOne)

	for _, bit := range []int{252, 255, 256, 319, 320, 383, 384, 447, 448, 511} {
		var input [64]byte
		input[bit/8] = 1 << uint(bit&7)
		inputs = append(inputs, input)
	}
	return inputs
}

func referenceUniformScalar(t testing.TB, input *[64]byte) [32]byte {
	t.Helper()
	scalar, err := edwardsref.NewScalar().SetUniformBytes(input[:])
	if err != nil {
		t.Fatalf("SetUniformBytes: %v", err)
	}
	var out [32]byte
	copy(out[:], scalar.Bytes())
	return out
}

// bitwiseUniformScalarOracle is intentionally slow and structurally unlike
// the Barrett candidate. The loop invariant is remainder < l, so each input
// bit requires at most one conditional subtraction after doubling.
func bitwiseUniformScalarOracle(input *[64]byte) [32]byte {
	order := [4]uint64{
		0x5812631a5cf5d3ed,
		0x14def9dea2f79cd6,
		0x0000000000000000,
		0x1000000000000000,
	}
	var remainder [4]uint64
	for bit := 511; bit >= 0; bit-- {
		carry := uint64((input[bit/8] >> uint(bit&7)) & 1)
		for word := range remainder {
			next := remainder[word] >> 63
			remainder[word] = remainder[word]<<1 | carry
			carry = next
		}

		var reduced [4]uint64
		var borrow uint64
		for word := range remainder {
			reduced[word], borrow = bits.Sub64(remainder[word], order[word], borrow)
		}
		if borrow == 0 {
			remainder = reduced
		}
	}
	var out [32]byte
	for word := range remainder {
		binary.LittleEndian.PutUint64(out[word*8:], remainder[word])
	}
	return out
}

func subOneLE(x []byte) {
	for i := range x {
		if x[i] != 0 {
			x[i]--
			return
		}
		x[i] = 0xff
	}
}

func addOneLE(x []byte) {
	for i := range x {
		x[i]++
		if x[i] != 0 {
			return
		}
	}
}

var (
	scalarReductionSinkX4   [X4Lanes][32]byte
	scalarReductionSinkX8   [X8Lanes][32]byte
	scalarReductionMaskSink uint8
)

func BenchmarkExperimentalUniformScalarReduction(b *testing.B) {
	rng := rand.New(rand.NewSource(0x513ca1a2))
	var input8 [X8Lanes][64]byte
	for lane := range input8 {
		_, _ = rng.Read(input8[lane][:])
	}
	var input4 [2][X4Lanes][64]byte
	copy(input4[0][:], input8[:X4Lanes])
	copy(input4[1][:], input8[X4Lanes:])

	b.Run("x4/full", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			scalarReductionMaskSink = ExperimentalReduceUniformScalarsX4(&scalarReductionSinkX4, &input4[0], 0x0f)
		}
	})
	b.Run("x8-scalar/full", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			scalarReductionMaskSink = reduceUniformScalarsScalarX8(&scalarReductionSinkX8, &input8, 0xff)
		}
	})
	b.Run("x8-dispatch/full", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			scalarReductionMaskSink = ExperimentalReduceUniformScalarsX8(&scalarReductionSinkX8, &input8, 0xff)
		}
	})
	b.Run("x8-ifma-candidate/full", func(b *testing.B) {
		if !ExperimentalIFMAAvailable() {
			b.Skip("AVX-512 IFMA unavailable")
		}
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			var ok bool
			scalarReductionMaskSink, ok = reduceUniformScalarsIFMAX8(&scalarReductionSinkX8, &input8, 0xff)
			if !ok {
				b.Fatal("native x8 reduction became unavailable")
			}
		}
	})
	b.Run("two-x4/full", func(b *testing.B) {
		var out [2][X4Lanes][32]byte
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			scalarReductionMaskSink = ExperimentalReduceUniformScalarsX4(&out[0], &input4[0], 0x0f)
			scalarReductionMaskSink &= ExperimentalReduceUniformScalarsX4(&out[1], &input4[1], 0x0f)
		}
		scalarReductionSinkX4 = out[0]
	})
	b.Run("set-uniform-bytes-eight/full", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			for lane := range input8 {
				scalar, err := edwardsref.NewScalar().SetUniformBytes(input8[lane][:])
				if err != nil {
					b.Fatal(err)
				}
				copy(scalarReductionSinkX8[lane][:], scalar.Bytes())
			}
		}
	})
	for active := 1; active <= X8Lanes; active++ {
		mask := uint8((1 << active) - 1)
		b.Run("x8/tail-"+string(rune('0'+active)), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				scalarReductionMaskSink = ExperimentalReduceUniformScalarsX8(&scalarReductionSinkX8, &input8, mask)
			}
		})
	}
}

func TestExperimentalUniformScalarReductionIFMAX8MatchesScalar(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("AVX-512 IFMA unavailable")
	}

	rng := rand.New(rand.NewSource(0x51_21_08_51))
	for iteration := 0; iteration < 2_048; iteration++ {
		var input [X8Lanes][64]byte
		for lane := range input {
			_, _ = rng.Read(input[lane][:])
		}
		if iteration < 512 {
			// Exercise carry-heavy byte patterns alongside random digests.
			fill := byte(iteration)
			for lane := range input {
				for index := range input[lane] {
					input[lane][index] = fill ^ byte(lane*0x33+index)
				}
			}
		}
		before := input
		active := uint8(iteration)
		var want, got [X8Lanes][32]byte
		wantMask := reduceUniformScalarsScalarX8(&want, &input, active)
		gotMask, ok := reduceUniformScalarsIFMAX8(&got, &input, active)
		if !ok {
			t.Fatal("native x8 reduction became unavailable")
		}
		if gotMask != wantMask || got != want {
			t.Fatalf("iteration=%d active=%02x native reduction differs", iteration, active)
		}
		if input != before {
			t.Fatalf("iteration=%d active=%02x input mutated", iteration, active)
		}
	}
}

func TestExperimentalUniformScalarReductionIFMAX8ZeroAllocations(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("AVX-512 IFMA unavailable")
	}
	var input [X8Lanes][64]byte
	for lane := range input {
		for index := range input[lane] {
			input[lane][index] = byte(lane*17 + index)
		}
	}
	var out [X8Lanes][32]byte
	allocations := testing.AllocsPerRun(1_000, func() {
		if _, ok := reduceUniformScalarsIFMAX8(&out, &input, 0xff); !ok {
			t.Fatal("native x8 reduction became unavailable")
		}
	})
	if allocations != 0 {
		t.Fatalf("allocations=%v want=0", allocations)
	}
}

func TestScalarReductionBenchmarkInputsDiffer(t *testing.T) {
	// Guard against accidentally benchmarking eight copies of one digest.
	rng := rand.New(rand.NewSource(0x513ca1a2))
	var input [X8Lanes][64]byte
	for lane := range input {
		_, _ = rng.Read(input[lane][:])
		for prior := 0; prior < lane; prior++ {
			if bytes.Equal(input[lane][:], input[prior][:]) {
				t.Fatalf("benchmark lanes %d and %d are equal", prior, lane)
			}
		}
	}
}
