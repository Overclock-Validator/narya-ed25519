package r51x5

import (
	"math/rand"
	"runtime"
	"testing"
)

func TestIFMARepeatedSquareNormalizedX8Differential(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	rng := rand.New(rand.NewSource(0x51_dec0_2026))
	counts := []int{0, 1, 2, 5, 10, 20, 50, 100, 252}
	for round := 0; round < 64; round++ {
		var input LimbsX8
		for limb := range input {
			for lane := range input[limb] {
				input[limb][lane] = rng.Uint64() & ((uint64(1) << 52) - 1)
			}
		}
		for _, count := range counts {
			want := input
			for range count {
				ifmaMulNormalizedUncheckedX8(&want, &want, &want)
			}
			var got LimbsX8
			ifmaRepeatedSquareNormalizedExperimentX8(&got, &input, count)
			if got != want {
				t.Fatalf("round=%d count=%d: representation mismatch", round, count)
			}
			alias := input
			ifmaRepeatedSquareNormalizedExperimentX8(&alias, &alias, count)
			if alias != want {
				t.Fatalf("round=%d count=%d: alias mismatch", round, count)
			}
		}
	}
}

func TestIFMARepeatedSquareNormalizedX8ZeroAllocations(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	var input, out LimbsX8
	input[0] = [X8Lanes]uint64{1, 2, 3, 4, 5, 6, 7, 8}
	if allocations := testing.AllocsPerRun(100, func() {
		ifmaRepeatedSquareNormalizedExperimentX8(&out, &input, 100)
	}); allocations != 0 {
		t.Fatalf("allocations=%v", allocations)
	}
	benchmarkIFMARepeatedSquareX8Sink = out
}

var benchmarkIFMARepeatedSquareX8Sink LimbsX8

func BenchmarkIFMARepeatedSquareNormalizedX8(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	var seed LimbsX8
	for limb := range seed {
		for lane := range seed[limb] {
			seed[limb][lane] = uint64(17 + 13*limb + lane)
		}
	}
	for _, count := range []int{1, 5, 20, 50, 100, 252} {
		b.Run("current/count="+itoaSmall(count), func(b *testing.B) {
			state := seed
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				for range count {
					ifmaMulNormalizedUncheckedX8(&state, &state, &state)
				}
			}
			benchmarkIFMARepeatedSquareX8Sink = state
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*count), "ns/square")
		})
		b.Run("registerized/count="+itoaSmall(count), func(b *testing.B) {
			state := seed
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				ifmaRepeatedSquareNormalizedExperimentX8(&state, &state, count)
			}
			benchmarkIFMARepeatedSquareX8Sink = state
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*count), "ns/square")
		})
	}
}

func itoaSmall(value int) string {
	if value == 0 {
		return "0"
	}
	var digits [20]byte
	index := len(digits)
	for value > 0 {
		index--
		digits[index] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[index:])
}
