package sha512mb

import (
	"math/rand"
	"testing"
)

func TestNativeCompress2X8ExpandedDifferential(t *testing.T) {
	if !nativeX8Available() {
		t.Skip("requires AVX-512F")
	}
	rng := rand.New(rand.NewSource(0x5122a8))
	for iteration := 0; iteration < 256; iteration++ {
		var gotA, gotB, wantA, wantB nativeStateX8
		var blockA, blockB nativeBlockX8
		for word := range gotA {
			for lane := range gotA[word] {
				gotA[word][lane] = rng.Uint64()
				gotB[word][lane] = rng.Uint64()
			}
		}
		wantA = gotA
		wantB = gotB
		for word := range blockA {
			for lane := range blockA[word] {
				blockA[word][lane] = rng.Uint64()
				blockB[word][lane] = rng.Uint64()
			}
		}

		nativeCompressX8Rolling(&wantA, &blockA)
		nativeCompressX8Rolling(&wantB, &blockB)
		nativeCompress2X8Expanded(&gotA, &blockA, &gotB, &blockB)
		if gotA != wantA {
			t.Fatalf("iteration=%d: wave A differs from the rolling x8 oracle", iteration)
		}
		if gotB != wantB {
			t.Fatalf("iteration=%d: wave B differs from the rolling x8 oracle", iteration)
		}
	}
}

var nativeCompress2X8Sink [2]nativeStateX8

func BenchmarkNativeCompress2X8Expanded(b *testing.B) {
	if !nativeX8Available() {
		b.Skip("requires AVX-512F")
	}
	rng := rand.New(rand.NewSource(0x5122be))
	var initialA, initialB nativeStateX8
	var blockA, blockB nativeBlockX8
	for word := range initialA {
		for lane := range initialA[word] {
			initialA[word][lane] = rng.Uint64()
			initialB[word][lane] = rng.Uint64()
		}
	}
	for word := range blockA {
		for lane := range blockA[word] {
			blockA[word][lane] = rng.Uint64()
			blockB[word][lane] = rng.Uint64()
		}
	}

	b.Run("two-rolling-x8", func(b *testing.B) {
		stateA, stateB := initialA, initialB
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			nativeCompressX8Rolling(&stateA, &blockA)
			nativeCompressX8Rolling(&stateB, &blockB)
		}
		b.StopTimer()
		nativeCompress2X8Sink = [2]nativeStateX8{stateA, stateB}
		b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*16), "ns/msg")
	})

	b.Run("interlaced-expanded-2x8", func(b *testing.B) {
		stateA, stateB := initialA, initialB
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			nativeCompress2X8Expanded(&stateA, &blockA, &stateB, &blockB)
		}
		b.StopTimer()
		nativeCompress2X8Sink = [2]nativeStateX8{stateA, stateB}
		b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*16), "ns/msg")
	})
}
