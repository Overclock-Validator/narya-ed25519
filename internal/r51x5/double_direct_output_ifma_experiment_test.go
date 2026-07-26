package r51x5

import (
	"math/rand"
	"runtime"
	"testing"
)

// TestIFMAPointDoubleDirectOutputX8Differential isolates the cost of the
// current Go scaffold's temporary IFMAPointX8 and final 1,280-byte copy. The
// field kernels and formula are intentionally unchanged. This is a regime
// experiment for native-wide x8 hardware, not a second arithmetic formula.
func TestIFMAPointDoubleDirectOutputX8Differential(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	rng := rand.New(rand.NewSource(0x51_d0_2026))
	for round := 0; round < 4096; round++ {
		input := randomSquareIFMAPointX8(rng)
		var got, want IFMAPointX8
		if err := ifmaPointDoubleDirectOutputExperimentX8(&got, &input); err != nil {
			t.Fatal(err)
		}
		if err := ifmaPointDoubleComposableStaticX8(&want, &input); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("round %d: direct-output/current representation mismatch", round)
		}

		alias := input
		if err := ifmaPointDoubleDirectOutputExperimentX8(&alias, &alias); err != nil {
			t.Fatal(err)
		}
		if alias != want {
			t.Fatalf("round %d: aliased direct-output/current representation mismatch", round)
		}
	}
}

func TestIFMAPointDoubleDirectOutputX8ZeroAllocations(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	rng := rand.New(rand.NewSource(0x51_d0_a110))
	state := randomSquareIFMAPointX8(rng)
	if allocs := testing.AllocsPerRun(1000, func() {
		if err := ifmaPointDoubleDirectOutputExperimentX8(&state, &state); err != nil {
			panic(err)
		}
	}); allocs != 0 {
		t.Fatalf("direct-output x8 point double allocations=%v", allocs)
	}
	benchmarkComposablePointX8Sink = state
}

func BenchmarkIFMAPointDoubleDirectOutputX8(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	reduced, _, _, _ := benchmarkMixedPointInputs(b)
	var seed IFMAPointX8
	seed.SetReduced(&reduced)

	b.Run("scaffold=current-temporary-copy", func(b *testing.B) {
		state := seed
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := ifmaPointDoubleComposableStaticX8(&state, &state); err != nil {
				b.Fatal(err)
			}
		}
		benchmarkComposablePointX8Sink = state
	})
	b.Run("scaffold=direct-output", func(b *testing.B) {
		state := seed
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := ifmaPointDoubleDirectOutputExperimentX8(&state, &state); err != nil {
				b.Fatal(err)
			}
		}
		benchmarkComposablePointX8Sink = state
	})
}

func ifmaPointDoubleDirectOutputExperimentX8(out, q *IFMAPointX8) error {
	var A, B, C, D, E, F, G, H IFMAElementX8
	if err := ifmaMultiplyComposableUncheckedX8(&A, &q.X, &q.X); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX8(&B, &q.Y, &q.Y); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX8(&C, &q.Z, &q.Z); err != nil {
		return err
	}
	C.Add(&C, &C)
	if err := ifmaMultiplyComposableUncheckedX8(&E, &q.X, &q.Y); err != nil {
		return err
	}
	E.Add(&E, &E)
	D.Negate(&A)
	G.Add(&D, &B)
	F.Subtract(&G, &C)
	H.Subtract(&D, &B)

	// q is dead at this point. Exact out==q aliasing is therefore safe, and
	// writing through avoids both zeroing a temporary point and copying it.
	if err := ifmaMultiplyComposableUncheckedX8(&out.X, &E, &F); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX8(&out.Y, &G, &H); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX8(&out.T, &E, &H); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX8(&out.Z, &F, &G); err != nil {
		return err
	}
	return nil
}
