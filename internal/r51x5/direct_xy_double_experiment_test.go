package r51x5

import (
	"math/rand"
	"runtime"
	"testing"
)

// ifmaPointDoubleSquareTrickStaticX4 preserves the previous production
// formula as an independently timed control. It intentionally mirrors the old
// static schedule instead of calling the selected production implementation.
func ifmaPointDoubleSquareTrickStaticX4(out, q *IFMAPointX4) error {
	qq := *q
	var A, B, C, D, E, F, G, H, xPlusY IFMAElementX4
	if err := ifmaMultiplyComposableUncheckedX4(&A, &qq.X, &qq.X); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX4(&B, &qq.Y, &qq.Y); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX4(&C, &qq.Z, &qq.Z); err != nil {
		return err
	}
	C.Add(&C, &C)
	D.Negate(&A)
	xPlusY.Add(&qq.X, &qq.Y)
	if err := ifmaMultiplyComposableUncheckedX4(&E, &xPlusY, &xPlusY); err != nil {
		return err
	}
	E.Subtract(&E, &A)
	E.Subtract(&E, &B)
	G.Add(&D, &B)
	F.Subtract(&G, &C)
	H.Subtract(&D, &B)

	var result IFMAPointX4
	if err := ifmaMultiplyComposableUncheckedX4(&result.X, &E, &F); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX4(&result.Y, &G, &H); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX4(&result.T, &E, &H); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX4(&result.Z, &F, &G); err != nil {
		return err
	}
	*out = result
	return nil
}

// ifmaPointDoubleDirectXYStaticX4 mirrors the current production direct-XY
// schedule in a test-only helper. Keeping it separate from
// ifmaPointDoubleSquareTrickStaticX4 above preserves an independently timed
// historical control for the formula A/B.
func ifmaPointDoubleDirectXYStaticX4(out, q *IFMAPointX4) error {
	qq := *q
	var A, B, C, D, E, F, G, H IFMAElementX4
	if err := ifmaMultiplyComposableUncheckedX4(&A, &qq.X, &qq.X); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX4(&B, &qq.Y, &qq.Y); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX4(&C, &qq.Z, &qq.Z); err != nil {
		return err
	}
	C.Add(&C, &C)
	if err := ifmaMultiplyComposableUncheckedX4(&E, &qq.X, &qq.Y); err != nil {
		return err
	}
	E.Add(&E, &E)
	D.Negate(&A)
	G.Add(&D, &B)
	F.Subtract(&G, &C)
	H.Subtract(&D, &B)

	var result IFMAPointX4
	if err := ifmaMultiplyComposableUncheckedX4(&result.X, &E, &F); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX4(&result.Y, &G, &H); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX4(&result.T, &E, &H); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX4(&result.Z, &F, &G); err != nil {
		return err
	}
	*out = result
	return nil
}

func ifmaPointDoubleDirectXYModelX4(out, q *IFMAPointX4) error {
	qq := *q
	var A, B, C, D, E, F, G, H IFMAElementX4
	if err := modelMultiplyComposableX4(&A, &qq.X, &qq.X); err != nil {
		return err
	}
	if err := modelMultiplyComposableX4(&B, &qq.Y, &qq.Y); err != nil {
		return err
	}
	if err := modelMultiplyComposableX4(&C, &qq.Z, &qq.Z); err != nil {
		return err
	}
	C.Add(&C, &C)
	if err := modelMultiplyComposableX4(&E, &qq.X, &qq.Y); err != nil {
		return err
	}
	E.Add(&E, &E)
	D.Negate(&A)
	G.Add(&D, &B)
	F.Subtract(&G, &C)
	H.Subtract(&D, &B)

	var result IFMAPointX4
	if err := modelMultiplyComposableX4(&result.X, &E, &F); err != nil {
		return err
	}
	if err := modelMultiplyComposableX4(&result.Y, &G, &H); err != nil {
		return err
	}
	if err := modelMultiplyComposableX4(&result.T, &E, &H); err != nil {
		return err
	}
	if err := modelMultiplyComposableX4(&result.Z, &F, &G); err != nil {
		return err
	}
	*out = result
	return nil
}

func directXYPointFixtureX4(t *testing.T, rng *rand.Rand, round int) (PointX4, IFMAPointX4) {
	t.Helper()
	torsion := referenceTorsionPoints(t)
	var encoded [X4Lanes][32]byte
	for lane := range encoded {
		point := randomMixedReferencePoint(t, rng, torsion[(round+lane)%len(torsion)])
		copy(encoded[lane][:], point.Bytes())
	}
	var reduced PointX4
	if mask := reduced.SetBytes(&encoded); mask != 0x0f {
		t.Fatalf("direct-XY fixture decode mask=%02x", mask)
	}
	var composable IFMAPointX4
	composable.SetReduced(&reduced)
	return reduced, composable
}

func TestExperimentalIFMADirectXYDoubleX4Differential(t *testing.T) {
	rng := rand.New(rand.NewSource(0x51d1_ec7a))
	for round := 0; round < 64; round++ {
		reduced, got := directXYPointFixtureX4(t, rng, round)
		want := reduced
		for step := 0; step < 32; step++ {
			if err := ifmaPointDoubleDirectXYModelX4(&got, &got); err != nil {
				t.Fatalf("round=%d step=%d: %v", round, step, err)
			}
			want.Double(&want)
			if reducedGot := got.Reduced(); reducedGot != want {
				t.Fatalf("round=%d step=%d: direct-XY/model mismatch", round, step)
			}
			if !isIFMAElementX4(&got.X) || !isIFMAElementX4(&got.Y) ||
				!isIFMAElementX4(&got.Z) || !isIFMAElementX4(&got.T) {
				t.Fatalf("round=%d step=%d: direct-XY output escaped u52", round, step)
			}
		}
	}
}

func TestExperimentalIFMADirectXYDoubleX4Hardware(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	rng := rand.New(rand.NewSource(0x51d1_a4d0))
	for round := 0; round < 256; round++ {
		_, input := directXYPointFixtureX4(t, rng, round)
		var got, want IFMAPointX4
		if err := ifmaPointDoubleDirectXYStaticX4(&got, &input); err != nil {
			t.Fatal(err)
		}
		if err := ifmaPointDoubleDirectXYModelX4(&want, &input); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("round=%d: direct-XY hardware/model representation mismatch", round)
		}
	}
}

func TestExperimentalIFMADirectXYDoubleX4ZeroAllocations(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	rng := rand.New(rand.NewSource(0x51d1_a110))
	_, input := directXYPointFixtureX4(t, rng, 0)
	var out IFMAPointX4
	if allocs := testing.AllocsPerRun(100, func() {
		if err := ifmaPointDoubleDirectXYStaticX4(&out, &input); err != nil {
			panic(err)
		}
	}); allocs != 0 {
		t.Fatalf("direct-XY x4 allocations=%v", allocs)
	}
	benchmarkDirectXYPointX4Sink = out
}

var benchmarkDirectXYPointX4Sink IFMAPointX4

func BenchmarkExperimentalIFMADirectXYDoubleX4(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	rng := rand.New(rand.NewSource(0x51d1_be4c))
	_, _, points, _ := benchmarkMixedPointInputs(b)
	var input IFMAPointX4
	input.SetReduced(&points[int(rng.Uint32())&1])

	b.Run("formula=standard-square-trick", func(b *testing.B) {
		acc := input
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := ifmaPointDoubleSquareTrickStaticX4(&acc, &acc); err != nil {
				b.Fatal(err)
			}
		}
		benchmarkDirectXYPointX4Sink = acc
	})
	b.Run("formula=direct-xy", func(b *testing.B) {
		acc := input
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := ifmaPointDoubleDirectXYStaticX4(&acc, &acc); err != nil {
				b.Fatal(err)
			}
		}
		benchmarkDirectXYPointX4Sink = acc
	})
}
