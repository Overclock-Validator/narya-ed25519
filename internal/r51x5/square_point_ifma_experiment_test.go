package r51x5

import (
	"math/rand"
	"runtime"
	"testing"
)

// ifmaPointDoubleDedicatedSquareStaticX4 is a test-only integration of the
// dedicated square kernel with the current direct-XY point formula. It keeps
// the production normalization boundaries unchanged: A, B, and C use the
// dedicated square, E=XY and the four output products use the general
// multiply-normalize kernel, and every linear operation uses the existing
// composable helpers.
func ifmaPointDoubleDedicatedSquareStaticX4(out, q *IFMAPointX4) error {
	qq := *q
	var A, B, C, D, E, F, G, H IFMAElementX4
	ifmaSquareNormalizedExperimentX4(&A.limbs, &qq.X.limbs)
	ifmaSquareNormalizedExperimentX4(&B.limbs, &qq.Y.limbs)
	ifmaSquareNormalizedExperimentX4(&C.limbs, &qq.Z.limbs)
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

func TestIFMADedicatedSquarePointDoubleX4Differential(t *testing.T) {
	requireDedicatedSquarePointIFMA(t)
	rng := rand.New(rand.NewSource(0x51_5d_d1ff))
	for round := 0; round < 256; round++ {
		reduced, input := directXYPointFixtureX4(t, rng, round)
		var got, current IFMAPointX4
		if err := ifmaPointDoubleDedicatedSquareStaticX4(&got, &input); err != nil {
			t.Fatalf("round=%d dedicated: %v", round, err)
		}
		if err := ifmaPointDoubleComposableStaticX4(&current, &input); err != nil {
			t.Fatalf("round=%d current: %v", round, err)
		}
		if got != current {
			t.Fatalf("round=%d: dedicated/current representation mismatch", round)
		}

		want := reduced
		want.Double(&want)
		if reducedGot := got.Reduced(); reducedGot != want {
			t.Fatalf("round=%d: dedicated/scalar mismatch", round)
		}
		assertDedicatedSquarePointX4U52(t, "differential", round, 0, &got)
	}
}

func TestIFMADedicatedSquarePointDoubleX4Chaining(t *testing.T) {
	requireDedicatedSquarePointIFMA(t)
	rng := rand.New(rand.NewSource(0x51_5d_c4a1))
	for round := 0; round < 64; round++ {
		reduced, got := directXYPointFixtureX4(t, rng, round)
		current := got
		want := reduced
		for step := 0; step < 64; step++ {
			if err := ifmaPointDoubleDedicatedSquareStaticX4(&got, &got); err != nil {
				t.Fatalf("round=%d step=%d dedicated: %v", round, step, err)
			}
			if err := ifmaPointDoubleComposableStaticX4(&current, &current); err != nil {
				t.Fatalf("round=%d step=%d current: %v", round, step, err)
			}
			want.Double(&want)
			if got != current {
				t.Fatalf("round=%d step=%d: dedicated/current representation mismatch", round, step)
			}
			if reducedGot := got.Reduced(); reducedGot != want {
				t.Fatalf("round=%d step=%d: dedicated/scalar mismatch", round, step)
			}
			assertDedicatedSquarePointX4U52(t, "chain", round, step, &got)
		}
	}
}

func TestIFMADedicatedSquarePointDoubleX4Aliasing(t *testing.T) {
	requireDedicatedSquarePointIFMA(t)
	rng := rand.New(rand.NewSource(0x51_5d_a11a))
	for round := 0; round < 256; round++ {
		_, input := directXYPointFixtureX4(t, rng, round)
		var want IFMAPointX4
		if err := ifmaPointDoubleDedicatedSquareStaticX4(&want, &input); err != nil {
			t.Fatalf("round=%d out-of-place: %v", round, err)
		}
		got := input
		if err := ifmaPointDoubleDedicatedSquareStaticX4(&got, &got); err != nil {
			t.Fatalf("round=%d aliased: %v", round, err)
		}
		if got != want {
			t.Fatalf("round=%d: aliased representation mismatch", round)
		}
	}
}

func TestIFMADedicatedSquarePointDoubleX4U52Envelope(t *testing.T) {
	requireDedicatedSquarePointIFMA(t)
	rng := rand.New(rand.NewSource(0x51_5d_052e))
	for round := 0; round < 4096; round++ {
		input := randomDedicatedSquarePointX4(rng)
		var got, current IFMAPointX4
		if err := ifmaPointDoubleDedicatedSquareStaticX4(&got, &input); err != nil {
			t.Fatalf("round=%d dedicated: %v", round, err)
		}
		if err := ifmaPointDoubleComposableStaticX4(&current, &input); err != nil {
			t.Fatalf("round=%d current: %v", round, err)
		}
		if got != current {
			t.Fatalf("round=%d: arbitrary-u52 representation mismatch", round)
		}
		assertDedicatedSquarePointX4U52(t, "u52-envelope", round, 0, &got)
	}
}

func TestIFMADedicatedSquarePointDoubleX4ZeroAllocations(t *testing.T) {
	requireDedicatedSquarePointIFMA(t)
	rng := rand.New(rand.NewSource(0x51_5d_a110))
	_, state := directXYPointFixtureX4(t, rng, 0)
	if allocs := testing.AllocsPerRun(1000, func() {
		if err := ifmaPointDoubleDedicatedSquareStaticX4(&state, &state); err != nil {
			panic(err)
		}
	}); allocs != 0 {
		t.Fatalf("dedicated-square point double allocations=%v", allocs)
	}
	benchmarkDedicatedSquarePointX4Sink[0] = state
}

func ifmaDedicatedSquarePreparedRadix64LoopX4(out, start, addend0, addend1 *IFMAPointX4) error {
	state := *start
	for round := 0; round < quadRadix64LoopRounds; round++ {
		if round != 0 {
			for doubling := 0; doubling < quadRadix64LoopDoubles; doubling++ {
				if err := ifmaPointDoubleDedicatedSquareStaticX4(&state, &state); err != nil {
					return err
				}
			}
		}
		if err := ifmaPointAddComposableStaticX4(&state, &state, addend0); err != nil {
			return err
		}
		if err := ifmaPointAddComposableStaticX4(&state, &state, addend1); err != nil {
			return err
		}
	}
	*out = state
	return nil
}

func TestIFMADedicatedSquarePreparedRadix64LoopX4(t *testing.T) {
	requireDedicatedSquarePointIFMA(t)
	fixture := newQuadRadix64LoopFixture(t)
	start := quadLoopOneActiveIFMAPoint(&fixture.start)
	addend0 := quadLoopOneActiveIFMAPoint(&fixture.addend0)
	addend1 := quadLoopOneActiveIFMAPoint(&fixture.signedAdd1)
	var got, current IFMAPointX4
	if err := ifmaDedicatedSquarePreparedRadix64LoopX4(&got, &start, &addend0, &addend1); err != nil {
		t.Fatal(err)
	}
	if err := quadRadix64PointLoopCurrentX4(&current, &start, &addend0, &addend1); err != nil {
		t.Fatal(err)
	}
	if got != current {
		t.Fatal("dedicated/current prepared-loop representation mismatch")
	}

	var want Point
	quadRadix64PointLoopScalar(&want, &fixture.start, &fixture.addend0, &fixture.signedAdd1)
	reduced := got.Reduced()
	if reducedPoint := reduced.Lane(0); reducedPoint.Equal(&want) != 1 {
		t.Fatal("dedicated prepared loop differs from scalar r51")
	}
	assertDedicatedSquarePointX4U52(t, "prepared-loop", 0, 0, &got)
}

func requireDedicatedSquarePointIFMA(tb testing.TB) {
	tb.Helper()
	if !ExperimentalIFMAAvailable() {
		tb.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
}

func randomDedicatedSquarePointX4(rng *rand.Rand) IFMAPointX4 {
	var point IFMAPointX4
	coordinates := [...]*IFMAElementX4{&point.X, &point.Y, &point.Z, &point.T}
	for _, coordinate := range coordinates {
		for limb := range coordinate.limbs {
			for lane := range coordinate.limbs[limb] {
				coordinate.limbs[limb][lane] = rng.Uint64() & squareIFMAExperimentU52Mask
			}
		}
	}
	return point
}

func assertDedicatedSquarePointX4U52(t *testing.T, label string, round, step int, point *IFMAPointX4) {
	t.Helper()
	if !isIFMAElementX4(&point.X) || !isIFMAElementX4(&point.Y) ||
		!isIFMAElementX4(&point.Z) || !isIFMAElementX4(&point.T) {
		t.Fatalf("%s round=%d step=%d: output escaped u52", label, round, step)
	}
}

func dedicatedSquarePointBenchmarkInputs(b *testing.B) [4]IFMAPointX4 {
	b.Helper()
	_, _, points, otherPoints := benchmarkMixedPointInputs(b)
	var states [4]IFMAPointX4
	states[0].SetReduced(&points[0])
	states[1].SetReduced(&points[1])
	states[2].SetReduced(&otherPoints[0])
	states[3].SetReduced(&otherPoints[1])
	return states
}

var benchmarkDedicatedSquarePointX4Sink [4]IFMAPointX4

func BenchmarkIFMADedicatedSquarePointDoubleX4(b *testing.B) {
	requireDedicatedSquarePointIFMA(b)

	b.Run("kernel=current-general-square/dependency=dependent", func(b *testing.B) {
		state := dedicatedSquarePointBenchmarkInputs(b)[0]
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := ifmaPointDoubleComposableStaticX4(&state, &state); err != nil {
				b.Fatal(err)
			}
		}
		benchmarkDedicatedSquarePointX4Sink[0] = state
	})

	b.Run("kernel=dedicated-square/dependency=dependent", func(b *testing.B) {
		state := dedicatedSquarePointBenchmarkInputs(b)[0]
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := ifmaPointDoubleDedicatedSquareStaticX4(&state, &state); err != nil {
				b.Fatal(err)
			}
		}
		benchmarkDedicatedSquarePointX4Sink[0] = state
	})

	b.Run("kernel=current-general-square/dependency=independent-4", func(b *testing.B) {
		states := dedicatedSquarePointBenchmarkInputs(b)
		b.ReportAllocs()
		b.ReportMetric(4, "doubles/op")
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for state := range states {
				if err := ifmaPointDoubleComposableStaticX4(&states[state], &states[state]); err != nil {
					b.Fatal(err)
				}
			}
		}
		benchmarkDedicatedSquarePointX4Sink = states
	})

	b.Run("kernel=dedicated-square/dependency=independent-4", func(b *testing.B) {
		states := dedicatedSquarePointBenchmarkInputs(b)
		b.ReportAllocs()
		b.ReportMetric(4, "doubles/op")
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for state := range states {
				if err := ifmaPointDoubleDedicatedSquareStaticX4(&states[state], &states[state]); err != nil {
					b.Fatal(err)
				}
			}
		}
		benchmarkDedicatedSquarePointX4Sink = states
	})
}

func BenchmarkIFMADedicatedSquarePreparedRadix64LoopX4(b *testing.B) {
	requireDedicatedSquarePointIFMA(b)
	fixture := newQuadRadix64LoopFixture(b)
	start := quadLoopOneActiveIFMAPoint(&fixture.start)
	addend0 := quadLoopOneActiveIFMAPoint(&fixture.addend0)
	addend1 := quadLoopOneActiveIFMAPoint(&fixture.signedAdd1)

	b.Run("doubling=current-general-square", func(b *testing.B) {
		var out IFMAPointX4
		b.ReportAllocs()
		b.ReportMetric(252, "doubles/op")
		b.ReportMetric(86, "adds/op")
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := quadRadix64PointLoopCurrentX4(&out, &start, &addend0, &addend1); err != nil {
				b.Fatal(err)
			}
		}
		benchmarkDedicatedSquarePointX4Sink[0] = out
	})

	b.Run("doubling=dedicated-square", func(b *testing.B) {
		var out IFMAPointX4
		b.ReportAllocs()
		b.ReportMetric(252, "doubles/op")
		b.ReportMetric(86, "adds/op")
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := ifmaDedicatedSquarePreparedRadix64LoopX4(&out, &start, &addend0, &addend1); err != nil {
				b.Fatal(err)
			}
		}
		benchmarkDedicatedSquarePointX4Sink[0] = out
	})
}
