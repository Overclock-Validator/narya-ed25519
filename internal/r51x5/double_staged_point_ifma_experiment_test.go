package r51x5

import (
	"math/rand"
	"runtime"
	"testing"
)

// ifmaPointDoubleRawStage2ExperimentX4 is a test-only integration of the
// wide Stage-2 leaf. Stage 1 deliberately uses the existing raw multiply four
// times so this A/B isolates deferred carry placement before a larger fused
// Stage-1 kernel is attempted.
func ifmaPointDoubleRawStage2ExperimentX4(out, q *IFMAPointX4) error {
	var workspace ifmaDoubleStage2WorkspaceX4
	ifmaMulRawX4(&workspace[0], &q.X.limbs, &q.X.limbs)
	ifmaMulRawX4(&workspace[1], &q.Y.limbs, &q.Y.limbs)
	ifmaMulRawX4(&workspace[2], &q.Z.limbs, &q.Z.limbs)
	ifmaMulRawX4(&workspace[3], &q.X.limbs, &q.Y.limbs)
	ifmaDoubleStage2ExperimentX4(&workspace)

	e := IFMAElementX4{limbs: LimbsX4(workspace[0])}
	f := IFMAElementX4{limbs: LimbsX4(workspace[1])}
	g := IFMAElementX4{limbs: LimbsX4(workspace[2])}
	h := IFMAElementX4{limbs: LimbsX4(workspace[3])}

	var result IFMAPointX4
	if err := ifmaMultiplyComposableUncheckedX4(&result.X, &e, &f); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX4(&result.Y, &g, &h); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX4(&result.T, &e, &h); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX4(&result.Z, &f, &g); err != nil {
		return err
	}
	*out = result
	return nil
}

// ifmaPointDoubleRawSquareStage2ExperimentX4 adds the symmetry-aware raw
// square to the staged candidate. It still uses four separate Stage-1 calls;
// a future fused Stage 1 would additionally remove those boundaries.
func ifmaPointDoubleRawSquareStage2ExperimentX4(out, q *IFMAPointX4) error {
	var workspace ifmaDoubleStage2WorkspaceX4
	ifmaSquareRawExperimentX4(&workspace[0], &q.X.limbs)
	ifmaSquareRawExperimentX4(&workspace[1], &q.Y.limbs)
	ifmaSquareRawExperimentX4(&workspace[2], &q.Z.limbs)
	ifmaMulRawX4(&workspace[3], &q.X.limbs, &q.Y.limbs)
	ifmaDoubleStage2ExperimentX4(&workspace)

	e := IFMAElementX4{limbs: LimbsX4(workspace[0])}
	f := IFMAElementX4{limbs: LimbsX4(workspace[1])}
	g := IFMAElementX4{limbs: LimbsX4(workspace[2])}
	h := IFMAElementX4{limbs: LimbsX4(workspace[3])}

	var result IFMAPointX4
	if err := ifmaMultiplyComposableUncheckedX4(&result.X, &e, &f); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX4(&result.Y, &g, &h); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX4(&result.T, &e, &h); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX4(&result.Z, &f, &g); err != nil {
		return err
	}
	*out = result
	return nil
}

// ifmaPointDoubleNoCopyExperimentX4 mirrors the current normalized production
// schedule while reading q directly. The output remains local until every
// input read is complete, so exact out==q aliasing does not require the
// current 640-byte qq copy. This control separates copy removal from deferred
// carry placement in the complete point A/B.
func ifmaPointDoubleNoCopyExperimentX4(out, q *IFMAPointX4) error {
	var a, b, c, d, e, f, g, h IFMAElementX4
	if err := ifmaMultiplyComposableUncheckedX4(&a, &q.X, &q.X); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX4(&b, &q.Y, &q.Y); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX4(&c, &q.Z, &q.Z); err != nil {
		return err
	}
	c.Add(&c, &c)
	if err := ifmaMultiplyComposableUncheckedX4(&e, &q.X, &q.Y); err != nil {
		return err
	}
	e.Add(&e, &e)
	d.Negate(&a)
	g.Add(&d, &b)
	f.Subtract(&g, &c)
	h.Subtract(&d, &b)

	var result IFMAPointX4
	if err := ifmaMultiplyComposableUncheckedX4(&result.X, &e, &f); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX4(&result.Y, &g, &h); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX4(&result.T, &e, &h); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX4(&result.Z, &f, &g); err != nil {
		return err
	}
	*out = result
	return nil
}

// ifmaPointAddNoCopyExperimentX4 is the analogous alias-safe control for the
// current extended-point addition. Both inputs remain untouched until the
// local result is complete, so neither 640-byte input copy is required.
func ifmaPointAddNoCopyExperimentX4(out, a, b *IFMAPointX4) error {
	var yMinusX1, yPlusX1, yMinusX2, yPlusX2 IFMAElementX4
	yMinusX1.Subtract(&a.Y, &a.X)
	yPlusX1.Add(&a.Y, &a.X)
	yMinusX2.Subtract(&b.Y, &b.X)
	yPlusX2.Add(&b.Y, &b.X)

	var A, B, C, D, E, F, G, H IFMAElementX4
	if err := ifmaMultiplyComposableUncheckedX4(&A, &yMinusX1, &yMinusX2); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX4(&B, &yPlusX1, &yPlusX2); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX4(&C, &a.T, &b.T); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX4(&C, &C, &ifmaCurve2DX4); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX4(&D, &a.Z, &b.Z); err != nil {
		return err
	}
	D.Add(&D, &D)
	E.Subtract(&B, &A)
	F.Subtract(&D, &C)
	G.Add(&D, &C)
	H.Add(&B, &A)

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

func TestExperimentalIFMARawStage2PointDoubleX4Differential(t *testing.T) {
	requireRawStage2PointIFMA(t)
	rng := rand.New(rand.NewSource(0x51_d02_d1ff))
	for round := 0; round < 256; round++ {
		reduced, input := directXYPointFixtureX4(t, rng, round)
		var got, current IFMAPointX4
		if err := ifmaPointDoubleRawStage2ExperimentX4(&got, &input); err != nil {
			t.Fatalf("round=%d staged: %v", round, err)
		}
		if err := ifmaPointDoubleComposableStaticX4(&current, &input); err != nil {
			t.Fatalf("round=%d current: %v", round, err)
		}
		want := reduced
		want.Double(&want)
		if reducedGot := got.Reduced(); reducedGot != want {
			t.Fatalf("round=%d: staged/scalar mismatch", round)
		}
		if reducedCurrent := current.Reduced(); reducedCurrent != want {
			t.Fatalf("round=%d: current/scalar mismatch", round)
		}
		assertRawStage2PointU52(t, "differential", round, 0, &got)
	}
}

func TestExperimentalIFMARawStage2PointDoubleX4Chaining(t *testing.T) {
	requireRawStage2PointIFMA(t)
	rng := rand.New(rand.NewSource(0x51_d02_c4a1))
	for round := 0; round < 64; round++ {
		reduced, got := directXYPointFixtureX4(t, rng, round)
		want := reduced
		for step := 0; step < 64; step++ {
			if err := ifmaPointDoubleRawStage2ExperimentX4(&got, &got); err != nil {
				t.Fatalf("round=%d step=%d: %v", round, step, err)
			}
			want.Double(&want)
			if reducedGot := got.Reduced(); reducedGot != want {
				t.Fatalf("round=%d step=%d: staged/scalar mismatch", round, step)
			}
			assertRawStage2PointU52(t, "chain", round, step, &got)
		}
	}
}

func TestExperimentalIFMARawSquareStage2PointDoubleX4Differential(t *testing.T) {
	requireRawStage2PointIFMA(t)
	rng := rand.New(rand.NewSource(0x51_d02_5a7e))
	for round := 0; round < 128; round++ {
		reduced, got := directXYPointFixtureX4(t, rng, round)
		want := reduced
		for step := 0; step < 32; step++ {
			if err := ifmaPointDoubleRawSquareStage2ExperimentX4(&got, &got); err != nil {
				t.Fatalf("round=%d step=%d: %v", round, step, err)
			}
			want.Double(&want)
			if got.Reduced() != want {
				t.Fatalf("round=%d step=%d: raw-square Stage2 mismatch", round, step)
			}
			assertRawStage2PointU52(t, "raw-square-chain", round, step, &got)
		}
	}
}

func TestExperimentalIFMARawStage2PointDoubleX4Aliasing(t *testing.T) {
	requireRawStage2PointIFMA(t)
	rng := rand.New(rand.NewSource(0x51_d02_a11a))
	for round := 0; round < 256; round++ {
		_, input := directXYPointFixtureX4(t, rng, round)
		var want IFMAPointX4
		if err := ifmaPointDoubleRawStage2ExperimentX4(&want, &input); err != nil {
			t.Fatal(err)
		}
		got := input
		if err := ifmaPointDoubleRawStage2ExperimentX4(&got, &got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("round=%d: aliased representation mismatch", round)
		}
	}
}

func TestExperimentalIFMANoCopyPointDoubleX4DifferentialAndAliasing(t *testing.T) {
	requireRawStage2PointIFMA(t)
	rng := rand.New(rand.NewSource(0x51_d02_c0f1))
	for round := 0; round < 512; round++ {
		_, input := directXYPointFixtureX4(t, rng, round)
		var want IFMAPointX4
		if err := ifmaPointDoubleComposableStaticX4(&want, &input); err != nil {
			t.Fatal(err)
		}
		got := input
		if err := ifmaPointDoubleNoCopyExperimentX4(&got, &got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("round=%d: no-copy/current representation mismatch", round)
		}
	}
}

func TestExperimentalIFMANoCopyPointAddX4DifferentialAndAliasing(t *testing.T) {
	requireRawStage2PointIFMA(t)
	rng := rand.New(rand.NewSource(0x51_add_c0f1))
	for round := 0; round < 256; round++ {
		_, left := directXYPointFixtureX4(t, rng, 2*round)
		_, right := directXYPointFixtureX4(t, rng, 2*round+1)
		var want IFMAPointX4
		if err := ifmaPointAddComposableStaticX4(&want, &left, &right); err != nil {
			t.Fatal(err)
		}
		leftAlias := left
		if err := ifmaPointAddNoCopyExperimentX4(&leftAlias, &leftAlias, &right); err != nil {
			t.Fatal(err)
		}
		if leftAlias != want {
			t.Fatalf("round=%d: left-alias representation mismatch", round)
		}
		rightAlias := right
		if err := ifmaPointAddNoCopyExperimentX4(&rightAlias, &left, &rightAlias); err != nil {
			t.Fatal(err)
		}
		if rightAlias != want {
			t.Fatalf("round=%d: right-alias representation mismatch", round)
		}
	}
}

func TestExperimentalIFMARawStage2PointDoubleX4U52Envelope(t *testing.T) {
	requireRawStage2PointIFMA(t)
	rng := rand.New(rand.NewSource(0x51_d02_052e))
	for round := 0; round < 4096; round++ {
		input := randomRawStage2PointX4(rng)
		var got, current IFMAPointX4
		if err := ifmaPointDoubleRawStage2ExperimentX4(&got, &input); err != nil {
			t.Fatal(err)
		}
		if err := ifmaPointDoubleComposableStaticX4(&current, &input); err != nil {
			t.Fatal(err)
		}
		if got.Reduced() != current.Reduced() {
			t.Fatalf("round=%d: arbitrary-u52 field mismatch", round)
		}
		assertRawStage2PointU52(t, "u52-envelope", round, 0, &got)
	}
}

func TestExperimentalIFMARawStage2PointDoubleX4ZeroAllocations(t *testing.T) {
	requireRawStage2PointIFMA(t)
	_, state := directXYPointFixtureX4(t, rand.New(rand.NewSource(0x51_d02_a110)), 0)
	if allocs := testing.AllocsPerRun(1000, func() {
		if err := ifmaPointDoubleRawStage2ExperimentX4(&state, &state); err != nil {
			panic(err)
		}
	}); allocs != 0 {
		t.Fatalf("raw-Stage2 point double allocations=%v", allocs)
	}
	benchmarkRawStage2PointSink = state
}

func ifmaRawStage2PreparedRadix64LoopX4(out, start, addend0, addend1 *IFMAPointX4) error {
	state := *start
	for round := 0; round < quadRadix64LoopRounds; round++ {
		if round != 0 {
			for doubling := 0; doubling < quadRadix64LoopDoubles; doubling++ {
				if err := ifmaPointDoubleRawStage2ExperimentX4(&state, &state); err != nil {
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

func ifmaRawSquareStage2PreparedRadix64LoopX4(out, start, addend0, addend1 *IFMAPointX4) error {
	state := *start
	for round := 0; round < quadRadix64LoopRounds; round++ {
		if round != 0 {
			for doubling := 0; doubling < quadRadix64LoopDoubles; doubling++ {
				if err := ifmaPointDoubleRawSquareStage2ExperimentX4(&state, &state); err != nil {
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

func ifmaNoCopyPreparedRadix64LoopX4(out, start, addend0, addend1 *IFMAPointX4) error {
	state := *start
	for round := 0; round < quadRadix64LoopRounds; round++ {
		if round != 0 {
			for doubling := 0; doubling < quadRadix64LoopDoubles; doubling++ {
				if err := ifmaPointDoubleNoCopyExperimentX4(&state, &state); err != nil {
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

func ifmaNoCopyAllPreparedRadix64LoopX4(out, start, addend0, addend1 *IFMAPointX4) error {
	state := *start
	for round := 0; round < quadRadix64LoopRounds; round++ {
		if round != 0 {
			for doubling := 0; doubling < quadRadix64LoopDoubles; doubling++ {
				if err := ifmaPointDoubleNoCopyExperimentX4(&state, &state); err != nil {
					return err
				}
			}
		}
		if err := ifmaPointAddNoCopyExperimentX4(&state, &state, addend0); err != nil {
			return err
		}
		if err := ifmaPointAddNoCopyExperimentX4(&state, &state, addend1); err != nil {
			return err
		}
	}
	*out = state
	return nil
}

func TestExperimentalIFMARawStage2PreparedRadix64LoopX4(t *testing.T) {
	requireRawStage2PointIFMA(t)
	fixture := newQuadRadix64LoopFixture(t)
	start := quadLoopOneActiveIFMAPoint(&fixture.start)
	addend0 := quadLoopOneActiveIFMAPoint(&fixture.addend0)
	addend1 := quadLoopOneActiveIFMAPoint(&fixture.signedAdd1)
	var got IFMAPointX4
	if err := ifmaRawStage2PreparedRadix64LoopX4(&got, &start, &addend0, &addend1); err != nil {
		t.Fatal(err)
	}
	var want Point
	quadRadix64PointLoopScalar(&want, &fixture.start, &fixture.addend0, &fixture.signedAdd1)
	reduced := got.Reduced()
	if reducedPoint := reduced.Lane(0); reducedPoint.Equal(&want) != 1 {
		t.Fatal("raw-Stage2 prepared loop differs from scalar r51")
	}
	assertRawStage2PointU52(t, "prepared-loop", 0, 0, &got)
}

func requireRawStage2PointIFMA(tb testing.TB) {
	tb.Helper()
	if !ExperimentalIFMAAvailable() {
		tb.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
}

func randomRawStage2PointX4(rng *rand.Rand) IFMAPointX4 {
	var point IFMAPointX4
	for _, coordinate := range [...]*IFMAElementX4{&point.X, &point.Y, &point.Z, &point.T} {
		for limb := range coordinate.limbs {
			for lane := range coordinate.limbs[limb] {
				coordinate.limbs[limb][lane] = rng.Uint64() & (ifmaComposableLimbLimit - 1)
			}
		}
	}
	return point
}

func assertRawStage2PointU52(t testing.TB, label string, round, step int, point *IFMAPointX4) {
	t.Helper()
	if !isIFMAElementX4(&point.X) || !isIFMAElementX4(&point.Y) ||
		!isIFMAElementX4(&point.Z) || !isIFMAElementX4(&point.T) {
		t.Fatalf("%s round=%d step=%d: output escaped u52", label, round, step)
	}
}

var benchmarkRawStage2PointSink IFMAPointX4

func BenchmarkExperimentalIFMANoCopyPointAddX4(b *testing.B) {
	requireRawStage2PointIFMA(b)
	_, _, leftPoints, rightPoints := benchmarkMixedPointInputs(b)
	var seed, addend IFMAPointX4
	seed.SetReduced(&leftPoints[0])
	addend.SetReduced(&rightPoints[0])

	b.Run("addition=current", func(b *testing.B) {
		state := seed
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := ifmaPointAddComposableStaticX4(&state, &state, &addend); err != nil {
				b.Fatal(err)
			}
		}
		benchmarkRawStage2PointSink = state
	})

	b.Run("addition=current-no-copy", func(b *testing.B) {
		state := seed
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := ifmaPointAddNoCopyExperimentX4(&state, &state, &addend); err != nil {
				b.Fatal(err)
			}
		}
		benchmarkRawStage2PointSink = state
	})
}

func BenchmarkExperimentalIFMARawStage2PointDoubleX4(b *testing.B) {
	requireRawStage2PointIFMA(b)
	_, _, points, _ := benchmarkMixedPointInputs(b)
	var seed IFMAPointX4
	seed.SetReduced(&points[0])

	b.Run("doubling=current", func(b *testing.B) {
		state := seed
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := ifmaPointDoubleComposableStaticX4(&state, &state); err != nil {
				b.Fatal(err)
			}
		}
		benchmarkRawStage2PointSink = state
	})

	b.Run("doubling=current-no-copy", func(b *testing.B) {
		state := seed
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := ifmaPointDoubleNoCopyExperimentX4(&state, &state); err != nil {
				b.Fatal(err)
			}
		}
		benchmarkRawStage2PointSink = state
	})

	b.Run("doubling=raw-stage2", func(b *testing.B) {
		state := seed
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := ifmaPointDoubleRawStage2ExperimentX4(&state, &state); err != nil {
				b.Fatal(err)
			}
		}
		benchmarkRawStage2PointSink = state
	})

	b.Run("doubling=raw-square-stage2", func(b *testing.B) {
		state := seed
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := ifmaPointDoubleRawSquareStage2ExperimentX4(&state, &state); err != nil {
				b.Fatal(err)
			}
		}
		benchmarkRawStage2PointSink = state
	})
}

func BenchmarkExperimentalIFMARawStage2PreparedRadix64LoopX4(b *testing.B) {
	requireRawStage2PointIFMA(b)
	fixture := newQuadRadix64LoopFixture(b)
	start := quadLoopOneActiveIFMAPoint(&fixture.start)
	addend0 := quadLoopOneActiveIFMAPoint(&fixture.addend0)
	addend1 := quadLoopOneActiveIFMAPoint(&fixture.signedAdd1)

	b.Run("doubling=current", func(b *testing.B) {
		var out IFMAPointX4
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := quadRadix64PointLoopCurrentX4(&out, &start, &addend0, &addend1); err != nil {
				b.Fatal(err)
			}
		}
		benchmarkRawStage2PointSink = out
	})

	b.Run("doubling-and-addition=current-no-copy", func(b *testing.B) {
		var out IFMAPointX4
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := ifmaNoCopyAllPreparedRadix64LoopX4(&out, &start, &addend0, &addend1); err != nil {
				b.Fatal(err)
			}
		}
		benchmarkRawStage2PointSink = out
	})

	b.Run("doubling=current-no-copy", func(b *testing.B) {
		var out IFMAPointX4
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := ifmaNoCopyPreparedRadix64LoopX4(&out, &start, &addend0, &addend1); err != nil {
				b.Fatal(err)
			}
		}
		benchmarkRawStage2PointSink = out
	})

	b.Run("doubling=raw-stage2", func(b *testing.B) {
		var out IFMAPointX4
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := ifmaRawStage2PreparedRadix64LoopX4(&out, &start, &addend0, &addend1); err != nil {
				b.Fatal(err)
			}
		}
		benchmarkRawStage2PointSink = out
	})

	b.Run("doubling=raw-square-stage2", func(b *testing.B) {
		var out IFMAPointX4
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := ifmaRawSquareStage2PreparedRadix64LoopX4(&out, &start, &addend0, &addend1); err != nil {
				b.Fatal(err)
			}
		}
		benchmarkRawStage2PointSink = out
	})
}
