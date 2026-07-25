package r51x5

import (
	"encoding/hex"
	"testing"
)

const (
	quadRadix64LoopRounds  = 43
	quadRadix64LoopDoubles = 6
)

type quadRadix64LoopFixture struct {
	start      Point
	addend0    Point
	addend1    Point
	signedAdd1 Point
	cached0    quadPackedCachedPointX4
	cached1    quadPackedCachedPointX4
}

// newQuadRadix64LoopFixture builds three deterministic mixed-order points and
// gives each a non-unit projective Z. The second cached addend is negated so a
// single loop also covers the signed cached representation used by public
// radix recoding.
func newQuadRadix64LoopFixture(tb testing.TB) quadRadix64LoopFixture {
	tb.Helper()
	var baseEncoding [32]byte
	baseEncoding[0] = 0x58
	for i := 1; i < len(baseEncoding); i++ {
		baseEncoding[i] = 0x66
	}
	var base Point
	if _, err := base.SetBytes(baseEncoding[:]); err != nil {
		tb.Fatal(err)
	}
	torsion0 := quadLoopDecodePoint(tb, pointTestEncodings[10])
	torsion1 := quadLoopDecodePoint(tb, pointTestEncodings[11])
	torsion2 := quadLoopDecodePoint(tb, pointTestEncodings[12])

	var twoBase, threeBase Point
	fixedBasePointDouble(&twoBase, &base)
	fixedBasePointAdd(&threeBase, &twoBase, &base)
	var fixture quadRadix64LoopFixture
	fixedBasePointAdd(&fixture.start, &base, &torsion0)
	fixedBasePointAdd(&fixture.addend0, &twoBase, &torsion1)
	fixedBasePointAdd(&fixture.addend1, &threeBase, &torsion2)

	quadLoopProjectiveScale(tb, &fixture.start, 7)
	quadLoopProjectiveScale(tb, &fixture.addend0, 11)
	quadLoopProjectiveScale(tb, &fixture.addend1, 13)
	fixture.signedAdd1 = signedPointX4Test(&fixture.addend1, true)
	fixture.cached0.setReduced(&fixture.addend0, false)
	fixture.cached1.setReduced(&fixture.addend1, true)
	return fixture
}

func quadLoopDecodePoint(tb testing.TB, encodedHex string) Point {
	tb.Helper()
	encoded, err := hex.DecodeString(encodedHex)
	if err != nil {
		tb.Fatal(err)
	}
	var point Point
	if _, err := point.SetBytes(encoded); err != nil {
		tb.Fatal(err)
	}
	return point
}

func quadLoopProjectiveScale(tb testing.TB, point *Point, scaleByte byte) {
	tb.Helper()
	var encoded [32]byte
	encoded[0] = scaleByte
	var scale Element
	if _, err := scale.SetBytes(encoded[:]); err != nil {
		tb.Fatal(err)
	}
	scaleProjectivePointX4Test(point, scale)
}

func quadRadix64PointLoopScalar(out, start, addend0, addend1 *Point) {
	state := *start
	for round := 0; round < quadRadix64LoopRounds; round++ {
		if round != 0 { // The most-significant radix-64 digit is added directly.
			for doubling := 0; doubling < quadRadix64LoopDoubles; doubling++ {
				fixedBasePointDouble(&state, &state)
			}
		}
		fixedBasePointAdd(&state, &state, addend0)
		fixedBasePointAdd(&state, &state, addend1)
	}
	*out = state
}

func quadRadix64PointLoopModel(out, start *quadPackedPointX4, cached0, cached1 *quadPackedCachedPointX4) error {
	state := *start
	for round := 0; round < quadRadix64LoopRounds; round++ {
		if round != 0 {
			for doubling := 0; doubling < quadRadix64LoopDoubles; doubling++ {
				if err := quadPointDoubleModelX4(&state, &state); err != nil {
					return err
				}
			}
		}
		if err := quadPointAddCachedModelX4(&state, &state, cached0); err != nil {
			return err
		}
		if err := quadPointAddCachedModelX4(&state, &state, cached1); err != nil {
			return err
		}
	}
	*out = state
	return nil
}

func quadRadix64PointLoopHardwareUnchecked(out, start *quadPackedPointX4, cached0, cached1 *quadPackedCachedPointX4) error {
	state := *start
	for round := 0; round < quadRadix64LoopRounds; round++ {
		if round != 0 {
			for doubling := 0; doubling < quadRadix64LoopDoubles; doubling++ {
				if err := quadPointDoubleHardwareUncheckedX4(&state, &state); err != nil {
					return err
				}
			}
		}
		if err := quadPointAddCachedHardwareUncheckedX4(&state, &state, cached0); err != nil {
			return err
		}
		if err := quadPointAddCachedHardwareUncheckedX4(&state, &state, cached1); err != nil {
			return err
		}
	}
	*out = state
	return nil
}

func quadRadix64PointLoopCurrentX4(out, start, addend0, addend1 *IFMAPointX4) error {
	state := *start
	for round := 0; round < quadRadix64LoopRounds; round++ {
		if round != 0 {
			for doubling := 0; doubling < quadRadix64LoopDoubles; doubling++ {
				if err := ifmaPointDoubleComposableStaticX4(&state, &state); err != nil {
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

func TestExperimentalCoordinateParallelRadix64PointLoopX4(t *testing.T) {
	fixture := newQuadRadix64LoopFixture(t)
	var want Point
	quadRadix64PointLoopScalar(&want, &fixture.start, &fixture.addend0, &fixture.signedAdd1)
	assertScalarPointInvariant(t, "radix64-loop scalar", &want)

	start := new(quadPackedPointX4).setReduced(&fixture.start)
	var model quadPackedPointX4
	if err := quadRadix64PointLoopModel(&model, start, &fixture.cached0, &fixture.cached1); err != nil {
		t.Fatal(err)
	}
	assertQuadRadix64LoopPoint(t, "model", &model, &want)

	if !ExperimentalIFMAAvailable() {
		return
	}
	var hardware quadPackedPointX4
	if err := quadRadix64PointLoopHardwareUnchecked(&hardware, start, &fixture.cached0, &fixture.cached1); err != nil {
		t.Fatal(err)
	}
	assertQuadRadix64LoopPoint(t, "quad hardware", &hardware, &want)

	currentStart := quadLoopOneActiveIFMAPoint(&fixture.start)
	currentAdd0 := quadLoopOneActiveIFMAPoint(&fixture.addend0)
	currentAdd1 := quadLoopOneActiveIFMAPoint(&fixture.signedAdd1)
	var current IFMAPointX4
	if err := quadRadix64PointLoopCurrentX4(&current, &currentStart, &currentAdd0, &currentAdd1); err != nil {
		t.Fatal(err)
	}
	currentReduced := current.Reduced()
	currentPoint := currentReduced.Lane(0)
	if currentPoint.Equal(&want) != 1 {
		t.Fatal("current one-active-lane loop differs from scalar r51")
	}
	assertScalarPointInvariant(t, "radix64-loop current", &currentPoint)
}

func TestExperimentalCoordinateParallelRadix64PointLoopX4ZeroAllocations(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("AVX-512 IFMA is unavailable")
	}
	fixture := newQuadRadix64LoopFixture(t)
	start := new(quadPackedPointX4).setReduced(&fixture.start)
	var quadOut quadPackedPointX4
	if allocs := testing.AllocsPerRun(20, func() {
		if err := quadRadix64PointLoopHardwareUnchecked(&quadOut, start, &fixture.cached0, &fixture.cached1); err != nil {
			panic(err)
		}
	}); allocs != 0 {
		t.Fatalf("quad loop allocations=%v want 0", allocs)
	}

	currentStart := quadLoopOneActiveIFMAPoint(&fixture.start)
	currentAdd0 := quadLoopOneActiveIFMAPoint(&fixture.addend0)
	currentAdd1 := quadLoopOneActiveIFMAPoint(&fixture.signedAdd1)
	var currentOut IFMAPointX4
	if allocs := testing.AllocsPerRun(20, func() {
		if err := quadRadix64PointLoopCurrentX4(&currentOut, &currentStart, &currentAdd0, &currentAdd1); err != nil {
			panic(err)
		}
	}); allocs != 0 {
		t.Fatalf("current loop allocations=%v want 0", allocs)
	}
}

func assertQuadRadix64LoopPoint(t *testing.T, label string, got *quadPackedPointX4, want *Point) {
	t.Helper()
	gotPoint := got.reduced()
	if gotPoint.Equal(want) != 1 {
		t.Fatalf("%s loop differs from scalar r51", label)
	}
	assertScalarPointInvariant(t, label, &gotPoint)
}

func quadLoopOneActiveIFMAPoint(point *Point) IFMAPointX4 {
	points := [X4Lanes]Point{
		*point,
		*NewIdentityPoint(),
		*NewIdentityPoint(),
		*NewIdentityPoint(),
	}
	var reduced PointX4
	reduced.SetPoints(&points)
	var result IFMAPointX4
	result.SetReduced(&reduced)
	return result
}

var (
	benchmarkQuadRadix64LoopSink    quadPackedPointX4
	benchmarkCurrentRadix64LoopSink IFMAPointX4
)

func BenchmarkExperimentalCoordinateParallelRadix64PointLoopX4(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skip("AVX-512 IFMA is unavailable")
	}
	fixture := newQuadRadix64LoopFixture(b)
	quadStart := new(quadPackedPointX4).setReduced(&fixture.start)
	currentStart := quadLoopOneActiveIFMAPoint(&fixture.start)
	currentAdd0 := quadLoopOneActiveIFMAPoint(&fixture.addend0)
	currentAdd1 := quadLoopOneActiveIFMAPoint(&fixture.signedAdd1)

	b.Run("quad-packed", func(b *testing.B) {
		var out quadPackedPointX4
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := quadRadix64PointLoopHardwareUnchecked(&out, quadStart, &fixture.cached0, &fixture.cached1); err != nil {
				b.Fatal(err)
			}
		}
		benchmarkQuadRadix64LoopSink = out
	})

	b.Run("current-one-active-lane", func(b *testing.B) {
		var out IFMAPointX4
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := quadRadix64PointLoopCurrentX4(&out, &currentStart, &currentAdd0, &currentAdd1); err != nil {
				b.Fatal(err)
			}
		}
		benchmarkCurrentRadix64LoopSink = out
	})
}
