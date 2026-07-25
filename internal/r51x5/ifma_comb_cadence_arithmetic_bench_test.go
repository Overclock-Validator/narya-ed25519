package r51x5

import (
	"fmt"
	"runtime"
	"testing"
)

type ifmaCombCadenceArithmeticCaseX4 struct {
	width int
	adds  int
}

var ifmaCombCadenceArithmeticCasesX4 = [...]ifmaCombCadenceArithmeticCaseX4{
	// With no intervening additions, repeated six-double blocks collapse
	// into one continuous dependent doubling chain. Keep this case in the
	// same runner so it is a structural reference rather than a second
	// implementation of the loop.
	{width: 6, adds: 0},
	{width: 0, adds: 1},
	{width: 0, adds: 2},
	{width: 1, adds: 1},
	{width: 1, adds: 2},
	{width: 2, adds: 1},
	{width: 2, adds: 2},
	{width: 4, adds: 1},
	{width: 4, adds: 2},
	{width: 6, adds: 1},
	{width: 6, adds: 2},
	{width: 8, adds: 1},
	{width: 8, adds: 2},
	{width: 10, adds: 1},
	{width: 10, adds: 2},
}

type ifmaCombCadenceArithmeticFixtureX4 struct {
	initial IFMAPointX4
	addends [2]PointX4
	cached  [2]fixedBaseIFMACachedX4
}

// newIFMACombCadenceArithmeticFixtureX4 prepares two lane-varying signed
// affine-cached operands. Table construction, lookup, and sign application all
// happen here so the benchmark times only the dependent point arithmetic.
func newIFMACombCadenceArithmeticFixtureX4(tb testing.TB) ifmaCombCadenceArithmeticFixtureX4 {
	tb.Helper()
	base, _ := fixedBaseGenerator(tb)
	table := BuildExperimentalFixedBaseCombTable(&base, 4)

	digits := [2][X4Lanes]int8{
		{1, -2, 3, -4},
		{-5, 6, -7, 8},
	}
	var rounds [2]RadixRoundX4
	for add := range rounds {
		for lane, digit := range digits[add] {
			setRadixRoundDigitX4(&rounds[add], lane, digit)
		}
	}

	var multiples [8]Point
	multiples[0] = base
	for index := 1; index < len(multiples); index++ {
		fixedBasePointAdd(&multiples[index], &multiples[index-1], &base)
	}

	var initialPoints [X4Lanes]Point
	for lane := range initialPoints {
		// Start away from the selected small multiples so the first block does
		// not immediately create an identity lane.
		initialPoints[lane] = multiples[7-lane]
	}
	var initial PointX4
	initial.SetPoints(&initialPoints)

	var fixture ifmaCombCadenceArithmeticFixtureX4
	fixture.initial.SetReduced(&initial)
	for add := range fixture.cached {
		selectFixedBaseIFMACachedX4(&fixture.cached[add], table, 0, &rounds[add], 0x0f)

		var points [X4Lanes]Point
		for lane, digit := range digits[add] {
			magnitude := int(digit)
			if magnitude < 0 {
				magnitude = -magnitude
			}
			points[lane] = multiples[magnitude-1]
			if digit < 0 {
				x, t := points[lane].X, points[lane].T
				points[lane].X.Negate(&x)
				points[lane].T.Negate(&t)
			}
		}
		fixture.addends[add].SetPoints(&points)
	}
	return fixture
}

// runIFMACombCadenceArithmeticBlockX4 applies one dependent D^width A^adds
// block. The addends are already selected and signed affine-cached points.
func runIFMACombCadenceArithmeticBlockX4(
	state *IFMAPointX4,
	cached *[2]fixedBaseIFMACachedX4,
	width, adds int,
) error {
	for doubling := 0; doubling < width; doubling++ {
		if err := ifmaPointDoubleComposableStaticX4(state, state); err != nil {
			return err
		}
	}
	for add := 0; add < adds; add++ {
		if err := addFixedBaseIFMACachedX4(state, state, &cached[add]); err != nil {
			return err
		}
	}
	return nil
}

func TestIFMACombCadenceArithmeticX4OneBlockMatchesScalar(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	fixture := newIFMACombCadenceArithmeticFixtureX4(t)
	initial := fixture.initial.Reduced()
	for _, test := range ifmaCombCadenceArithmeticCasesX4 {
		t.Run(fmt.Sprintf("width=%d/adds=%d", test.width, test.adds), func(t *testing.T) {
			got := fixture.initial
			if err := runIFMACombCadenceArithmeticBlockX4(&got, &fixture.cached, test.width, test.adds); err != nil {
				t.Fatal(err)
			}

			want := initial
			for doubling := 0; doubling < test.width; doubling++ {
				want.Double(&want)
			}
			for add := 0; add < test.adds; add++ {
				want.Add(&want, &fixture.addends[add])
			}
			gotReduced := got.Reduced()
			if equality := gotReduced.Equal(&want); equality != 0x0f {
				t.Fatalf("equality mask=%02x want=0f", equality)
			}
		})
	}
}

func TestIFMACombCadenceArithmeticX4ZeroAllocations(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	fixture := newIFMACombCadenceArithmeticFixtureX4(t)
	for _, test := range ifmaCombCadenceArithmeticCasesX4 {
		t.Run(fmt.Sprintf("width=%d/adds=%d", test.width, test.adds), func(t *testing.T) {
			state := fixture.initial
			if allocs := testing.AllocsPerRun(100, func() {
				if err := runIFMACombCadenceArithmeticBlockX4(&state, &fixture.cached, test.width, test.adds); err != nil {
					panic(err)
				}
			}); allocs != 0 {
				t.Fatalf("allocations=%v want=0", allocs)
			}
			benchmarkIFMACombCadenceArithmeticSinkX4 = state
		})
	}
}

var benchmarkIFMACombCadenceArithmeticSinkX4 IFMAPointX4

// BenchmarkIFMACombCadenceArithmeticX4 isolates the dependent arithmetic
// cadence used by shared-chain comb/window schedules. Each benchmark iteration
// applies width consecutive doublings and then one or two already-selected
// affine-cached additions. The width=6/adds=0 case is the continuous-doubling
// reference through the identical repeated-block runner.
func BenchmarkIFMACombCadenceArithmeticX4(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	b.StopTimer()
	fixture := newIFMACombCadenceArithmeticFixtureX4(b)

	for _, test := range ifmaCombCadenceArithmeticCasesX4 {
		name := fmt.Sprintf("width=%d/adds=%d", test.width, test.adds)
		if test.adds == 0 {
			name += "/reference=continuous-doubling"
		}
		b.Run(name, func(b *testing.B) {
			state := fixture.initial
			b.ReportAllocs()
			b.ReportMetric(float64(test.width), "doublings/op")
			b.ReportMetric(float64(test.adds), "cached-adds/op")
			b.ReportMetric(X4Lanes, "lanes/op")
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				if err := runIFMACombCadenceArithmeticBlockX4(&state, &fixture.cached, test.width, test.adds); err != nil {
					b.Fatal(err)
				}
			}
			benchmarkIFMACombCadenceArithmeticSinkX4 = state
		})
	}
}
