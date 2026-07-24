package r51x5

import (
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"testing"
)

func TestRoundMajorRecodingPreservesEveryLane(t *testing.T) {
	values := scalarWindowSignedLaneValues()
	var scalars8 [X8Lanes]SignedMagnitude
	for lane := range scalars8 {
		scalars8[lane] = signedMagnitudeFromTestBig(values[lane])
	}

	for _, radixBits := range []uint{4, 5, 6} {
		recoded8 := RecodeRegularRadixX8(&scalars8, radixBits)
		assertRoundMajorX8MatchesLaneRecoding(t, &recoded8, &scalars8)

		for half := 0; half < 2; half++ {
			var scalars4 [X4Lanes]SignedMagnitude
			for lane := range scalars4 {
				scalars4[lane] = scalars8[half*X4Lanes+lane]
			}
			recoded4 := RecodeRegularRadixX4(&scalars4, radixBits)
			assertRoundMajorX4MatchesLaneRecoding(t, &recoded4, &scalars4)
		}
	}
}

func TestSelectFullTablePublicExhaustiveSignedDigits(t *testing.T) {
	rng := rand.New(rand.NewSource(0x51e1ec7))
	torsion := referenceTorsionPoints(t)
	refs, bases8 := scalarWindowMixedBasesX8(t, rng, &torsion)

	for _, radixBits := range []uint{4, 5, 6} {
		table8 := BuildFullTableX8(&bases8, radixBits)
		half := 1 << (radixBits - 1)
		for start := -half; start <= half; start += X8Lanes {
			var round8 RadixRoundX8
			var digits [X8Lanes]int8
			for lane := range digits {
				digit := start + lane
				if digit > half {
					digit = -half + (digit - half - 1)
				}
				digits[lane] = int8(digit)
				setRadixRoundDigitX8(&round8, lane, digits[lane])
			}

			for _, active := range []uint8{0, 0x01, 0x55, 0xaa, 0x7f, 0xff} {
				var got8 PointX8
				SelectFullTableX8Public(&got8, &table8, &round8, active)
				for lane := 0; lane < X8Lanes; lane++ {
					got := got8.Lane(lane)
					if active&(1<<lane) == 0 {
						if got.IsIdentity() != 1 {
							t.Fatalf("radix %d start %d active %02x lane %d is not identity", 1<<radixBits, start, active, lane)
						}
						continue
					}
					want := exactReferenceIntegerMult(refs[lane], big.NewInt(int64(digits[lane])))
					assertScalarPointMatchesReference(t, fmt.Sprintf("radix %d start %d active %02x lane %d", 1<<radixBits, start, active, lane), &got, want)
				}
			}

			assertSelectX8MatchesTwoX4(t, &bases8, &round8, radixBits)
		}
	}
}

func TestSelectFullTablePublicPreservesReducedZeroOnNegation(t *testing.T) {
	identity8 := identityPointX8Value()
	table8 := BuildFullTableX8(&identity8, 5)
	var round8 RadixRoundX8
	for lane := 0; lane < X8Lanes; lane++ {
		setRadixRoundDigitX8(&round8, lane, -int8(lane%16+1))
	}
	var got8 PointX8
	SelectFullTableX8Public(&got8, &table8, &round8, 0xff)
	if mask := got8.IsIdentity(); mask != 0xff {
		t.Fatalf("x8 negative identity mask=%02x", mask)
	}
	if !IsReducedX8(got8.X.limbs) || !IsReducedX8(got8.T.limbs) {
		t.Fatal("x8 negative identity produced unreduced zero coordinates")
	}

	identity4 := identityPointX4Value()
	table4 := BuildFullTableX4(&identity4, 5)
	var round4 RadixRoundX4
	for lane := 0; lane < X4Lanes; lane++ {
		setRadixRoundDigitX4(&round4, lane, -int8(lane+1))
	}
	var got4 PointX4
	SelectFullTableX4Public(&got4, &table4, &round4, 0x0f)
	if mask := got4.IsIdentity(); mask != 0x0f {
		t.Fatalf("x4 negative identity mask=%02x", mask)
	}
	if !IsReducedX4(got4.X.limbs) || !IsReducedX4(got4.T.limbs) {
		t.Fatal("x4 negative identity produced unreduced zero coordinates")
	}
}

func TestSelectFullTablePublicOutputMayAliasTable(t *testing.T) {
	bases4, _, _, _ := scalarWindowBenchmarkFixtures(t)
	table := BuildFullTableX4(&bases4, 5)
	var round RadixRoundX4
	for lane, digit := range []int8{-16, 1, -7, 12} {
		setRadixRoundDigitX4(&round, lane, digit)
	}
	var want PointX4
	SelectFullTableX4Public(&want, &table, &round, 0x0f)

	aliasTable := table
	SelectFullTableX4Public(&aliasTable.points[0], &aliasTable, &round, 0x0f)
	if mask := aliasTable.points[0].Equal(&want); mask != 0x0f {
		t.Fatalf("aliased selection equality mask=%02x", mask)
	}
}

func TestSelectFullTablePublicRejectsActiveInconsistentMetadata(t *testing.T) {
	base4, _, _, _ := scalarWindowBenchmarkFixtures(t)
	table := BuildFullTableX4(&base4, 4)
	tests := []RadixRoundX4{
		{Magnitude: [X4Lanes]uint8{1}},
		{NonzeroMask: 1},
		{Magnitude: [X4Lanes]uint8{9}, NonzeroMask: 1},
		{NegativeMask: 1},
	}
	for index := range tests {
		t.Run(fmt.Sprintf("case=%d", index), func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("selection accepted inconsistent active metadata")
				}
			}()
			var got PointX4
			SelectFullTableX4Public(&got, &table, &tests[index], 1)
		})
	}

	// Metadata in inactive lanes is intentionally ignored.
	round := RadixRoundX4{Magnitude: [X4Lanes]uint8{0, 255}, NonzeroMask: 2, NegativeMask: 2}
	var got PointX4
	SelectFullTableX4Public(&got, &table, &round, 1)
	if mask := got.IsIdentity(); mask != 0x0f {
		t.Fatalf("inactive malformed metadata changed output: identity mask=%02x", mask)
	}
}

func TestExperimentalIFMAScalarLoopsUnavailablePreserveOutput(t *testing.T) {
	if ExperimentalIFMAAvailable() {
		t.Skip("unavailable-path test")
	}
	base4, base8, scalars4, scalars8 := scalarWindowBenchmarkFixtures(t)
	table4 := BuildFullTableX4(&base4, 4)
	recoded4 := RecodeRegularRadixX4(&scalars4, 4)
	got4 := base4
	if err := ExperimentalIFMAScalarMultLoopX4(&got4, &table4, &recoded4, 0x0f); !errors.Is(err, ErrIFMAUnavailable) {
		t.Fatalf("x4 error=%v", err)
	}
	if mask := got4.Equal(&base4); mask != 0x0f {
		t.Fatalf("x4 unavailable path changed output: mask=%02x", mask)
	}

	table8 := BuildFullTableX8(&base8, 5)
	recoded8 := RecodeRegularRadixX8(&scalars8, 5)
	got8 := base8
	if err := ExperimentalIFMAScalarMultLoopX8(&got8, &table8, &recoded8, 0xff); !errors.Is(err, ErrIFMAUnavailable) {
		t.Fatalf("x8 error=%v", err)
	}
	if mask := got8.Equal(&base8); mask != 0xff {
		t.Fatalf("x8 unavailable path changed output: mask=%02x", mask)
	}
}

func assertRoundMajorX8MatchesLaneRecoding(t *testing.T, got *RadixDigitsX8, scalars *[X8Lanes]SignedMagnitude) {
	t.Helper()
	maxRounds := 0
	var expected [X8Lanes][]int8
	for lane := range scalars {
		expected[lane] = RecodeRegularRadix(scalars[lane], got.RadixBits)
		if len(expected[lane]) > maxRounds {
			maxRounds = len(expected[lane])
		}
	}
	if len(got.Rounds) != maxRounds {
		t.Fatalf("x8 rounds=%d want=%d", len(got.Rounds), maxRounds)
	}
	for round := range got.Rounds {
		for lane := 0; lane < X8Lanes; lane++ {
			var want int8
			if round < len(expected[lane]) {
				want = expected[lane][round]
			}
			if digit := got.Rounds[round].Digit(lane); digit != want {
				t.Fatalf("x8 round %d lane %d digit=%d want=%d", round, lane, digit, want)
			}
			assertRoundMetadata(t, got.Rounds[round].Magnitude[lane], got.Rounds[round].NonzeroMask, got.Rounds[round].NegativeMask, lane, want)
		}
	}
}

func assertRoundMajorX4MatchesLaneRecoding(t *testing.T, got *RadixDigitsX4, scalars *[X4Lanes]SignedMagnitude) {
	t.Helper()
	maxRounds := 0
	var expected [X4Lanes][]int8
	for lane := range scalars {
		expected[lane] = RecodeRegularRadix(scalars[lane], got.RadixBits)
		if len(expected[lane]) > maxRounds {
			maxRounds = len(expected[lane])
		}
	}
	if len(got.Rounds) != maxRounds {
		t.Fatalf("x4 rounds=%d want=%d", len(got.Rounds), maxRounds)
	}
	for round := range got.Rounds {
		for lane := 0; lane < X4Lanes; lane++ {
			var want int8
			if round < len(expected[lane]) {
				want = expected[lane][round]
			}
			if digit := got.Rounds[round].Digit(lane); digit != want {
				t.Fatalf("x4 round %d lane %d digit=%d want=%d", round, lane, digit, want)
			}
			assertRoundMetadata(t, got.Rounds[round].Magnitude[lane], got.Rounds[round].NonzeroMask, got.Rounds[round].NegativeMask, lane, want)
		}
	}
}

func assertRoundMetadata(t *testing.T, magnitude uint8, nonzeroMask, negativeMask uint8, lane int, digit int8) {
	t.Helper()
	wantMagnitude, wantNegative := signedDigitMagnitude(digit)
	if magnitude != wantMagnitude {
		t.Fatalf("lane %d magnitude=%d want=%d", lane, magnitude, wantMagnitude)
	}
	if got := nonzeroMask&(1<<lane) != 0; got != (digit != 0) {
		t.Fatalf("lane %d nonzero=%t want=%t", lane, got, digit != 0)
	}
	if got := negativeMask&(1<<lane) != 0; got != wantNegative {
		t.Fatalf("lane %d negative=%t want=%t", lane, got, wantNegative)
	}
}

func assertSelectX8MatchesTwoX4(t *testing.T, base8 *PointX8, round8 *RadixRoundX8, radixBits uint) {
	t.Helper()
	table8 := BuildFullTableX8(base8, radixBits)
	var got8 PointX8
	SelectFullTableX8Public(&got8, &table8, round8, 0xff)

	for half := 0; half < 2; half++ {
		var points4 [X4Lanes]Point
		var round4 RadixRoundX4
		for lane := 0; lane < X4Lanes; lane++ {
			lane8 := half*X4Lanes + lane
			points4[lane] = base8.Lane(lane8)
			setRadixRoundDigitX4(&round4, lane, round8.Digit(lane8))
		}
		var base4 PointX4
		base4.SetPoints(&points4)
		table4 := BuildFullTableX4(&base4, radixBits)
		var got4 PointX4
		SelectFullTableX4Public(&got4, &table4, &round4, 0x0f)
		for lane := 0; lane < X4Lanes; lane++ {
			point8 := got8.Lane(half*X4Lanes + lane)
			point4 := got4.Lane(lane)
			if point8.Equal(&point4) != 1 {
				t.Fatalf("radix %d half %d lane %d x8/two-x4 mismatch", 1<<radixBits, half, lane)
			}
		}
	}
}

var (
	publicSelectPointX4Sink PointX4
	publicSelectPointX8Sink PointX8
)

func BenchmarkPublicFullTableSelect(b *testing.B) {
	base4, base8, scalars4, scalars8 := scalarWindowBenchmarkFixtures(b)
	for _, radixBits := range []uint{4, 5, 6} {
		table4 := BuildFullTableX4(&base4, radixBits)
		rounds4 := RecodeRegularRadixX4(&scalars4, radixBits).Rounds
		b.Run(fmt.Sprintf("x4/radix=%d/implementation=direct-soa", 1<<radixBits), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				SelectFullTableX4Public(&publicSelectPointX4Sink, &table4, &rounds4[i%len(rounds4)], 0x0f)
			}
		})
		b.Run(fmt.Sprintf("x4/radix=%d/implementation=lane-oracle", 1<<radixBits), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				selectFullTableLaneOracleX4(&publicSelectPointX4Sink, &table4, &rounds4[i%len(rounds4)], 0x0f)
			}
		})

		table8 := BuildFullTableX8(&base8, radixBits)
		rounds8 := RecodeRegularRadixX8(&scalars8, radixBits).Rounds
		b.Run(fmt.Sprintf("x8/radix=%d/implementation=direct-soa", 1<<radixBits), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				SelectFullTableX8Public(&publicSelectPointX8Sink, &table8, &rounds8[i%len(rounds8)], 0xff)
			}
		})
		b.Run(fmt.Sprintf("x8/radix=%d/implementation=lane-oracle", 1<<radixBits), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				selectFullTableLaneOracleX8(&publicSelectPointX8Sink, &table8, &rounds8[i%len(rounds8)], 0xff)
			}
		})
	}
}

func selectFullTableLaneOracleX4(out *PointX4, table *FullTableX4, round *RadixRoundX4, active uint8) {
	selected := NewIdentityPointX4()
	for lane := 0; lane < X4Lanes; lane++ {
		if active&(1<<lane) == 0 {
			continue
		}
		digit := round.Digit(lane)
		if digit == 0 {
			continue
		}
		magnitude, negative := signedDigitMagnitude(digit)
		point := table.points[int(magnitude)-1].Lane(lane)
		if negative {
			point.X.Negate(&point.X)
			point.T.Negate(&point.T)
		}
		selected.SetLane(lane, &point)
	}
	*out = *selected
}

func selectFullTableLaneOracleX8(out *PointX8, table *FullTableX8, round *RadixRoundX8, active uint8) {
	selected := NewIdentityPointX8()
	for lane := 0; lane < X8Lanes; lane++ {
		if active&(1<<lane) == 0 {
			continue
		}
		digit := round.Digit(lane)
		if digit == 0 {
			continue
		}
		magnitude, negative := signedDigitMagnitude(digit)
		point := table.points[int(magnitude)-1].Lane(lane)
		if negative {
			point.X.Negate(&point.X)
			point.T.Negate(&point.T)
		}
		selected.SetLane(lane, &point)
	}
	*out = *selected
}
