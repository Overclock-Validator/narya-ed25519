package r51x5

import (
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"testing"

	edwardsref "github.com/Overclock-Validator/narya/internal/edwards25519"
)

func TestIFMAFullTableSelectMatchesExactMixedOrderPoints(t *testing.T) {
	rng := rand.New(rand.NewSource(0x1f4a_51ec7))
	torsion := referenceTorsionPoints(t)
	refs, bases := scalarWindowMixedBasesX8(t, rng, &torsion)
	for _, radixBits := range []uint{4, 5, 6} {
		reducedTable := BuildFullTableX8(&bases, radixBits)
		switch radixBits {
		case 4:
			table := ImportIFMAFullTableRadix16X8(&reducedTable)
			testIFMAFullTableSelectMatchesExact(t, &table, radixBits, &refs)
		case 5:
			table := ImportIFMAFullTableX8(&reducedTable)
			testIFMAFullTableSelectMatchesExact(t, &table, radixBits, &refs)
		case 6:
			table := ImportIFMAFullTableRadix64X8(&reducedTable)
			testIFMAFullTableSelectMatchesExact(t, &table, radixBits, &refs)
		}
	}
}

func testIFMAFullTableSelectMatchesExact[Storage ifmaFullTableStorageX8](t *testing.T, table *ifmaFullTableX8[Storage], radixBits uint, refs *[X8Lanes]*edwardsref.Point) {
	t.Helper()
	half := 1 << (radixBits - 1)
	for start := -half; start <= half; start += X8Lanes {
		var round RadixRoundX8
		var digits [X8Lanes]int8
		for lane := range digits {
			digit := start + lane
			if digit > half {
				digit = -half + digit - half - 1
			}
			digits[lane] = int8(digit)
			setRadixRoundDigitX8(&round, lane, digits[lane])
		}
		var selected IFMAPointX8
		SelectIFMAFullTableX8Public(&selected, table, &round, 0xff)
		got := selected.Reduced()
		for lane := 0; lane < X8Lanes; lane++ {
			point := got.Lane(lane)
			want := exactReferenceIntegerMult(refs[lane], big.NewInt(int64(digits[lane])))
			assertScalarPointMatchesReference(t, fmt.Sprintf("radix %d start %d lane %d", 1<<radixBits, start, lane), &point, want)
		}
	}
}

func TestIFMAFullTableSelectHandlesLooseRepresentatives(t *testing.T) {
	bases, _, _, _ := scalarWindowBenchmarkFixtures(t)
	reducedTable := BuildFullTableX4(&bases, 5)
	table := ImportIFMAFullTableX4(&reducedTable)
	for entry := 0; entry < table.entries; entry++ {
		for lane := 0; lane < X4Lanes; lane++ {
			for limb, modulus := range modulusLimbs {
				table.points[entry].X.limbs[limb][lane] += modulus
				table.points[entry].Y.limbs[limb][lane] += modulus
				table.points[entry].Z.limbs[limb][lane] += modulus
				table.points[entry].T.limbs[limb][lane] += modulus
			}
		}
	}
	var round RadixRoundX4
	for lane, digit := range []int8{-16, 0, 7, -1} {
		setRadixRoundDigitX4(&round, lane, digit)
	}
	var got IFMAPointX4
	SelectIFMAFullTableX4Public(&got, &table, &round, 0x0f)
	reduced := got.Reduced()
	referenceTable := BuildFullTableX4(&bases, 5)
	var want PointX4
	SelectFullTableX4Public(&want, &referenceTable, &round, 0x0f)
	if mask := reduced.Equal(&want); mask != 0x0f {
		t.Fatalf("loose representative selection mask=%02x", mask)
	}
}

func TestExperimentalIFMAComposableScalarLoopsUnavailable(t *testing.T) {
	if ExperimentalIFMAAvailable() {
		t.Skip("unavailable-path test")
	}
	base4, base8, scalars4, scalars8 := scalarWindowBenchmarkFixtures(t)
	reduced4 := BuildFullTableX4(&base4, 4)
	table4 := ImportIFMAFullTableRadix16X4(&reduced4)
	recoded4 := RecodeRegularRadixX4(&scalars4, 4)
	sentinel4 := identityIFMAPointX4Value()
	got4 := sentinel4
	if err := ExperimentalIFMAComposableScalarMultLoopX4(&got4, &table4, &recoded4, 0x0f); !errors.Is(err, ErrIFMAUnavailable) {
		t.Fatalf("x4 error=%v", err)
	}
	if got4 != sentinel4 {
		t.Fatal("x4 unavailable path changed output")
	}

	reduced8 := BuildFullTableX8(&base8, 5)
	table8 := ImportIFMAFullTableX8(&reduced8)
	recoded8 := RecodeRegularRadixX8(&scalars8, 5)
	sentinel8 := identityIFMAPointX8Value()
	got8 := sentinel8
	if err := ExperimentalIFMAComposableScalarMultLoopX8(&got8, &table8, &recoded8, 0xff); !errors.Is(err, ErrIFMAUnavailable) {
		t.Fatalf("x8 error=%v", err)
	}
	if got8 != sentinel8 {
		t.Fatal("x8 unavailable path changed output")
	}
}

var (
	ifmaSelectPointX4Sink IFMAPointX4
	ifmaSelectPointX8Sink IFMAPointX8
)

func BenchmarkIFMAFullTableSelect(b *testing.B) {
	base4, base8, scalars4, scalars8 := scalarWindowBenchmarkFixtures(b)
	for _, radixBits := range []uint{4, 5, 6} {
		reduced4 := BuildFullTableX4(&base4, radixBits)
		reduced8 := BuildFullTableX8(&base8, radixBits)
		switch radixBits {
		case 4:
			table4 := ImportIFMAFullTableRadix16X4(&reduced4)
			table8 := ImportIFMAFullTableRadix16X8(&reduced8)
			benchmarkIFMAFullTableSelect(b, &table4, &table8, &scalars4, &scalars8, radixBits)
		case 5:
			table4 := ImportIFMAFullTableX4(&reduced4)
			table8 := ImportIFMAFullTableX8(&reduced8)
			benchmarkIFMAFullTableSelect(b, &table4, &table8, &scalars4, &scalars8, radixBits)
		case 6:
			table4 := ImportIFMAFullTableRadix64X4(&reduced4)
			table8 := ImportIFMAFullTableRadix64X8(&reduced8)
			benchmarkIFMAFullTableSelect(b, &table4, &table8, &scalars4, &scalars8, radixBits)
		}
	}
}

func benchmarkIFMAFullTableSelect[Storage4 ifmaFullTableStorageX4, Storage8 ifmaFullTableStorageX8](b *testing.B, table4 *ifmaFullTableX4[Storage4], table8 *ifmaFullTableX8[Storage8], scalars4 *[X4Lanes]SignedMagnitude, scalars8 *[X8Lanes]SignedMagnitude, radixBits uint) {
	rounds4 := RecodeRegularRadixX4(scalars4, radixBits).Rounds
	b.Run(fmt.Sprintf("x4/radix=%d", 1<<radixBits), func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			SelectIFMAFullTableX4Public(&ifmaSelectPointX4Sink, table4, &rounds4[i%len(rounds4)], 0x0f)
		}
	})

	rounds8 := RecodeRegularRadixX8(scalars8, radixBits).Rounds
	b.Run(fmt.Sprintf("x8/radix=%d", 1<<radixBits), func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			SelectIFMAFullTableX8Public(&ifmaSelectPointX8Sink, table8, &rounds8[i%len(rounds8)], 0xff)
		}
	})
}
