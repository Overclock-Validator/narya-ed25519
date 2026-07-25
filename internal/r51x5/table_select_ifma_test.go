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

func TestIFMAFullTableSelectUncheckedNoAliasMatchesChecked(t *testing.T) {
	base4, _, _, _ := scalarWindowBenchmarkFixtures(t)
	for _, radixBits := range []uint{4, 5, 6} {
		reducedTable := BuildFullTableX4(&base4, radixBits)
		switch radixBits {
		case 4:
			table := ImportIFMAFullTableRadix16X4(&reducedTable)
			testIFMAFullTableSelectUncheckedNoAliasMatchesChecked(t, "reduced", &table, radixBits)
			loosenIFMAFullTableX4(&table)
			testIFMAFullTableSelectUncheckedNoAliasMatchesChecked(t, "loose", &table, radixBits)
		case 5:
			table := ImportIFMAFullTableX4(&reducedTable)
			testIFMAFullTableSelectUncheckedNoAliasMatchesChecked(t, "reduced", &table, radixBits)
			loosenIFMAFullTableX4(&table)
			testIFMAFullTableSelectUncheckedNoAliasMatchesChecked(t, "loose", &table, radixBits)
		case 6:
			table := ImportIFMAFullTableRadix64X4(&reducedTable)
			testIFMAFullTableSelectUncheckedNoAliasMatchesChecked(t, "reduced", &table, radixBits)
			loosenIFMAFullTableX4(&table)
			testIFMAFullTableSelectUncheckedNoAliasMatchesChecked(t, "loose", &table, radixBits)
		}
	}
}

func testIFMAFullTableSelectUncheckedNoAliasMatchesChecked[Storage ifmaFullTableStorageX4](t *testing.T, representation string, table *ifmaFullTableX4[Storage], radixBits uint) {
	t.Helper()
	half := 1 << (radixBits - 1)
	patterns := [][X4Lanes]int8{
		{},
		{1, -1, int8(half), int8(-half)},
		{int8(-half), int8(half - 1), -2, 2},
	}
	for digit := -half; digit <= half; digit++ {
		patterns = append(patterns, [X4Lanes]int8{int8(digit), int8(-digit), int8(digit), int8(-digit)})
	}
	for patternIndex, digits := range patterns {
		var round RadixRoundX4
		for lane, digit := range digits {
			setRadixRoundDigitX4(&round, lane, digit)
		}
		for active := 0; active < 1<<X4Lanes; active++ {
			var checked IFMAPointX4
			SelectIFMAFullTableX4Public(&checked, table, &round, uint8(active))

			unchecked := patternedIFMAPointX4Garbage()
			selectIFMAFullTableX4PublicUncheckedNoAlias(&unchecked, table, &round, uint8(active))
			if unchecked != checked {
				t.Fatalf("representation=%s radix=%d pattern=%d digits=%v active=%02x mismatch", representation, 1<<radixBits, patternIndex, digits, active)
			}
		}
	}

	// Metadata outside the active mask is intentionally ignored before table
	// indexing. This mirrors fixed recoding, where inactive lanes stay zero,
	// while proving that an inactive poisoned lane cannot trigger an access.
	poisoned := RadixRoundX4{
		Magnitude:    [X4Lanes]uint8{1, 2, 3, 0xff},
		NonzeroMask:  0x0f,
		NegativeMask: 0x08,
	}
	var checked IFMAPointX4
	SelectIFMAFullTableX4Public(&checked, table, &poisoned, 0x07)
	unchecked := patternedIFMAPointX4Garbage()
	selectIFMAFullTableX4PublicUncheckedNoAlias(&unchecked, table, &poisoned, 0x07)
	if unchecked != checked {
		t.Fatalf("representation=%s radix=%d inactive poison mismatch", representation, 1<<radixBits)
	}
}

func loosenIFMAFullTableX4[Storage ifmaFullTableStorageX4](table *ifmaFullTableX4[Storage]) {
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
}

func patternedIFMAPointX4Garbage() IFMAPointX4 {
	var point IFMAPointX4
	coordinates := []*IFMAElementX4{&point.X, &point.Y, &point.Z, &point.T}
	for coordinate, element := range coordinates {
		for limb := range element.limbs {
			for lane := range element.limbs[limb] {
				element.limbs[limb][lane] = uint64(0x51 + coordinate*0x100 + limb*0x10 + lane)
			}
		}
	}
	return point
}

func TestIFMAFullTableSelectX8UncheckedNoAliasMatchesChecked(t *testing.T) {
	_, base8, _, _ := scalarWindowBenchmarkFixtures(t)
	for _, radixBits := range []uint{4, 5, 6} {
		reducedTable := BuildFullTableX8(&base8, radixBits)
		switch radixBits {
		case 4:
			table := ImportIFMAFullTableRadix16X8(&reducedTable)
			testIFMAFullTableSelectX8UncheckedNoAliasMatchesChecked(t, "reduced", &table, radixBits)
			loosenIFMAFullTableX8(&table)
			testIFMAFullTableSelectX8UncheckedNoAliasMatchesChecked(t, "loose", &table, radixBits)
		case 5:
			table := ImportIFMAFullTableX8(&reducedTable)
			testIFMAFullTableSelectX8UncheckedNoAliasMatchesChecked(t, "reduced", &table, radixBits)
			loosenIFMAFullTableX8(&table)
			testIFMAFullTableSelectX8UncheckedNoAliasMatchesChecked(t, "loose", &table, radixBits)
		case 6:
			table := ImportIFMAFullTableRadix64X8(&reducedTable)
			testIFMAFullTableSelectX8UncheckedNoAliasMatchesChecked(t, "reduced", &table, radixBits)
			loosenIFMAFullTableX8(&table)
			testIFMAFullTableSelectX8UncheckedNoAliasMatchesChecked(t, "loose", &table, radixBits)
		}
	}
}

func testIFMAFullTableSelectX8UncheckedNoAliasMatchesChecked[Storage ifmaFullTableStorageX8](t *testing.T, representation string, table *ifmaFullTableX8[Storage], radixBits uint) {
	t.Helper()
	half := 1 << (radixBits - 1)
	patterns := [][X8Lanes]int8{
		{},
		{1, -1, int8(half), int8(-half), 2, -2, int8(half - 1), int8(1 - half)},
		{int8(-half), int8(half - 1), -2, 2, -3, 3, -4, 4},
	}
	for digit := -half; digit <= half; digit++ {
		patterns = append(patterns, [X8Lanes]int8{
			int8(digit), int8(-digit), int8(digit), int8(-digit),
			int8(digit), int8(-digit), int8(digit), int8(-digit),
		})
	}
	for patternIndex, digits := range patterns {
		var round RadixRoundX8
		for lane, digit := range digits {
			setRadixRoundDigitX8(&round, lane, digit)
		}
		for active := 0; active < 1<<X8Lanes; active++ {
			var checked IFMAPointX8
			SelectIFMAFullTableX8Public(&checked, table, &round, uint8(active))

			unchecked := patternedIFMAPointX8Garbage()
			selectIFMAFullTableX8PublicUncheckedNoAlias(&unchecked, table, &round, uint8(active))
			if unchecked != checked {
				t.Fatalf("representation=%s radix=%d pattern=%d digits=%v active=%02x mismatch", representation, 1<<radixBits, patternIndex, digits, active)
			}
		}
	}

	poisoned := RadixRoundX8{
		Magnitude:    [X8Lanes]uint8{1, 2, 3, 4, 5, 6, 7, 0xff},
		NonzeroMask:  0xff,
		NegativeMask: 0x80,
	}
	var checked IFMAPointX8
	SelectIFMAFullTableX8Public(&checked, table, &poisoned, 0x7f)
	unchecked := patternedIFMAPointX8Garbage()
	selectIFMAFullTableX8PublicUncheckedNoAlias(&unchecked, table, &poisoned, 0x7f)
	if unchecked != checked {
		t.Fatalf("representation=%s radix=%d inactive poison mismatch", representation, 1<<radixBits)
	}
}

func loosenIFMAFullTableX8[Storage ifmaFullTableStorageX8](table *ifmaFullTableX8[Storage]) {
	for entry := 0; entry < table.entries; entry++ {
		for lane := 0; lane < X8Lanes; lane++ {
			for limb, modulus := range modulusLimbs {
				table.points[entry].X.limbs[limb][lane] += modulus
				table.points[entry].Y.limbs[limb][lane] += modulus
				table.points[entry].Z.limbs[limb][lane] += modulus
				table.points[entry].T.limbs[limb][lane] += modulus
			}
		}
	}
}

func patternedIFMAPointX8Garbage() IFMAPointX8 {
	var point IFMAPointX8
	coordinates := []*IFMAElementX8{&point.X, &point.Y, &point.Z, &point.T}
	for coordinate, element := range coordinates {
		for limb := range element.limbs {
			for lane := range element.limbs[limb] {
				element.limbs[limb][lane] = uint64(0x81 + coordinate*0x100 + limb*0x10 + lane)
			}
		}
	}
	return point
}

func TestConditionalNegateIFMAElementsMasksAndBoundaries(t *testing.T) {
	fixtures8 := []struct {
		name    string
		element IFMAElementX8
	}{
		{name: "zero", element: IFMAElementX8{}},
		{name: "maximum", element: filledIFMAElementX8(ifmaComposableLimbLimit - 1)},
		{name: "mixed", element: patternedIFMAElementX8(false)},
	}
	for _, fixture := range fixtures8 {
		normalized := referenceAddIFMAElementX8(t, &fixture.element, &IFMAElementX8{})
		negated := referenceNegateIFMAElementX8(t, &fixture.element)
		for mask := 0; mask < 1<<X8Lanes; mask++ {
			got := fixture.element
			conditionalNegateIFMAElementX8(&got, uint8(mask))
			want := normalized
			for limb := range want.limbs {
				for lane := range want.limbs[limb] {
					if mask&(1<<lane) != 0 {
						want.limbs[limb][lane] = negated.limbs[limb][lane]
					}
				}
			}
			if got != want {
				t.Fatalf("x8 %s mask=%02x mismatch\ngot  %x\nwant %x", fixture.name, mask, got.limbs, want.limbs)
			}
			if !isIFMAElementX8(&got) {
				t.Fatalf("x8 %s mask=%02x escaped u52", fixture.name, mask)
			}
		}
	}

	for group := 0; group < 2; group++ {
		for _, fixture := range fixtures8 {
			element := ifmaElementX4Half(&fixture.element, group)
			normalized := referenceAddIFMAElementX4(t, &element, &IFMAElementX4{})
			negated := referenceNegateIFMAElementX4(t, &element)
			for mask := 0; mask < 1<<X4Lanes; mask++ {
				got := element
				conditionalNegateIFMAElementX4(&got, uint8(mask))
				want := normalized
				for limb := range want.limbs {
					for lane := range want.limbs[limb] {
						if mask&(1<<lane) != 0 {
							want.limbs[limb][lane] = negated.limbs[limb][lane]
						}
					}
				}
				if got != want {
					t.Fatalf("x4 group=%d %s mask=%02x mismatch\ngot  %x\nwant %x", group, fixture.name, mask, got.limbs, want.limbs)
				}
				if !isIFMAElementX4(&got) {
					t.Fatalf("x4 group=%d %s mask=%02x escaped u52", group, fixture.name, mask)
				}
			}
		}
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
	b.Run(fmt.Sprintf("x4/radix=%d/implementation=checked", 1<<radixBits), func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			SelectIFMAFullTableX4Public(&ifmaSelectPointX4Sink, table4, &rounds4[i%len(rounds4)], 0x0f)
		}
	})
	b.Run(fmt.Sprintf("x4/radix=%d/implementation=unchecked-noalias", 1<<radixBits), func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			selectIFMAFullTableX4PublicUncheckedNoAlias(&ifmaSelectPointX4Sink, table4, &rounds4[i%len(rounds4)], 0x0f)
		}
	})

	rounds8 := RecodeRegularRadixX8(scalars8, radixBits).Rounds
	b.Run(fmt.Sprintf("x8/radix=%d/implementation=checked", 1<<radixBits), func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			SelectIFMAFullTableX8Public(&ifmaSelectPointX8Sink, table8, &rounds8[i%len(rounds8)], 0xff)
		}
	})
	b.Run(fmt.Sprintf("x8/radix=%d/implementation=unchecked-noalias", 1<<radixBits), func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			selectIFMAFullTableX8PublicUncheckedNoAlias(&ifmaSelectPointX8Sink, table8, &rounds8[i%len(rounds8)], 0xff)
		}
	})
}

// BenchmarkIFMAFullTableSelectDense prices the full-lane, distinct-entry case
// that dominates ordinary verification. The older scalar fixture deliberately
// includes zero and sparse boundary scalars, which is useful for correctness
// diagnostics but systematically underprices table extraction.
func BenchmarkIFMAFullTableSelectDense(b *testing.B) {
	base4, base8, _, _ := scalarWindowBenchmarkFixtures(b)
	for _, radixBits := range []uint{4, 5, 6} {
		reduced4 := BuildFullTableX4(&base4, radixBits)
		reduced8 := BuildFullTableX8(&base8, radixBits)
		switch radixBits {
		case 4:
			table4 := ImportIFMAFullTableRadix16X4(&reduced4)
			table8 := ImportIFMAFullTableRadix16X8(&reduced8)
			benchmarkIFMAFullTableSelectDense(b, &table4, &table8, radixBits)
		case 5:
			table4 := ImportIFMAFullTableX4(&reduced4)
			table8 := ImportIFMAFullTableX8(&reduced8)
			benchmarkIFMAFullTableSelectDense(b, &table4, &table8, radixBits)
		case 6:
			table4 := ImportIFMAFullTableRadix64X4(&reduced4)
			table8 := ImportIFMAFullTableRadix64X8(&reduced8)
			benchmarkIFMAFullTableSelectDense(b, &table4, &table8, radixBits)
		}
	}
}

func benchmarkIFMAFullTableSelectDense[Storage4 ifmaFullTableStorageX4, Storage8 ifmaFullTableStorageX8](b *testing.B, table4 *ifmaFullTableX4[Storage4], table8 *ifmaFullTableX8[Storage8], radixBits uint) {
	rounds4 := denseIFMAFullTableRoundsX4(table4.entries)
	b.Run(fmt.Sprintf("x4/radix=%d/implementation=checked", 1<<radixBits), func(b *testing.B) {
		b.ReportAllocs()
		b.ReportMetric(X4Lanes, "selected-lanes/op")
		for i := 0; i < b.N; i++ {
			SelectIFMAFullTableX4Public(&ifmaSelectPointX4Sink, table4, &rounds4[i%len(rounds4)], 0x0f)
		}
	})
	b.Run(fmt.Sprintf("x4/radix=%d/implementation=unchecked-noalias", 1<<radixBits), func(b *testing.B) {
		b.ReportAllocs()
		b.ReportMetric(X4Lanes, "selected-lanes/op")
		for i := 0; i < b.N; i++ {
			selectIFMAFullTableX4PublicUncheckedNoAlias(&ifmaSelectPointX4Sink, table4, &rounds4[i%len(rounds4)], 0x0f)
		}
	})

	rounds8 := denseIFMAFullTableRoundsX8(table8.entries)
	b.Run(fmt.Sprintf("x8/radix=%d/implementation=checked", 1<<radixBits), func(b *testing.B) {
		b.ReportAllocs()
		b.ReportMetric(X8Lanes, "selected-lanes/op")
		for i := 0; i < b.N; i++ {
			SelectIFMAFullTableX8Public(&ifmaSelectPointX8Sink, table8, &rounds8[i%len(rounds8)], 0xff)
		}
	})
	b.Run(fmt.Sprintf("x8/radix=%d/implementation=unchecked-copy", 1<<radixBits), func(b *testing.B) {
		b.ReportAllocs()
		b.ReportMetric(X8Lanes, "selected-lanes/op")
		for i := 0; i < b.N; i++ {
			selectIFMAFullTableX8BenchmarkCopyNoValidate(&ifmaSelectPointX8Sink, table8, &rounds8[i%len(rounds8)], 0xff)
		}
	})
	b.Run(fmt.Sprintf("x8/radix=%d/implementation=unchecked-direct-identity", 1<<radixBits), func(b *testing.B) {
		b.ReportAllocs()
		b.ReportMetric(X8Lanes, "selected-lanes/op")
		for i := 0; i < b.N; i++ {
			selectIFMAFullTableX8BenchmarkDirectIdentity(&ifmaSelectPointX8Sink, table8, &rounds8[i%len(rounds8)], 0xff)
		}
	})
	b.Run(fmt.Sprintf("x8/radix=%d/implementation=unchecked-noalias", 1<<radixBits), func(b *testing.B) {
		b.ReportAllocs()
		b.ReportMetric(X8Lanes, "selected-lanes/op")
		for i := 0; i < b.N; i++ {
			selectIFMAFullTableX8PublicUncheckedNoAlias(&ifmaSelectPointX8Sink, table8, &rounds8[i%len(rounds8)], 0xff)
		}
	})
}

// selectIFMAFullTableX8BenchmarkCopyNoValidate retains the old identity and
// final-copy schedule while removing only digit validation. It is benchmark
// scaffolding, not an implementation candidate.
func selectIFMAFullTableX8BenchmarkCopyNoValidate[Storage ifmaFullTableStorageX8](out *IFMAPointX8, table *ifmaFullTableX8[Storage], round *RadixRoundX8, active uint8) {
	selected := identityIFMAPointX8Value()
	lookupMask := round.NonzeroMask & active
	negativeMask := round.NegativeMask & lookupMask
	for lane := 0; lane < X8Lanes; lane++ {
		laneMask := uint8(1 << lane)
		if lookupMask&laneMask == 0 {
			continue
		}
		source := &table.points[int(round.Magnitude[lane])-1]
		gatherIFMAPointLaneX8(&selected, source, lane)
	}
	conditionalNegateIFMAPointX8(&selected, negativeMask)
	*out = selected
}

// selectIFMAFullTableX8BenchmarkDirectIdentity removes the final selected-to-
// out copy but still initializes all 1,280 output bytes as identity. Comparing
// it with the no-alias candidate prices whole-point initialization separately.
func selectIFMAFullTableX8BenchmarkDirectIdentity[Storage ifmaFullTableStorageX8](out *IFMAPointX8, table *ifmaFullTableX8[Storage], round *RadixRoundX8, active uint8) {
	*out = identityIFMAPointX8Value()
	lookupMask := round.NonzeroMask & active
	negativeMask := round.NegativeMask & lookupMask
	for lane := 0; lane < X8Lanes; lane++ {
		laneMask := uint8(1 << lane)
		if lookupMask&laneMask == 0 {
			continue
		}
		source := &table.points[int(round.Magnitude[lane])-1]
		gatherIFMAPointLaneX8(out, source, lane)
	}
	conditionalNegateIFMAPointX8(out, negativeMask)
}

func denseIFMAFullTableRoundsX4(entries int) []RadixRoundX4 {
	rounds := make([]RadixRoundX4, entries)
	for round := range rounds {
		for lane := 0; lane < X4Lanes; lane++ {
			digit := int8((round+lane)%entries + 1)
			if (round+lane)&1 != 0 {
				digit = -digit
			}
			setRadixRoundDigitX4(&rounds[round], lane, digit)
		}
	}
	return rounds
}

func denseIFMAFullTableRoundsX8(entries int) []RadixRoundX8 {
	rounds := make([]RadixRoundX8, entries)
	for round := range rounds {
		for lane := 0; lane < X8Lanes; lane++ {
			digit := int8((round+lane)%entries + 1)
			if (round+lane)&1 != 0 {
				digit = -digit
			}
			setRadixRoundDigitX8(&rounds[round], lane, digit)
		}
	}
	return rounds
}
