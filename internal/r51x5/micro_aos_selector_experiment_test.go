package r51x5

import (
	"fmt"
	"runtime"
	"testing"
	"unsafe"
)

func microAoSSelectorExperimentCanCall() bool {
	return runtime.GOARCH != "amd64" || ExperimentalIFMAAvailable()
}

func importIFMAMicroAoSTablesExperimentX4[Storage ifmaFullTableStorageX4](grouped *ifmaFullTableX4[Storage]) [X4Lanes]ifmaMicroAoSPerKeyTableExperiment {
	var perKey [X4Lanes]ifmaMicroAoSPerKeyTableExperiment
	for lane := 0; lane < X4Lanes; lane++ {
		perKey[lane].points = make([]ifmaMicroAoSPointEntryExperiment, grouped.entries)
	}
	for entry := 0; entry < grouped.entries; entry++ {
		for limb := 0; limb < 5; limb++ {
			for lane := 0; lane < X4Lanes; lane++ {
				perKey[lane].points[entry][limb] = [4]uint64{
					grouped.points[entry].X.limbs[limb][lane],
					grouped.points[entry].Y.limbs[limb][lane],
					grouped.points[entry].Z.limbs[limb][lane],
					grouped.points[entry].T.limbs[limb][lane],
				}
			}
		}
	}
	return perKey
}

func TestIFMAMicroAoSSelectorExperimentMatchesCheckedAllRadices(t *testing.T) {
	if !microAoSSelectorExperimentCanCall() {
		t.Skip("requires AVX-512 IFMA target on amd64")
	}
	base4, _, _, _ := scalarWindowBenchmarkFixtures(t)
	for _, radixBits := range []uint{4, 5, 6} {
		reduced := BuildFullTableX4(&base4, radixBits)
		switch radixBits {
		case 4:
			grouped := ImportIFMAFullTableRadix16X4(&reduced)
			testIFMAMicroAoSSelectorExperimentAgainstChecked(t, "reduced", &grouped, radixBits)
			loosenIFMAFullTableX4(&grouped)
			testIFMAMicroAoSSelectorExperimentAgainstChecked(t, "loose", &grouped, radixBits)
		case 5:
			grouped := ImportIFMAFullTableX4(&reduced)
			testIFMAMicroAoSSelectorExperimentAgainstChecked(t, "reduced", &grouped, radixBits)
			loosenIFMAFullTableX4(&grouped)
			testIFMAMicroAoSSelectorExperimentAgainstChecked(t, "loose", &grouped, radixBits)
		case 6:
			grouped := ImportIFMAFullTableRadix64X4(&reduced)
			testIFMAMicroAoSSelectorExperimentAgainstChecked(t, "reduced", &grouped, radixBits)
			loosenIFMAFullTableX4(&grouped)
			testIFMAMicroAoSSelectorExperimentAgainstChecked(t, "loose", &grouped, radixBits)
		}
	}
}

func testIFMAMicroAoSSelectorExperimentAgainstChecked[Storage ifmaFullTableStorageX4](t *testing.T, representation string, grouped *ifmaFullTableX4[Storage], radixBits uint) {
	t.Helper()
	perKey := importIFMAMicroAoSTablesExperimentX4(grouped)
	half := 1 << (radixBits - 1)
	patterns := [][X4Lanes]int8{
		{},
		{1, -1, int8(half), int8(-half)},
		{int8(-half), int8(half - 1), -2, 2},
	}
	for magnitude := 0; magnitude <= half; magnitude++ {
		patterns = append(patterns, [X4Lanes]int8{
			int8(magnitude), -int8(magnitude),
			int8((magnitude + 1) % (half + 1)), -int8((magnitude + 1) % (half + 1)),
		})
	}
	for patternIndex, digits := range patterns {
		var round RadixRoundX4
		for lane, digit := range digits {
			setRadixRoundDigitX4(&round, lane, digit)
		}
		for active := 0; active < 1<<X4Lanes; active++ {
			var want, got IFMAPointX4
			SelectIFMAFullTableX4Public(&want, grouped, &round, uint8(active))
			selectIFMAMicroAoSCheckedExperimentX4(&got, &perKey, &round, uint8(active))
			if got != want {
				t.Fatalf("representation=%s radix=%d pattern=%d digits=%v active=%02x mismatch", representation, 1<<radixBits, patternIndex, digits, active)
			}

			unchecked := patternedIFMAPointX4Garbage()
			selectIFMAMicroAoSUncheckedExperimentX4(&unchecked, &perKey, &round, uint8(active))
			if unchecked != want {
				t.Fatalf("representation=%s radix=%d pattern=%d digits=%v active=%02x unchecked mismatch", representation, 1<<radixBits, patternIndex, digits, active)
			}
		}
	}

	// Inactive metadata is never allowed to reach an index calculation.
	poisoned := RadixRoundX4{
		Magnitude:    [X4Lanes]uint8{1, 2, 3, 0xff},
		NonzeroMask:  0x0f,
		NegativeMask: 0x08,
	}
	var want, got IFMAPointX4
	SelectIFMAFullTableX4Public(&want, grouped, &poisoned, 0x07)
	selectIFMAMicroAoSCheckedExperimentX4(&got, &perKey, &poisoned, 0x07)
	if got != want {
		t.Fatalf("representation=%s radix=%d inactive poison mismatch", representation, 1<<radixBits)
	}
}

func TestIFMAMicroAoSSelectorExperimentFailClosedMetadata(t *testing.T) {
	if !microAoSSelectorExperimentCanCall() {
		t.Skip("requires AVX-512 IFMA target on amd64")
	}
	base4, _, _, _ := scalarWindowBenchmarkFixtures(t)
	reduced := BuildFullTableX4(&base4, 4)
	grouped := ImportIFMAFullTableRadix16X4(&reduced)
	perKey := importIFMAMicroAoSTablesExperimentX4(&grouped)
	tests := []struct {
		name  string
		round RadixRoundX4
	}{
		{
			name: "magnitude-out-of-range",
			round: RadixRoundX4{
				Magnitude:   [X4Lanes]uint8{9},
				NonzeroMask: 1,
			},
		},
		{
			name: "nonzero-bit-with-zero-magnitude",
			round: RadixRoundX4{
				NonzeroMask: 1,
			},
		},
		{
			name: "negative-zero",
			round: RadixRoundX4{
				NegativeMask: 1,
			},
		},
		{
			name: "missing-nonzero-bit",
			round: RadixRoundX4{
				Magnitude: [X4Lanes]uint8{1},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sentinel := patternedIFMAPointX4Garbage()
			got := sentinel
			if !microAoSSelectorExperimentPanics(func() {
				selectIFMAMicroAoSCheckedExperimentX4(&got, &perKey, &test.round, 1)
			}) {
				t.Fatal("invalid active metadata did not panic")
			}
			if got != sentinel {
				t.Fatal("invalid active metadata changed output before panic")
			}
		})
	}
}

func microAoSSelectorExperimentPanics(f func()) (panicked bool) {
	defer func() {
		panicked = recover() != nil
	}()
	f()
	return false
}

func TestIFMAMicroAoSTransposeExperimentPreservesU52Boundary(t *testing.T) {
	if !microAoSSelectorExperimentCanCall() {
		t.Skip("requires AVX-512 IFMA target on amd64")
	}
	var entries [X4Lanes]ifmaMicroAoSPointEntryExperiment
	for lane := 0; lane < X4Lanes; lane++ {
		for limb := 0; limb < 5; limb++ {
			for coordinate := 0; coordinate < 4; coordinate++ {
				entries[lane][limb][coordinate] = ifmaComposableLimbLimit - 1 - uint64((lane+limb+coordinate)%17)
			}
		}
	}
	var got IFMAPointX4
	ifmaMicroAoSTransposeSelectExperimentX4(&got, &entries[0], &entries[1], &entries[2], &entries[3])
	for limb := 0; limb < 5; limb++ {
		coordinates := [4]*IFMAElementX4{&got.X, &got.Y, &got.Z, &got.T}
		for coordinate, element := range coordinates {
			for lane := 0; lane < X4Lanes; lane++ {
				want := entries[lane][limb][coordinate]
				if value := element.limbs[limb][lane]; value != want {
					t.Fatalf("limb=%d coordinate=%d lane=%d got=%x want=%x", limb, coordinate, lane, value, want)
				}
				if element.limbs[limb][lane] >= ifmaComposableLimbLimit {
					t.Fatalf("limb=%d coordinate=%d lane=%d escaped u52", limb, coordinate, lane)
				}
			}
		}
	}
}

func TestIFMAMicroAoSTransposeExperimentExactAlias(t *testing.T) {
	if !microAoSSelectorExperimentCanCall() {
		t.Skip("requires AVX-512 IFMA target on amd64")
	}
	if got, want := unsafe.Sizeof([X4Lanes]ifmaMicroAoSPointEntryExperiment{}), unsafe.Sizeof(IFMAPointX4{}); got != want {
		t.Fatalf("alias storage=%d point=%d", got, want)
	}
	var storage [X4Lanes]ifmaMicroAoSPointEntryExperiment
	for lane := range storage {
		for limb := range storage[lane] {
			for coordinate := range storage[lane][limb] {
				storage[lane][limb][coordinate] = uint64(1 + lane*0x100 + limb*0x10 + coordinate)
			}
		}
	}
	original := storage
	var want IFMAPointX4
	ifmaMicroAoSTransposeSelectExperimentX4(&want, &original[0], &original[1], &original[2], &original[3])
	aliased := (*IFMAPointX4)(unsafe.Pointer(&storage[0]))
	ifmaMicroAoSTransposeSelectExperimentX4(aliased, &storage[0], &storage[1], &storage[2], &storage[3])
	if *aliased != want {
		t.Fatal("exactly aliased transpose mismatch")
	}
}

func TestIFMAMicroAoSSelectorExperimentZeroAllocations(t *testing.T) {
	if !microAoSSelectorExperimentCanCall() {
		t.Skip("requires AVX-512 IFMA target on amd64")
	}
	base4, _, _, _ := scalarWindowBenchmarkFixtures(t)
	reduced := BuildFullTableX4(&base4, 6)
	grouped := ImportIFMAFullTableRadix64X4(&reduced)
	perKey := importIFMAMicroAoSTablesExperimentX4(&grouped)
	var round RadixRoundX4
	for lane, digit := range []int8{1, -7, 19, -32} {
		setRadixRoundDigitX4(&round, lane, digit)
	}
	var out IFMAPointX4
	if allocations := testing.AllocsPerRun(1000, func() {
		selectIFMAMicroAoSCheckedExperimentX4(&out, &perKey, &round, 0x0f)
	}); allocations != 0 {
		t.Fatalf("checked allocations=%v want=0", allocations)
	}
	if allocations := testing.AllocsPerRun(1000, func() {
		selectIFMAMicroAoSUncheckedExperimentX4(&out, &perKey, &round, 0x0f)
	}); allocations != 0 {
		t.Fatalf("unchecked allocations=%v want=0", allocations)
	}
}

type ifmaGroupedTableSelectorExperimentX4 struct {
	points []IFMAPointX4
}

func selectIFMAGroupedTableExperimentX4(out *IFMAPointX4, table *ifmaGroupedTableSelectorExperimentX4, round *RadixRoundX4, active uint8) {
	lookupMask := round.NonzeroMask & active & 0x0f
	negativeMask := round.NegativeMask & lookupMask
	for lane := 0; lane < X4Lanes; lane++ {
		if lookupMask&(1<<lane) == 0 {
			setIdentityIFMAPointLaneX4(out, lane)
			continue
		}
		gatherIFMAPointLaneX4(out, &table.points[int(round.Magnitude[lane])-1], lane)
	}
	conditionalNegateIFMAPointX4(out, negativeMask)
}

func makeIFMAMicroAoSSelectorBenchmarkSet(entries, salt int) (ifmaGroupedTableSelectorExperimentX4, [X4Lanes]ifmaMicroAoSPerKeyTableExperiment, RadixRoundX4) {
	grouped := ifmaGroupedTableSelectorExperimentX4{points: make([]IFMAPointX4, entries)}
	var perKey [X4Lanes]ifmaMicroAoSPerKeyTableExperiment
	for lane := range perKey {
		perKey[lane].points = make([]ifmaMicroAoSPointEntryExperiment, entries)
	}
	for entry := 0; entry < entries; entry++ {
		for limb := 0; limb < 5; limb++ {
			for lane := 0; lane < X4Lanes; lane++ {
				for coordinate := 0; coordinate < 4; coordinate++ {
					value := uint64(1+salt*131+entry*37+limb*11+lane*5+coordinate) & limbMask
					perKey[lane].points[entry][limb][coordinate] = value
					switch coordinate {
					case 0:
						grouped.points[entry].X.limbs[limb][lane] = value
					case 1:
						grouped.points[entry].Y.limbs[limb][lane] = value
					case 2:
						grouped.points[entry].Z.limbs[limb][lane] = value
					case 3:
						grouped.points[entry].T.limbs[limb][lane] = value
					}
				}
			}
		}
	}
	var round RadixRoundX4
	for lane := 0; lane < X4Lanes; lane++ {
		setRadixRoundDigitX4(&round, lane, int8(1+(salt*7+lane*13)%entries))
	}
	return grouped, perKey, round
}

var benchmarkIFMAMicroAoSSelectorPointSink IFMAPointX4

// BenchmarkIFMAMicroAoSSelectorExperiment compares the existing grouped-SoA
// extraction schedule with the cacheable per-key micro-AoS layout. The
// standalone candidate materializes IFMAPointX4, so its count includes twenty
// output stores; a future selector+cached-add fusion can remove those stores.
func BenchmarkIFMAMicroAoSSelectorExperiment(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skip("requires AVX-512 IFMA target")
	}
	for _, config := range []struct {
		entries     int
		workingSets int
	}{
		{entries: 32, workingSets: 1},
		{entries: 32, workingSets: 32},
		{entries: 32, workingSets: 1024},
		{entries: 176, workingSets: 1},
		{entries: 176, workingSets: 6},
		{entries: 176, workingSets: 182},
	} {
		grouped := make([]ifmaGroupedTableSelectorExperimentX4, config.workingSets)
		perKey := make([][X4Lanes]ifmaMicroAoSPerKeyTableExperiment, config.workingSets)
		rounds := make([]RadixRoundX4, config.workingSets)
		for set := 0; set < config.workingSets; set++ {
			grouped[set], perKey[set], rounds[set] = makeIFMAMicroAoSSelectorBenchmarkSet(config.entries, set+1)
		}
		payloadBytes := int64(config.entries * int(unsafe.Sizeof(IFMAPointX4{})) * config.workingSets)
		name := fmt.Sprintf("entries=%d/working-set=%d/payload=%dKiB", config.entries, config.workingSets, payloadBytes/1024)
		b.Run(name+"/implementation=current-grouped-soa", func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(unsafe.Sizeof(IFMAPointX4{})))
			set := 0
			for i := 0; i < b.N; i++ {
				selectIFMAGroupedTableExperimentX4(&benchmarkIFMAMicroAoSSelectorPointSink, &grouped[set], &rounds[set], 0x0f)
				set++
				if set == config.workingSets {
					set = 0
				}
			}
		})
		b.Run(name+"/implementation=micro-aos-transpose", func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(unsafe.Sizeof(IFMAPointX4{})))
			set := 0
			for i := 0; i < b.N; i++ {
				selectIFMAMicroAoSUncheckedExperimentX4(&benchmarkIFMAMicroAoSSelectorPointSink, &perKey[set], &rounds[set], 0x0f)
				set++
				if set == config.workingSets {
					set = 0
				}
			}
		})
	}
}
