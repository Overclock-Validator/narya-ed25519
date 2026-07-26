package r51x5

import (
	"fmt"
	"testing"
	"unsafe"
)

func makeIFMAAffine3MicroAoSFixture(entries, salt int) [X4Lanes]ifmaAffine3MicroAoSPerKeyTableExperiment {
	var tables [X4Lanes]ifmaAffine3MicroAoSPerKeyTableExperiment
	for lane := range tables {
		tables[lane].points = make([]ifmaAffine3MicroAoSEntryExperiment, entries)
		for entry := 0; entry < entries; entry++ {
			for limb := 0; limb < 5; limb++ {
				for coordinate := 0; coordinate < 3; coordinate++ {
					tables[lane].points[entry][limb][coordinate] =
						uint64(1+salt*131+entry*37+limb*11+lane*5+coordinate) & limbMask
				}
			}
		}
	}
	return tables
}

func expectedIFMAAffine3MicroAoSSelection(
	tables *[X4Lanes]ifmaAffine3MicroAoSPerKeyTableExperiment,
	round *RadixRoundX4,
	active uint8,
) fixedBaseIFMACachedX4 {
	result := identityFixedBaseIFMACachedX4()
	lookupMask := round.NonzeroMask & active & 0x0f
	for lane := 0; lane < X4Lanes; lane++ {
		laneMask := uint8(1 << lane)
		if lookupMask&laneMask == 0 {
			continue
		}
		entry := &tables[lane].points[int(round.Magnitude[lane])-1]
		var source fixedBaseAffineCached
		for limb := 0; limb < 5; limb++ {
			source.YPlusX.limbs[limb] = entry[limb][0]
			source.YMinusX.limbs[limb] = entry[limb][1]
			source.T2D.limbs[limb] = entry[limb][2]
		}
		setFixedBaseIFMACachedLaneX4(&result, &source, lane, round.NegativeMask&laneMask != 0)
	}
	return result
}

func TestIFMAAffine3MicroAoSSelectorAllMasksAndSigns(t *testing.T) {
	if !microAoSSelectorExperimentCanCall() {
		t.Skip("requires AVX-512 IFMA target on amd64")
	}
	tables := makeIFMAAffine3MicroAoSFixture(32, 1)
	patterns := [][X4Lanes]int8{
		{},
		{1, -7, 19, -32},
		{-32, 31, -2, 2},
	}
	for patternIndex, digits := range patterns {
		var round RadixRoundX4
		for lane, digit := range digits {
			setRadixRoundDigitX4(&round, lane, digit)
		}
		for active := 0; active < 1<<X4Lanes; active++ {
			want := expectedIFMAAffine3MicroAoSSelection(&tables, &round, uint8(active))
			var checked fixedBaseIFMACachedX4
			selectIFMAAffine3MicroAoSCheckedExperimentX4(&checked, &tables, &round, uint8(active))
			if checked != want {
				t.Fatalf("pattern=%d digits=%v active=%02x checked mismatch", patternIndex, digits, active)
			}
			var unchecked fixedBaseIFMACachedX4
			selectIFMAAffine3MicroAoSUncheckedExperimentX4(&unchecked, &tables, &round, uint8(active))
			if unchecked != want {
				t.Fatalf("pattern=%d digits=%v active=%02x unchecked mismatch", patternIndex, digits, active)
			}
		}
	}

	poisoned := RadixRoundX4{
		Magnitude:    [X4Lanes]uint8{1, 2, 3, 0xff},
		NonzeroMask:  0x0f,
		NegativeMask: 0x08,
	}
	want := expectedIFMAAffine3MicroAoSSelection(&tables, &poisoned, 0x07)
	var got fixedBaseIFMACachedX4
	selectIFMAAffine3MicroAoSCheckedExperimentX4(&got, &tables, &poisoned, 0x07)
	if got != want {
		t.Fatal("inactive poisoned metadata mismatch")
	}
}

func TestIFMAAffine3MicroAoSTransposeU52Boundary(t *testing.T) {
	if !microAoSSelectorExperimentCanCall() {
		t.Skip("requires AVX-512 IFMA target on amd64")
	}
	var entries [X4Lanes]ifmaAffine3MicroAoSEntryExperiment
	for lane := range entries {
		for limb := range entries[lane] {
			for coordinate := range entries[lane][limb] {
				entries[lane][limb][coordinate] = ifmaComposableLimbLimit - 1 - uint64((lane+limb+coordinate)%17)
			}
		}
	}
	var got fixedBaseIFMACachedX4
	ifmaAffine3MicroAoSTransposeSelectExperimentX4(&got, &entries[0], &entries[1], &entries[2], &entries[3])
	coordinates := [3]*IFMAElementX4{&got.YPlusX, &got.YMinusX, &got.T2D}
	for coordinate, element := range coordinates {
		for limb := 0; limb < 5; limb++ {
			for lane := 0; lane < X4Lanes; lane++ {
				if value, want := element.limbs[limb][lane], entries[lane][limb][coordinate]; value != want {
					t.Fatalf("coordinate=%d limb=%d lane=%d got=%x want=%x", coordinate, limb, lane, value, want)
				}
			}
		}
	}
}

func TestIFMAAffine3MicroAoSTransposeX8U52Boundary(t *testing.T) {
	if !microAoSSelectorExperimentCanCall() {
		t.Skip("requires AVX-512 IFMA target on amd64")
	}
	var entries [X8Lanes]ifmaAffine3MicroAoSEntryExperiment
	for lane := range entries {
		for limb := range entries[lane] {
			for coordinate := range entries[lane][limb] {
				entries[lane][limb][coordinate] = ifmaComposableLimbLimit - 1 - uint64((lane+limb+coordinate)%29)
			}
		}
	}
	var got fixedBaseIFMACachedX8
	ifmaAffine3MicroAoSTransposeSelectExperimentX8(
		&got,
		&entries[0], &entries[1], &entries[2], &entries[3],
		&entries[4], &entries[5], &entries[6], &entries[7],
	)
	coordinates := [3]*IFMAElementX8{&got.YPlusX, &got.YMinusX, &got.T2D}
	for coordinate, element := range coordinates {
		for limb := 0; limb < 5; limb++ {
			for lane := 0; lane < X8Lanes; lane++ {
				if value, want := element.limbs[limb][lane], entries[lane][limb][coordinate]; value != want {
					t.Fatalf("coordinate=%d limb=%d lane=%d got=%x want=%x", coordinate, limb, lane, value, want)
				}
			}
		}
	}
}

func TestIFMAAffine3MicroAoSTransposeExactAlias(t *testing.T) {
	if !microAoSSelectorExperimentCanCall() {
		t.Skip("requires AVX-512 IFMA target on amd64")
	}
	var entries [X4Lanes]ifmaAffine3MicroAoSEntryExperiment
	for lane := range entries {
		for limb := range entries[lane] {
			for coordinate := range entries[lane][limb] {
				entries[lane][limb][coordinate] = uint64(1 + lane*101 + limb*11 + coordinate)
			}
		}
	}
	var want fixedBaseIFMACachedX4
	ifmaAffine3MicroAoSTransposeSelectExperimentX4(&want, &entries[0], &entries[1], &entries[2], &entries[3])

	aliased := entries
	if unsafe.Sizeof(aliased) != unsafe.Sizeof(want) {
		t.Fatalf("alias fixture size=%d output size=%d", unsafe.Sizeof(aliased), unsafe.Sizeof(want))
	}
	out := (*fixedBaseIFMACachedX4)(unsafe.Pointer(&aliased[0]))
	ifmaAffine3MicroAoSTransposeSelectExperimentX4(out, &aliased[0], &aliased[1], &aliased[2], &aliased[3])
	if *out != want {
		t.Fatal("exact-alias transpose mismatch")
	}
}

func TestIFMAAffine3MicroAoSSelectorFailClosedAndZeroAllocations(t *testing.T) {
	if !microAoSSelectorExperimentCanCall() {
		t.Skip("requires AVX-512 IFMA target on amd64")
	}
	tables := makeIFMAAffine3MicroAoSFixture(8, 2)
	bad := RadixRoundX4{Magnitude: [X4Lanes]uint8{9}, NonzeroMask: 1}
	sentinel := fixedBaseIFMACachedX4{
		YPlusX:  patternedIFMAElementX4Garbage(),
		YMinusX: patternedIFMAElementX4Garbage(),
		T2D:     patternedIFMAElementX4Garbage(),
	}
	got := sentinel
	if !microAoSSelectorExperimentPanics(func() {
		selectIFMAAffine3MicroAoSCheckedExperimentX4(&got, &tables, &bad, 1)
	}) {
		t.Fatal("invalid metadata did not panic")
	}
	if got != sentinel {
		t.Fatal("invalid metadata changed output")
	}

	var round RadixRoundX4
	for lane, digit := range []int8{1, -2, 3, -4} {
		setRadixRoundDigitX4(&round, lane, digit)
	}
	if allocations := testing.AllocsPerRun(1000, func() {
		selectIFMAAffine3MicroAoSUncheckedExperimentX4(&got, &tables, &round, 0x0f)
	}); allocations != 0 {
		t.Fatalf("unchecked allocations=%v want=0", allocations)
	}
}

func patternedIFMAElementX4Garbage() IFMAElementX4 {
	var out IFMAElementX4
	for limb := range out.limbs {
		for lane := 0; lane < X4Lanes; lane++ {
			out.limbs[limb][lane] = uint64(0x1000 + limb*0x10 + lane)
		}
	}
	return out
}

var benchmarkIFMAAffine3MicroAoSSink fixedBaseIFMACachedX4

func BenchmarkIFMAAffine3MicroAoSSelectorExperiment(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skip("requires AVX-512 IFMA target")
	}
	for _, config := range []struct {
		entries     int
		workingSets int
	}{
		{entries: 32, workingSets: 1},
		{entries: 32, workingSets: 32},
		{entries: 160, workingSets: 1},
		{entries: 160, workingSets: 6},
		{entries: 160, workingSets: 16},
		{entries: 256, workingSets: 1},
		{entries: 256, workingSets: 16},
	} {
		tables := make([][X4Lanes]ifmaAffine3MicroAoSPerKeyTableExperiment, config.workingSets)
		fullTables := make([][X4Lanes]ifmaMicroAoSPerKeyTableExperiment, config.workingSets)
		rounds := make([]RadixRoundX4, config.workingSets)
		for set := range tables {
			tables[set] = makeIFMAAffine3MicroAoSFixture(config.entries, set+1)
			_, fullTables[set], rounds[set] = makeIFMAMicroAoSSelectorBenchmarkSet(config.entries, set+1)
		}
		affine3Payload := int64(config.entries * config.workingSets * X4Lanes * int(unsafe.Sizeof(ifmaAffine3MicroAoSEntryExperiment{})))
		full4Payload := int64(config.entries * config.workingSets * X4Lanes * int(unsafe.Sizeof(ifmaMicroAoSPointEntryExperiment{})))
		prefix := fmt.Sprintf("entries=%d/working-sets=%d", config.entries, config.workingSets)
		for _, signs := range []struct {
			name  string
			mixed bool
		}{
			{name: "positive"},
			{name: "mixed", mixed: true},
		} {
			benchmarkRounds := append([]RadixRoundX4(nil), rounds...)
			if signs.mixed {
				for set := range benchmarkRounds {
					// Exercise the realistic nonzero sign path while retaining the
					// same table magnitudes and memory access pattern.
					benchmarkRounds[set].NegativeMask = 0x05
				}
			}
			b.Run(fmt.Sprintf("%s/signs=%s/implementation=affine3/payload=%dKiB", prefix, signs.name, affine3Payload/1024), func(b *testing.B) {
				b.ReportAllocs()
				set := 0
				for i := 0; i < b.N; i++ {
					selectIFMAAffine3MicroAoSUncheckedExperimentX4(&benchmarkIFMAAffine3MicroAoSSink, &tables[set], &benchmarkRounds[set], 0x0f)
					set++
					if set == len(tables) {
						set = 0
					}
				}
			})
			b.Run(fmt.Sprintf("%s/signs=%s/implementation=full4/payload=%dKiB", prefix, signs.name, full4Payload/1024), func(b *testing.B) {
				b.ReportAllocs()
				set := 0
				for i := 0; i < b.N; i++ {
					selectIFMAMicroAoSUncheckedExperimentX4(&benchmarkIFMAMicroAoSSelectorPointSink, &fullTables[set], &benchmarkRounds[set], 0x0f)
					set++
					if set == len(fullTables) {
						set = 0
					}
				}
			})
		}
	}
}
