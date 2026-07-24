package r51x5

import (
	"fmt"
	"testing"
	"unsafe"
)

func TestIFMAFullTablePhysicalFootprintMatchesRadix(t *testing.T) {
	metadata4 := unsafe.Sizeof(IFMAFullTableRadix16X4{}) - 8*unsafe.Sizeof(IFMAPointX4{})
	metadata8 := unsafe.Sizeof(IFMAFullTableRadix16X8{}) - 8*unsafe.Sizeof(IFMAPointX8{})
	if metadata4 != metadata8 {
		t.Fatalf("table metadata differs by width: x4=%d x8=%d", metadata4, metadata8)
	}

	tests := []struct {
		name       string
		lanes      int
		radixBits  uint
		physical   uintptr
		pointBytes uintptr
		metadata   uintptr
	}{
		{"x4/radix16", X4Lanes, 4, unsafe.Sizeof(IFMAFullTableRadix16X4{}), unsafe.Sizeof(IFMAPointX4{}), metadata4},
		{"x4/radix32", X4Lanes, 5, unsafe.Sizeof(IFMAFullTableX4{}), unsafe.Sizeof(IFMAPointX4{}), metadata4},
		{"x4/radix64", X4Lanes, 6, unsafe.Sizeof(IFMAFullTableRadix64X4{}), unsafe.Sizeof(IFMAPointX4{}), metadata4},
		{"x8/radix16", X8Lanes, 4, unsafe.Sizeof(IFMAFullTableRadix16X8{}), unsafe.Sizeof(IFMAPointX8{}), metadata8},
		{"x8/radix32", X8Lanes, 5, unsafe.Sizeof(IFMAFullTableX8{}), unsafe.Sizeof(IFMAPointX8{}), metadata8},
		{"x8/radix64", X8Lanes, 6, unsafe.Sizeof(IFMAFullTableRadix64X8{}), unsafe.Sizeof(IFMAPointX8{}), metadata8},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entries := uintptr(regularRadixEntries(test.radixBits))
			activePayload := uintptr(NominalFullTableBytes(test.lanes, 4, test.radixBits))
			if got := entries * test.pointBytes; got != activePayload {
				t.Fatalf("point-array payload=%d, nominal active payload=%d", got, activePayload)
			}
			if want := activePayload + test.metadata; test.physical != want {
				t.Fatalf("physical table=%d, want active payload %d + metadata %d = %d", test.physical, activePayload, test.metadata, want)
			}
		})
	}

	if got, want := unsafe.Sizeof(IFMAFullTableX8{}), uintptr(NominalFullTableBytes(X8Lanes, 4, 5))+metadata8; got != want {
		t.Fatalf("radix-32 x8 physical table=%d, want %d", got, want)
	}
	if unsafe.Sizeof(IFMAFullTableX8{})*2 >= unsafe.Sizeof(IFMAFullTableRadix64X8{})*2 {
		t.Fatal("radix-32 retained tables did not shrink below radix-64")
	}
}

func TestIFMARadixSpecificWorkspacePhysicalFootprint(t *testing.T) {
	if got, max := unsafe.Sizeof(ExperimentalIFMAFixedDSMWorkspaceX8{}), unsafe.Sizeof(ExperimentalIFMAFixedDSMWorkspaceRadix64X8{}); got >= max {
		t.Fatalf("ordinary radix-32 x8 workspace=%d, radix-64=%d", got, max)
	}
	if got, max := unsafe.Sizeof(ExperimentalIFMAHEEABaseSplitWorkspaceX8{}), unsafe.Sizeof(ExperimentalIFMAHEEABaseSplitWorkspaceRadix64X8{}); got >= max {
		t.Fatalf("HEEA radix-32 x8 workspace=%d, radix-64=%d", got, max)
	}
	if got, max := unsafe.Sizeof(ExperimentalIFMAFixedDSMWorkspaceRadix16X8{}), unsafe.Sizeof(ExperimentalIFMAFixedDSMWorkspaceX8{}); got >= max {
		t.Fatalf("ordinary radix-16 x8 workspace=%d, radix-32=%d", got, max)
	}
	if got, max := unsafe.Sizeof(ExperimentalIFMAHEEABaseSplitWorkspaceRadix16X8{}), unsafe.Sizeof(ExperimentalIFMAHEEABaseSplitWorkspaceX8{}); got >= max {
		t.Fatalf("HEEA radix-16 x8 workspace=%d, radix-32=%d", got, max)
	}
}

func TestIFMAFullTableBuildDoesNotClearInactiveCapacity(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("requires the complete IFMA gate")
	}
	_, base, _, _ := scalarWindowBenchmarkFixtures(t)

	var reducedBaseTable IFMAFullTableX8
	for entry := 8; entry < len(reducedBaseTable.points); entry++ {
		reducedBaseTable.points[entry].X.limbs[0][0] = uint64(0x5100 + entry)
	}
	beforeReduced := reducedBaseTable.points
	if err := buildIFMAFullTableX8Into(&reducedBaseTable, &base, 4); err != nil {
		t.Fatal(err)
	}
	for entry := 8; entry < len(reducedBaseTable.points); entry++ {
		if reducedBaseTable.points[entry] != beforeReduced[entry] {
			t.Fatalf("reduced-base builder touched inactive entry %d", entry)
		}
	}

	var composableBase IFMAPointX8
	composableBase.SetReduced(&base)
	var composableBaseTable IFMAFullTableX8
	for entry := 8; entry < len(composableBaseTable.points); entry++ {
		composableBaseTable.points[entry].Y.limbs[0][1] = uint64(0x5200 + entry)
	}
	beforeComposable := composableBaseTable.points
	if err := buildIFMAFullTableFromComposableX8Into(&composableBaseTable, &composableBase, 4); err != nil {
		t.Fatal(err)
	}
	for entry := 8; entry < len(composableBaseTable.points); entry++ {
		if composableBaseTable.points[entry] != beforeComposable[entry] {
			t.Fatalf("composable-base builder touched inactive entry %d", entry)
		}
	}
}

func BenchmarkIFMATableFootprint(b *testing.B) {
	benchmarkIFMATableFootprint(b, "x4/radix16", X4Lanes, 4,
		unsafe.Sizeof(IFMAFullTableRadix16X4{}),
		unsafe.Sizeof(ExperimentalIFMAFixedDSMWorkspaceRadix16X4{}),
		unsafe.Sizeof(ExperimentalIFMAHEEABaseSplitWorkspaceRadix16X4{}))
	benchmarkIFMATableFootprint(b, "x4/radix32", X4Lanes, 5,
		unsafe.Sizeof(IFMAFullTableX4{}),
		unsafe.Sizeof(ExperimentalIFMAFixedDSMWorkspaceX4{}),
		unsafe.Sizeof(ExperimentalIFMAHEEABaseSplitWorkspaceX4{}))
	benchmarkIFMATableFootprint(b, "x4/radix64", X4Lanes, 6,
		unsafe.Sizeof(IFMAFullTableRadix64X4{}),
		unsafe.Sizeof(ExperimentalIFMAFixedDSMWorkspaceRadix64X4{}),
		unsafe.Sizeof(ExperimentalIFMAHEEABaseSplitWorkspaceRadix64X4{}))
	benchmarkIFMATableFootprint(b, "x8/radix16", X8Lanes, 4,
		unsafe.Sizeof(IFMAFullTableRadix16X8{}),
		unsafe.Sizeof(ExperimentalIFMAFixedDSMWorkspaceRadix16X8{}),
		unsafe.Sizeof(ExperimentalIFMAHEEABaseSplitWorkspaceRadix16X8{}))
	benchmarkIFMATableFootprint(b, "x8/radix32", X8Lanes, 5,
		unsafe.Sizeof(IFMAFullTableX8{}),
		unsafe.Sizeof(ExperimentalIFMAFixedDSMWorkspaceX8{}),
		unsafe.Sizeof(ExperimentalIFMAHEEABaseSplitWorkspaceX8{}))
	benchmarkIFMATableFootprint(b, "x8/radix64", X8Lanes, 6,
		unsafe.Sizeof(IFMAFullTableRadix64X8{}),
		unsafe.Sizeof(ExperimentalIFMAFixedDSMWorkspaceRadix64X8{}),
		unsafe.Sizeof(ExperimentalIFMAHEEABaseSplitWorkspaceRadix64X8{}))
}

func benchmarkIFMATableFootprint(b *testing.B, name string, lanes int, radixBits uint, physicalTable, ordinaryWorkspace, heeaWorkspace uintptr) {
	b.Run(name, func(b *testing.B) {
		activeTable := NominalFullTableBytes(lanes, 4, radixBits)
		b.ReportMetric(float64(activeTable), "active-table-payload-B")
		b.ReportMetric(float64(DSMTerms*activeTable), "ordinary-active-tables-B")
		b.ReportMetric(float64(QSMTerms*activeTable), "heea-active-tables-B")
		b.ReportMetric(float64(physicalTable), "physical-table-B")
		b.ReportMetric(float64(ordinaryWorkspace), "ordinary-physical-workspace-B")
		b.ReportMetric(float64(heeaWorkspace), "heea-physical-workspace-B")
		for i := 0; i < b.N; i++ {
			if physicalTable == 0 {
				b.Fatal(fmt.Sprintf("invalid table size for %s", name))
			}
		}
	})
}
