package r51x5

import (
	"errors"
	"testing"
	"unsafe"
)

type testIFMAVariableWorkspaceX4 interface {
	Prepare(*PointX4, uint) error
	Evaluate(*IFMAPointX4, *[X4Lanes][32]byte, uint8, uint8) (uint8, error)
}

type testIFMAVariableWorkspaceX8 interface {
	Prepare(*PointX8, uint) error
	Evaluate(*IFMAPointX8, *[X8Lanes][32]byte, uint8, uint8) (uint8, error)
}

type testIFMAFixedWorkspaceX8 interface {
	PrepareBoth(*[DSMTerms]PointX8, uint) error
	Evaluate(*IFMAPointX8, *FixedDSMScalarsX8, *[DSMTerms]uint8, uint8) (uint8, error)
}

func testIFMAVariableX4(radixBits uint) testIFMAVariableWorkspaceX4 {
	switch radixBits {
	case 4:
		return new(ExperimentalIFMAVariableBaseWorkspaceRadix16X4)
	case 5:
		return new(ExperimentalIFMAVariableBaseWorkspaceX4)
	case 6:
		return new(ExperimentalIFMAVariableBaseWorkspaceRadix64X4)
	default:
		panic("invalid test radix")
	}
}

func testIFMAVariableX8(radixBits uint) testIFMAVariableWorkspaceX8 {
	switch radixBits {
	case 4:
		return new(ExperimentalIFMAVariableBaseWorkspaceRadix16X8)
	case 5:
		return new(ExperimentalIFMAVariableBaseWorkspaceX8)
	case 6:
		return new(ExperimentalIFMAVariableBaseWorkspaceRadix64X8)
	default:
		panic("invalid test radix")
	}
}

func testIFMAFixedX8(radixBits uint) testIFMAFixedWorkspaceX8 {
	switch radixBits {
	case 4:
		return new(ExperimentalIFMAFixedDSMWorkspaceRadix16X8)
	case 5:
		return new(ExperimentalIFMAFixedDSMWorkspaceX8)
	case 6:
		return new(ExperimentalIFMAFixedDSMWorkspaceRadix64X8)
	default:
		panic("invalid test radix")
	}
}

func TestExperimentalIFMAVariableBaseWorkspaceUnavailable(t *testing.T) {
	if ExperimentalIFMAAvailable() {
		t.Skip("requires a host without the complete IFMA gate")
	}
	var base4 PointX4
	var workspace4 ExperimentalIFMAVariableBaseWorkspaceX4
	if err := workspace4.Prepare(&base4, 5); !errors.Is(err, ErrIFMAUnavailable) {
		t.Fatalf("x4 Prepare error = %v, want ErrIFMAUnavailable", err)
	}
	var base8 PointX8
	var workspace8 ExperimentalIFMAVariableBaseWorkspaceX8
	if err := workspace8.Prepare(&base8, 5); !errors.Is(err, ErrIFMAUnavailable) {
		t.Fatalf("x8 Prepare error = %v, want ErrIFMAUnavailable", err)
	}
}

func TestExperimentalIFMAVariableBaseWorkspaceOwnsOneTable(t *testing.T) {
	if got, twoTerm := unsafe.Sizeof(ExperimentalVariableBaseWorkspaceX8{}), unsafe.Sizeof(FixedDSMWorkspaceX8{}); got >= twoTerm {
		t.Fatalf("scalar x8 variable workspace size = %d, two-term = %d", got, twoTerm)
	}
	if got, twoTerm := unsafe.Sizeof(ExperimentalVariableBaseWorkspaceX4{}), unsafe.Sizeof(FixedDSMWorkspaceX4{}); got >= twoTerm {
		t.Fatalf("scalar x4 variable workspace size = %d, two-term = %d", got, twoTerm)
	}
	if got, twoTerm := unsafe.Sizeof(ExperimentalIFMAVariableBaseWorkspaceX8{}), unsafe.Sizeof(ExperimentalIFMAFixedDSMWorkspaceX8{}); got >= twoTerm {
		t.Fatalf("x8 variable workspace size = %d, two-term = %d", got, twoTerm)
	}
	if got, twoTerm := unsafe.Sizeof(ExperimentalIFMAVariableBaseWorkspaceX4{}), unsafe.Sizeof(ExperimentalIFMAFixedDSMWorkspaceX4{}); got >= twoTerm {
		t.Fatalf("x4 variable workspace size = %d, two-term = %d", got, twoTerm)
	}
}

func TestExperimentalIFMAVariableBaseWorkspaceX4MicroAoSBuildMatchesGrouped(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("requires AVX-512 IFMA target")
	}
	base, _, _, _ := scalarWindowBenchmarkFixtures(t)
	var got ExperimentalIFMAVariableBaseWorkspaceX4
	if err := got.Prepare(&base, 5); err != nil {
		t.Fatal(err)
	}
	var want ifmaFullTableX4[ifmaFullTableStorageRadix32X4]
	if err := buildIFMAFullTableX4Into(&want, &base, 5); err != nil {
		t.Fatal(err)
	}
	for entry := 0; entry < want.entries; entry++ {
		for limb := 0; limb < 5; limb++ {
			for lane := 0; lane < X4Lanes; lane++ {
				wantCoordinates := [4]uint64{
					want.points[entry].X.limbs[limb][lane],
					want.points[entry].Y.limbs[limb][lane],
					want.points[entry].Z.limbs[limb][lane],
					want.points[entry].T.limbs[limb][lane],
				}
				if gotCoordinates := got.table[lane][entry][limb]; gotCoordinates != wantCoordinates {
					t.Fatalf("entry=%d limb=%d lane=%d got=%x want=%x", entry, limb, lane, gotCoordinates, wantCoordinates)
				}
			}
		}
	}
}

func TestExperimentalVariableBaseWorkspaceMatchesTwoTermDSM(t *testing.T) {
	_, variable, _, scalars := fixedBaseCombDSMFixtures(t)
	identity := identityPointX8Value()
	bases := [DSMTerms]PointX8{identity, variable}
	var coefficients FixedDSMScalarsX8
	coefficients[1] = scalars
	negative := [DSMTerms]uint8{0, 0xff}
	for _, radixBits := range []uint{4, 5, 6} {
		var single ExperimentalVariableBaseWorkspaceX8
		single.Prepare(&variable, radixBits)
		var reference FixedDSMWorkspaceX8
		reference.Prepare(&bases, radixBits)
		for active := 0; active < 256; active++ {
			var got, want PointX8
			gotMask := single.Evaluate(&got, &scalars, uint8(active), uint8(active))
			wantMask := reference.Evaluate(&want, &coefficients, &negative, uint8(active))
			if gotMask != wantMask || got.Equal(&want) != 0xff {
				t.Fatalf("radix=%d active=%02x masks=%02x/%02x equality=%02x", 1<<radixBits, active, gotMask, wantMask, got.Equal(&want))
			}
		}
	}
}

func TestExperimentalVariableBaseWorkspaceX4MasksAndInvalidScalar(t *testing.T) {
	_, variable8, _, scalars8 := fixedBaseCombDSMFixtures(t)
	variable4 := pointX4Half(&variable8, 0)
	var scalars4 [X4Lanes][32]byte
	copy(scalars4[:], scalars8[:X4Lanes])
	scalars4[2] = scalarOrderBytes
	identity4 := identityPointX4Value()
	bases4 := [DSMTerms]PointX4{identity4, variable4}
	var coefficients FixedDSMScalarsX4
	coefficients[1] = scalars4
	for _, radixBits := range []uint{4, 5, 6} {
		var single ExperimentalVariableBaseWorkspaceX4
		single.Prepare(&variable4, radixBits)
		var reference FixedDSMWorkspaceX4
		reference.Prepare(&bases4, radixBits)
		for active := 0; active < 16; active++ {
			negative := [DSMTerms]uint8{0, uint8(active)}
			var got, want PointX4
			gotMask := single.Evaluate(&got, &scalars4, uint8(active), uint8(active))
			wantMask := reference.Evaluate(&want, &coefficients, &negative, uint8(active))
			if gotMask != wantMask || got.Equal(&want) != 0x0f {
				t.Fatalf("radix=%d active=%x masks=%x/%x equality=%x", 1<<radixBits, active, gotMask, wantMask, got.Equal(&want))
			}
		}
		if allocs := testing.AllocsPerRun(20, func() {
			single.Prepare(&variable4, radixBits)
			var out PointX4
			single.Evaluate(&out, &scalars4, 0x0f, 0x0f)
		}); allocs != 0 {
			t.Fatalf("scalar radix=%d cold prepare+evaluate allocations=%v", 1<<radixBits, allocs)
		}

		if !ExperimentalIFMAAvailable() {
			continue
		}
		singleIFMA := testIFMAVariableX4(radixBits)
		if err := singleIFMA.Prepare(&variable4, radixBits); err != nil {
			t.Fatal(err)
		}
		for active := 0; active < 16; active++ {
			var gotIFMA IFMAPointX4
			gotMask, err := singleIFMA.Evaluate(&gotIFMA, &scalars4, uint8(active), uint8(active))
			if err != nil {
				t.Fatal(err)
			}
			var want PointX4
			wantMask := single.Evaluate(&want, &scalars4, uint8(active), uint8(active))
			got := gotIFMA.Reduced()
			if gotMask != wantMask || got.Equal(&want) != 0x0f {
				t.Fatalf("IFMA radix=%d active=%x masks=%x/%x equality=%x", 1<<radixBits, active, gotMask, wantMask, got.Equal(&want))
			}
		}
		var out IFMAPointX4
		if allocs := testing.AllocsPerRun(20, func() {
			if err := singleIFMA.Prepare(&variable4, radixBits); err != nil {
				panic(err)
			}
			if _, err := singleIFMA.Evaluate(&out, &scalars4, 0x0f, 0x0f); err != nil {
				panic(err)
			}
		}); allocs != 0 {
			t.Fatalf("IFMA radix=%d cold prepare+evaluate allocations=%v", 1<<radixBits, allocs)
		}
	}
}

func TestExperimentalIFMAVariableBaseWorkspaceMatchesTwoTermDSM(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("requires the complete IFMA gate")
	}
	_, variable, _, scalars := fixedBaseCombDSMFixtures(t)
	identity := identityPointX8Value()
	bases := [DSMTerms]PointX8{identity, variable}
	var coefficients FixedDSMScalarsX8
	coefficients[1] = scalars
	negative := [DSMTerms]uint8{0, 0xff}

	for _, radixBits := range []uint{4, 5, 6} {
		single := testIFMAVariableX8(radixBits)
		if err := single.Prepare(&variable, radixBits); err != nil {
			t.Fatal(err)
		}
		reference := testIFMAFixedX8(radixBits)
		if err := reference.PrepareBoth(&bases, radixBits); err != nil {
			t.Fatal(err)
		}
		for active := 0; active < 256; active++ {
			var got, want IFMAPointX8
			gotMask, err := single.Evaluate(&got, &scalars, uint8(active), uint8(active))
			if err != nil {
				t.Fatal(err)
			}
			wantMask, err := reference.Evaluate(&want, &coefficients, &negative, uint8(active))
			if err != nil {
				t.Fatal(err)
			}
			gotReduced, wantReduced := got.Reduced(), want.Reduced()
			if gotMask != wantMask || gotReduced.Bytes() != wantReduced.Bytes() {
				t.Fatalf("radix=%d active=%02x masks=%02x/%02x", 1<<radixBits, active, gotMask, wantMask)
			}
		}
	}
}

func TestExperimentalIFMAVariableBaseWorkspaceZeroAllocations(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("requires the complete IFMA gate")
	}
	_, variable, _, scalars := fixedBaseCombDSMFixtures(t)
	var workspace ExperimentalIFMAVariableBaseWorkspaceX8
	if err := workspace.Prepare(&variable, 5); err != nil {
		t.Fatal(err)
	}
	var out IFMAPointX8
	if allocs := testing.AllocsPerRun(20, func() {
		if _, err := workspace.Evaluate(&out, &scalars, 0xff, 0xff); err != nil {
			panic(err)
		}
	}); allocs != 0 {
		t.Fatalf("allocations = %v", allocs)
	}
}
