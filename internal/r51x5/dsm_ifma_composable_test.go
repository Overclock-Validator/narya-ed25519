package r51x5

import (
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"runtime"
	"testing"
	"unsafe"

	edwardsref "github.com/Overclock-Validator/narya-ed25519/internal/edwards25519"
)

func TestIFMAFixedDSMModelExactSignedMixedOrderAndMasks(t *testing.T) {
	rng := rand.New(rand.NewSource(0x1f4a_d5a2))
	torsion := referenceTorsionPoints(t)
	refs, fixture := scalarWindowQSMBasesX8(t, rng, &torsion)
	bases := [DSMTerms]PointX8{fixture[0], fixture[1]}
	for term := range bases {
		bases[term] = randomProjectiveScaleX8(t, rng, &bases[term])
	}
	scalars, signs, exact := randomIFMAFixedDSMScalars(rng)
	// Force a particularly discriminating -1 coefficient on a mixed-order A.
	// Replacing -1 with L-1 would differ by [L]A's torsion component.
	scalars[1][0] = [32]byte{1}
	exact[1][0] = big.NewInt(-1)
	want := exactIFMAFixedDSMWant(&refs, &exact)

	for _, radixBits := range []uint{4, 5, 6} {
		var workspace modelIFMAFixedDSMWorkspaceX8
		if err := workspace.prepare(&bases, radixBits); err != nil {
			t.Fatal(err)
		}
		for _, active := range everyIFMADSMActiveMaskX8() {
			var gotLoose IFMAPointX8
			usable, err := workspace.evaluate(&gotLoose, &scalars, &signs, active)
			if err != nil {
				t.Fatal(err)
			}
			if usable != active {
				t.Fatalf("radix %d active=%02x usable=%02x", 1<<radixBits, active, usable)
			}
			got := gotLoose.Reduced()
			assertMaskedPointX8(t, fmt.Sprintf("IFMA model radix %d active %02x", 1<<radixBits, active), &got, &want, active)
		}
		assertModelIFMAX4Halves(t, &bases, &scalars, &signs, radixBits, &workspace)

		// Refresh public scalars while retaining both prepared tables.
		for iteration := 0; iteration < 8; iteration++ {
			randomScalars, randomSigns, randomExact := randomIFMAFixedDSMScalars(rng)
			randomWant := exactIFMAFixedDSMWant(&refs, &randomExact)
			active := uint8(rng.Uint32())
			var gotLoose IFMAPointX8
			usable, err := workspace.evaluate(&gotLoose, &randomScalars, &randomSigns, active)
			if err != nil || usable != active {
				t.Fatalf("radix %d iteration %d evaluate=(%02x,%v) want=%02x", 1<<radixBits, iteration, usable, err, active)
			}
			got := gotLoose.Reduced()
			assertMaskedPointX8(t, fmt.Sprintf("IFMA model random radix %d iteration %d", 1<<radixBits, iteration), &got, &randomWant, active)
		}

		// Each lane independently becomes unusable when either term is not a
		// canonical scalar. The point result for that lane must be identity.
		for invalidLane := 0; invalidLane < X8Lanes; invalidLane++ {
			invalid := scalars
			invalid[invalidLane&1][invalidLane] = scalarOrderBytes
			var gotLoose IFMAPointX8
			usable, err := workspace.evaluate(&gotLoose, &invalid, &signs, 0xff)
			wantUsable := uint8(0xff &^ (1 << invalidLane))
			if err != nil || usable != wantUsable {
				t.Fatalf("radix %d invalid lane %d evaluate=(%02x,%v) want=%02x", 1<<radixBits, invalidLane, usable, err, wantUsable)
			}
			got := gotLoose.Reduced()
			gotLane := got.Lane(invalidLane)
			if gotLane.IsIdentity() != 1 {
				t.Fatalf("radix %d invalid lane %d is not identity", 1<<radixBits, invalidLane)
			}
		}

	}
}

func TestExperimentalIFMAFixedDSMHardware(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	rng := rand.New(rand.NewSource(0x1f4a_d5a2_51))
	torsion := referenceTorsionPoints(t)
	_, fixture := scalarWindowQSMBasesX8(t, rng, &torsion)
	bases := [DSMTerms]PointX8{fixture[0], fixture[1]}
	for term := range bases {
		bases[term] = randomProjectiveScaleX8(t, rng, &bases[term])
	}
	scalars, signs, _ := randomIFMAFixedDSMScalars(rng)

	for _, radixBits := range []uint{4, 5, 6} {
		switch radixBits {
		case 4:
			var hardware ExperimentalIFMAFixedDSMWorkspaceRadix16X8
			var hardware4 [2]ExperimentalIFMAFixedDSMWorkspaceRadix16X4
			testExperimentalIFMAFixedDSMHardwareRadix(t, rng, &bases, &scalars, &signs, radixBits, &hardware, &hardware4)
		case 5:
			var hardware ExperimentalIFMAFixedDSMWorkspaceX8
			var hardware4 [2]ExperimentalIFMAFixedDSMWorkspaceX4
			testExperimentalIFMAFixedDSMHardwareRadix(t, rng, &bases, &scalars, &signs, radixBits, &hardware, &hardware4)
		case 6:
			var hardware ExperimentalIFMAFixedDSMWorkspaceRadix64X8
			var hardware4 [2]ExperimentalIFMAFixedDSMWorkspaceRadix64X4
			testExperimentalIFMAFixedDSMHardwareRadix(t, rng, &bases, &scalars, &signs, radixBits, &hardware, &hardware4)
		}
	}
}

func testExperimentalIFMAFixedDSMHardwareRadix[Storage8 ifmaFullTableStorageX8, Storage4 ifmaFullTableStorageX4](t *testing.T, rng *rand.Rand, bases *[DSMTerms]PointX8, scalars *FixedDSMScalarsX8, signs *[DSMTerms]uint8, radixBits uint, hardware *experimentalIFMAFixedDSMWorkspaceX8[Storage8], hardware4 *[2]experimentalIFMAFixedDSMWorkspaceX4[Storage4]) {
	t.Helper()
	if err := hardware.PrepareFixedBase(&bases[0], radixBits); err != nil {
		t.Fatal(err)
	}
	if err := hardware.PrepareVariableBase(&bases[1]); err != nil {
		t.Fatal(err)
	}
	var model modelIFMAFixedDSMWorkspaceX8
	if err := model.prepare(bases, radixBits); err != nil {
		t.Fatal(err)
	}
	var bases4 [2][DSMTerms]PointX4
	for half := 0; half < 2; half++ {
		for term := 0; term < DSMTerms; term++ {
			bases4[half][term] = pointX4Half(&bases[term], half)
		}
		if err := hardware4[half].PrepareFixedBase(&bases4[half][0], radixBits); err != nil {
			t.Fatal(err)
		}
		if err := hardware4[half].PrepareVariableBase(&bases4[half][1]); err != nil {
			t.Fatal(err)
		}
	}
	for _, active := range everyIFMADSMActiveMaskX8() {
		var got, want IFMAPointX8
		gotMask, err := hardware.Evaluate(&got, scalars, signs, active)
		if err != nil {
			t.Fatal(err)
		}
		wantMask, err := model.evaluate(&want, scalars, signs, active)
		gotReduced, wantReduced := got.Reduced(), want.Reduced()
		if err != nil || gotMask != wantMask || gotReduced.Equal(&wantReduced) != 0xff {
			t.Fatalf("radix %d active=%02x hardware/model masks=(%02x,%02x) err=%v", 1<<radixBits, active, gotMask, wantMask, err)
		}
		joined, joinedMask := evaluateExperimentalIFMAX4Halves(t, hardware4, scalars, signs, active)
		if joinedMask != gotMask || joined.Equal(&gotReduced) != 0xff {
			t.Fatalf("radix %d active=%02x two-x4/x8 masks=(%02x,%02x)", 1<<radixBits, active, joinedMask, gotMask)
		}
	}
	for iteration := 0; iteration < 16; iteration++ {
		randomScalars, randomSigns, _ := randomIFMAFixedDSMScalars(rng)
		active := uint8(rng.Uint32())
		var got, want IFMAPointX8
		gotMask, gotErr := hardware.Evaluate(&got, &randomScalars, &randomSigns, active)
		wantMask, wantErr := model.evaluate(&want, &randomScalars, &randomSigns, active)
		gotReduced, wantReduced := got.Reduced(), want.Reduced()
		if gotErr != nil || wantErr != nil || gotMask != wantMask || gotReduced.Equal(&wantReduced) != 0xff {
			t.Fatalf("radix %d iteration %d hardware=(%02x,%v) model=(%02x,%v)", 1<<radixBits, iteration, gotMask, gotErr, wantMask, wantErr)
		}
	}
	for invalidLane := 0; invalidLane < X8Lanes; invalidLane++ {
		invalid := *scalars
		invalid[invalidLane&1][invalidLane] = scalarOrderBytes
		var got, want IFMAPointX8
		gotMask, gotErr := hardware.Evaluate(&got, &invalid, signs, 0xff)
		wantMask, wantErr := model.evaluate(&want, &invalid, signs, 0xff)
		gotReduced, wantReduced := got.Reduced(), want.Reduced()
		if gotErr != nil || wantErr != nil || gotMask != wantMask || gotMask != uint8(0xff&^(1<<invalidLane)) || gotReduced.Equal(&wantReduced) != 0xff {
			t.Fatalf("radix %d invalid lane %d hardware=(%02x,%v) model=(%02x,%v)", 1<<radixBits, invalidLane, gotMask, gotErr, wantMask, wantErr)
		}
	}
	fixedTableBefore := hardware.tables[0]
	newVariable := bases[1]
	newVariable.Double(&newVariable)
	if err := hardware.PrepareVariableBase(&newVariable); err != nil {
		t.Fatal(err)
	}
	if hardware.tables[0] != fixedTableBefore {
		t.Fatalf("radix %d variable-base preparation changed fixed B table", 1<<radixBits)
	}
	newBases := [DSMTerms]PointX8{bases[0], newVariable}
	var newModel modelIFMAFixedDSMWorkspaceX8
	if err := newModel.prepare(&newBases, radixBits); err != nil {
		t.Fatal(err)
	}
	var got, want IFMAPointX8
	gotMask, gotErr := hardware.Evaluate(&got, scalars, signs, 0xff)
	wantMask, wantErr := newModel.evaluate(&want, scalars, signs, 0xff)
	gotReduced, wantReduced := got.Reduced(), want.Reduced()
	if gotErr != nil || wantErr != nil || gotMask != wantMask || gotReduced.Equal(&wantReduced) != 0xff {
		t.Fatalf("radix %d replaced A hardware=(%02x,%v) model=(%02x,%v)", 1<<radixBits, gotMask, gotErr, wantMask, wantErr)
	}
}

func TestExperimentalIFMAFixedDSMGate(t *testing.T) {
	if ExperimentalIFMAAvailable() {
		t.Skip("unavailable-path test")
	}
	var workspace ExperimentalIFMAFixedDSMWorkspaceX8
	before := workspace
	var base PointX8
	if err := workspace.PrepareFixedBase(&base, 4); !errors.Is(err, ErrIFMAUnavailable) {
		t.Fatalf("prepare error=%v want=%v", err, ErrIFMAUnavailable)
	}
	if workspace != before {
		t.Fatal("unavailable fixed-base preparation changed workspace")
	}

	workspace.fixedBasePrepared = true
	workspace.variableBasePrepared = true
	workspace.radixBits = 4
	var out IFMAPointX8
	out.X.limbs[0][0] = 7
	want := out
	var scalars FixedDSMScalarsX8
	var signs [DSMTerms]uint8
	if mask, err := workspace.Evaluate(&out, &scalars, &signs, 0xff); mask != 0 || !errors.Is(err, ErrIFMAUnavailable) {
		t.Fatalf("evaluate=(%02x,%v) want=(00,%v)", mask, err, ErrIFMAUnavailable)
	}
	if out != want {
		t.Fatal("unavailable evaluation changed output")
	}
}

func TestExperimentalIFMAFixedDSMRequiresFixedBaseFirst(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("variable-base preparation before fixed base did not panic")
		}
	}()
	var unordered ExperimentalIFMAFixedDSMWorkspaceX4
	var base4 PointX4
	_ = unordered.PrepareVariableBase(&base4)
}

func TestExperimentalIFMAFixedDSMZeroAllocations(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	_, bases8, _, _ := scalarWindowBenchmarkFixtures(t)
	variable8 := bases8
	variable8.Double(&variable8)
	bases := [DSMTerms]PointX8{bases8, variable8}
	var scalars FixedDSMScalarsX8
	for term := range scalars {
		for lane := range scalars[term] {
			scalars[term][lane][0] = byte(1 + term + lane)
			scalars[term][lane][31] = 0x0f
		}
	}
	signs := [DSMTerms]uint8{0, 0xff}
	for _, radixBits := range []uint{4, 5, 6} {
		switch radixBits {
		case 4:
			var workspace ExperimentalIFMAFixedDSMWorkspaceRadix16X8
			var workspace4 ExperimentalIFMAFixedDSMWorkspaceRadix16X4
			testExperimentalIFMAFixedDSMZeroAllocationsRadix(t, &workspace, &workspace4, &bases, &scalars, &signs, radixBits)
		case 5:
			var workspace ExperimentalIFMAFixedDSMWorkspaceX8
			var workspace4 ExperimentalIFMAFixedDSMWorkspaceX4
			testExperimentalIFMAFixedDSMZeroAllocationsRadix(t, &workspace, &workspace4, &bases, &scalars, &signs, radixBits)
		case 6:
			var workspace ExperimentalIFMAFixedDSMWorkspaceRadix64X8
			var workspace4 ExperimentalIFMAFixedDSMWorkspaceRadix64X4
			testExperimentalIFMAFixedDSMZeroAllocationsRadix(t, &workspace, &workspace4, &bases, &scalars, &signs, radixBits)
		}
	}
}

func testExperimentalIFMAFixedDSMZeroAllocationsRadix[Storage8 ifmaFullTableStorageX8, Storage4 ifmaFullTableStorageX4](t *testing.T, workspace *experimentalIFMAFixedDSMWorkspaceX8[Storage8], workspace4 *experimentalIFMAFixedDSMWorkspaceX4[Storage4], bases *[DSMTerms]PointX8, scalars *FixedDSMScalarsX8, signs *[DSMTerms]uint8, radixBits uint) {
	t.Helper()
	if err := workspace.PrepareBoth(bases, radixBits); err != nil {
		t.Fatal(err)
	}
	var out IFMAPointX8
	if allocs := testing.AllocsPerRun(10, func() {
		if _, err := workspace.Evaluate(&out, scalars, signs, 0xff); err != nil {
			panic(err)
		}
	}); allocs != 0 {
		t.Fatalf("radix %d prepared allocations=%v", 1<<radixBits, allocs)
	}
	if allocs := testing.AllocsPerRun(10, func() {
		if err := workspace.PrepareVariableBase(&bases[1]); err != nil {
			panic(err)
		}
		if _, err := workspace.Evaluate(&out, scalars, signs, 0xff); err != nil {
			panic(err)
		}
	}); allocs != 0 {
		t.Fatalf("radix %d cold-A allocations=%v", 1<<radixBits, allocs)
	}
	if allocs := testing.AllocsPerRun(10, func() {
		if err := workspace.PrepareBoth(bases, radixBits); err != nil {
			panic(err)
		}
		if _, err := workspace.Evaluate(&out, scalars, signs, 0xff); err != nil {
			panic(err)
		}
	}); allocs != 0 {
		t.Fatalf("radix %d full-cold allocations=%v", 1<<radixBits, allocs)
	}
	bases4 := [DSMTerms]PointX4{pointX4Half(&bases[0], 0), pointX4Half(&bases[1], 0)}
	var scalars4 FixedDSMScalarsX4
	var signs4 [DSMTerms]uint8
	for term := 0; term < DSMTerms; term++ {
		copy(scalars4[term][:], scalars[term][:X4Lanes])
		signs4[term] = signs[term] & 0x0f
	}
	if err := workspace4.PrepareBoth(&bases4, radixBits); err != nil {
		t.Fatal(err)
	}
	var out4 IFMAPointX4
	if allocs := testing.AllocsPerRun(10, func() {
		if _, err := workspace4.Evaluate(&out4, &scalars4, &signs4, 0x0f); err != nil {
			panic(err)
		}
	}); allocs != 0 {
		t.Fatalf("radix %d x4 prepared allocations=%v", 1<<radixBits, allocs)
	}
	if allocs := testing.AllocsPerRun(10, func() {
		if err := workspace4.PrepareVariableBase(&bases4[1]); err != nil {
			panic(err)
		}
		if _, err := workspace4.Evaluate(&out4, &scalars4, &signs4, 0x0f); err != nil {
			panic(err)
		}
	}); allocs != 0 {
		t.Fatalf("radix %d x4 cold-A allocations=%v", 1<<radixBits, allocs)
	}
	if allocs := testing.AllocsPerRun(10, func() {
		if err := workspace4.PrepareBoth(&bases4, radixBits); err != nil {
			panic(err)
		}
		if _, err := workspace4.Evaluate(&out4, &scalars4, &signs4, 0x0f); err != nil {
			panic(err)
		}
	}); allocs != 0 {
		t.Fatalf("radix %d x4 full-cold allocations=%v", 1<<radixBits, allocs)
	}
}

var (
	benchmarkIFMADSMPointX4 [2]IFMAPointX4
	benchmarkIFMADSMPointX8 IFMAPointX8
)

func BenchmarkExperimentalIFMAFixedDSM(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	base4, base8, _, _ := scalarWindowBenchmarkFixtures(b)
	variable8 := base8
	variable8.Double(&variable8)
	bases8 := [DSMTerms]PointX8{base8, variable8}
	var bases4 [2][DSMTerms]PointX4
	for half := 0; half < 2; half++ {
		for term := 0; term < DSMTerms; term++ {
			bases4[half][term] = pointX4Half(&bases8[term], half)
		}
	}
	// The fixture helper's x4 value is also checked here so accidental changes
	// to the half packing cannot silently skew the two-x4 benchmark.
	if bases4[0][0].Equal(&base4) != 0x0f {
		b.Fatal("x4 benchmark fixture does not match first x8 half")
	}
	var scalars8 FixedDSMScalarsX8
	for term := range scalars8 {
		for lane := range scalars8[term] {
			scalars8[term][lane][0] = byte(1 + term + lane)
			scalars8[term][lane][15] = byte(17 + term + lane)
			scalars8[term][lane][31] = 0x0f
		}
	}
	signs8 := [DSMTerms]uint8{0, 0xff}

	for _, radixBits := range []uint{4, 5, 6} {
		switch radixBits {
		case 4:
			var x8 ExperimentalIFMAFixedDSMWorkspaceRadix16X8
			var x4 [2]ExperimentalIFMAFixedDSMWorkspaceRadix16X4
			b.Run("x8/radix=16", func(b *testing.B) { benchmarkExperimentalIFMAX8DSM(b, &x8, &bases8, &scalars8, &signs8, radixBits) })
			b.Run("two-x4/radix=16", func(b *testing.B) { benchmarkExperimentalIFMATwoX4DSM(b, &x4, &bases4, &scalars8, &signs8, radixBits) })
		case 5:
			var x8 ExperimentalIFMAFixedDSMWorkspaceX8
			var x4 [2]ExperimentalIFMAFixedDSMWorkspaceX4
			b.Run("x8/radix=32", func(b *testing.B) { benchmarkExperimentalIFMAX8DSM(b, &x8, &bases8, &scalars8, &signs8, radixBits) })
			b.Run("two-x4/radix=32", func(b *testing.B) { benchmarkExperimentalIFMATwoX4DSM(b, &x4, &bases4, &scalars8, &signs8, radixBits) })
		case 6:
			var x8 ExperimentalIFMAFixedDSMWorkspaceRadix64X8
			var x4 [2]ExperimentalIFMAFixedDSMWorkspaceRadix64X4
			b.Run("x8/radix=64", func(b *testing.B) { benchmarkExperimentalIFMAX8DSM(b, &x8, &bases8, &scalars8, &signs8, radixBits) })
			b.Run("two-x4/radix=64", func(b *testing.B) { benchmarkExperimentalIFMATwoX4DSM(b, &x4, &bases4, &scalars8, &signs8, radixBits) })
		}
	}
}

func benchmarkExperimentalIFMAX8DSM[Storage ifmaFullTableStorageX8](b *testing.B, workspace *experimentalIFMAFixedDSMWorkspaceX8[Storage], bases *[DSMTerms]PointX8, scalars *FixedDSMScalarsX8, signs *[DSMTerms]uint8, radixBits uint) {
	if err := workspace.PrepareBoth(bases, radixBits); err != nil {
		b.Fatal(err)
	}
	for _, path := range []string{"prepared-loop", "cold-A-table+loop", "full-cold-both-tables+loop"} {
		b.Run(path, func(b *testing.B) {
			b.ReportAllocs()
			b.ReportMetric(float64(NominalFullTableBytes(X8Lanes, 4, radixBits)), "active-cold-A-table-B")
			b.ReportMetric(float64(DSMTerms*NominalFullTableBytes(X8Lanes, 4, radixBits)), "active-retained-tables-B")
			b.ReportMetric(float64(unsafe.Sizeof(workspace.tables[0])), "physical-table-B")
			b.ReportMetric(float64(unsafe.Sizeof(*workspace)), "physical-workspace-B")
			var out IFMAPointX8
			for i := 0; i < b.N; i++ {
				switch path {
				case "cold-A-table+loop":
					if err := workspace.PrepareVariableBase(&bases[1]); err != nil {
						b.Fatal(err)
					}
				case "full-cold-both-tables+loop":
					if err := workspace.PrepareBoth(bases, radixBits); err != nil {
						b.Fatal(err)
					}
				}
				if _, err := workspace.Evaluate(&out, scalars, signs, 0xff); err != nil {
					b.Fatal(err)
				}
			}
			benchmarkIFMADSMPointX8 = out
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*X8Lanes), "ns/signature")
		})
	}
}

func benchmarkExperimentalIFMATwoX4DSM[Storage ifmaFullTableStorageX4](b *testing.B, workspace *[2]experimentalIFMAFixedDSMWorkspaceX4[Storage], bases *[2][DSMTerms]PointX4, scalars8 *FixedDSMScalarsX8, signs8 *[DSMTerms]uint8, radixBits uint) {
	var scalars [2]FixedDSMScalarsX4
	var signs [2][DSMTerms]uint8
	for half := 0; half < 2; half++ {
		if err := workspace[half].PrepareBoth(&bases[half], radixBits); err != nil {
			b.Fatal(err)
		}
		for term := 0; term < DSMTerms; term++ {
			copy(scalars[half][term][:], scalars8[term][half*X4Lanes:(half+1)*X4Lanes])
			signs[half][term] = (signs8[term] >> (half * X4Lanes)) & 0x0f
		}
	}
	for _, path := range []string{"prepared-loop", "cold-A-table+loop", "full-cold-both-tables+loop"} {
		b.Run(path, func(b *testing.B) {
			b.ReportAllocs()
			// Two x4 groups retain the same nominal coordinate payload as one
			// x8 group, but exercise a distinct YMM schedule and table build.
			b.ReportMetric(float64(2*NominalFullTableBytes(X4Lanes, 4, radixBits)), "active-cold-A-table-B")
			b.ReportMetric(float64(2*DSMTerms*NominalFullTableBytes(X4Lanes, 4, radixBits)), "active-retained-tables-B")
			b.ReportMetric(float64(2*unsafe.Sizeof(workspace[0].tables[0])), "physical-tables-per-term-B")
			b.ReportMetric(float64(unsafe.Sizeof(*workspace)), "physical-workspace-B")
			var out [2]IFMAPointX4
			for i := 0; i < b.N; i++ {
				for half := 0; half < 2; half++ {
					switch path {
					case "cold-A-table+loop":
						if err := workspace[half].PrepareVariableBase(&bases[half][1]); err != nil {
							b.Fatal(err)
						}
					case "full-cold-both-tables+loop":
						if err := workspace[half].PrepareBoth(&bases[half], radixBits); err != nil {
							b.Fatal(err)
						}
					}
					if _, err := workspace[half].Evaluate(&out[half], &scalars[half], &signs[half], 0x0f); err != nil {
						b.Fatal(err)
					}
				}
			}
			benchmarkIFMADSMPointX4 = out
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*X8Lanes), "ns/signature")
		})
	}
}

type modelIFMAFixedDSMWorkspaceX4 struct {
	tables    [DSMTerms]IFMAFullTableRadix64X4
	digits    [DSMTerms]FixedRadixDigitsX4
	radixBits uint8
}

type modelIFMAFixedDSMWorkspaceX8 struct {
	tables    [DSMTerms]IFMAFullTableRadix64X8
	digits    [DSMTerms]FixedRadixDigitsX8
	radixBits uint8
}

func (w *modelIFMAFixedDSMWorkspaceX4) prepare(bases *[DSMTerms]PointX4, radixBits uint) error {
	fixedScalarRoundCount(radixBits)
	for term := 0; term < DSMTerms; term++ {
		if err := modelBuildIFMAFullTableX4Into(&w.tables[term], &bases[term], radixBits); err != nil {
			return err
		}
	}
	w.radixBits = uint8(radixBits)
	return nil
}

func (w *modelIFMAFixedDSMWorkspaceX8) prepare(bases *[DSMTerms]PointX8, radixBits uint) error {
	fixedScalarRoundCount(radixBits)
	for term := 0; term < DSMTerms; term++ {
		if err := modelBuildIFMAFullTableX8Into(&w.tables[term], &bases[term], radixBits); err != nil {
			return err
		}
	}
	w.radixBits = uint8(radixBits)
	return nil
}

func (w *modelIFMAFixedDSMWorkspaceX4) evaluate(out *IFMAPointX4, scalars *FixedDSMScalarsX4, signs *[DSMTerms]uint8, active uint8) (uint8, error) {
	active &= 0x0f
	usable := active
	for term := 0; term < DSMTerms; term++ {
		usable &= RecodeCanonicalScalarsX4(&w.digits[term], &scalars[term], signs[term], active, uint(w.radixBits))
	}
	acc := identityIFMAPointX4Value()
	if usable == 0 {
		*out = acc
		return 0, nil
	}
	rounds := w.digits[0].RoundCount()
	for round := rounds - 1; round >= 0; round-- {
		if round != rounds-1 {
			for doubling := uint8(0); doubling < w.radixBits; doubling++ {
				if err := ifmaPointDoubleComposableX4(&acc, &acc, modelMultiplyComposableX4); err != nil {
					return 0, err
				}
			}
		}
		for term := 0; term < DSMTerms; term++ {
			digit := w.digits[term].Round(round)
			if digit.NonzeroMask&usable == 0 {
				continue
			}
			var selected IFMAPointX4
			SelectIFMAFullTableX4Public(&selected, &w.tables[term], digit, usable)
			if err := ifmaPointAddComposableX4(&acc, &acc, &selected, modelMultiplyComposableX4); err != nil {
				return 0, err
			}
		}
	}
	*out = acc
	return usable, nil
}

func (w *modelIFMAFixedDSMWorkspaceX8) evaluate(out *IFMAPointX8, scalars *FixedDSMScalarsX8, signs *[DSMTerms]uint8, active uint8) (uint8, error) {
	usable := active
	for term := 0; term < DSMTerms; term++ {
		usable &= RecodeCanonicalScalarsX8(&w.digits[term], &scalars[term], signs[term], active, uint(w.radixBits))
	}
	acc := identityIFMAPointX8Value()
	if usable == 0 {
		*out = acc
		return 0, nil
	}
	rounds := w.digits[0].RoundCount()
	for round := rounds - 1; round >= 0; round-- {
		if round != rounds-1 {
			for doubling := uint8(0); doubling < w.radixBits; doubling++ {
				if err := ifmaPointDoubleComposableX8(&acc, &acc, modelMultiplyComposableX8); err != nil {
					return 0, err
				}
			}
		}
		for term := 0; term < DSMTerms; term++ {
			digit := w.digits[term].Round(round)
			if digit.NonzeroMask&usable == 0 {
				continue
			}
			var selected IFMAPointX8
			SelectIFMAFullTableX8Public(&selected, &w.tables[term], digit, usable)
			if err := ifmaPointAddComposableX8(&acc, &acc, &selected, modelMultiplyComposableX8); err != nil {
				return 0, err
			}
		}
	}
	*out = acc
	return usable, nil
}

func modelBuildIFMAFullTableX4Into[Storage ifmaFullTableStorageX4](table *ifmaFullTableX4[Storage], base *PointX4, radixBits uint) error {
	*table = ifmaFullTableX4[Storage]{}
	table.entries = regularRadixEntries(radixBits)
	if table.entries > len(table.points) {
		panic("r51x5: model IFMA x4 table is too small for radix")
	}
	table.radixBits = radixBits
	var composableBase IFMAPointX4
	composableBase.SetReduced(base)
	table.points[0] = composableBase
	for entry := 1; entry < table.entries; entry++ {
		if err := ifmaPointAddComposableX4(&table.points[entry], &table.points[entry-1], &composableBase, modelMultiplyComposableX4); err != nil {
			return err
		}
	}
	return nil
}

func modelBuildIFMAFullTableX8Into[Storage ifmaFullTableStorageX8](table *ifmaFullTableX8[Storage], base *PointX8, radixBits uint) error {
	*table = ifmaFullTableX8[Storage]{}
	table.entries = regularRadixEntries(radixBits)
	if table.entries > len(table.points) {
		panic("r51x5: model IFMA x8 table is too small for radix")
	}
	table.radixBits = radixBits
	var composableBase IFMAPointX8
	composableBase.SetReduced(base)
	table.points[0] = composableBase
	for entry := 1; entry < table.entries; entry++ {
		if err := ifmaPointAddComposableX8(&table.points[entry], &table.points[entry-1], &composableBase, modelMultiplyComposableX8); err != nil {
			return err
		}
	}
	return nil
}

func randomIFMAFixedDSMScalars(rng *rand.Rand) (FixedDSMScalarsX8, [DSMTerms]uint8, [DSMTerms][X8Lanes]*big.Int) {
	var scalars FixedDSMScalarsX8
	signs := [DSMTerms]uint8{0, 0xff} // [s]B + [-k]A
	var exact [DSMTerms][X8Lanes]*big.Int
	for term := 0; term < DSMTerms; term++ {
		for lane := 0; lane < X8Lanes; lane++ {
			_, _ = rng.Read(scalars[term][lane][:])
			// Any value below 2^252 is below L and therefore canonical.
			scalars[term][lane][31] &= 0x0f
			exact[term][lane] = signedMagnitudeToBig(NewSignedMagnitude(scalars[term][lane][:], signs[term]&(1<<lane) != 0))
		}
	}
	return scalars, signs, exact
}

func exactIFMAFixedDSMWant(refs *[QSMTerms][X8Lanes]*edwardsref.Point, exact *[DSMTerms][X8Lanes]*big.Int) [X8Lanes]*edwardsref.Point {
	var want [X8Lanes]*edwardsref.Point
	for lane := 0; lane < X8Lanes; lane++ {
		want[lane] = edwardsref.NewIdentityPoint()
		for term := 0; term < DSMTerms; term++ {
			multiple := exactReferenceIntegerMult(refs[term][lane], exact[term][lane])
			want[lane].Add(want[lane], multiple)
		}
	}
	return want
}

func everyIFMADSMActiveMaskX8() []uint8 {
	masks := make([]uint8, 0, X8Lanes*2+2)
	for tail := 0; tail <= X8Lanes; tail++ {
		masks = append(masks, uint8((1<<tail)-1))
	}
	for lane := 0; lane < X8Lanes; lane++ {
		masks = append(masks, uint8(0xff&^(1<<lane)))
	}
	return masks
}

func assertModelIFMAX4Halves(t *testing.T, bases *[DSMTerms]PointX8, scalars *FixedDSMScalarsX8, signs *[DSMTerms]uint8, radixBits uint, workspace8 *modelIFMAFixedDSMWorkspaceX8) {
	t.Helper()
	var workspaces4 [2]modelIFMAFixedDSMWorkspaceX4
	var bases4 [2][DSMTerms]PointX4
	for half := 0; half < 2; half++ {
		for term := 0; term < DSMTerms; term++ {
			bases4[half][term] = pointX4Half(&bases[term], half)
		}
		if err := workspaces4[half].prepare(&bases4[half], radixBits); err != nil {
			t.Fatal(err)
		}
	}
	for _, active := range everyIFMADSMActiveMaskX8() {
		var wantLoose IFMAPointX8
		wantMask, err := workspace8.evaluate(&wantLoose, scalars, signs, active)
		if err != nil {
			t.Fatal(err)
		}
		var joined PointX8
		var joinedMask uint8
		for half := 0; half < 2; half++ {
			var scalars4 FixedDSMScalarsX4
			var signs4 [DSMTerms]uint8
			for term := 0; term < DSMTerms; term++ {
				copy(scalars4[term][:], scalars[term][half*X4Lanes:(half+1)*X4Lanes])
				signs4[term] = (signs[term] >> (half * X4Lanes)) & 0x0f
			}
			var gotLoose IFMAPointX4
			mask, err := workspaces4[half].evaluate(&gotLoose, &scalars4, &signs4, (active>>(half*X4Lanes))&0x0f)
			if err != nil {
				t.Fatal(err)
			}
			joinedMask |= mask << (half * X4Lanes)
			got := gotLoose.Reduced()
			for lane := 0; lane < X4Lanes; lane++ {
				point := got.Lane(lane)
				joined.SetLane(half*X4Lanes+lane, &point)
			}
		}
		want := wantLoose.Reduced()
		if joinedMask != wantMask || joined.Equal(&want) != 0xff {
			t.Fatalf("radix %d active=%02x two-x4/model-x8 masks=(%02x,%02x)", 1<<radixBits, active, joinedMask, wantMask)
		}
	}
}

func evaluateExperimentalIFMAX4Halves[Storage ifmaFullTableStorageX4](t *testing.T, workspaces *[2]experimentalIFMAFixedDSMWorkspaceX4[Storage], scalars *FixedDSMScalarsX8, signs *[DSMTerms]uint8, active uint8) (PointX8, uint8) {
	t.Helper()
	var joined PointX8
	var joinedMask uint8
	for half := 0; half < 2; half++ {
		var scalars4 FixedDSMScalarsX4
		var signs4 [DSMTerms]uint8
		for term := 0; term < DSMTerms; term++ {
			copy(scalars4[term][:], scalars[term][half*X4Lanes:(half+1)*X4Lanes])
			signs4[term] = (signs[term] >> (half * X4Lanes)) & 0x0f
		}
		var loose IFMAPointX4
		mask, err := workspaces[half].Evaluate(&loose, &scalars4, &signs4, (active>>(half*X4Lanes))&0x0f)
		if err != nil {
			t.Fatal(err)
		}
		joinedMask |= mask << (half * X4Lanes)
		got := loose.Reduced()
		for lane := 0; lane < X4Lanes; lane++ {
			point := got.Lane(lane)
			joined.SetLane(half*X4Lanes+lane, &point)
		}
	}
	return joined, joinedMask
}
