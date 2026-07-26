package r51x5

import (
	"errors"
	"math/rand"
	"testing"
	"unsafe"

	edwardsref "github.com/Overclock-Validator/narya-ed25519/internal/edwards25519"
)

func assertHeterogeneousPartialCombA6R9VectorTablesMatchScalarExperiment(
	t testing.TB,
	got *heterogeneousPartialCombA6R9VectorTableGroupExperiment,
	want *[X4Lanes]*heterogeneousPartialCombTableExperiment,
) {
	t.Helper()
	for lane := 0; lane < X4Lanes; lane++ {
		if got.tables[lane].spec != heterogeneousPartialCombA6R9Experiment {
			t.Fatalf("lane=%d vector spec=%+v", lane, got.tables[lane].spec)
		}
		if len(got.tables[lane].points) != len(want[lane].points) {
			t.Fatalf("lane=%d entries=%d want=%d", lane, len(got.tables[lane].points), len(want[lane].points))
		}
		for entry := range got.tables[lane].points {
			for coordinate := 0; coordinate < 3; coordinate++ {
				for limb, value := range got.tables[lane].points[entry] {
					if value[coordinate] >= ifmaComposableLimbLimit {
						t.Fatalf("lane=%d entry=%d coordinate=%d limb=%d escaped u52: %x", lane, entry, coordinate, limb, value[coordinate])
					}
				}
				gotCoordinate := reducedHeterogeneousPartialCombAffine3CoordinateExperiment(&got.tables[lane].points[entry], coordinate)
				wantCoordinate := reducedHeterogeneousPartialCombAffine3CoordinateExperiment(&want[lane].points[entry], coordinate)
				if gotCoordinate.Equal(&wantCoordinate) != 1 {
					t.Fatalf("lane=%d entry=%d coordinate=%d scalar/vector field mismatch", lane, entry, coordinate)
				}
			}
		}
	}
}

func TestHeterogeneousPartialCombA6R9VectorBuilderShapeAndWorkspaceExperiment(t *testing.T) {
	if heterogeneousPartialCombA6R9Experiment.rowCount() != heterogeneousPartialCombA6R9VectorRowsExperiment ||
		heterogeneousPartialCombA6R9Experiment.entriesPerRow() != heterogeneousPartialCombA6R9VectorEntriesExperiment {
		t.Fatalf("A6/r9 vector constants no longer match spec")
	}
	if got := int(unsafe.Sizeof(heterogeneousPartialCombA6R9VectorBuildWorkspaceExperiment{})); got != 231_040 {
		t.Fatalf("workspace bytes=%d want=231040", got)
	}
	if got := int(unsafe.Sizeof([X4Lanes][heterogeneousPartialCombA6R9VectorPointCountExperiment]ifmaAffine3MicroAoSEntryExperiment{})); got != 76_800 {
		t.Fatalf("output payload bytes=%d want=76800", got)
	}
}

func TestHeterogeneousPartialCombA6R9VectorBuilderMatchesScalarMixedOrderProjectiveExperiment(t *testing.T) {
	rng := rand.New(rand.NewSource(0xa6_09_ba7c))
	torsion := referenceTorsionPoints(t)
	var laneTorsion [X8Lanes]*edwardsref.Point
	for lane := range laneTorsion {
		laneTorsion[lane] = torsion[(lane+1)%X8Lanes]
	}
	_, affine := scalarWindowMixedBasesX8(t, rng, &laneTorsion)

	for iteration := 0; iteration < 3; iteration++ {
		projective := randomProjectiveScaleX8(t, rng, &affine)
		bases := pointX4Half(&projective, 0)
		want := buildHeterogeneousPartialCombATablesX4Experiment(&bases, heterogeneousPartialCombA6R9Experiment)
		var workspace heterogeneousPartialCombA6R9VectorBuildWorkspaceExperiment
		var got heterogeneousPartialCombA6R9VectorTableGroupExperiment
		if err := buildHeterogeneousPartialCombA6R9VectorGroupModelExperiment(&got, &bases, &workspace); err != nil {
			t.Fatalf("iteration=%d vector build: %v", iteration, err)
		}
		assertHeterogeneousPartialCombA6R9VectorTablesMatchScalarExperiment(t, &got, &want)
		if ExperimentalIFMAAvailable() {
			var hardwareWorkspace heterogeneousPartialCombA6R9VectorBuildWorkspaceExperiment
			var hardware heterogeneousPartialCombA6R9VectorTableGroupExperiment
			if err := buildHeterogeneousPartialCombA6R9VectorGroupExperiment(&hardware, &bases, &hardwareWorkspace); err != nil {
				t.Fatalf("iteration=%d hardware vector build: %v", iteration, err)
			}
			assertHeterogeneousPartialCombA6R9VectorTablesMatchScalarExperiment(t, &hardware, &want)
		}
	}
}

func TestHeterogeneousPartialCombA6R9VectorBuilderOnlineMatchesScalarTablesExperiment(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("requires AVX-512 IFMA target")
	}
	rng := rand.New(rand.NewSource(0xa6_09_0d51))
	torsion := referenceTorsionPoints(t)
	var laneTorsion [X8Lanes]*edwardsref.Point
	for lane := range laneTorsion {
		laneTorsion[lane] = torsion[(lane+3)%X8Lanes]
	}
	_, aX8 := scalarWindowMixedBasesX8(t, rng, &laneTorsion)
	aX8 = randomProjectiveScaleX8(t, rng, &aX8)
	aX4 := pointX4Half(&aX8, 0)

	bRef := new(edwardsref.Point).Add(edwardsref.NewGeneratorPoint(), torsion[5])
	var bEncoded [32]byte
	copy(bEncoded[:], bRef.Bytes())
	var bPoint Point
	if _, err := bPoint.SetBytes(bEncoded[:]); err != nil {
		t.Fatal(err)
	}
	bTable := buildHeterogeneousPartialCombTableExperiment(&bPoint, heterogeneousPartialCombB8R3Experiment)
	scalarA := buildHeterogeneousPartialCombATablesX4Experiment(&aX4, heterogeneousPartialCombA6R9Experiment)
	var workspace heterogeneousPartialCombA6R9VectorBuildWorkspaceExperiment
	var vectorGroup heterogeneousPartialCombA6R9VectorTableGroupExperiment
	if err := buildHeterogeneousPartialCombA6R9VectorGroupExperiment(&vectorGroup, &aX4, &workspace); err != nil {
		t.Fatal(err)
	}
	vectorA := vectorGroup.tablePointers()

	for iteration := 0; iteration < 4; iteration++ {
		scalars8, signs8, _ := randomIFMAFixedDSMScalars(rng)
		var scalars4 FixedDSMScalarsX4
		var signs4 [DSMTerms]uint8
		for term := 0; term < DSMTerms; term++ {
			copy(scalars4[term][:], scalars8[term][:X4Lanes])
			signs4[term] = signs8[term] & 0x0f
		}
		for active := uint8(0); active < 1<<X4Lanes; active++ {
			var scalarLoose, vectorLoose IFMAPointX4
			scalarMask, scalarErr := evaluateHeterogeneousPartialCombDSMX4Experiment(&scalarLoose, &scalarA, bTable, &scalars4, &signs4, active)
			vectorMask, vectorErr := evaluateHeterogeneousPartialCombDSMX4Experiment(&vectorLoose, &vectorA, bTable, &scalars4, &signs4, active)
			if scalarErr != nil || vectorErr != nil || scalarMask != vectorMask {
				t.Fatalf("iteration=%d active=%02x scalar=(%02x,%v) vector=(%02x,%v)", iteration, active, scalarMask, scalarErr, vectorMask, vectorErr)
			}
			scalarPoint, vectorPoint := scalarLoose.Reduced(), vectorLoose.Reduced()
			if !asymmetricFixedBProjectivelyEqual(&vectorPoint, &scalarPoint, scalarMask) {
				t.Fatalf("iteration=%d active=%02x online scalar/vector mismatch", iteration, active)
			}
		}
	}
}

func TestHeterogeneousPartialCombA6R9VectorBuilderErrorsAreAtomicExperiment(t *testing.T) {
	_, aX8, _, _ := fixedBaseCombDSMFixtures(t)
	bases := pointX4Half(&aX8, 0)
	var output heterogeneousPartialCombA6R9VectorTableGroupExperiment
	for lane := range output.storage {
		for entry := range output.storage[lane] {
			for limb := range output.storage[lane][entry] {
				output.storage[lane][entry][limb] = [3]uint64{uint64(lane + 1), uint64(entry + 1), uint64(limb + 1)}
			}
		}
	}
	output.resetTableViews()
	want := output.storage
	var workspace heterogeneousPartialCombA6R9VectorBuildWorkspaceExperiment

	points := bases.Points()
	points[2].Z = Element{}
	var zeroZ PointX4
	zeroZ.SetPoints(&points)
	if err := buildHeterogeneousPartialCombA6R9VectorGroupModelExperiment(&output, &zeroZ, &workspace); !errors.Is(err, errIFMABatchEncodeZeroZ) {
		t.Fatalf("zero-Z error=%v want=%v", err, errIFMABatchEncodeZeroZ)
	}
	if output.storage != want {
		t.Fatal("zero-Z failure changed output")
	}

	failingOps := decode2IFMAOpsX4{failAt: 1}
	if err := buildHeterogeneousPartialCombA6R9VectorGroupWithOpsExperiment(&output, &bases, &workspace, &failingOps); !errors.Is(err, errIFMAOutputRange) {
		t.Fatalf("injected error=%v want=%v", err, errIFMAOutputRange)
	}
	if output.storage != want {
		t.Fatal("injected arithmetic failure changed output")
	}
}

func TestHeterogeneousPartialCombA6R9VectorBatchInversionRejectsFieldZeroAliasExperiment(t *testing.T) {
	var workspace heterogeneousPartialCombA6R9VectorBuildWorkspaceExperiment
	for index := range workspace.projective {
		workspace.projective[index].Z.limbs[0] = [X4Lanes]uint64{1, 1, 1, 1}
	}
	// p is a valid u52 composable representative of field zero. Place it in
	// one lane so a regression to literal-limb zero checking cannot pass.
	for limb, value := range modulusLimbs {
		workspace.projective[37].Z.limbs[limb][2] = value
	}
	if !isIFMAElementX4(&workspace.projective[37].Z) {
		t.Fatal("field-zero alias unexpectedly escaped the u52 domain")
	}
	ops := decode2IFMAOpsX4{}
	if err := batchInvertHeterogeneousPartialCombA6R9ZX4Experiment(&workspace, &ops); !errors.Is(err, errIFMABatchEncodeZeroZ) {
		t.Fatalf("field-zero alias error=%v want=%v", err, errIFMABatchEncodeZeroZ)
	}
}

func TestHeterogeneousPartialCombA6R9VectorBuilderZeroAllocationsExperiment(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("requires AVX-512 IFMA target")
	}
	_, aX8, _, _ := fixedBaseCombDSMFixtures(t)
	bases := pointX4Half(&aX8, 0)
	var workspace heterogeneousPartialCombA6R9VectorBuildWorkspaceExperiment
	var output heterogeneousPartialCombA6R9VectorTableGroupExperiment
	if err := buildHeterogeneousPartialCombA6R9VectorGroupExperiment(&output, &bases, &workspace); err != nil {
		t.Fatal(err)
	}
	if allocations := testing.AllocsPerRun(10, func() {
		if err := buildHeterogeneousPartialCombA6R9VectorGroupExperiment(&output, &bases, &workspace); err != nil {
			panic(err)
		}
	}); allocations != 0 {
		t.Fatalf("allocations=%v want=0", allocations)
	}
}

var (
	benchmarkHeterogeneousPartialCombA6R9VectorBuildOutputSink *heterogeneousPartialCombA6R9VectorTableGroupExperiment
	benchmarkHeterogeneousPartialCombA6R9VectorBuildScalarSink [X4Lanes]*heterogeneousPartialCombTableExperiment
)

func BenchmarkHeterogeneousPartialCombA6R9VectorBuildExperiment(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skip("requires AVX-512 IFMA target")
	}
	_, aX8, _, _ := fixedBaseCombDSMFixtures(b)
	bases := pointX4Half(&aX8, 0)
	want := buildHeterogeneousPartialCombATablesX4Experiment(&bases, heterogeneousPartialCombA6R9Experiment)
	var workspace heterogeneousPartialCombA6R9VectorBuildWorkspaceExperiment
	var vectorOutput heterogeneousPartialCombA6R9VectorTableGroupExperiment
	if err := buildHeterogeneousPartialCombA6R9VectorGroupExperiment(&vectorOutput, &bases, &workspace); err != nil {
		b.Fatal(err)
	}
	assertHeterogeneousPartialCombA6R9VectorTablesMatchScalarExperiment(b, &vectorOutput, &want)
	payload := X4Lanes * heterogeneousPartialCombA6R9VectorPointCountExperiment * int(unsafe.Sizeof(ifmaAffine3MicroAoSEntryExperiment{}))

	b.Run("implementation=scalar-four-builders", func(b *testing.B) {
		var tables [X4Lanes]*heterogeneousPartialCombTableExperiment
		b.ReportAllocs()
		b.ReportMetric(X4Lanes, "keys/build")
		b.ReportMetric(float64(payload), "retained-table-bytes")
		b.ResetTimer()
		for iteration := 0; iteration < b.N; iteration++ {
			tables = buildHeterogeneousPartialCombATablesX4Experiment(&bases, heterogeneousPartialCombA6R9Experiment)
		}
		b.StopTimer()
		benchmarkHeterogeneousPartialCombA6R9VectorBuildScalarSink = tables
		b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*X4Lanes), "ns/key")
	})

	b.Run("implementation=vector-x4-one-inversion", func(b *testing.B) {
		b.ReportAllocs()
		b.ReportMetric(X4Lanes, "keys/build")
		b.ReportMetric(float64(payload), "retained-table-bytes")
		b.ReportMetric(float64(unsafe.Sizeof(workspace)), "workspace-bytes")
		b.ResetTimer()
		for iteration := 0; iteration < b.N; iteration++ {
			if err := buildHeterogeneousPartialCombA6R9VectorGroupExperiment(&vectorOutput, &bases, &workspace); err != nil {
				b.Fatal(err)
			}
		}
		b.StopTimer()
		benchmarkHeterogeneousPartialCombA6R9VectorBuildOutputSink = &vectorOutput
		b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*X4Lanes), "ns/key")
	})
}
