package r51x5

import (
	"math/rand"
	"runtime"
	"testing"
)

func separatePointLinearNielsStage2X8(
	out *ifmaNielsStage2WorkspaceX8,
	point *IFMAPointX8,
	cached *IFMAProjectiveNielsX8,
) {
	var yMinusX, yPlusX IFMAElementX8
	ifmaSubtractComposableUncheckedX8(&yMinusX, &point.Y, &point.X)
	ifmaAddComposableUncheckedX8(&yPlusX, &point.Y, &point.X)
	ifmaFourRawProductsNielsStage2UncheckedX8(
		out,
		&yMinusX.limbs, &cached.YMinusX.limbs,
		&yPlusX.limbs, &cached.YPlusX.limbs,
		&point.T.limbs, &cached.T2D.limbs,
		&point.Z.limbs, &cached.Z.limbs,
	)
}

func TestIFMAPointLinearFourRawNielsStage2X8MatchesSeparateLeaves(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	maximum := filledIFMAElementX8(ifmaComposableLimbLimit - 1)
	fixtures := []struct {
		name   string
		point  IFMAPointX8
		cached IFMAProjectiveNielsX8
	}{
		{name: "zero"},
		{
			name:   "maximum-u52",
			point:  IFMAPointX8{X: maximum, Y: maximum, Z: maximum, T: maximum},
			cached: IFMAProjectiveNielsX8{YPlusX: maximum, YMinusX: maximum, Z: maximum, T2D: maximum},
		},
	}

	check := func(name string, point IFMAPointX8, cached IFMAProjectiveNielsX8) {
		t.Helper()
		pointBefore, cachedBefore := point, cached
		var want, got ifmaNielsStage2WorkspaceX8
		separatePointLinearNielsStage2X8(&want, &point, &cached)
		ifmaPointLinearFourRawNielsStage2ExperimentX8(&got, &point, &cached)
		if got != want {
			t.Fatalf("%s: compound point-linear Niels Stage 2 differs from separate exact leaves", name)
		}
		if point != pointBefore || cached != cachedBefore {
			t.Fatalf("%s: compound point-linear Niels Stage 2 modified input", name)
		}
	}

	for _, fixture := range fixtures {
		check(fixture.name, fixture.point, fixture.cached)
	}

	rng := rand.New(rand.NewSource(0x51_1a_4e15))
	for round := 0; round < 10_000; round++ {
		point := IFMAPointX8{
			X: randomIFMAElementX8(rng),
			Y: randomIFMAElementX8(rng),
			Z: randomIFMAElementX8(rng),
			T: randomIFMAElementX8(rng),
		}
		cached := IFMAProjectiveNielsX8{
			YPlusX:  randomIFMAElementX8(rng),
			YMinusX: randomIFMAElementX8(rng),
			Z:       randomIFMAElementX8(rng),
			T2D:     randomIFMAElementX8(rng),
		}
		check("random", point, cached)
	}
}

func TestIFMAPointLinearFourRawNielsStage2X8ZeroAllocations(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	rng := rand.New(rand.NewSource(0x51_1a_a110))
	point := IFMAPointX8{
		X: randomIFMAElementX8(rng), Y: randomIFMAElementX8(rng),
		Z: randomIFMAElementX8(rng), T: randomIFMAElementX8(rng),
	}
	cached := IFMAProjectiveNielsX8{
		YPlusX: randomIFMAElementX8(rng), YMinusX: randomIFMAElementX8(rng),
		Z: randomIFMAElementX8(rng), T2D: randomIFMAElementX8(rng),
	}
	var out ifmaNielsStage2WorkspaceX8
	allocations := testing.AllocsPerRun(1_000, func() {
		ifmaPointLinearFourRawNielsStage2ExperimentX8(&out, &point, &cached)
	})
	if allocations != 0 {
		t.Fatalf("allocations = %v, want 0", allocations)
	}
}

func TestIFMAFourRawProductsStage2X8MatchesSeparateLeaves(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	// The underlying four-product differential already covers 10,000
	// zero/max/random input sets. This test additionally locks the ABI0 tail
	// continuation and exact in-place Stage-2 representations on a stable
	// nontrivial input set.
	inputs := benchmarkFourRawProductInputsX8()
	before := inputs
	var raw [4]IFMAProductX8
	fourRawProductsFourCallsX8(&raw, &inputs)

	wantDouble := ifmaDoubleStage2WorkspaceX8(raw)
	ifmaDoubleStage2X8(&wantDouble)
	var gotDouble ifmaDoubleStage2WorkspaceX8
	ifmaFourRawProductsDoubleStage2UncheckedX8(
		&gotDouble,
		&inputs[0], &inputs[1],
		&inputs[2], &inputs[3],
		&inputs[4], &inputs[5],
		&inputs[6], &inputs[7],
	)
	if gotDouble != wantDouble {
		t.Fatal("compound double Stage 2 differs from separate exact leaves")
	}

	wantNiels := ifmaNielsStage2WorkspaceX8(raw)
	ifmaNielsStage2X8(&wantNiels)
	var gotNiels ifmaNielsStage2WorkspaceX8
	ifmaFourRawProductsNielsStage2UncheckedX8(
		&gotNiels,
		&inputs[0], &inputs[1],
		&inputs[2], &inputs[3],
		&inputs[4], &inputs[5],
		&inputs[6], &inputs[7],
	)
	if gotNiels != wantNiels {
		t.Fatal("compound Niels Stage 2 differs from separate exact leaves")
	}
	if inputs != before {
		t.Fatal("compound Stage-2 leaves modified input workspace")
	}
}

func TestIFMAFourRawProductsStage2X8ZeroAllocations(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	inputs := benchmarkFourRawProductInputsX8()
	var double ifmaDoubleStage2WorkspaceX8
	var niels ifmaNielsStage2WorkspaceX8
	allocations := testing.AllocsPerRun(1_000, func() {
		ifmaFourRawProductsDoubleStage2UncheckedX8(
			&double,
			&inputs[0], &inputs[1], &inputs[2], &inputs[3],
			&inputs[4], &inputs[5], &inputs[6], &inputs[7],
		)
		ifmaFourRawProductsNielsStage2UncheckedX8(
			&niels,
			&inputs[0], &inputs[1], &inputs[2], &inputs[3],
			&inputs[4], &inputs[5], &inputs[6], &inputs[7],
		)
	})
	if allocations != 0 {
		t.Fatalf("allocations = %v, want 0", allocations)
	}
}

var benchmarkFourRawStage2DoubleSinkX8 ifmaDoubleStage2WorkspaceX8
var benchmarkFourRawStage2NielsSinkX8 ifmaNielsStage2WorkspaceX8

func BenchmarkIFMAPointLinearFourRawNielsStage2X8(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	rng := rand.New(rand.NewSource(0x51_1a_be4c))
	point := IFMAPointX8{
		X: randomIFMAElementX8(rng), Y: randomIFMAElementX8(rng),
		Z: randomIFMAElementX8(rng), T: randomIFMAElementX8(rng),
	}
	cached := IFMAProjectiveNielsX8{
		YPlusX: randomIFMAElementX8(rng), YMinusX: randomIFMAElementX8(rng),
		Z: randomIFMAElementX8(rng), T2D: randomIFMAElementX8(rng),
	}
	b.Run("separate", func(b *testing.B) {
		var out ifmaNielsStage2WorkspaceX8
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			separatePointLinearNielsStage2X8(&out, &point, &cached)
		}
		benchmarkFourRawStage2NielsSinkX8 = out
	})
	b.Run("compound", func(b *testing.B) {
		var out ifmaNielsStage2WorkspaceX8
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ifmaPointLinearFourRawNielsStage2ExperimentX8(&out, &point, &cached)
		}
		benchmarkFourRawStage2NielsSinkX8 = out
	})
}

func BenchmarkIFMAFourRawProductsStage2X8(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	inputs := benchmarkFourRawProductInputsX8()
	b.Run("double/separate", func(b *testing.B) {
		var workspace ifmaDoubleStage2WorkspaceX8
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ifmaFourRawProductsUncheckedX8(
				(*[4]IFMAProductX8)(&workspace),
				&inputs[0], &inputs[1], &inputs[2], &inputs[3],
				&inputs[4], &inputs[5], &inputs[6], &inputs[7],
			)
			ifmaDoubleStage2X8(&workspace)
		}
		benchmarkFourRawStage2DoubleSinkX8 = workspace
	})
	b.Run("double/tail", func(b *testing.B) {
		var workspace ifmaDoubleStage2WorkspaceX8
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ifmaFourRawProductsDoubleStage2UncheckedX8(
				&workspace,
				&inputs[0], &inputs[1], &inputs[2], &inputs[3],
				&inputs[4], &inputs[5], &inputs[6], &inputs[7],
			)
		}
		benchmarkFourRawStage2DoubleSinkX8 = workspace
	})
	b.Run("niels/separate", func(b *testing.B) {
		var workspace ifmaNielsStage2WorkspaceX8
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ifmaFourRawProductsUncheckedX8(
				(*[4]IFMAProductX8)(&workspace),
				&inputs[0], &inputs[1], &inputs[2], &inputs[3],
				&inputs[4], &inputs[5], &inputs[6], &inputs[7],
			)
			ifmaNielsStage2X8(&workspace)
		}
		benchmarkFourRawStage2NielsSinkX8 = workspace
	})
	b.Run("niels/tail", func(b *testing.B) {
		var workspace ifmaNielsStage2WorkspaceX8
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ifmaFourRawProductsNielsStage2UncheckedX8(
				&workspace,
				&inputs[0], &inputs[1], &inputs[2], &inputs[3],
				&inputs[4], &inputs[5], &inputs[6], &inputs[7],
			)
		}
		benchmarkFourRawStage2NielsSinkX8 = workspace
	})
}
