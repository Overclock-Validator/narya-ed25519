package r51x5

import (
	"runtime"
	"testing"
)

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
		&gotDouble[0],
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
		&gotNiels[0],
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
			&double[0],
			&inputs[0], &inputs[1], &inputs[2], &inputs[3],
			&inputs[4], &inputs[5], &inputs[6], &inputs[7],
		)
		ifmaFourRawProductsNielsStage2UncheckedX8(
			&niels[0],
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
				&workspace[0],
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
				&workspace[0],
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
				&workspace[0],
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
				&workspace[0],
				&inputs[0], &inputs[1], &inputs[2], &inputs[3],
				&inputs[4], &inputs[5], &inputs[6], &inputs[7],
			)
		}
		benchmarkFourRawStage2NielsSinkX8 = workspace
	})
}
