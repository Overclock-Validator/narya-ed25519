package r51x5

import (
	"runtime"
	"testing"
)

func TestIFMASquareRawExperimentX4Differential(t *testing.T) {
	requireRawSquareExperiment(t)
	for index, input := range squareIFMAExperimentInputs() {
		var got IFMAProductX4
		ifmaSquareRawExperimentX4(&got, &input)
		want := rawSquareExperimentModelX4(input)
		if got != want {
			t.Fatalf("input=%d raw model mismatch\n got=%#v\nwant=%#v", index, got, want)
		}
		if !isIFMAProductX4(got) {
			t.Fatalf("input=%d output escaped u61: %#v", index, got)
		}
		if runtime.GOARCH == "amd64" {
			var general IFMAProductX4
			ifmaMulRawX4(&general, &input, &input)
			if got != general {
				t.Fatalf("input=%d raw general-multiply mismatch", index)
			}
		}
	}
}

func TestIFMASquareRawExperimentX4Aliasing(t *testing.T) {
	requireRawSquareExperiment(t)
	for index, input := range squareIFMAExperimentBoundaryInputs() {
		want := rawSquareExperimentModelX4(input)
		storage := input
		out := (*IFMAProductX4)(&storage)
		ifmaSquareRawExperimentX4(out, &storage)
		if *out != want {
			t.Fatalf("input=%d exact alias mismatch", index)
		}
	}
}

func TestIFMASquareRawExperimentX4ZeroAllocations(t *testing.T) {
	requireRawSquareExperiment(t)
	input := squareIFMAExperimentDenseInput(0x51_a4_0001)
	var out IFMAProductX4
	if allocs := testing.AllocsPerRun(1000, func() {
		ifmaSquareRawExperimentX4(&out, &input)
	}); allocs != 0 {
		t.Fatalf("raw square allocations=%v", allocs)
	}
	rawSquareExperimentSink[0] = out
}

func TestIFMASquareRawExperimentX8Differential(t *testing.T) {
	requireRawSquareExperiment(t)
	for index, input := range squareIFMAX8ExperimentInputs() {
		var got IFMAProductX8
		ifmaSquareRawExperimentX8(&got, &input)
		want := rawSquareExperimentModelX8(input)
		if got != want {
			t.Fatalf("input=%d raw model mismatch\n got=%#v\nwant=%#v", index, got, want)
		}
		if !isIFMAProductX8(got) {
			t.Fatalf("input=%d output escaped u61: %#v", index, got)
		}
		if runtime.GOARCH == "amd64" {
			var general IFMAProductX8
			ifmaMulRawX8(&general, &input, &input)
			if got != general {
				t.Fatalf("input=%d raw general-multiply mismatch", index)
			}
		}
	}
}

func TestIFMASquareRawExperimentX8Aliasing(t *testing.T) {
	requireRawSquareExperiment(t)
	for index, input := range squareIFMAX8ExperimentBoundaryInputs() {
		want := rawSquareExperimentModelX8(input)
		storage := input
		out := (*IFMAProductX8)(&storage)
		ifmaSquareRawExperimentX8(out, &storage)
		if *out != want {
			t.Fatalf("input=%d exact alias mismatch", index)
		}
	}
}

func TestIFMASquareRawExperimentX8ZeroAllocations(t *testing.T) {
	requireRawSquareExperiment(t)
	input := benchmarkIFMAX8ComposableInput(0x51_a8_0001)
	var out IFMAProductX8
	if allocs := testing.AllocsPerRun(1000, func() {
		ifmaSquareRawExperimentX8(&out, &input)
	}); allocs != 0 {
		t.Fatalf("raw x8 square allocations=%v", allocs)
	}
	rawSquareExperimentSinkX8[0] = out
}

func requireRawSquareExperiment(tb testing.TB) {
	tb.Helper()
	if runtime.GOARCH == "amd64" && !ExperimentalIFMAAvailable() {
		tb.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
}

func rawSquareExperimentModelX4(input LimbsX4) IFMAProductX4 {
	var out IFMAProductX4
	for lane := 0; lane < X4Lanes; lane++ {
		var scalar Limbs
		for limb := range scalar {
			scalar[limb] = input[limb][lane]
		}
		product := ifmaLooseLaneModel(scalar, scalar)
		for limb := range product {
			out[limb][lane] = product[limb]
		}
	}
	return out
}

func rawSquareExperimentModelX8(input LimbsX8) IFMAProductX8 {
	var out IFMAProductX8
	for lane := 0; lane < X8Lanes; lane++ {
		var scalar Limbs
		for limb := range scalar {
			scalar[limb] = input[limb][lane]
		}
		product := ifmaLooseLaneModel(scalar, scalar)
		for limb := range product {
			out[limb][lane] = product[limb]
		}
	}
	return out
}

var rawSquareExperimentSink [4]IFMAProductX4
var rawSquareExperimentSinkX8 [4]IFMAProductX8

func BenchmarkIFMASquareRawExperimentX4(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	b.Run("kernel=general-multiply/schedule=single", func(b *testing.B) {
		input := squareIFMAExperimentDenseInput(0x51_a4_1001)
		var out IFMAProductX4
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ifmaMulRawX4(&out, &input, &input)
		}
		rawSquareExperimentSink[0] = out
	})

	b.Run("kernel=dedicated-square/schedule=single", func(b *testing.B) {
		input := squareIFMAExperimentDenseInput(0x51_a4_1001)
		var out IFMAProductX4
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ifmaSquareRawExperimentX4(&out, &input)
		}
		rawSquareExperimentSink[0] = out
	})

	b.Run("kernel=general-multiply/schedule=independent-4", func(b *testing.B) {
		inputs := squareIFMAExperimentIndependentInputs(0x51_a4_4001)
		var outputs [4]IFMAProductX4
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for state := range inputs {
				ifmaMulRawX4(&outputs[state], &inputs[state], &inputs[state])
			}
		}
		rawSquareExperimentSink = outputs
	})

	b.Run("kernel=dedicated-square/schedule=independent-4", func(b *testing.B) {
		inputs := squareIFMAExperimentIndependentInputs(0x51_a4_4001)
		var outputs [4]IFMAProductX4
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for state := range inputs {
				ifmaSquareRawExperimentX4(&outputs[state], &inputs[state])
			}
		}
		rawSquareExperimentSink = outputs
	})
}

func BenchmarkIFMASquareRawExperimentX8(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	b.Run("kernel=general-multiply/schedule=single", func(b *testing.B) {
		input := benchmarkIFMAX8ComposableInput(0x51_a8_1001)
		var out IFMAProductX8
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ifmaMulRawX8(&out, &input, &input)
		}
		rawSquareExperimentSinkX8[0] = out
	})

	b.Run("kernel=dedicated-square/schedule=single", func(b *testing.B) {
		input := benchmarkIFMAX8ComposableInput(0x51_a8_1001)
		var out IFMAProductX8
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ifmaSquareRawExperimentX8(&out, &input)
		}
		rawSquareExperimentSinkX8[0] = out
	})

	b.Run("kernel=general-multiply/schedule=independent-4", func(b *testing.B) {
		inputs := squareIFMAX8IndependentInputs(0x51_a8_4001)
		var outputs [4]IFMAProductX8
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for state := range inputs {
				ifmaMulRawX8(&outputs[state], &inputs[state], &inputs[state])
			}
		}
		rawSquareExperimentSinkX8 = outputs
	})

	b.Run("kernel=dedicated-square/schedule=independent-4", func(b *testing.B) {
		inputs := squareIFMAX8IndependentInputs(0x51_a8_4001)
		var outputs [4]IFMAProductX8
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for state := range inputs {
				ifmaSquareRawExperimentX8(&outputs[state], &inputs[state])
			}
		}
		rawSquareExperimentSinkX8 = outputs
	})
}
