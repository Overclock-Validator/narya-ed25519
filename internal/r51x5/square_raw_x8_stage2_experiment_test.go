package r51x5

import (
	"math/rand"
	"runtime"
	"testing"
)

func TestIFMAPointDoubleRawSquareStage2X8Differential(t *testing.T) {
	requireNativeRawSquareX8(t)
	rng := rand.New(rand.NewSource(0x51_a8_d0b1))
	for round := 0; round < 4096; round++ {
		input := randomSquareIFMAPointX8(rng)
		var got, want IFMAPointX8
		var gotWorkspace, wantWorkspace ifmaPointDoubleWorkspaceX8
		if err := ifmaPointDoubleRawSquareStage2ExperimentX8(&got, &input, &gotWorkspace); err != nil {
			t.Fatal(err)
		}
		if err := ifmaPointDoubleComposableWorkspaceStaticX8(&want, &input, &wantWorkspace); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("round=%d dedicated/current representation mismatch", round)
		}
	}
}

func TestIFMAPointDoubleRawSquareStage2X8Aliasing(t *testing.T) {
	requireNativeRawSquareX8(t)
	rng := rand.New(rand.NewSource(0x51_a8_a11a))
	for round := 0; round < 1024; round++ {
		got := randomSquareIFMAPointX8(rng)
		want := got
		var gotWorkspace, wantWorkspace ifmaPointDoubleWorkspaceX8
		if err := ifmaPointDoubleRawSquareStage2ExperimentX8(&got, &got, &gotWorkspace); err != nil {
			t.Fatal(err)
		}
		if err := ifmaPointDoubleComposableWorkspaceStaticX8(&want, &want, &wantWorkspace); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("round=%d in-place representation mismatch", round)
		}
	}
}

func TestIFMAPointDoubleRawSquareStage2X8PoisonedWorkspace(t *testing.T) {
	requireNativeRawSquareX8(t)
	input := randomSquareIFMAPointX8(rand.New(rand.NewSource(0x51_a8_9015)))
	var got, want IFMAPointX8
	var workspace ifmaPointDoubleWorkspaceX8
	for product := range workspace.stage2 {
		for limb := range workspace.stage2[product] {
			for lane := range workspace.stage2[product][limb] {
				workspace.stage2[product][limb][lane] = ^uint64(0) - uint64(product*40+limb*8+lane)
			}
		}
	}
	if err := ifmaPointDoubleRawSquareStage2ExperimentX8(&got, &input, &workspace); err != nil {
		t.Fatal(err)
	}
	var wantWorkspace ifmaPointDoubleWorkspaceX8
	if err := ifmaPointDoubleComposableWorkspaceStaticX8(&want, &input, &wantWorkspace); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatal("poisoned workspace changed the result")
	}
}

func TestIFMAPointDoubleRawSquareStage2X8ZeroAllocations(t *testing.T) {
	requireNativeRawSquareX8(t)
	state := randomSquareIFMAPointX8(rand.New(rand.NewSource(0x51_a8_a110)))
	var workspace ifmaPointDoubleWorkspaceX8
	if allocs := testing.AllocsPerRun(1000, func() {
		if err := ifmaPointDoubleRawSquareStage2ExperimentX8(&state, &state, &workspace); err != nil {
			panic(err)
		}
	}); allocs != 0 {
		t.Fatalf("raw-square x8 doubling allocations=%v", allocs)
	}
	benchmarkComposablePointX8Sink = state
}

func TestIFMAPointDoubleFourSquareStage2X8Differential(t *testing.T) {
	requireNativeRawSquareX8(t)
	rng := rand.New(rand.NewSource(0x51_a8_45a4))
	for round := 0; round < 4096; round++ {
		input := randomSquareIFMAPointX8(rng)
		var got, want IFMAPointX8
		var gotWorkspace, wantWorkspace ifmaPointDoubleWorkspaceX8
		if err := ifmaPointDoubleFourSquareStage2ExperimentX8(&got, &input, &gotWorkspace); err != nil {
			t.Fatal(err)
		}
		if err := ifmaPointDoubleRawSquareStage2ExperimentX8(&want, &input, &wantWorkspace); err != nil {
			t.Fatal(err)
		}
		if got.Reduced() != want.Reduced() {
			t.Fatalf("round=%d four-square/current point mismatch", round)
		}
	}
}

func TestIFMAPointDoubleFourSquareStage2X8Aliasing(t *testing.T) {
	requireNativeRawSquareX8(t)
	rng := rand.New(rand.NewSource(0x51_a8_45a1))
	for round := 0; round < 1024; round++ {
		got := randomSquareIFMAPointX8(rng)
		want := got
		var gotWorkspace, wantWorkspace ifmaPointDoubleWorkspaceX8
		if err := ifmaPointDoubleFourSquareStage2ExperimentX8(&got, &got, &gotWorkspace); err != nil {
			t.Fatal(err)
		}
		if err := ifmaPointDoubleRawSquareStage2ExperimentX8(&want, &want, &wantWorkspace); err != nil {
			t.Fatal(err)
		}
		if got.Reduced() != want.Reduced() {
			t.Fatalf("round=%d in-place four-square point mismatch", round)
		}
	}
}

func TestIFMAPointDoubleFourSquareStage2X8ZeroAllocations(t *testing.T) {
	requireNativeRawSquareX8(t)
	state := randomSquareIFMAPointX8(rand.New(rand.NewSource(0x51_a8_45a0)))
	var workspace ifmaPointDoubleWorkspaceX8
	if allocs := testing.AllocsPerRun(1000, func() {
		if err := ifmaPointDoubleFourSquareStage2ExperimentX8(&state, &state, &workspace); err != nil {
			panic(err)
		}
	}); allocs != 0 {
		t.Fatalf("four-square x8 doubling allocations=%v", allocs)
	}
	benchmarkComposablePointX8Sink = state
}

func BenchmarkIFMAPointDoubleRawSquareStage2X8(b *testing.B) {
	if runtime.GOARCH != "amd64" || !ExperimentalIFMAAvailable() {
		b.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	reduced, _, _, _ := benchmarkMixedPointInputs(b)
	var seed IFMAPointX8
	seed.SetReduced(&reduced)

	b.Run("kernel=current-general-square", func(b *testing.B) {
		state := seed
		var workspace ifmaPointDoubleWorkspaceX8
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := ifmaPointDoubleComposableWorkspaceStaticX8(&state, &state, &workspace); err != nil {
				b.Fatal(err)
			}
		}
		benchmarkComposablePointX8Sink = state
	})

	b.Run("kernel=dedicated-raw-square", func(b *testing.B) {
		state := seed
		var workspace ifmaPointDoubleWorkspaceX8
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := ifmaPointDoubleRawSquareStage2ExperimentX8(&state, &state, &workspace); err != nil {
				b.Fatal(err)
			}
		}
		benchmarkComposablePointX8Sink = state
	})

	b.Run("kernel=four-dedicated-raw-squares", func(b *testing.B) {
		state := seed
		var workspace ifmaPointDoubleWorkspaceX8
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := ifmaPointDoubleFourSquareStage2ExperimentX8(&state, &state, &workspace); err != nil {
				b.Fatal(err)
			}
		}
		benchmarkComposablePointX8Sink = state
	})
}

func requireNativeRawSquareX8(tb testing.TB) {
	tb.Helper()
	if runtime.GOARCH != "amd64" || !ExperimentalIFMAAvailable() {
		tb.Skipf("native x8 AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
}
