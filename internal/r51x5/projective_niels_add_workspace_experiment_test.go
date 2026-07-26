package r51x5

import (
	"math/rand"
	"runtime"
	"testing"
)

type ifmaProjectiveNielsAddWorkspaceExperimentX8 struct {
	yMinusX, yPlusX        IFMAElementX8
	A, B, C, D, E, F, G, H IFMAElementX8
}

func TestIFMAProjectiveNielsAddReusedWorkspaceX8Differential(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	rng := rand.New(rand.NewSource(0x51_add_2026))
	var workspace ifmaProjectiveNielsAddWorkspaceExperimentX8
	for round := 0; round < 4096; round++ {
		point := randomSquareIFMAPointX8(rng)
		cachedPoint := randomSquareIFMAPointX8(rng)
		var cached IFMAProjectiveNielsX8
		if err := ifmaProjectiveNielsFromPointX8(&cached, &cachedPoint); err != nil {
			t.Fatal(err)
		}

		var got, want IFMAPointX8
		if err := ifmaPointAddProjectiveNielsReusedWorkspaceExperimentX8(&got, &point, &cached, &workspace); err != nil {
			t.Fatal(err)
		}
		if err := ifmaPointAddProjectiveNielsX8(&want, &point, &cached); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("round %d: reused-workspace/current representation mismatch", round)
		}

		aliasPoint := point
		if err := ifmaPointAddProjectiveNielsReusedWorkspaceExperimentX8(&aliasPoint, &aliasPoint, &cached, &workspace); err != nil {
			t.Fatal(err)
		}
		if aliasPoint != want {
			t.Fatalf("round %d: point-alias representation mismatch", round)
		}
	}
}

func TestIFMAProjectiveNielsAddReusedWorkspaceX8ZeroAllocations(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	rng := rand.New(rand.NewSource(0x51_add_a110))
	state := randomSquareIFMAPointX8(rng)
	cachedPoint := randomSquareIFMAPointX8(rng)
	var cached IFMAProjectiveNielsX8
	if err := ifmaProjectiveNielsFromPointX8(&cached, &cachedPoint); err != nil {
		t.Fatal(err)
	}
	var workspace ifmaProjectiveNielsAddWorkspaceExperimentX8
	if allocs := testing.AllocsPerRun(1000, func() {
		if err := ifmaPointAddProjectiveNielsReusedWorkspaceExperimentX8(&state, &state, &cached, &workspace); err != nil {
			panic(err)
		}
	}); allocs != 0 {
		t.Fatalf("reused-workspace projective-Niels x8 add allocations=%v", allocs)
	}
	benchmarkComposablePointX8Sink = state
}

func BenchmarkIFMAProjectiveNielsAddReusedWorkspaceX8(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	rng := rand.New(rand.NewSource(0x51_add_beef))
	seed := randomSquareIFMAPointX8(rng)
	cachedPoint := randomSquareIFMAPointX8(rng)
	var cached IFMAProjectiveNielsX8
	if err := ifmaProjectiveNielsFromPointX8(&cached, &cachedPoint); err != nil {
		b.Fatal(err)
	}

	b.Run("scaffold=current-temporary-copy", func(b *testing.B) {
		state := seed
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			if err := ifmaPointAddProjectiveNielsX8(&state, &state, &cached); err != nil {
				b.Fatal(err)
			}
		}
		benchmarkComposablePointX8Sink = state
	})
	b.Run("scaffold=reused-workspace", func(b *testing.B) {
		state := seed
		var workspace ifmaProjectiveNielsAddWorkspaceExperimentX8
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			if err := ifmaPointAddProjectiveNielsReusedWorkspaceExperimentX8(&state, &state, &cached, &workspace); err != nil {
				b.Fatal(err)
			}
		}
		benchmarkComposablePointX8Sink = state
	})
}

func ifmaPointAddProjectiveNielsReusedWorkspaceExperimentX8(
	out, point *IFMAPointX8,
	cached *IFMAProjectiveNielsX8,
	workspace *ifmaProjectiveNielsAddWorkspaceExperimentX8,
) error {
	yMinusX, yPlusX := &workspace.yMinusX, &workspace.yPlusX
	A, B, C, D := &workspace.A, &workspace.B, &workspace.C, &workspace.D
	E, F, G, H := &workspace.E, &workspace.F, &workspace.G, &workspace.H
	yMinusX.Subtract(&point.Y, &point.X)
	yPlusX.Add(&point.Y, &point.X)
	if err := ifmaMultiplyComposableUncheckedX8(A, yMinusX, &cached.YMinusX); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX8(B, yPlusX, &cached.YPlusX); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX8(C, &point.T, &cached.T2D); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX8(D, &point.Z, &cached.Z); err != nil {
		return err
	}
	D.Add(D, D)
	E.Subtract(B, A)
	F.Subtract(D, C)
	G.Add(D, C)
	H.Add(B, A)

	if err := ifmaMultiplyComposableUncheckedX8(&out.X, E, F); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX8(&out.Y, G, H); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX8(&out.T, E, H); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX8(&out.Z, F, G); err != nil {
		return err
	}
	return nil
}
