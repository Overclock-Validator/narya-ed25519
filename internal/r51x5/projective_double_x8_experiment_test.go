package r51x5

import (
	"math/rand"
	"testing"
)

func TestIFMAProjectiveFinalProductsX8MatchesCompleteLeaf(t *testing.T) {
	requireNativeRawSquareX8(t)
	rng := rand.New(rand.NewSource(0x51_92_f1a1))
	for iteration := 0; iteration < 10_000; iteration++ {
		var operands [4]IFMAProductX8
		for operand := range operands {
			for limb := range operands[operand] {
				for lane := range operands[operand][limb] {
					switch iteration {
					case 0:
						operands[operand][limb][lane] = 0
					case 1:
						operands[operand][limb][lane] = ifmaComposableLimbLimit - 1
					default:
						operands[operand][limb][lane] = rng.Uint64() & (ifmaComposableLimbLimit - 1)
					}
				}
			}
		}
		before := operands
		var complete IFMAPointX8
		ifmaPointFinalProductsUncheckedX8(&complete, &operands[0])
		var projective ifmaProjectivePointX8
		ifmaProjectiveFinalProductsUncheckedX8(&projective, &operands[0])
		if projective.X != complete.X || projective.Y != complete.Y || projective.Z != complete.Z {
			t.Fatalf("iteration=%d projective/complete representation mismatch", iteration)
		}
		if operands != before {
			t.Fatalf("iteration=%d projective leaf modified operand workspace", iteration)
		}
	}
}

func TestIFMAProjectiveDoublingFiveRunExactRepresentation(t *testing.T) {
	requireNativeRawSquareX8(t)
	rng := rand.New(rand.NewSource(0x51_92_d0b1))
	for iteration := 0; iteration < 2_048; iteration++ {
		input := randomSquareIFMAPointX8(rng)
		want := input
		var projective ifmaProjectivePointX8
		var gotWorkspace, wantWorkspace ifmaPointDoubleWorkspaceX8

		ifmaPointDoubleRawSquareP3ToP2ExperimentX8(&projective, &input, &gotWorkspace)
		if err := ifmaPointDoubleRawSquareStage2ExperimentX8(&want, &want, &wantWorkspace); err != nil {
			t.Fatal(err)
		}
		if gotWorkspace.stage2 != wantWorkspace.stage2 {
			t.Fatalf("iteration=%d doubling=1 fused/split Stage-2 representation mismatch", iteration)
		}
		assertProjectiveMatchesCompleteX8(t, iteration, 1, &projective, &want)

		for doubling := 2; doubling <= 4; doubling++ {
			ifmaPointDoubleRawSquareP2ToP2ExperimentX8(&projective, &projective, &gotWorkspace)
			if err := ifmaPointDoubleRawSquareStage2ExperimentX8(&want, &want, &wantWorkspace); err != nil {
				t.Fatal(err)
			}
			if gotWorkspace.stage2 != wantWorkspace.stage2 {
				t.Fatalf("iteration=%d doubling=%d fused/split Stage-2 representation mismatch", iteration, doubling)
			}
			assertProjectiveMatchesCompleteX8(t, iteration, doubling, &projective, &want)
		}

		var got IFMAPointX8
		ifmaPointDoubleRawSquareP2ToP3ExperimentX8(&got, &projective, &gotWorkspace)
		if err := ifmaPointDoubleRawSquareStage2ExperimentX8(&want, &want, &wantWorkspace); err != nil {
			t.Fatal(err)
		}
		if gotWorkspace.stage2 != wantWorkspace.stage2 {
			t.Fatalf("iteration=%d doubling=5 fused/split Stage-2 representation mismatch", iteration)
		}
		if got != want {
			t.Fatalf("iteration=%d fifth doubling representation mismatch", iteration)
		}
	}
}

func assertProjectiveMatchesCompleteX8(t *testing.T, iteration, doubling int, got *ifmaProjectivePointX8, want *IFMAPointX8) {
	t.Helper()
	if got.X != want.X || got.Y != want.Y || got.Z != want.Z {
		t.Fatalf("iteration=%d doubling=%d projective/complete representation mismatch", iteration, doubling)
	}
}

func TestIFMAProjectiveDoublingPoisonedWorkspaceAndZeroAllocations(t *testing.T) {
	requireNativeRawSquareX8(t)
	seed := randomSquareIFMAPointX8(rand.New(rand.NewSource(0x51_92_9015)))
	var workspace ifmaPointDoubleWorkspaceX8
	for product := range workspace.stage2 {
		for limb := range workspace.stage2[product] {
			for lane := range workspace.stage2[product][limb] {
				workspace.stage2[product][limb][lane] = ^uint64(0) - uint64(product*40+limb*8+lane)
			}
		}
	}
	var state IFMAPointX8
	allocations := testing.AllocsPerRun(1_000, func() {
		var projective ifmaProjectivePointX8
		ifmaPointDoubleRawSquareP3ToP2ExperimentX8(&projective, &seed, &workspace)
		for doubling := 2; doubling <= 4; doubling++ {
			ifmaPointDoubleRawSquareP2ToP2ExperimentX8(&projective, &projective, &workspace)
		}
		ifmaPointDoubleRawSquareP2ToP3ExperimentX8(&state, &projective, &workspace)
	})
	if allocations != 0 {
		t.Fatalf("projective five-doubling allocations=%v", allocations)
	}
	var want IFMAPointX8
	var wantWorkspace ifmaPointDoubleWorkspaceX8
	want = seed
	for doubling := 0; doubling < 5; doubling++ {
		if err := ifmaPointDoubleRawSquareStage2ExperimentX8(&want, &want, &wantWorkspace); err != nil {
			t.Fatal(err)
		}
	}
	if state != want {
		t.Fatal("poisoned projective workspace changed the five-doubling result")
	}
}

func TestIFMAProjectiveDoublingEvaluatorAllMasks(t *testing.T) {
	requireNativeRawSquareX8(t)
	_, variable, _, scalars := fixedBaseCombDSMFixtures(t)
	var workspace ExperimentalIFMAProjectiveNielsPreSignedMicroAoSVariableBaseWorkspaceX8
	if err := workspace.Prepare(&variable, 5); err != nil {
		t.Fatal(err)
	}
	for active := 0; active < 256; active++ {
		for _, negative := range []uint8{0, uint8(active), 0xa5, 0xff} {
			var got, want IFMAPointX8
			gotMask, gotErr := workspace.EvaluateProjectiveDoubleExperiment(&got, &scalars, negative, uint8(active))
			wantMask, wantErr := workspace.EvaluateRawSquareExperiment(&want, &scalars, negative, uint8(active))
			if gotErr != nil || wantErr != nil {
				t.Fatalf("active=%02x negative=%02x errors=%v/%v", active, negative, gotErr, wantErr)
			}
			if gotMask != wantMask || got != want {
				t.Fatalf("active=%02x negative=%02x masks=%02x/%02x representation mismatch", active, negative, gotMask, wantMask)
			}
		}
	}
	var out IFMAPointX8
	if allocations := testing.AllocsPerRun(100, func() {
		if _, err := workspace.EvaluateProjectiveDoubleExperiment(&out, &scalars, 0xa5, 0xff); err != nil {
			panic(err)
		}
	}); allocations != 0 {
		t.Fatalf("projective evaluator allocations=%v", allocations)
	}
}

var benchmarkIFMAProjectivePointX8Sink ifmaProjectivePointX8

func BenchmarkIFMAProjectiveFinalProductsX8(b *testing.B) {
	requireNativeRawSquareX8(b)
	operands := benchmarkPointFinalProductOperandsX8()
	b.Run("complete-p3", func(b *testing.B) {
		var out IFMAPointX8
		b.ReportAllocs()
		for range b.N {
			ifmaPointFinalProductsUncheckedX8(&out, &operands[0])
		}
		benchmarkPointFinalProductsSinkX8 = out
	})
	b.Run("projective-p2", func(b *testing.B) {
		var out ifmaProjectivePointX8
		b.ReportAllocs()
		for range b.N {
			ifmaProjectiveFinalProductsUncheckedX8(&out, &operands[0])
		}
		benchmarkIFMAProjectivePointX8Sink = out
	})
}

func BenchmarkIFMAProjectiveDoublingEvaluatorX8(b *testing.B) {
	requireNativeRawSquareX8(b)
	_, variable, _, scalars := fixedBaseCombDSMFixtures(b)
	var workspace ExperimentalIFMAProjectiveNielsPreSignedMicroAoSVariableBaseWorkspaceX8
	if err := workspace.Prepare(&variable, 5); err != nil {
		b.Fatal(err)
	}
	for _, candidate := range []struct {
		name string
		run  func(*IFMAPointX8) (uint8, error)
	}{
		{name: "complete-p3", run: func(out *IFMAPointX8) (uint8, error) {
			return workspace.EvaluateRawSquareExperiment(out, &scalars, 0xa5, 0xff)
		}},
		{name: "intermediate-p2", run: func(out *IFMAPointX8) (uint8, error) {
			return workspace.EvaluateProjectiveDoubleExperiment(out, &scalars, 0xa5, 0xff)
		}},
	} {
		candidate := candidate
		b.Run(candidate.name, func(b *testing.B) {
			var out IFMAPointX8
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if mask, err := candidate.run(&out); err != nil || mask != 0xff {
					b.Fatalf("evaluate mask=%02x err=%v", mask, err)
				}
			}
			benchmarkComposablePointX8Sink = out
		})
	}
}
