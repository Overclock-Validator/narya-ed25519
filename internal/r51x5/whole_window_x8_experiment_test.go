package r51x5

import (
	"math/rand"
	"testing"
)

var wholeWindowRawProductUpperExclusive = [5]uint64{
	1202461100507921976,
	959266720629915282,
	716072340751908588,
	472877960873901894,
	229683580995895200,
}

func TestIFMACompletedProductsToLinearX8CertificateBoundary(t *testing.T) {
	requireNativeRawSquareX8(t)
	var products [4]IFMAProductX8
	for product := range products {
		for limb, upper := range wholeWindowRawProductUpperExclusive {
			for lane := 0; lane < X8Lanes; lane++ {
				products[product][limb][lane] = upper - 1
			}
		}
	}
	before := products
	var got, want ifmaCompletedLinearPointX8
	ifmaCompletedProductsToLinearUncheckedX8(&got, &products)
	ifmaCompletedProductsToLinearModelX8(&want, &products)
	if got != want {
		t.Fatal("certificate-boundary native/model representation mismatch")
	}
	if products != before {
		t.Fatal("completed linear leaf modified raw products")
	}
	if !isIFMAElementX8(&got.YMinusX) || !isIFMAElementX8(&got.YPlusX) ||
		!isIFMAElementX8(&got.Z) || !isIFMAElementX8(&got.T) {
		t.Fatal("certificate-boundary output escaped u52")
	}
}

func TestIFMACompletedProductsToLinearX8Differential(t *testing.T) {
	requireNativeRawSquareX8(t)
	rng := rand.New(rand.NewSource(0x51_6f_1e_d5))
	for iteration := 0; iteration < 10_000; iteration++ {
		var operands [8]LimbsX8
		for operand := range operands {
			for limb := range operands[operand] {
				for lane := range operands[operand][limb] {
					operands[operand][limb][lane] = rng.Uint64() & (ifmaComposableLimbLimit - 1)
				}
			}
		}
		var products [4]IFMAProductX8
		ifmaFourRawProductsUncheckedX8(
			&products[0],
			&operands[0], &operands[1],
			&operands[2], &operands[3],
			&operands[4], &operands[5],
			&operands[6], &operands[7],
		)
		var got, want ifmaCompletedLinearPointX8
		ifmaCompletedProductsToLinearUncheckedX8(&got, &products)
		ifmaCompletedProductsToLinearModelX8(&want, &products)
		if got != want {
			t.Fatalf("iteration=%d native/model representation mismatch", iteration)
		}
	}
}

func TestIFMAWholeWindowFiveDoublesExactRepresentation(t *testing.T) {
	requireNativeRawSquareX8(t)
	rng := rand.New(rand.NewSource(0x51_5d_c0_6d))
	for iteration := 0; iteration < 2_048; iteration++ {
		input := randomSquareIFMAPointX8(rng)
		want := input
		var wantWorkspace ifmaPointDoubleWorkspaceX8
		for doubling := 0; doubling < 5; doubling++ {
			if err := ifmaPointDoubleRawSquareStage2ExperimentX8(&want, &want, &wantWorkspace); err != nil {
				t.Fatal(err)
			}
		}
		var completed ifmaCompletedPointX8
		var projective ifmaProjectivePointX8
		var gotWorkspace ifmaPointDoubleWorkspaceX8
		ifmaFiveDoublesP3ToCompletedExperimentX8(&completed, &input, &projective, &gotWorkspace)
		var got IFMAPointX8
		ifmaCompletedToP3ExperimentX8(&got, &completed)
		if got != want {
			t.Fatalf("iteration=%d five-doubling representation mismatch", iteration)
		}
	}
}

func TestAsymmetricFixedB10WholeWindowX8Experiment(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("requires AVX-512 IFMA")
	}
	variable, _, fixed, s, k := asymmetricFixedBNielsX8Fixture(t)
	check := func(name string, active uint8) {
		t.Helper()
		var control, candidate IFMAPointX8
		controlMask, controlErr := IFMAAsymmetricFixedB10EvaluateX8(&control, variable, fixed, &s, &k, active)
		candidateMask, candidateErr := IFMAAsymmetricFixedB10EvaluateWholeWindowExperimentX8(&candidate, variable, fixed, &s, &k, active)
		if controlErr != nil || candidateErr != nil || controlMask != candidateMask {
			t.Fatalf("%s active=%02x control=(%02x,%v) candidate=(%02x,%v)", name, active, controlMask, controlErr, candidateMask, candidateErr)
		}
		controlReduced, candidateReduced := control.Reduced(), candidate.Reduced()
		if controlReduced.Equal(&candidateReduced)&controlMask != controlMask {
			t.Fatalf("%s active=%02x point mismatch", name, active)
		}
	}
	for active := 0; active < 256; active++ {
		check("fixture", uint8(active))
	}

	rng := rand.New(rand.NewSource(0x51_b10_5d))
	for iteration := 0; iteration < 512; iteration++ {
		for lane := 0; lane < X8Lanes; lane++ {
			s[lane] = randomCanonicalFixedBaseScalar(t, rng)
			k[lane] = randomCanonicalFixedBaseScalar(t, rng)
		}
		check("random", uint8(rng.Uint32()))
	}
}

func TestAsymmetricFixedB10WholeWindowX8ZeroAllocations(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("requires AVX-512 IFMA")
	}
	variable, _, fixed, s, k := asymmetricFixedBNielsX8Fixture(t)
	var out IFMAPointX8
	allocations := testing.AllocsPerRun(100, func() {
		if mask, err := IFMAAsymmetricFixedB10EvaluateWholeWindowExperimentX8(&out, variable, fixed, &s, &k, 0xff); err != nil || mask != 0xff {
			panic("whole-window evaluator failed")
		}
	})
	if allocations != 0 {
		t.Fatalf("whole-window evaluator allocations=%v", allocations)
	}
}

func BenchmarkAsymmetricFixedB10WholeWindowX8Experiment(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skip("requires AVX-512 IFMA")
	}
	variable, _, fixed, s, k := asymmetricFixedBNielsX8Fixture(b)
	for _, candidate := range []struct {
		name string
		run  func(*IFMAPointX8) (uint8, error)
	}{
		{name: "materialized-boundary", run: func(out *IFMAPointX8) (uint8, error) {
			return IFMAAsymmetricFixedB10EvaluateX8(out, variable, fixed, &s, &k, 0xff)
		}},
		{name: "whole-window", run: func(out *IFMAPointX8) (uint8, error) {
			return IFMAAsymmetricFixedB10EvaluateWholeWindowExperimentX8(out, variable, fixed, &s, &k, 0xff)
		}},
	} {
		candidate := candidate
		b.Run(candidate.name, func(b *testing.B) {
			var out IFMAPointX8
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if mask, err := candidate.run(&out); err != nil || mask != 0xff {
					b.Fatalf("evaluate=(%02x,%v)", mask, err)
				}
			}
			benchmarkAsymmetricFixedBNielsPointX8 = out
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*X8Lanes), "ns/signature")
		})
	}
}
