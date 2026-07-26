package r51x5

import (
	"math/rand"
	"runtime"
	"testing"
)

func TestIFMAPointFinalProductsX8MatchesFourMultiplies(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	rng := rand.New(rand.NewSource(0x51_f1_a1_0008))
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

		var want IFMAPointX8
		pointFinalProductsFourCallsX8(&want, &operands)
		var got IFMAPointX8
		ifmaPointFinalProductsUncheckedX8(&got, &operands[0])

		if got != want {
			t.Fatalf("iteration %d: fused final products differ from four-call representation", iteration)
		}
		if operands != before {
			t.Fatalf("iteration %d: fused final products modified operand workspace", iteration)
		}
	}
}

func TestIFMAPointFinalProductsX8ZeroAllocations(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	operands := benchmarkPointFinalProductOperandsX8()
	var out IFMAPointX8
	allocations := testing.AllocsPerRun(1_000, func() {
		ifmaPointFinalProductsUncheckedX8(&out, &operands[0])
	})
	if allocations != 0 {
		t.Fatalf("allocations = %v, want 0", allocations)
	}
}

var benchmarkPointFinalProductsSinkX8 IFMAPointX8

func BenchmarkIFMAPointFinalProductsX8(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	operands := benchmarkPointFinalProductOperandsX8()
	b.Run("four-calls", func(b *testing.B) {
		var out IFMAPointX8
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			pointFinalProductsFourCallsX8(&out, &operands)
		}
		benchmarkPointFinalProductsSinkX8 = out
	})
	b.Run("one-leaf", func(b *testing.B) {
		var out IFMAPointX8
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ifmaPointFinalProductsUncheckedX8(&out, &operands[0])
		}
		benchmarkPointFinalProductsSinkX8 = out
	})
}

func pointFinalProductsFourCallsX8(out *IFMAPointX8, operands *[4]IFMAProductX8) {
	e := (*LimbsX8)(&operands[0])
	f := (*LimbsX8)(&operands[1])
	g := (*LimbsX8)(&operands[2])
	h := (*LimbsX8)(&operands[3])
	ifmaMulNormalizedUncheckedX8(&out.X.limbs, e, f)
	ifmaMulNormalizedUncheckedX8(&out.Y.limbs, g, h)
	ifmaMulNormalizedUncheckedX8(&out.T.limbs, e, h)
	ifmaMulNormalizedUncheckedX8(&out.Z.limbs, f, g)
}

func benchmarkPointFinalProductOperandsX8() [4]IFMAProductX8 {
	var operands [4]IFMAProductX8
	for operand := range operands {
		for limb := range operands[operand] {
			for lane := range operands[operand][limb] {
				value := uint64(operand+1)*0x9e37_79b9 + uint64(limb+1)*0x7f4a_7c15 + uint64(lane+1)*0x51_8101
				operands[operand][limb][lane] = value & (ifmaComposableLimbLimit - 1)
			}
		}
	}
	return operands
}
