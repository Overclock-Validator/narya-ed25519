package r51x5

import (
	"math/big"
	"math/rand"
	"runtime"
	"testing"
)

const (
	nielsStage2A = iota
	nielsStage2B
	nielsStage2C
	nielsStage2D
)

var nielsStage2RawWeights = [...]uint64{267, 213, 159, 105, 51}
var nielsStage2RawDeficits = [...]uint64{457, 367, 277, 187, 97}

func nielsStage2RawMaximum(limb int) uint64 {
	return nielsStage2RawWeights[limb]*(uint64(1)<<IFMAComposableLimbBits) -
		nielsStage2RawDeficits[limb]
}

func nielsStage2ModulusCoefficient(limb int) uint64 {
	if limb == 0 {
		return uint64(1)<<LimbBits - 19
	}
	return limbMask
}

// nielsStage2Oracle uses arbitrary-precision integers and performs every
// quotient/remainder extraction before propagating any carry. It shares no
// normalization helper or vector schedule with the production leaf.
func nielsStage2Oracle(t testing.TB, input *ifmaNielsStage2WorkspaceX8) ifmaNielsStage2WorkspaceX8 {
	t.Helper()
	var wide [4][5][X8Lanes]*big.Int
	for limb := 0; limb < 5; limb++ {
		p := new(big.Int).SetUint64(nielsStage2ModulusCoefficient(limb))
		bias := new(big.Int).Mul(new(big.Int).Set(p), big.NewInt(535))
		for lane := 0; lane < X8Lanes; lane++ {
			a := new(big.Int).SetUint64(input[nielsStage2A][limb][lane])
			b := new(big.Int).SetUint64(input[nielsStage2B][limb][lane])
			c := new(big.Int).SetUint64(input[nielsStage2C][limb][lane])
			d := new(big.Int).SetUint64(input[nielsStage2D][limb][lane])
			d2 := new(big.Int).Lsh(new(big.Int).Set(d), 1)

			wide[0][limb][lane] = new(big.Int).Sub(new(big.Int).Add(new(big.Int).Set(b), bias), a)
			wide[1][limb][lane] = new(big.Int).Sub(new(big.Int).Add(new(big.Int).Set(d2), bias), c)
			wide[2][limb][lane] = new(big.Int).Add(new(big.Int).Set(d2), c)
			wide[3][limb][lane] = new(big.Int).Add(new(big.Int).Set(b), a)
			for slot := range wide {
				value := wide[slot][limb][lane]
				if value.Sign() < 0 {
					t.Fatalf("slot=%d limb=%d lane=%d underflowed: %s", slot, limb, lane, value)
				}
				if value.BitLen() > 62 {
					t.Fatalf("slot=%d limb=%d lane=%d escaped u62: %x", slot, limb, lane, value)
				}
			}
		}
	}

	radix := new(big.Int).Lsh(big.NewInt(1), LimbBits)
	var output ifmaNielsStage2WorkspaceX8
	for slot := range wide {
		for lane := 0; lane < X8Lanes; lane++ {
			var carry, remainder [5]*big.Int
			for limb := 0; limb < 5; limb++ {
				carry[limb] = new(big.Int)
				remainder[limb] = new(big.Int)
				carry[limb].QuoRem(wide[slot][limb][lane], radix, remainder[limb])
				if carry[limb].Cmp(big.NewInt(1603)) > 0 {
					t.Fatalf("slot=%d limb=%d lane=%d carry=%s exceeds proof bound", slot, limb, lane, carry[limb])
				}
			}
			for limb := 0; limb < 5; limb++ {
				value := new(big.Int).Set(remainder[limb])
				if limb == 0 {
					value.Add(value, new(big.Int).Mul(carry[4], big.NewInt(19)))
				} else {
					value.Add(value, carry[limb-1])
				}
				if !value.IsUint64() || value.BitLen() > IFMAComposableLimbBits {
					t.Fatalf("slot=%d limb=%d lane=%d escaped u52: %x", slot, limb, lane, value)
				}
				output[slot][limb][lane] = value.Uint64()
			}
		}
	}
	return output
}

func nielsStage2BoundaryInputs() []struct {
	name      string
	workspace ifmaNielsStage2WorkspaceX8
} {
	var zero, maximum, subtractionEdges, stripes ifmaNielsStage2WorkspaceX8
	for slot := range maximum {
		for limb := range maximum[slot] {
			max := nielsStage2RawMaximum(limb)
			for lane := 0; lane < X8Lanes; lane++ {
				maximum[slot][limb][lane] = max
				stripes[slot][limb][lane] = max - uint64((slot+2*limb+lane)%31)
			}
		}
	}
	for limb := 0; limb < 5; limb++ {
		max := nielsStage2RawMaximum(limb)
		for lane := 0; lane < X8Lanes; lane++ {
			subtractionEdges[nielsStage2A][limb][lane] = max
			subtractionEdges[nielsStage2B][limb][lane] = uint64(lane & 1)
			subtractionEdges[nielsStage2C][limb][lane] = max
			subtractionEdges[nielsStage2D][limb][lane] = uint64((lane >> 1) & 1)
		}
	}
	return []struct {
		name      string
		workspace ifmaNielsStage2WorkspaceX8
	}{
		{name: "zero", workspace: zero},
		{name: "maximum", workspace: maximum},
		{name: "subtraction-edges", workspace: subtractionEdges},
		{name: "limb-lane-stripes", workspace: stripes},
	}
}

func nielsStage2CanCall() bool {
	return runtime.GOARCH != "amd64" || ExperimentalIFMAAvailable()
}

func TestIFMANielsStage2X8BoundariesAgainstIndependentOracle(t *testing.T) {
	if !nielsStage2CanCall() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	for _, fixture := range nielsStage2BoundaryInputs() {
		t.Run(fixture.name, func(t *testing.T) {
			want := nielsStage2Oracle(t, &fixture.workspace)
			got := fixture.workspace
			ifmaNielsStage2X8(&got)
			if got != want {
				t.Fatalf("Stage 2 mismatch\n got %x\nwant %x", got, want)
			}
		})
	}
}

func TestIFMANielsStage2X8MultiplicandDerived(t *testing.T) {
	if !nielsStage2CanCall() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	rng := rand.New(rand.NewSource(0x51_a66_2026))
	for round := 0; round < 1024; round++ {
		var operands [8]LimbsX8
		for operand := range operands {
			for limb := range operands[operand] {
				for lane := range operands[operand][limb] {
					operands[operand][limb][lane] = rng.Uint64() & (ifmaComposableLimbLimit - 1)
				}
			}
		}
		var input ifmaNielsStage2WorkspaceX8
		for slot := range input {
			for lane := 0; lane < X8Lanes; lane++ {
				var left, right Limbs
				for limb := range left {
					left[limb] = operands[2*slot][limb][lane]
					right[limb] = operands[2*slot+1][limb][lane]
				}
				product := ifmaLooseLaneModel(left, right)
				for limb := range product {
					input[slot][limb][lane] = product[limb]
				}
			}
		}
		want := nielsStage2Oracle(t, &input)
		got := input
		ifmaNielsStage2X8(&got)
		if got != want {
			t.Fatalf("round=%d: multiplicand-derived mismatch", round)
		}
	}
}

func TestIFMANielsStage2X8AcceptsComposableD(t *testing.T) {
	if !nielsStage2CanCall() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	rng := rand.New(rand.NewSource(0xaff1_3d_2026))
	for round := 0; round < 1024; round++ {
		var operands [6]LimbsX8
		for operand := range operands {
			for limb := range operands[operand] {
				for lane := range operands[operand][limb] {
					operands[operand][limb][lane] = rng.Uint64() & (ifmaComposableLimbLimit - 1)
				}
			}
		}
		var input ifmaNielsStage2WorkspaceX8
		for slot := 0; slot < 3; slot++ {
			for lane := 0; lane < X8Lanes; lane++ {
				var left, right Limbs
				for limb := range left {
					left[limb] = operands[2*slot][limb][lane]
					right[limb] = operands[2*slot+1][limb][lane]
				}
				product := ifmaLooseLaneModel(left, right)
				for limb := range product {
					input[slot][limb][lane] = product[limb]
				}
			}
		}
		for limb := range input[nielsStage2D] {
			for lane := range input[nielsStage2D][limb] {
				input[nielsStage2D][limb][lane] = rng.Uint64() & (ifmaComposableLimbLimit - 1)
			}
		}

		want := nielsStage2Oracle(t, &input)
		got := input
		ifmaNielsStage2X8(&got)
		if got != want {
			t.Fatalf("round=%d: composable-D mismatch", round)
		}
	}
}

var benchmarkIFMANielsStage2X8Sink ifmaNielsStage2WorkspaceX8

func TestIFMANielsStage2X8ZeroAllocations(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	seed := nielsStage2BoundaryInputs()[1].workspace
	var workspace ifmaNielsStage2WorkspaceX8
	if allocs := testing.AllocsPerRun(1000, func() {
		workspace = seed
		ifmaNielsStage2X8(&workspace)
	}); allocs != 0 {
		t.Fatalf("Stage 2 allocations=%v", allocs)
	}
	benchmarkIFMANielsStage2X8Sink = workspace
}

func BenchmarkIFMANielsStage2X8(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	seed := nielsStage2BoundaryInputs()[3].workspace
	workspace := seed
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		workspace = seed
		ifmaNielsStage2X8(&workspace)
	}
	benchmarkIFMANielsStage2X8Sink = workspace
}
