package r51x5

import (
	"math/big"
	"math/rand"
	"runtime"
	"testing"
)

const (
	doubleStage2TestA = iota
	doubleStage2TestB
	doubleStage2TestC
	doubleStage2TestXY
)

const (
	doubleStage2TestE = iota
	doubleStage2TestF
	doubleStage2TestG
	doubleStage2TestH
)

// These are inclusive coefficient bounds for the exact folded output of a
// u52-by-u52 raw IFMA product. They refine the public u61 bound using
// LUQ <= 2^52-1 and HUQ <= 2^52-2.
var doubleStage2TestRawWeights = [...]uint64{267, 213, 159, 105, 51}
var doubleStage2TestRawDeficits = [...]uint64{457, 367, 277, 187, 97}

func doubleStage2TestRawMaximum(limb int) uint64 {
	return doubleStage2TestRawWeights[limb]*(uint64(1)<<IFMAComposableLimbBits) -
		doubleStage2TestRawDeficits[limb]
}

func doubleStage2TestModulusCoefficient(limb int) uint64 {
	if limb == 0 {
		return uint64(1)<<LimbBits - 19
	}
	return limbMask
}

// doubleStage2TestOracle computes the Stage-2 representative with arbitrary
// precision. It deliberately does not call the production normalizer: the
// quotient and remainder of every original coefficient are computed first,
// followed by the single parallel radix-51 carry/fold.
func doubleStage2TestOracle(t testing.TB, input *ifmaDoubleStage2WorkspaceX4) ifmaDoubleStage2WorkspaceX4 {
	t.Helper()
	var wide [4][5][X4Lanes]*big.Int
	for limb := 0; limb < 5; limb++ {
		p := new(big.Int).SetUint64(doubleStage2TestModulusCoefficient(limb))
		for lane := 0; lane < X4Lanes; lane++ {
			a := new(big.Int).SetUint64(input[doubleStage2TestA][limb][lane])
			b := new(big.Int).SetUint64(input[doubleStage2TestB][limb][lane])
			c := new(big.Int).SetUint64(input[doubleStage2TestC][limb][lane])
			xy := new(big.Int).SetUint64(input[doubleStage2TestXY][limb][lane])

			e := new(big.Int).Lsh(new(big.Int).Set(xy), 1)
			g := new(big.Int).Mul(new(big.Int).Set(p), big.NewInt(535))
			g.Add(g, b)
			g.Sub(g, a)
			c2 := new(big.Int).Lsh(new(big.Int).Set(c), 1)
			f := new(big.Int).Mul(new(big.Int).Set(p), big.NewInt(1068))
			f.Add(f, g)
			f.Sub(f, c2)
			h := new(big.Int).Mul(new(big.Int).Set(p), big.NewInt(1069))
			h.Sub(h, a)
			h.Sub(h, b)

			wide[doubleStage2TestE][limb][lane] = e
			wide[doubleStage2TestF][limb][lane] = f
			wide[doubleStage2TestG][limb][lane] = g
			wide[doubleStage2TestH][limb][lane] = h
			for slot := range wide {
				if wide[slot][limb][lane].Sign() < 0 {
					t.Fatalf("slot=%d limb=%d lane=%d underflowed: %s", slot, limb, lane, wide[slot][limb][lane])
				}
				if wide[slot][limb][lane].BitLen() > 63 {
					t.Fatalf("slot=%d limb=%d lane=%d escaped u63: %x", slot, limb, lane, wide[slot][limb][lane])
				}
			}
		}
	}

	radix := new(big.Int).Lsh(big.NewInt(1), LimbBits)
	var output ifmaDoubleStage2WorkspaceX4
	for slot := range wide {
		for lane := 0; lane < X4Lanes; lane++ {
			var carry, remainder [5]*big.Int
			for limb := 0; limb < 5; limb++ {
				carry[limb] = new(big.Int)
				remainder[limb] = new(big.Int)
				carry[limb].QuoRem(wide[slot][limb][lane], radix, remainder[limb])
			}
			for limb := 0; limb < 5; limb++ {
				value := new(big.Int).Set(remainder[limb])
				if limb == 0 {
					value.Add(value, new(big.Int).Mul(carry[4], big.NewInt(19)))
				} else {
					value.Add(value, carry[limb-1])
				}
				if !value.IsUint64() || value.BitLen() > IFMAComposableLimbBits {
					t.Fatalf("slot=%d limb=%d lane=%d escaped u52 after carry: %x", slot, limb, lane, value)
				}
				output[slot][limb][lane] = value.Uint64()
			}
		}
	}
	return output
}

func doubleStage2TestLaneValue(workspace *ifmaDoubleStage2WorkspaceX4, slot, lane int) *big.Int {
	value := new(big.Int)
	for limb := 4; limb >= 0; limb-- {
		value.Lsh(value, LimbBits)
		value.Add(value, new(big.Int).SetUint64(workspace[slot][limb][lane]))
	}
	return value
}

func doubleStage2TestAssertFieldValues(t testing.TB, input, output *ifmaDoubleStage2WorkspaceX4) {
	t.Helper()
	for lane := 0; lane < X4Lanes; lane++ {
		a := doubleStage2TestLaneValue(input, doubleStage2TestA, lane)
		b := doubleStage2TestLaneValue(input, doubleStage2TestB, lane)
		c := doubleStage2TestLaneValue(input, doubleStage2TestC, lane)
		xy := doubleStage2TestLaneValue(input, doubleStage2TestXY, lane)

		want := [4]*big.Int{
			new(big.Int).Lsh(new(big.Int).Set(xy), 1),
			new(big.Int).Sub(new(big.Int).Sub(new(big.Int).Set(b), a), new(big.Int).Lsh(new(big.Int).Set(c), 1)),
			new(big.Int).Sub(new(big.Int).Set(b), a),
			new(big.Int).Neg(new(big.Int).Add(new(big.Int).Set(a), b)),
		}
		for slot := range want {
			want[slot].Mod(want[slot], testModulus)
			got := doubleStage2TestLaneValue(output, slot, lane)
			got.Mod(got, testModulus)
			if got.Cmp(want[slot]) != 0 {
				t.Fatalf("slot=%d lane=%d field mismatch: got %x want %x", slot, lane, got, want[slot])
			}
		}
	}
}

func doubleStage2TestCanCall() bool {
	return runtime.GOARCH != "amd64" || ExperimentalIFMAAvailable()
}

func doubleStage2TestRunAndCheck(t testing.TB, input ifmaDoubleStage2WorkspaceX4) ifmaDoubleStage2WorkspaceX4 {
	t.Helper()
	want := doubleStage2TestOracle(t, &input)
	got := input
	ifmaDoubleStage2X4(&got)
	if got != want {
		t.Fatalf("in-place Stage 2 mismatch\n got %x\nwant %x", got, want)
	}
	doubleStage2TestAssertFieldValues(t, &input, &got)
	for slot := range got {
		if !isIFMAProductX4Below(&got[slot], ifmaComposableLimbLimit) {
			t.Fatalf("slot=%d escaped downstream u52", slot)
		}
	}
	return got
}

func isIFMAProductX4Below(product *IFMAProductX4, limit uint64) bool {
	for limb := range product {
		for lane := range product[limb] {
			if product[limb][lane] >= limit {
				return false
			}
		}
	}
	return true
}

func doubleStage2TestBoundaryInputs() []struct {
	name      string
	workspace ifmaDoubleStage2WorkspaceX4
} {
	var zero, allMaximum, subtractionEdges, limbStripes ifmaDoubleStage2WorkspaceX4
	for slot := range allMaximum {
		for limb := range allMaximum[slot] {
			maximum := doubleStage2TestRawMaximum(limb)
			for lane := range allMaximum[slot][limb] {
				allMaximum[slot][limb][lane] = maximum
			}
		}
	}
	for limb := 0; limb < 5; limb++ {
		maximum := doubleStage2TestRawMaximum(limb)
		// Lane 0 minimizes G and maximizes E.
		subtractionEdges[doubleStage2TestA][limb][0] = maximum
		subtractionEdges[doubleStage2TestXY][limb][0] = maximum
		// Lane 1 minimizes H.
		subtractionEdges[doubleStage2TestA][limb][1] = maximum
		subtractionEdges[doubleStage2TestB][limb][1] = maximum
		// Lane 2 minimizes F = B-A-2C.
		subtractionEdges[doubleStage2TestA][limb][2] = maximum
		subtractionEdges[doubleStage2TestC][limb][2] = maximum
		// Lane 3 maximizes the positive B contribution to G and F.
		subtractionEdges[doubleStage2TestB][limb][3] = maximum
		subtractionEdges[doubleStage2TestXY][limb][3] = maximum

		lane := limb % X4Lanes
		limbStripes[limb%4][limb][lane] = maximum
		limbStripes[(limb+1)%4][limb][(lane+1)%X4Lanes] = maximum - uint64(limb+1)
	}
	return []struct {
		name      string
		workspace ifmaDoubleStage2WorkspaceX4
	}{
		{name: "zero-products", workspace: zero},
		{name: "analytic-maximum", workspace: allMaximum},
		{name: "subtraction-edges", workspace: subtractionEdges},
		{name: "limb-stripes", workspace: limbStripes},
	}
}

func TestIFMADoubleStage2AnalyticEnvelope(t *testing.T) {
	radix := new(big.Int).Lsh(big.NewInt(1), LimbBits)
	u63 := new(big.Int).Lsh(big.NewInt(1), 63)
	for limb := 0; limb < 5; limb++ {
		maximum := new(big.Int).SetUint64(doubleStage2TestRawMaximum(limb))
		p := new(big.Int).SetUint64(doubleStage2TestModulusCoefficient(limb))

		minimumG := new(big.Int).Sub(new(big.Int).Mul(new(big.Int).Set(p), big.NewInt(535)), maximum)
		minimumH := new(big.Int).Sub(new(big.Int).Mul(new(big.Int).Set(p), big.NewInt(1069)), new(big.Int).Lsh(new(big.Int).Set(maximum), 1))
		minimumF := new(big.Int).Sub(new(big.Int).Mul(new(big.Int).Set(p), big.NewInt(1603)), new(big.Int).Mul(new(big.Int).Set(maximum), big.NewInt(3)))
		if minimumG.Sign() < 0 || minimumH.Sign() < 0 || minimumF.Sign() < 0 {
			t.Fatalf("limb=%d subtraction proof failed: G=%s H=%s F=%s", limb, minimumG, minimumH, minimumF)
		}

		maxima := []*big.Int{
			new(big.Int).Lsh(new(big.Int).Set(maximum), 1),
			new(big.Int).Add(new(big.Int).Set(maximum), new(big.Int).Mul(new(big.Int).Set(p), big.NewInt(1603))),
			new(big.Int).Add(new(big.Int).Set(maximum), new(big.Int).Mul(new(big.Int).Set(p), big.NewInt(535))),
			new(big.Int).Mul(new(big.Int).Set(p), big.NewInt(1069)),
		}
		for slot, value := range maxima {
			if value.Cmp(u63) >= 0 {
				t.Fatalf("slot=%d limb=%d escaped u63: %x", slot, limb, value)
			}
			carry := new(big.Int).Quo(value, radix)
			if carry.BitLen() > 12 {
				t.Fatalf("slot=%d limb=%d carry unexpectedly wide: %x", slot, limb, carry)
			}
		}
	}

	// Limb zero binds whole-modulus bias selection under the current product
	// envelope. One fewer copy is not established by that envelope.
	maximum0 := new(big.Int).SetUint64(doubleStage2TestRawMaximum(0))
	p0 := new(big.Int).SetUint64(doubleStage2TestModulusCoefficient(0))
	insufficient := []*big.Int{
		new(big.Int).Sub(new(big.Int).Mul(new(big.Int).Set(p0), big.NewInt(534)), maximum0),
		new(big.Int).Sub(new(big.Int).Mul(new(big.Int).Set(p0), big.NewInt(1068)), new(big.Int).Lsh(new(big.Int).Set(maximum0), 1)),
		new(big.Int).Sub(new(big.Int).Mul(new(big.Int).Set(p0), big.NewInt(1602)), new(big.Int).Mul(new(big.Int).Set(maximum0), big.NewInt(3))),
	}
	for index, margin := range insufficient {
		if margin.Sign() >= 0 {
			t.Fatalf("lower bias %d unexpectedly covered the current envelope: %s", index, margin)
		}
	}
}

func TestIFMADoubleStage2BoundariesAndInPlace(t *testing.T) {
	if !doubleStage2TestCanCall() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	for _, fixture := range doubleStage2TestBoundaryInputs() {
		t.Run(fixture.name, func(t *testing.T) {
			doubleStage2TestRunAndCheck(t, fixture.workspace)
		})
	}
}

func doubleStage2TestRandomWorkspace(rng *rand.Rand) ifmaDoubleStage2WorkspaceX4 {
	var workspace ifmaDoubleStage2WorkspaceX4
	for lane := 0; lane < X4Lanes; lane++ {
		var x, y, z Limbs
		for limb := 0; limb < 5; limb++ {
			x[limb] = rng.Uint64() & (ifmaComposableLimbLimit - 1)
			y[limb] = rng.Uint64() & (ifmaComposableLimbLimit - 1)
			z[limb] = rng.Uint64() & (ifmaComposableLimbLimit - 1)
		}
		products := [4]Limbs{
			ifmaLooseLaneModel(x, x),
			ifmaLooseLaneModel(y, y),
			ifmaLooseLaneModel(z, z),
			ifmaLooseLaneModel(x, y),
		}
		for slot := range products {
			for limb := range products[slot] {
				workspace[slot][limb][lane] = products[slot][limb]
			}
		}
	}
	return workspace
}

func TestIFMADoubleStage2MultiplicandDerived(t *testing.T) {
	if !doubleStage2TestCanCall() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	rng := rand.New(rand.NewSource(0x51_d02_b1a5))
	for round := 0; round < 512; round++ {
		workspace := doubleStage2TestRandomWorkspace(rng)
		for slot := range workspace {
			for limb := range workspace[slot] {
				for lane, value := range workspace[slot][limb] {
					if value > doubleStage2TestRawMaximum(limb) {
						t.Fatalf("round=%d slot=%d limb=%d lane=%d raw product exceeded analytic maximum: %x", round, slot, limb, lane, value)
					}
				}
			}
		}
		doubleStage2TestRunAndCheck(t, workspace)
	}
}

func TestIFMADoubleStage2ZeroAllocations(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	seed := doubleStage2TestRandomWorkspace(rand.New(rand.NewSource(0x51_d02_a110)))
	var workspace ifmaDoubleStage2WorkspaceX4
	if allocs := testing.AllocsPerRun(1000, func() {
		workspace = seed
		ifmaDoubleStage2X4(&workspace)
	}); allocs != 0 {
		t.Fatalf("Stage 2 allocations=%v", allocs)
	}
	benchmarkIFMADoubleStage2WorkspaceSink = workspace
}

// doubleStage2TestOracleX8 deliberately derives the native-wide expectation
// by splitting it into two independent x4 inputs and invoking the existing
// arbitrary-precision oracle. It therefore checks every x8 lane without
// sharing the ZMM implementation or its load/store schedule.
func doubleStage2TestOracleX8(t testing.TB, input *ifmaDoubleStage2WorkspaceX8) ifmaDoubleStage2WorkspaceX8 {
	t.Helper()
	var output ifmaDoubleStage2WorkspaceX8
	for half := 0; half < 2; half++ {
		var inputX4 ifmaDoubleStage2WorkspaceX4
		for slot := range inputX4 {
			for limb := range inputX4[slot] {
				for lane := 0; lane < X4Lanes; lane++ {
					inputX4[slot][limb][lane] = input[slot][limb][half*X4Lanes+lane]
				}
			}
		}
		outputX4 := doubleStage2TestOracle(t, &inputX4)
		for slot := range outputX4 {
			for limb := range outputX4[slot] {
				for lane := 0; lane < X4Lanes; lane++ {
					output[slot][limb][half*X4Lanes+lane] = outputX4[slot][limb][lane]
				}
			}
		}
	}
	return output
}

func doubleStage2TestAssertX8U52(t testing.TB, workspace *ifmaDoubleStage2WorkspaceX8) {
	t.Helper()
	for slot := range workspace {
		for limb := range workspace[slot] {
			for lane, value := range workspace[slot][limb] {
				if value >= ifmaComposableLimbLimit {
					t.Fatalf("slot=%d limb=%d lane=%d escaped u52: %x", slot, limb, lane, value)
				}
			}
		}
	}
}

func TestIFMADoubleStage2X8BoundariesAgainstIndependentOracle(t *testing.T) {
	if !doubleStage2TestCanCall() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	for _, fixture := range doubleStage2TestBoundaryInputs() {
		t.Run(fixture.name, func(t *testing.T) {
			var input ifmaDoubleStage2WorkspaceX8
			for slot := range fixture.workspace {
				for limb := range fixture.workspace[slot] {
					for lane := 0; lane < X8Lanes; lane++ {
						input[slot][limb][lane] = fixture.workspace[slot][limb][lane%X4Lanes]
					}
				}
			}
			want := doubleStage2TestOracleX8(t, &input)
			got := input
			ifmaDoubleStage2X8(&got)
			if got != want {
				t.Fatalf("x8 Stage 2 mismatch\n got %x\nwant %x", got, want)
			}
			doubleStage2TestAssertX8U52(t, &got)
		})
	}
}

func TestIFMADoubleStage2X8MultiplicandDerived(t *testing.T) {
	if !doubleStage2TestCanCall() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	rng := rand.New(rand.NewSource(0x51_d02_8b1a5))
	for round := 0; round < 512; round++ {
		var x, y, z LimbsX8
		for limb := 0; limb < 5; limb++ {
			for lane := 0; lane < X8Lanes; lane++ {
				x[limb][lane] = rng.Uint64() & (ifmaComposableLimbLimit - 1)
				y[limb][lane] = rng.Uint64() & (ifmaComposableLimbLimit - 1)
				z[limb][lane] = rng.Uint64() & (ifmaComposableLimbLimit - 1)
			}
		}
		var input ifmaDoubleStage2WorkspaceX8
		for lane := 0; lane < X8Lanes; lane++ {
			var xLane, yLane, zLane Limbs
			for limb := 0; limb < 5; limb++ {
				xLane[limb] = x[limb][lane]
				yLane[limb] = y[limb][lane]
				zLane[limb] = z[limb][lane]
			}
			products := [4]Limbs{
				ifmaLooseLaneModel(xLane, xLane),
				ifmaLooseLaneModel(yLane, yLane),
				ifmaLooseLaneModel(zLane, zLane),
				ifmaLooseLaneModel(xLane, yLane),
			}
			for slot := range products {
				for limb := range products[slot] {
					input[slot][limb][lane] = products[slot][limb]
				}
			}
		}
		want := doubleStage2TestOracleX8(t, &input)
		got := input
		ifmaDoubleStage2X8(&got)
		if got != want {
			t.Fatalf("round=%d: x8 multiplicand-derived mismatch", round)
		}
		doubleStage2TestAssertX8U52(t, &got)
	}
}

var benchmarkIFMADoubleStage2WorkspaceX8Sink ifmaDoubleStage2WorkspaceX8

func TestIFMADoubleStage2X8ZeroAllocations(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	var seed ifmaDoubleStage2WorkspaceX8
	for slot := range seed {
		for limb := range seed[slot] {
			maximum := doubleStage2TestRawMaximum(limb)
			for lane := range seed[slot][limb] {
				seed[slot][limb][lane] = maximum - uint64((slot+limb+lane)%17)
			}
		}
	}
	var workspace ifmaDoubleStage2WorkspaceX8
	if allocs := testing.AllocsPerRun(1000, func() {
		workspace = seed
		ifmaDoubleStage2X8(&workspace)
	}); allocs != 0 {
		t.Fatalf("x8 Stage 2 allocations=%v", allocs)
	}
	benchmarkIFMADoubleStage2WorkspaceX8Sink = workspace
}

func doubleStage2TestCurrentSixLinearOps(out *[4]IFMAElementX4, input *[4]IFMAElementX4) {
	a, b, c, xy := input[0], input[1], input[2], input[3]
	var d, e, f, g, h IFMAElementX4
	c.Add(&c, &c)
	e.Add(&xy, &xy)
	d.Negate(&a)
	g.Add(&d, &b)
	f.Subtract(&g, &c)
	h.Subtract(&d, &b)
	out[0], out[1], out[2], out[3] = e, f, g, h
}

//go:noinline
func doubleStage2TestCopyWorkspace(out, input *ifmaDoubleStage2WorkspaceX4) {
	*out = *input
}

var (
	benchmarkIFMADoubleStage2WorkspaceSink ifmaDoubleStage2WorkspaceX4
	benchmarkIFMADoubleStage2ElementsSink  [4]IFMAElementX4
)

func BenchmarkIFMADoubleStage2X4(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	seed := doubleStage2TestRandomWorkspace(rand.New(rand.NewSource(0x51_d02_be4c)))
	var normalized [4]IFMAElementX4
	for slot := range normalized {
		limbs, ok := normalizeIFMAProductX4(&seed[slot])
		if !ok {
			b.Fatalf("slot=%d seed escaped raw-product domain", slot)
		}
		normalized[slot].limbs = limbs
	}

	// The in-place primitive needs a fresh 640-byte raw workspace each
	// iteration. Report that mandatory harness cost separately; the current
	// row below also value-copies four 160-byte normalized inputs before its
	// six operations.
	b.Run("control/copy-raw-workspace-640B", func(b *testing.B) {
		var workspace ifmaDoubleStage2WorkspaceX4
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			doubleStage2TestCopyWorkspace(&workspace, &seed)
		}
		benchmarkIFMADoubleStage2WorkspaceSink = workspace
	})

	b.Run("new/raw-to-u52-in-place", func(b *testing.B) {
		var workspace ifmaDoubleStage2WorkspaceX4
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			workspace = seed
			ifmaDoubleStage2X4(&workspace)
		}
		benchmarkIFMADoubleStage2WorkspaceSink = workspace
	})

	// This is the current direct-XY linear sub-DAG after four independently
	// normalized products. Its entry ABI differs from the new raw Stage 2, so
	// this comparison intentionally measures only the six linear/carry calls.
	b.Run("current/six-normalized-linear-ops", func(b *testing.B) {
		var output [4]IFMAElementX4
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			doubleStage2TestCurrentSixLinearOps(&output, &normalized)
		}
		benchmarkIFMADoubleStage2ElementsSink = output
	})
}
