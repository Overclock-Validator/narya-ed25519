package r51x5

import (
	"encoding/hex"
	"math/rand"
	"testing"
)

func quadPointAddCachedHardwareX4(out, point *quadPackedPointX4, cached *quadPackedCachedPointX4) error {
	if !ExperimentalIFMAAvailable() {
		return ErrIFMAUnavailable
	}
	return quadPointAddCachedHardwareUncheckedX4(out, point, cached)
}

func TestExperimentalCoordinateParallelCachedAddX4(t *testing.T) {
	rng := rand.New(rand.NewSource(0x514addca))
	torsion := referenceTorsionPoints(t)
	for round := 0; round < 64; round++ {
		accRef := randomMixedReferencePoint(t, rng, torsion[round%len(torsion)])
		addRef := randomMixedReferencePoint(t, rng, torsion[(round+3)%len(torsion)])
		var accumulator, addend Point
		if _, err := accumulator.SetBytes(accRef.Bytes()); err != nil {
			t.Fatalf("round %d: decode accumulator: %v", round, err)
		}
		if _, err := addend.SetBytes(addRef.Bytes()); err != nil {
			t.Fatalf("round %d: decode addend: %v", round, err)
		}
		scaleProjectivePointX4Test(&accumulator, randomNonUnitElement(t, rng))
		scaleProjectivePointX4Test(&addend, randomNonUnitElement(t, rng))

		for _, negative := range []bool{false, true} {
			signedAddend := signedPointX4Test(&addend, negative)
			accumulatorPoints := [X4Lanes]Point{
				accumulator,
				*NewIdentityPoint(),
				*NewIdentityPoint(),
				*NewIdentityPoint(),
			}
			addendPoints := [X4Lanes]Point{
				signedAddend,
				*NewIdentityPoint(),
				*NewIdentityPoint(),
				*NewIdentityPoint(),
			}
			var want, addendX4 PointX4
			want.SetPoints(&accumulatorPoints)
			addendX4.SetPoints(&addendPoints)
			model := new(quadPackedPointX4).setReduced(&accumulator)
			hardware := *model
			cached := new(quadPackedCachedPointX4).setReduced(&addend, negative)

			chain := 1 + round%17
			for step := 0; step < chain; step++ {
				want.Add(&want, &addendX4)
				if err := quadPointAddCachedModelX4(model, model, cached); err != nil {
					t.Fatalf("round %d negative=%v step %d: model: %v", round, negative, step, err)
				}
				assertQuadPackedPointX4(t, "cached-add model", round, step, model, &want)
				if ExperimentalIFMAAvailable() {
					if err := quadPointAddCachedHardwareX4(&hardware, &hardware, cached); err != nil {
						t.Fatalf("round %d negative=%v step %d: hardware: %v", round, negative, step, err)
					}
					assertQuadPackedPointX4(t, "cached-add hardware", round, step, &hardware, &want)
				}
			}
		}
	}
}

func TestExperimentalCoordinateParallelCachedAddX4TorsionEdges(t *testing.T) {
	indexes := []int{2, 4, 0, 1}
	for _, accumulatorIndex := range indexes {
		for _, addendIndex := range indexes {
			accumulator := decodePointX4TestHex(t, pointTestEncodings[accumulatorIndex])
			addend := decodePointX4TestHex(t, pointTestEncodings[addendIndex])
			for _, negative := range []bool{false, true} {
				signedAddend := signedPointX4Test(&addend, negative)
				accumulatorPoints := [X4Lanes]Point{accumulator, *NewIdentityPoint(), *NewIdentityPoint(), *NewIdentityPoint()}
				addendPoints := [X4Lanes]Point{signedAddend, *NewIdentityPoint(), *NewIdentityPoint(), *NewIdentityPoint()}
				var want, addendX4 PointX4
				want.SetPoints(&accumulatorPoints)
				addendX4.SetPoints(&addendPoints)
				want.Add(&want, &addendX4)

				model := new(quadPackedPointX4).setReduced(&accumulator)
				cached := new(quadPackedCachedPointX4).setReduced(&addend, negative)
				if err := quadPointAddCachedModelX4(model, model, cached); err != nil {
					t.Fatal(err)
				}
				assertQuadPackedPointX4(t, "cached torsion model", accumulatorIndex, addendIndex, model, &want)
				if ExperimentalIFMAAvailable() {
					hardware := new(quadPackedPointX4).setReduced(&accumulator)
					if err := quadPointAddCachedHardwareX4(hardware, hardware, cached); err != nil {
						t.Fatal(err)
					}
					assertQuadPackedPointX4(t, "cached torsion hardware", accumulatorIndex, addendIndex, hardware, &want)
				}
			}
		}
	}
}

func TestExperimentalCoordinateParallelCachedAddX4RangeEnvelope(t *testing.T) {
	var point quadPackedPointX4
	var cached quadPackedCachedPointX4
	for limb := range point.coordinates.limbs {
		for lane := range point.coordinates.limbs[limb] {
			point.coordinates.limbs[limb][lane] = ifmaComposableLimbLimit - 1
			cached.coordinates.limbs[limb][lane] = ifmaComposableLimbLimit - 1
		}
	}
	var pointOperand IFMAElementX4
	quadCachedAddFirstOperandX4(&pointOperand, &point)
	if !isIFMAElementX4(&pointOperand) || !isIFMAElementX4(&cached.coordinates) {
		t.Fatal("cached-add first operands escaped u52")
	}
	var products IFMAElementX4
	if err := modelMultiplyComposableX4(&products, &pointOperand, &cached.coordinates); err != nil {
		t.Fatalf("maximum-u52 cached product: %v", err)
	}

	// Maximize the independent A/B/C/D boundary to prove B+A and the biased
	// subtractions are normalized safely before the second multiply.
	for limb := range products.limbs {
		for lane := range products.limbs[limb] {
			products.limbs[limb][lane] = ifmaComposableLimbLimit - 1
		}
	}
	var left, right IFMAElementX4
	quadCachedAddFinalOperandsX4(&left, &right, &products)
	if !isIFMAElementX4(&left) || !isIFMAElementX4(&right) {
		t.Fatal("cached-add final operands escaped u52")
	}
	var result IFMAElementX4
	if err := modelMultiplyComposableX4(&result, &left, &right); err != nil {
		t.Fatalf("maximum-u52 cached final product: %v", err)
	}
	if !isIFMAElementX4(&result) {
		t.Fatal("cached-add result escaped u52")
	}
}

func TestIFMAQuadCachedAddFinalOperandsX4MatchesPortable(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		return
	}

	inputs := make([]IFMAElementX4, 0, 1026)
	inputs = append(inputs, IFMAElementX4{})
	var maximum IFMAElementX4
	for limb := range maximum.limbs {
		for lane := range maximum.limbs[limb] {
			maximum.limbs[limb][lane] = ifmaComposableLimbLimit - 1
		}
	}
	inputs = append(inputs, maximum)
	rng := rand.New(rand.NewSource(0x514ca5ed))
	for sample := 0; sample < 1024; sample++ {
		var input IFMAElementX4
		for limb := range input.limbs {
			for lane := range input.limbs[limb] {
				input.limbs[limb][lane] = rng.Uint64() & (ifmaComposableLimbLimit - 1)
			}
		}
		inputs = append(inputs, input)
	}

	for index := range inputs {
		input := inputs[index]
		var wantLeft, wantRight IFMAElementX4
		quadCachedAddFinalOperandsX4(&wantLeft, &wantRight, &input)

		var gotLeft, gotRight IFMAElementX4
		ifmaQuadCachedAddFinalOperandsUncheckedX4(&gotLeft.limbs, &gotRight.limbs, &input.limbs)
		if gotLeft != wantLeft || gotRight != wantRight {
			t.Fatalf("input %d: native packed cached-add Stage 2 differs from portable oracle", index)
		}

		aliasedLeft := input
		var aliasRight IFMAElementX4
		ifmaQuadCachedAddFinalOperandsUncheckedX4(&aliasedLeft.limbs, &aliasRight.limbs, &aliasedLeft.limbs)
		if aliasedLeft != wantLeft || aliasRight != wantRight {
			t.Fatalf("input %d: input/left alias differs from portable oracle", index)
		}

		aliasedRight := input
		var aliasLeft IFMAElementX4
		ifmaQuadCachedAddFinalOperandsUncheckedX4(&aliasLeft.limbs, &aliasedRight.limbs, &aliasedRight.limbs)
		if aliasLeft != wantLeft || aliasedRight != wantRight {
			t.Fatalf("input %d: input/right alias differs from portable oracle", index)
		}
	}
}

func TestIFMAQuadCachedAddFinalOperandsX4ZeroAllocations(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		return
	}
	var input, left, right IFMAElementX4
	for limb := range input.limbs {
		for lane := range input.limbs[limb] {
			input.limbs[limb][lane] = uint64(1 + limb*X4Lanes + lane)
		}
	}
	if allocs := testing.AllocsPerRun(100, func() {
		ifmaQuadCachedAddFinalOperandsUncheckedX4(&left.limbs, &right.limbs, &input.limbs)
	}); allocs != 0 {
		t.Fatalf("allocations=%v", allocs)
	}
}

func TestExperimentalCoordinateParallelCachedAddWorkspaceX4IgnoresPriorScratch(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		return
	}

	accumulator := decodePointX4TestHex(t, pointTestEncodings[6])
	addend := decodePointX4TestHex(t, pointTestEncodings[7])
	clean := new(quadPackedPointX4).setReduced(&accumulator)
	poisoned := *clean
	cached := new(quadPackedCachedPointX4).setReduced(&addend, false)
	var cleanWorkspace, poisonedWorkspace quadPointAddCachedWorkspaceX4
	for limb := range poisonedWorkspace.pointOperand.limbs {
		for lane := range poisonedWorkspace.pointOperand.limbs[limb] {
			value := uint64(0x5a5a_0000_0000_0000 | uint64(limb<<8|lane))
			poisonedWorkspace.pointOperand.limbs[limb][lane] = value
			poisonedWorkspace.products.limbs[limb][lane] = ^value
			poisonedWorkspace.left.limbs[limb][lane] = value ^ 0x1111
			poisonedWorkspace.right.limbs[limb][lane] = value ^ 0x2222
		}
	}

	for step := 0; step < 32; step++ {
		if err := quadPointAddCachedHardwareWorkspaceUncheckedX4(clean, clean, cached, &cleanWorkspace); err != nil {
			t.Fatalf("step %d clean: %v", step, err)
		}
		if err := quadPointAddCachedHardwareWorkspaceUncheckedX4(&poisoned, &poisoned, cached, &poisonedWorkspace); err != nil {
			t.Fatalf("step %d poisoned: %v", step, err)
		}
		if poisoned.coordinates != clean.coordinates {
			t.Fatalf("step %d: prior scratch changed the cached-add result", step)
		}
	}
}

func scaleProjectivePointX4Test(point *Point, lambda Element) {
	point.X.Multiply(&point.X, &lambda)
	point.Y.Multiply(&point.Y, &lambda)
	point.T.Multiply(&point.T, &lambda)
	point.Z.Multiply(&point.Z, &lambda)
}

func signedPointX4Test(point *Point, negative bool) Point {
	result := *point
	if negative {
		result.X.Negate(&result.X)
		result.T.Negate(&result.T)
	}
	return result
}

func decodePointX4TestHex(t *testing.T, encodedHex string) Point {
	t.Helper()
	encoded, err := hex.DecodeString(encodedHex)
	if err != nil {
		t.Fatal(err)
	}
	var point Point
	if _, err := point.SetBytes(encoded); err != nil {
		t.Fatal(err)
	}
	return point
}

var (
	benchmarkQuadPackedCachedAddX4Sink quadPackedPointX4
	benchmarkQuadLaneCachedAddX4Sink   IFMAPointX4
)

func BenchmarkExperimentalCoordinateParallelCachedAddX4(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skip("AVX-512 IFMA is unavailable")
	}

	var encoded [32]byte
	encoded[0] = 0x58
	for i := 1; i < len(encoded); i++ {
		encoded[i] = 0x66
	}
	var accumulator Point
	if _, err := accumulator.SetBytes(encoded[:]); err != nil {
		b.Fatal(err)
	}
	points := [X4Lanes]Point{accumulator, *NewIdentityPoint(), *NewIdentityPoint(), *NewIdentityPoint()}
	var doubled PointX4
	doubled.SetPoints(&points)
	doubled.Double(&doubled)
	addend := doubled.Lane(0)

	var accumulatorScaleBytes, addendScaleBytes [32]byte
	accumulatorScaleBytes[0] = 7
	addendScaleBytes[0] = 11
	var accumulatorScale, addendScale Element
	if _, err := accumulatorScale.SetBytes(accumulatorScaleBytes[:]); err != nil {
		b.Fatal(err)
	}
	if _, err := addendScale.SetBytes(addendScaleBytes[:]); err != nil {
		b.Fatal(err)
	}
	scaleProjectivePointX4Test(&accumulator, accumulatorScale)
	scaleProjectivePointX4Test(&addend, addendScale)
	cached := new(quadPackedCachedPointX4).setReduced(&addend, false)

	b.Run("chained/quad-packed-cached", func(b *testing.B) {
		state := new(quadPackedPointX4).setReduced(&accumulator)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := quadPointAddCachedHardwareUncheckedX4(state, state, cached); err != nil {
				b.Fatal(err)
			}
		}
		benchmarkQuadPackedCachedAddX4Sink = *state
	})

	b.Run("chained/quad-packed-cached-reused-workspace", func(b *testing.B) {
		state := new(quadPackedPointX4).setReduced(&accumulator)
		var workspace quadPointAddCachedWorkspaceX4
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := quadPointAddCachedHardwareWorkspaceUncheckedX4(state, state, cached, &workspace); err != nil {
				b.Fatal(err)
			}
		}
		benchmarkQuadPackedCachedAddX4Sink = *state
	})

	b.Run("chained/current-one-active-lane", func(b *testing.B) {
		accumulatorPoints := [X4Lanes]Point{accumulator, *NewIdentityPoint(), *NewIdentityPoint(), *NewIdentityPoint()}
		addendPoints := [X4Lanes]Point{addend, *NewIdentityPoint(), *NewIdentityPoint(), *NewIdentityPoint()}
		var reducedAccumulator, reducedAddend PointX4
		reducedAccumulator.SetPoints(&accumulatorPoints)
		reducedAddend.SetPoints(&addendPoints)
		var state, addendIFMA IFMAPointX4
		state.SetReduced(&reducedAccumulator)
		addendIFMA.SetReduced(&reducedAddend)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := ifmaPointAddComposableStaticX4(&state, &state, &addendIFMA); err != nil {
				b.Fatal(err)
			}
		}
		benchmarkQuadLaneCachedAddX4Sink = state
	})
}
