package r51x5

import (
	"encoding/hex"
	"math/rand"
	"testing"
)

// quadPackedCachedPointX4 is the coordinate-parallel projective cached/Niels
// representation [Y-X, Y+X, 2dT, 2Z] for one public table point. Its lanes
// line up with [Y-X, Y+X, T, Z] from a quadPackedPointX4 accumulator, producing
// [A,B,C,D] in one call to the existing four-lane field multiply.
type quadPackedCachedPointX4 struct {
	coordinates IFMAElementX4
}

func (c *quadPackedCachedPointX4) setReduced(q *Point, negative bool) *quadPackedCachedPointX4 {
	var yMinusX, yPlusX, t2D, z2 Element
	yMinusX.Subtract(&q.Y, &q.X)
	yPlusX.Add(&q.Y, &q.X)
	t2D.Multiply(&q.T, &curve2D)
	z2.Add(&q.Z, &q.Z)
	if negative {
		yMinusX, yPlusX = yPlusX, yMinusX
		t2D.Negate(&t2D)
	}
	var coordinates ElementX4
	coordinates.SetLane(0, &yMinusX)
	coordinates.SetLane(1, &yPlusX)
	coordinates.SetLane(2, &t2D)
	coordinates.SetLane(3, &z2)
	c.coordinates.SetReduced(&coordinates)
	return c
}

// quadCachedAddFirstOperandX4 normalizes [Y-X,Y+X,T,Z] in one packed pass.
// Under the generic composable-u52 contract, both Y+X and a non-negative
// representative of Y-X can exceed u52 before carrying, so this boundary
// cannot safely be only a lane copy.
func quadCachedAddFirstOperandX4(out *IFMAElementX4, point *quadPackedPointX4) {
	var raw IFMAProductX4
	for limb := range raw {
		x := point.coordinates.limbs[limb][0]
		y := point.coordinates.limbs[limb][1]
		t := point.coordinates.limbs[limb][2]
		z := point.coordinates.limbs[limb][3]
		raw[limb] = [X4Lanes]uint64{
			y + ifmaSubtractionBias(limb) - x,
			y + x,
			t,
			z,
		}
	}
	ifmaNormalizeProductUncheckedX4(&out.limbs, &raw)
}

// quadCachedAddFinalOperandsX4 converts [A,B,C,D] into one normalized
// K=[E,G,H,F], then lane-copies the final multiplicands:
//
//	E=B-A  F=D-C  G=D+C  H=B+A
//	left  = [E,G,E,F]
//	right = [F,H,H,G]
//
// B+A can exceed u52 by the composable multiplication slack, making this
// second standalone normalization independently necessary for generic-u52
// chaining.
func quadCachedAddFinalOperandsX4(left, right, products *IFMAElementX4) {
	var rawK IFMAProductX4
	for limb := range rawK {
		a := products.limbs[limb][0]
		b := products.limbs[limb][1]
		c := products.limbs[limb][2]
		d := products.limbs[limb][3]
		bias8P := 2 * ifmaSubtractionBias(limb)
		rawK[limb] = [X4Lanes]uint64{
			b + bias8P - a,
			d + c,
			b + a,
			d + bias8P - c,
		}
	}

	var k IFMAElementX4
	ifmaNormalizeProductUncheckedX4(&k.limbs, &rawK)
	for limb := range k.limbs {
		e := k.limbs[limb][0]
		g := k.limbs[limb][1]
		h := k.limbs[limb][2]
		f := k.limbs[limb][3]
		left.limbs[limb] = [X4Lanes]uint64{e, g, e, f}
		right.limbs[limb] = [X4Lanes]uint64{f, h, h, g}
	}
}

func quadPointAddCachedHardwareX4(out, point *quadPackedPointX4, cached *quadPackedCachedPointX4) error {
	if !ExperimentalIFMAAvailable() {
		return ErrIFMAUnavailable
	}
	return quadPointAddCachedHardwareUncheckedX4(out, point, cached)
}

// quadPointAddCachedHardwareUncheckedX4 is a test-only two-multiply,
// two-standalone-normalize schedule. The two normalizes are the safe minimum
// for the current generic-u52 domain; removing either requires a stronger
// range invariant than IFMAElementX4 currently promises.
func quadPointAddCachedHardwareUncheckedX4(out, point *quadPackedPointX4, cached *quadPackedCachedPointX4) error {
	var pointOperand, products, left, right IFMAElementX4
	quadCachedAddFirstOperandX4(&pointOperand, point)
	if err := ifmaMultiplyComposableUncheckedX4(&products, &pointOperand, &cached.coordinates); err != nil {
		return err
	}
	quadCachedAddFinalOperandsX4(&left, &right, &products)
	var result IFMAElementX4
	if err := ifmaMultiplyComposableUncheckedX4(&result, &left, &right); err != nil {
		return err
	}
	out.coordinates = result
	return nil
}

func quadPointAddCachedModelX4(out, point *quadPackedPointX4, cached *quadPackedCachedPointX4) error {
	var pointOperand, products, left, right IFMAElementX4
	quadCachedAddFirstOperandX4(&pointOperand, point)
	if err := modelMultiplyComposableX4(&products, &pointOperand, &cached.coordinates); err != nil {
		return err
	}
	quadCachedAddFinalOperandsX4(&left, &right, &products)
	var result IFMAElementX4
	if err := modelMultiplyComposableX4(&result, &left, &right); err != nil {
		return err
	}
	out.coordinates = result
	return nil
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
