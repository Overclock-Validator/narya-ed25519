package r51x5

import (
	"encoding/hex"
	"math/rand"
	"testing"
)

// quadPackedPointX4 is a test-only coordinate-parallel point layout. Unlike
// IFMAPointX4, whose lanes hold four independent points, its lanes hold the
// four coordinates of one point in [X, Y, T, Z] order. The field multiply ABI
// is unchanged: it still computes four independent radix-2^51 products.
type quadPackedPointX4 struct {
	coordinates IFMAElementX4
}

func (p *quadPackedPointX4) setReduced(q *Point) *quadPackedPointX4 {
	var coordinates ElementX4
	coordinates.SetLane(0, &q.X)
	coordinates.SetLane(1, &q.Y)
	coordinates.SetLane(2, &q.T)
	coordinates.SetLane(3, &q.Z)
	p.coordinates.SetReduced(&coordinates)
	return p
}

func (p *quadPackedPointX4) reduced() Point {
	coordinates := p.coordinates.Reduced()
	return Point{
		X: coordinates.Lane(0),
		Y: coordinates.Lane(1),
		T: coordinates.Lane(2),
		Z: coordinates.Lane(3),
	}
}

// quadDoubleFirstOperandsX4 permutes [X,Y,T,Z] into the operands
// U=[X,Y,Z,X] and V=[X,Y,Z,Y]. Their lane-wise product is [A,B,C,D] with
// A=X^2, B=Y^2, C=Z^2, and D=XY. T is deliberately not read: the doubling
// formula computes the new extended T coordinate from X, Y, and Z.
func quadDoubleFirstOperandsX4(u, v *IFMAElementX4, q *quadPackedPointX4) {
	for limb := range q.coordinates.limbs {
		x := q.coordinates.limbs[limb][0]
		y := q.coordinates.limbs[limb][1]
		z := q.coordinates.limbs[limb][3]
		u.limbs[limb] = [X4Lanes]uint64{x, y, z, x}
		v.limbs[limb] = [X4Lanes]uint64{x, y, z, y}
	}
}

// quadDoubleFinalOperandsX4 normalizes one packed vector
// K=[E,G,H,F], then derives the two multiplicands for the final lane-wise
// multiply with pure lane copies:
//
//	left  = [E, G, E, F]
//	right = [F, H, H, G]
//
// Their product is [X3,Y3,T3,Z3]. Eight copies of p keep every subtraction
// non-negative even for F=B-A-2*Z^2; the normalizer then returns the standard
// bounded u52 composable representation.
func quadDoubleFinalOperandsX4(left, right, products *IFMAElementX4) {
	var rawK IFMAProductX4
	for limb := range rawK {
		a := products.limbs[limb][0]
		b := products.limbs[limb][1]
		c := products.limbs[limb][2]
		d := products.limbs[limb][3]
		bias8P := 2 * ifmaSubtractionBias(limb)

		e := 2 * d
		g := b + bias8P - a
		h := bias8P - a - b
		f := b + bias8P - a - 2*c
		rawK[limb] = [X4Lanes]uint64{e, g, h, f}
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

// quadPointDoubleHardwareX4 is the minimum coordinate-parallel hardware
// prototype: two existing x4 IFMA multiplications plus one standalone packed
// normalization. It is intentionally test-only and is not wired into verifier
// dispatch.
func quadPointDoubleHardwareX4(out, q *quadPackedPointX4) error {
	if !ExperimentalIFMAAvailable() {
		return ErrIFMAUnavailable
	}
	return quadPointDoubleHardwareUncheckedX4(out, q)
}

// quadPointDoubleHardwareUncheckedX4 is the benchmarkable core used after a
// caller has gated IFMA once. This matches the existing DSM point schedule,
// which does not repeat the CPU feature check for every doubling.
func quadPointDoubleHardwareUncheckedX4(out, q *quadPackedPointX4) error {
	var u, v, products, left, right IFMAElementX4
	quadDoubleFirstOperandsX4(&u, &v, q)
	if err := ifmaMultiplyComposableUncheckedX4(&products, &u, &v); err != nil {
		return err
	}
	quadDoubleFinalOperandsX4(&left, &right, &products)
	var result IFMAElementX4
	if err := ifmaMultiplyComposableUncheckedX4(&result, &left, &right); err != nil {
		return err
	}
	out.coordinates = result
	return nil
}

// quadPointDoubleModelX4 exercises the identical packing schedule through the
// independent scalar model, so its algebra and range handling remain tested
// on machines without AVX-512 IFMA.
func quadPointDoubleModelX4(out, q *quadPackedPointX4) error {
	var u, v, products, left, right IFMAElementX4
	quadDoubleFirstOperandsX4(&u, &v, q)
	if err := modelMultiplyComposableX4(&products, &u, &v); err != nil {
		return err
	}
	quadDoubleFinalOperandsX4(&left, &right, &products)
	var result IFMAElementX4
	if err := modelMultiplyComposableX4(&result, &left, &right); err != nil {
		return err
	}
	out.coordinates = result
	return nil
}

func TestExperimentalCoordinateParallelDoubleX4(t *testing.T) {
	rng := rand.New(rand.NewSource(0x514d0b1e))
	torsion := referenceTorsionPoints(t)
	for round := 0; round < 64; round++ {
		ref := randomMixedReferencePoint(t, rng, torsion[round%len(torsion)])
		var start Point
		if _, err := start.SetBytes(ref.Bytes()); err != nil {
			t.Fatalf("round %d: decode fixture: %v", round, err)
		}

		// Exercise genuinely projective inputs rather than only the affine Z=1
		// decoder output. Scaling all four extended coordinates preserves XY=ZT.
		lambda := randomNonUnitElement(t, rng)
		start.X.Multiply(&start.X, &lambda)
		start.Y.Multiply(&start.Y, &lambda)
		start.T.Multiply(&start.T, &lambda)
		start.Z.Multiply(&start.Z, &lambda)
		assertScalarPointInvariant(t, "quad start", &start)

		points := [X4Lanes]Point{
			start,
			*NewIdentityPoint(),
			*NewIdentityPoint(),
			*NewIdentityPoint(),
		}
		var want PointX4
		want.SetPoints(&points)
		model := new(quadPackedPointX4).setReduced(&start)
		hardware := *model

		// Repeated aliasing exercises the composable output range as well as a
		// single point operation. The scalar PointX4 path is the r51 oracle.
		chain := 1 + round%19
		for step := 0; step < chain; step++ {
			want.Double(&want)
			if err := quadPointDoubleModelX4(model, model); err != nil {
				t.Fatalf("round %d step %d: model double: %v", round, step, err)
			}
			assertQuadPackedPointX4(t, "model", round, step, model, &want)

			if ExperimentalIFMAAvailable() {
				if err := quadPointDoubleHardwareX4(&hardware, &hardware); err != nil {
					t.Fatalf("round %d step %d: hardware double: %v", round, step, err)
				}
				assertQuadPackedPointX4(t, "hardware", round, step, &hardware, &want)
			}
		}
	}
}

func TestExperimentalCoordinateParallelDoubleX4TorsionEdges(t *testing.T) {
	// Identity, order two, and both order-four points stress x=0 and y=0.
	for _, index := range []int{2, 4, 0, 1} {
		encoded, err := hex.DecodeString(pointTestEncodings[index])
		if err != nil {
			t.Fatal(err)
		}
		var start Point
		if _, err := start.SetBytes(encoded); err != nil {
			t.Fatalf("fixture %d: %v", index, err)
		}

		points := [X4Lanes]Point{
			start,
			*NewIdentityPoint(),
			*NewIdentityPoint(),
			*NewIdentityPoint(),
		}
		var want PointX4
		want.SetPoints(&points)
		model := new(quadPackedPointX4).setReduced(&start)
		hardware := *model
		for step := 0; step < 8; step++ {
			want.Double(&want)
			if err := quadPointDoubleModelX4(model, model); err != nil {
				t.Fatalf("fixture %d step %d: model: %v", index, step, err)
			}
			assertQuadPackedPointX4(t, "torsion model", index, step, model, &want)
			if ExperimentalIFMAAvailable() {
				if err := quadPointDoubleHardwareX4(&hardware, &hardware); err != nil {
					t.Fatalf("fixture %d step %d: hardware: %v", index, step, err)
				}
				assertQuadPackedPointX4(t, "torsion hardware", index, step, &hardware, &want)
			}
		}
	}
}

func TestExperimentalCoordinateParallelDoubleX4IgnoresInputT(t *testing.T) {
	var encoded [32]byte
	encoded[0] = 0x58
	for i := 1; i < len(encoded); i++ {
		encoded[i] = 0x66
	}
	var start Point
	if _, err := start.SetBytes(encoded[:]); err != nil {
		t.Fatal(err)
	}

	rng := rand.New(rand.NewSource(0x514bad7))
	model := new(quadPackedPointX4).setReduced(&start)
	corruptModel := *model
	hardware := *model
	corruptHardware := *model
	for step := 0; step < 24; step++ {
		badT := randomNonUnitElement(t, rng)
		for limb := range badT.limbs {
			corruptModel.coordinates.limbs[limb][2] = badT.limbs[limb]
			corruptHardware.coordinates.limbs[limb][2] = badT.limbs[limb]
		}
		if err := quadPointDoubleModelX4(model, model); err != nil {
			t.Fatal(err)
		}
		if err := quadPointDoubleModelX4(&corruptModel, &corruptModel); err != nil {
			t.Fatal(err)
		}
		if corruptModel.coordinates != model.coordinates {
			t.Fatalf("step %d: corrupted input T changed model output", step)
		}

		if ExperimentalIFMAAvailable() {
			if err := quadPointDoubleHardwareX4(&hardware, &hardware); err != nil {
				t.Fatal(err)
			}
			if err := quadPointDoubleHardwareX4(&corruptHardware, &corruptHardware); err != nil {
				t.Fatal(err)
			}
			if corruptHardware.coordinates != hardware.coordinates {
				t.Fatalf("step %d: corrupted input T changed hardware output", step)
			}
		}
	}
}

func TestExperimentalCoordinateParallelDoubleX4RangeEnvelope(t *testing.T) {
	// The packed permutations must preserve the generic composable u52
	// contract, even at its exclusive upper bound rather than only on point
	// fixtures emitted by current formulas.
	var q quadPackedPointX4
	for limb := range q.coordinates.limbs {
		for lane := range q.coordinates.limbs[limb] {
			q.coordinates.limbs[limb][lane] = ifmaComposableLimbLimit - 1
		}
	}
	var u, v IFMAElementX4
	quadDoubleFirstOperandsX4(&u, &v, &q)
	if !isIFMAElementX4(&u) || !isIFMAElementX4(&v) {
		t.Fatal("first packed operands escaped u52")
	}

	var products IFMAElementX4
	if err := modelMultiplyComposableX4(&products, &u, &v); err != nil {
		t.Fatalf("maximum-u52 first product: %v", err)
	}
	if !isIFMAElementX4(&products) {
		t.Fatal("first packed product escaped u52")
	}

	// Independently maximize A/B/C/D before the biased E/G/H/F schedule.
	// This directly covers its unsigned-subtraction and normalizer bounds.
	for limb := range products.limbs {
		for lane := range products.limbs[limb] {
			products.limbs[limb][lane] = ifmaComposableLimbLimit - 1
		}
	}
	var left, right IFMAElementX4
	quadDoubleFinalOperandsX4(&left, &right, &products)
	if !isIFMAElementX4(&left) || !isIFMAElementX4(&right) {
		t.Fatal("final packed operands escaped u52")
	}
	var result IFMAElementX4
	if err := modelMultiplyComposableX4(&result, &left, &right); err != nil {
		t.Fatalf("maximum-u52 final product: %v", err)
	}
	if !isIFMAElementX4(&result) {
		t.Fatal("final packed product escaped u52")
	}
}

func assertQuadPackedPointX4(t *testing.T, label string, round, step int, got *quadPackedPointX4, want *PointX4) {
	t.Helper()
	gotPoint := got.reduced()
	wantPoint := want.Lane(0)
	if gotPoint.Equal(&wantPoint) != 1 {
		t.Fatalf("%s round %d step %d: packed double differs from scalar r51", label, round, step)
	}
	assertScalarPointInvariant(t, label, &gotPoint)
}

var (
	benchmarkQuadPackedPointX4Sink quadPackedPointX4
	benchmarkQuadLanePointX4Sink   IFMAPointX4
)

func BenchmarkExperimentalCoordinateParallelDoubleX4(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skip("AVX-512 IFMA is unavailable")
	}

	// Canonical Ed25519 basepoint encoding.
	var encoded [32]byte
	encoded[0] = 0x58
	for i := 1; i < len(encoded); i++ {
		encoded[i] = 0x66
	}
	var point Point
	if _, err := point.SetBytes(encoded[:]); err != nil {
		b.Fatal(err)
	}
	// Keep the benchmark input projective so it matches the DSM accumulator.
	var scaleBytes [32]byte
	scaleBytes[0] = 7
	var scale Element
	if _, err := scale.SetBytes(scaleBytes[:]); err != nil {
		b.Fatal(err)
	}
	point.X.Multiply(&point.X, &scale)
	point.Y.Multiply(&point.Y, &scale)
	point.T.Multiply(&point.T, &scale)
	point.Z.Multiply(&point.Z, &scale)

	b.Run("chained/quad-packed-xytz", func(b *testing.B) {
		state := new(quadPackedPointX4).setReduced(&point)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := quadPointDoubleHardwareUncheckedX4(state, state); err != nil {
				b.Fatal(err)
			}
		}
		benchmarkQuadPackedPointX4Sink = *state
	})

	b.Run("chained/current-one-active-lane", func(b *testing.B) {
		points := [X4Lanes]Point{
			point,
			*NewIdentityPoint(),
			*NewIdentityPoint(),
			*NewIdentityPoint(),
		}
		var reduced PointX4
		reduced.SetPoints(&points)
		var state IFMAPointX4
		state.SetReduced(&reduced)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := ifmaPointDoubleComposableStaticX4(&state, &state); err != nil {
				b.Fatal(err)
			}
		}
		benchmarkQuadLanePointX4Sink = state
	})
}
