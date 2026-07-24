package r43x6

import (
	"encoding/hex"
	"math/rand"
	"testing"

	edwardsref "github.com/Overclock-Validator/narya/internal/edwards25519"
)

var pointEdgeEncodings = [...]string{
	"0000000000000000000000000000000000000000000000000000000000000000",
	"0000000000000000000000000000000000000000000000000000000000000080",
	"0100000000000000000000000000000000000000000000000000000000000000",
	"0100000000000000000000000000000000000000000000000000000000000080",
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
	"f3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
}

func compareDecode(t *testing.T, label string, encoded []byte) bool {
	t.Helper()
	got, gotErr := new(Point).SetBytes(encoded)
	want, wantErr := new(edwardsref.Point).SetBytes(encoded)
	if (gotErr != nil) != (wantErr != nil) {
		t.Fatalf("%s: decode result differs: r43x6=%v reference=%v\nencoding=%x", label, gotErr, wantErr, encoded)
	}
	if gotErr != nil {
		return false
	}
	gotBytes := got.Bytes()
	if wantBytes := want.Bytes(); string(gotBytes[:]) != string(wantBytes) {
		t.Fatalf("%s: canonical encoding differs\ngot  %x\nwant %x\ninput %x", label, gotBytes, wantBytes, encoded)
	}
	if got.EqualAffine(got) != 1 || !pointCoordinatesReduced(got) {
		t.Fatalf("%s: decoded point invariant failed", label)
	}
	return true
}

func TestPermissivePointDecodeMatchesReference(t *testing.T) {
	for _, encodedHex := range pointEdgeEncodings {
		encoded, err := hex.DecodeString(encodedHex)
		if err != nil {
			t.Fatal(err)
		}
		compareDecode(t, "edge", encoded)
	}
	for _, length := range []int{0, 1, 31, 33, 64} {
		compareDecode(t, "wrong length", make([]byte, length))
	}

	// Explicitly lock down the permissive negative-zero behavior.
	negativeZero := make([]byte, 32)
	negativeZero[0] = 1
	negativeZero[31] = 0x80
	p, err := new(Point).SetBytes(negativeZero)
	if err != nil {
		t.Fatalf("negative zero rejected: %v", err)
	}
	canonical := p.Bytes()
	if canonical[31]&0x80 != 0 {
		t.Fatalf("negative zero re-encoded with sign bit set: %x", canonical)
	}

	rng := rand.New(rand.NewSource(0xdec0de))
	var valid, invalid int
	for i := 0; i < 2048; i++ {
		encoded := make([]byte, 32)
		_, _ = rng.Read(encoded)
		if compareDecode(t, "random", encoded) {
			valid++
		} else {
			invalid++
		}
	}
	if valid < 500 || invalid < 500 {
		t.Fatalf("decode differential mix was unbalanced: valid=%d invalid=%d", valid, invalid)
	}
}

func TestPointGroupOperationsMatchReference(t *testing.T) {
	rng := rand.New(rand.NewSource(0xadd))
	torsion := mustReferencePoint(t, pointEdgeEncodings[10])

	for round := 0; round < 192; round++ {
		aScalarRef, _ := randomScalarPair(t, rng)
		bScalarRef, _ := randomScalarPair(t, rng)
		aRef := new(edwardsref.Point).ScalarBaseMult(aScalarRef)
		bRef := new(edwardsref.Point).ScalarBaseMult(bScalarRef)
		if round%3 == 0 {
			aRef.Add(aRef, torsion)
		}
		if round%5 == 0 {
			bRef.Add(bRef, torsion)
		}

		a := mustPoint(t, aRef.Bytes())
		b := mustPoint(t, bRef.Bytes())

		var got Point
		got.Add(a, b)
		want := new(edwardsref.Point).Add(aRef, bRef)
		assertPointMatches(t, "add", &got, want)

		got.Subtract(a, b)
		want.Subtract(aRef, bRef)
		assertPointMatches(t, "subtract", &got, want)

		got.Negate(a)
		want.Negate(aRef)
		assertPointMatches(t, "negate", &got, want)

		got.Double(a)
		want.Add(aRef, aRef)
		assertPointMatches(t, "double", &got, want)

		got.MultByCofactor(a)
		want.MultByCofactor(aRef)
		assertPointMatches(t, "cofactor", &got, want)

		if gotEqual, wantEqual := a.Equal(b), aRef.Equal(bRef); gotEqual != wantEqual {
			t.Fatalf("round %d: equality got=%d want=%d", round, gotEqual, wantEqual)
		}

		lambda, _ := randomElement(t, rng)
		var one Element
		one.One()
		if lambda.IsZero() == 1 || lambda.Equal(&one) == 1 {
			lambda.Add(&one, &one)
		}
		scaled := *a
		scaled.X.Multiply(&a.X, &lambda)
		scaled.Y.Multiply(&a.Y, &lambda)
		scaled.Z.Multiply(&a.Z, &lambda)
		scaled.T.Multiply(&a.T, &lambda)
		if scaled.Equal(a) != 1 || scaled.EqualAffine(a) != 1 {
			t.Fatalf("round %d: projective scaling changed equality", round)
		}
		negA := new(Point).Negate(a)
		if scaled.EqualAffine(negA) != 0 {
			t.Fatalf("round %d: affine equality ignored X", round)
		}
		sameXNegY := *a
		sameXNegY.Y.Negate(&a.Y)
		sameXNegY.T.Negate(&a.T)
		if scaled.EqualAffine(&sameXNegY) != 0 {
			t.Fatalf("round %d: affine equality ignored Y", round)
		}
	}
}

func TestDoubleScalarBaseMultMatchesReference(t *testing.T) {
	rng := rand.New(rand.NewSource(0xd5))
	torsion := mustReferencePoint(t, pointEdgeEncodings[10])

	for round := 0; round < 64; round++ {
		seedRef, _ := randomScalarPair(t, rng)
		aRef := new(edwardsref.Point).ScalarBaseMult(seedRef)
		if round%2 == 0 {
			aRef.Add(aRef, torsion)
		}
		a := mustPoint(t, aRef.Bytes())
		aScalarRef, aScalar := randomScalarPair(t, rng)
		bScalarRef, bScalar := randomScalarPair(t, rng)

		var got Point
		got.VarTimeDoubleScalarBaseMult(aScalar, a, bScalar)
		want := new(edwardsref.Point).VarTimeDoubleScalarBaseMult(aScalarRef, aRef, bScalarRef)
		assertPointMatches(t, "double scalar", &got, want)

		got.VarTimeVerifyMult(bScalar, aScalar, a)
		minusA := new(edwardsref.Point).Negate(aRef)
		want.VarTimeDoubleScalarBaseMult(aScalarRef, minusA, bScalarRef)
		assertPointMatches(t, "verify mult", &got, want)
	}

	// Small-order variable bases and zero scalars are valid group inputs.
	for _, encodedHex := range pointEdgeEncodings[:14] {
		refA := mustReferencePoint(t, encodedHex)
		a := mustPoint(t, refA.Bytes())
		var zero Scalar
		var got Point
		got.VarTimeDoubleScalarBaseMult(&zero, a, &zero)
		if got.IsIdentity() != 1 {
			t.Fatalf("zero DSM was not identity for A=%s", encodedHex)
		}
	}
}

func TestScalarCanonicalEncoding(t *testing.T) {
	var s Scalar
	order := scalarOrder
	if _, err := s.SetCanonicalBytes(order[:]); err == nil {
		t.Fatal("accepted the group order as a canonical scalar")
	}
	orderMinusOne := order
	for i := 0; i < len(orderMinusOne); i++ {
		if orderMinusOne[i] != 0 {
			orderMinusOne[i]--
			break
		}
		orderMinusOne[i] = 0xff
	}
	if _, err := s.SetCanonicalBytes(orderMinusOne[:]); err != nil {
		t.Fatalf("rejected order-1: %v", err)
	}
	for _, length := range []int{0, 31, 33} {
		if _, err := s.SetCanonicalBytes(make([]byte, length)); err == nil {
			t.Fatalf("accepted scalar length %d", length)
		}
	}
}

func randomScalarPair(t *testing.T, rng *rand.Rand) (*edwardsref.Scalar, *Scalar) {
	t.Helper()
	var wide [64]byte
	_, _ = rng.Read(wide[:])
	ref, err := edwardsref.NewScalar().SetUniformBytes(wide[:])
	if err != nil {
		t.Fatal(err)
	}
	s, err := new(Scalar).SetCanonicalBytes(ref.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return ref, s
}

func mustReferencePoint(t *testing.T, encodedHex string) *edwardsref.Point {
	t.Helper()
	encoded, err := hex.DecodeString(encodedHex)
	if err != nil {
		t.Fatal(err)
	}
	p, err := new(edwardsref.Point).SetBytes(encoded)
	if err != nil {
		t.Fatalf("reference rejected %s: %v", encodedHex, err)
	}
	return p
}

func mustPoint(t *testing.T, encoded []byte) *Point {
	t.Helper()
	p, err := new(Point).SetBytes(encoded)
	if err != nil {
		t.Fatalf("r43x6 rejected point %x: %v", encoded, err)
	}
	return p
}

func assertPointMatches(t *testing.T, label string, got *Point, want *edwardsref.Point) {
	t.Helper()
	gotBytes := got.Bytes()
	wantBytes := want.Bytes()
	if string(gotBytes[:]) != string(wantBytes) {
		t.Fatalf("%s mismatch\ngot  %x\nwant %x", label, gotBytes, wantBytes)
	}
	if !pointCoordinatesReduced(got) {
		t.Fatalf("%s produced a non-reduced coordinate", label)
	}
}

func pointCoordinatesReduced(p *Point) bool {
	return IsReduced(p.X.Limbs()) && IsReduced(p.Y.Limbs()) &&
		IsReduced(p.Z.Limbs()) && IsReduced(p.T.Limbs())
}
