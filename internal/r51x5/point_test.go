package r51x5

import (
	"bytes"
	"encoding/hex"
	"math/rand"
	"testing"

	edwardsref "github.com/Overclock-Validator/narya/internal/edwards25519"
)

var pointTestEncodings = [...]string{
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

var canonicalTorsionIndexes = [...]int{0, 1, 2, 4, 10, 11, 12, 13}

func TestPointPermissiveDecodeMatchesReference(t *testing.T) {
	for i, encodedHex := range pointTestEncodings {
		encoded, err := hex.DecodeString(encodedHex)
		if err != nil {
			t.Fatal(err)
		}
		comparePointDecode(t, i, encoded)
	}

	rng := rand.New(rand.NewSource(0x5135dec0de))
	for i := 0; i < 1024; i++ {
		var encoded [32]byte
		_, _ = rng.Read(encoded[:])
		comparePointDecode(t, len(pointTestEncodings)+i, encoded[:])
	}

	identity := NewIdentityPoint()
	unchanged := *identity
	if _, err := unchanged.SetBytes(make([]byte, 31)); err == nil {
		t.Fatal("accepted a short point encoding")
	}
	if unchanged.Equal(identity) != 1 {
		t.Fatal("length failure changed the scalar receiver")
	}
}

func comparePointDecode(t *testing.T, index int, encoded []byte) {
	t.Helper()
	got, gotErr := new(Point).SetBytes(encoded)
	want, wantErr := new(edwardsref.Point).SetBytes(encoded)
	if (gotErr != nil) != (wantErr != nil) {
		t.Fatalf("input %d decode mismatch: r51x5=%v reference=%v\nencoding=%x", index, gotErr, wantErr, encoded)
	}
	if gotErr != nil {
		return
	}
	gotBytes := got.Bytes()
	if !bytes.Equal(gotBytes[:], want.Bytes()) {
		t.Fatalf("input %d canonical encoding mismatch\ngot  %x\nwant %x", index, gotBytes, want.Bytes())
	}
	assertScalarPointInvariant(t, "decoded", got)
}

func TestPointX8GroupOperationsMatchReference(t *testing.T) {
	rng := rand.New(rand.NewSource(0x518518))
	torsion := referenceTorsionPoints(t)
	for round := 0; round < 20; round++ {
		var aRefs, bRefs [X8Lanes]*edwardsref.Point
		var aBytes, bBytes [X8Lanes][32]byte
		for lane := 0; lane < X8Lanes; lane++ {
			aRefs[lane] = randomMixedReferencePoint(t, rng, torsion[lane])
			bRefs[lane] = randomMixedReferencePoint(t, rng, torsion[(lane+3)%X8Lanes])
			copy(aBytes[lane][:], aRefs[lane].Bytes())
			copy(bBytes[lane][:], bRefs[lane].Bytes())
		}

		var a, b PointX8
		if mask := a.SetBytes(&aBytes); mask != 0xff {
			t.Fatalf("round %d: A valid mask=%02x", round, mask)
		}
		if mask := b.SetBytes(&bBytes); mask != 0xff {
			t.Fatalf("round %d: B valid mask=%02x", round, mask)
		}
		assertPointX8Matches(t, "decode A", &a, &aRefs)
		assertPointX8Matches(t, "decode B", &b, &bRefs)

		var addRefs, subRefs, doubleRefs, negRefs [X8Lanes]*edwardsref.Point
		for lane := 0; lane < X8Lanes; lane++ {
			addRefs[lane] = new(edwardsref.Point).Add(aRefs[lane], bRefs[lane])
			subRefs[lane] = new(edwardsref.Point).Subtract(aRefs[lane], bRefs[lane])
			doubleRefs[lane] = new(edwardsref.Point).Add(aRefs[lane], aRefs[lane])
			negRefs[lane] = new(edwardsref.Point).Negate(aRefs[lane])
		}

		var add, sub, doubled, negated PointX8
		add.Add(&a, &b)
		sub.Subtract(&a, &b)
		doubled.Double(&a)
		negated.Negate(&a)
		assertPointX8Matches(t, "add", &add, &addRefs)
		assertPointX8Matches(t, "subtract", &sub, &subRefs)
		assertPointX8Matches(t, "double", &doubled, &doubleRefs)
		assertPointX8Matches(t, "negate", &negated, &negRefs)

		alias := a
		alias.Add(&alias, &b)
		if alias.Equal(&add) != 0xff {
			t.Fatalf("round %d: aliased add mismatch mask=%02x", round, alias.Equal(&add))
		}
		alias = a
		alias.Double(&alias)
		if alias.Equal(&doubled) != 0xff {
			t.Fatalf("round %d: aliased double mismatch mask=%02x", round, alias.Equal(&doubled))
		}

		points := a.Points()
		var repacked PointX8
		repacked.SetPoints(&points)
		if repacked.Equal(&a) != 0xff {
			t.Fatalf("round %d: pack/unpack mismatch mask=%02x", round, repacked.Equal(&a))
		}
	}
}

func TestPointX4GroupOperationsMatchReference(t *testing.T) {
	rng := rand.New(rand.NewSource(0x514514))
	torsion := referenceTorsionPoints(t)
	for round := 0; round < 20; round++ {
		var aRefs, bRefs [X4Lanes]*edwardsref.Point
		var aBytes, bBytes [X4Lanes][32]byte
		for lane := 0; lane < X4Lanes; lane++ {
			torsionIndex := (round*X4Lanes + lane) % len(torsion)
			aRefs[lane] = randomMixedReferencePoint(t, rng, torsion[torsionIndex])
			bRefs[lane] = randomMixedReferencePoint(t, rng, torsion[(torsionIndex+5)%len(torsion)])
			copy(aBytes[lane][:], aRefs[lane].Bytes())
			copy(bBytes[lane][:], bRefs[lane].Bytes())
		}

		var a, b PointX4
		if mask := a.SetBytes(&aBytes); mask != 0x0f {
			t.Fatalf("round %d: A valid mask=%02x", round, mask)
		}
		if mask := b.SetBytes(&bBytes); mask != 0x0f {
			t.Fatalf("round %d: B valid mask=%02x", round, mask)
		}

		var addRefs, subRefs, doubleRefs, negRefs [X4Lanes]*edwardsref.Point
		for lane := 0; lane < X4Lanes; lane++ {
			addRefs[lane] = new(edwardsref.Point).Add(aRefs[lane], bRefs[lane])
			subRefs[lane] = new(edwardsref.Point).Subtract(aRefs[lane], bRefs[lane])
			doubleRefs[lane] = new(edwardsref.Point).Add(aRefs[lane], aRefs[lane])
			negRefs[lane] = new(edwardsref.Point).Negate(aRefs[lane])
		}

		var add, sub, doubled, negated PointX4
		add.Add(&a, &b)
		sub.Subtract(&a, &b)
		doubled.Double(&a)
		negated.Negate(&a)
		assertPointX4Matches(t, "add", &add, &addRefs)
		assertPointX4Matches(t, "subtract", &sub, &subRefs)
		assertPointX4Matches(t, "double", &doubled, &doubleRefs)
		assertPointX4Matches(t, "negate", &negated, &negRefs)

		alias := a
		alias.Subtract(&alias, &b)
		if alias.Equal(&sub) != 0x0f {
			t.Fatalf("round %d: aliased subtract mismatch mask=%02x", round, alias.Equal(&sub))
		}
		points := a.Points()
		var repacked PointX4
		repacked.SetPoints(&points)
		if repacked.Equal(&a) != 0x0f {
			t.Fatalf("round %d: pack/unpack mismatch mask=%02x", round, repacked.Equal(&a))
		}
	}
}

func TestPointProjectiveEqualityAndIdentityMasks(t *testing.T) {
	rng := rand.New(rand.NewSource(0x51e9))
	torsion := referenceTorsionPoints(t)
	var refs [X8Lanes]*edwardsref.Point
	var encodings [X8Lanes][32]byte
	for lane := 0; lane < X8Lanes; lane++ {
		refs[lane] = randomMixedReferencePoint(t, rng, torsion[lane])
		copy(encodings[lane][:], refs[lane].Bytes())
	}
	var affine PointX8
	if affine.SetBytes(&encodings) != 0xff {
		t.Fatal("failed to decode equality fixtures")
	}

	projectivePoints := affine.Points()
	for lane := range projectivePoints {
		lambda := randomNonUnitElement(t, rng)
		projectivePoints[lane].X.Multiply(&projectivePoints[lane].X, &lambda)
		projectivePoints[lane].Y.Multiply(&projectivePoints[lane].Y, &lambda)
		projectivePoints[lane].Z.Multiply(&projectivePoints[lane].Z, &lambda)
		projectivePoints[lane].T.Multiply(&projectivePoints[lane].T, &lambda)
		assertScalarPointInvariant(t, "random projective scaling", &projectivePoints[lane])
	}
	var projective PointX8
	projective.SetPoints(&projectivePoints)
	if mask := projective.Equal(&affine); mask != 0xff {
		t.Fatalf("projective equality mask=%02x", mask)
	}
	if mask := projective.EqualAffine(&affine); mask != 0xff {
		t.Fatalf("projective/affine equality mask=%02x", mask)
	}
	compactAffine := AffinePointX8{X: affine.X, Y: affine.Y}
	if mask := projective.EqualCompactAffine(&compactAffine); mask != 0xff {
		t.Fatalf("projective/compact-affine equality mask=%02x", mask)
	}

	for lane := 0; lane < X8Lanes; lane++ {
		mutated := affine
		replacement := mutated.Lane(lane)
		replacement.X.Negate(&replacement.X)
		replacement.T.Negate(&replacement.T)
		mutated.SetLane(lane, &replacement)
		want := uint8(0xff &^ (1 << lane))
		if mask := affine.Equal(&mutated); mask != want {
			t.Fatalf("X lane %d equality mask=%02x want=%02x", lane, mask, want)
		}
		// -Q shares Q's y-coordinate, so this specifically proves that the
		// projective/affine comparator uses the X cross-product too.
		if mask := projective.EqualAffine(&mutated); mask != want {
			t.Fatalf("X lane %d projective/affine mask=%02x want=%02x", lane, mask, want)
		}
		compactMutated := AffinePointX8{X: mutated.X, Y: mutated.Y}
		if mask := projective.EqualCompactAffine(&compactMutated); mask != want {
			t.Fatalf("X lane %d projective/compact-affine mask=%02x want=%02x", lane, mask, want)
		}

		mutated = affine
		replacement = mutated.Lane(lane)
		replacement.Y.Negate(&replacement.Y)
		replacement.T.Negate(&replacement.T)
		mutated.SetLane(lane, &replacement)
		if mask := affine.Equal(&mutated); mask != want {
			t.Fatalf("Y lane %d equality mask=%02x want=%02x", lane, mask, want)
		}
		compactMutated = AffinePointX8{X: mutated.X, Y: mutated.Y}
		if mask := projective.EqualCompactAffine(&compactMutated); mask != want {
			t.Fatalf("Y lane %d projective/compact-affine mask=%02x want=%02x", lane, mask, want)
		}

		identity := NewIdentityPointX8()
		identity.SetLane(lane, &projectivePoints[lane])
		if mask := identity.IsIdentity(); mask != want {
			t.Fatalf("identity lane %d mask=%02x want=%02x", lane, mask, want)
		}
	}
	if mask := NewIdentityPointX8().IsIdentity(); mask != 0xff {
		t.Fatalf("all-identity x8 mask=%02x", mask)
	}

	// Exercise the same mask behavior in both four-lane halves.
	for half := 0; half < 2; half++ {
		var points, scaledPoints [X4Lanes]Point
		for lane := range points {
			points[lane] = affine.Lane(half*X4Lanes + lane)
			scaledPoints[lane] = projective.Lane(half*X4Lanes + lane)
		}
		var base, scaled PointX4
		base.SetPoints(&points)
		scaled.SetPoints(&scaledPoints)
		if mask := scaled.EqualAffine(&base); mask != 0x0f {
			t.Fatalf("half %d x4 projective/affine mask=%02x", half, mask)
		}
		compactBase := AffinePointX4{X: base.X, Y: base.Y}
		if mask := scaled.EqualCompactAffine(&compactBase); mask != 0x0f {
			t.Fatalf("half %d x4 projective/compact-affine mask=%02x", half, mask)
		}
		for lane := 0; lane < X4Lanes; lane++ {
			mutated := base
			replacement := mutated.Lane(lane)
			replacement.X.Negate(&replacement.X)
			replacement.T.Negate(&replacement.T)
			mutated.SetLane(lane, &replacement)
			want := uint8(0x0f &^ (1 << lane))
			if mask := base.Equal(&mutated); mask != want {
				t.Fatalf("half %d lane %d x4 equality mask=%02x want=%02x", half, lane, mask, want)
			}
			if mask := scaled.EqualAffine(&mutated); mask != want {
				t.Fatalf("half %d lane %d x4 projective/affine mask=%02x want=%02x", half, lane, mask, want)
			}
			compactMutated := AffinePointX4{X: mutated.X, Y: mutated.Y}
			if mask := scaled.EqualCompactAffine(&compactMutated); mask != want {
				t.Fatalf("half %d lane %d x4 projective/compact-affine mask=%02x want=%02x", half, lane, mask, want)
			}
			mutated = base
			replacement = mutated.Lane(lane)
			replacement.Y.Negate(&replacement.Y)
			replacement.T.Negate(&replacement.T)
			mutated.SetLane(lane, &replacement)
			compactMutated = AffinePointX4{X: mutated.X, Y: mutated.Y}
			if mask := scaled.EqualCompactAffine(&compactMutated); mask != want {
				t.Fatalf("half %d lane %d x4 compact-affine Y mask=%02x want=%02x", half, lane, mask, want)
			}
			identity := NewIdentityPointX4()
			identity.SetLane(lane, &points[lane])
			if mask := identity.IsIdentity(); mask != want {
				t.Fatalf("half %d lane %d x4 identity mask=%02x want=%02x", half, lane, mask, want)
			}
		}
	}
}

func TestPointDecodeFailureMasksEveryLane(t *testing.T) {
	bad := deterministicInvalidPointEncoding(t)
	if _, err := new(edwardsref.Point).SetBytes(bad[:]); err == nil {
		t.Fatal("invalid-mask fixture unexpectedly decodes")
	}
	generator := edwardsref.NewGeneratorPoint().Bytes()

	var valid8 [X8Lanes][32]byte
	for lane := range valid8 {
		copy(valid8[lane][:], generator)
	}
	for lane := 0; lane < X8Lanes; lane++ {
		inputs := valid8
		copy(inputs[lane][:], bad[:])
		var got PointX8
		wantValid := uint8(0xff &^ (1 << lane))
		if mask := got.SetBytes(&inputs); mask != wantValid {
			t.Fatalf("x8 invalid lane %d valid mask=%02x want=%02x", lane, mask, wantValid)
		}
		if mask := got.IsIdentity(); mask != 1<<lane {
			t.Fatalf("x8 invalid lane %d identity mask=%02x want=%02x", lane, mask, uint8(1<<lane))
		}
	}

	var valid4 [X4Lanes][32]byte
	for lane := range valid4 {
		copy(valid4[lane][:], generator)
	}
	for lane := 0; lane < X4Lanes; lane++ {
		inputs := valid4
		copy(inputs[lane][:], bad[:])
		var got PointX4
		wantValid := uint8(0x0f &^ (1 << lane))
		if mask := got.SetBytes(&inputs); mask != wantValid {
			t.Fatalf("x4 invalid lane %d valid mask=%02x want=%02x", lane, mask, wantValid)
		}
		if mask := got.IsIdentity(); mask != 1<<lane {
			t.Fatalf("x4 invalid lane %d identity mask=%02x want=%02x", lane, mask, uint8(1<<lane))
		}
	}
}

func deterministicInvalidPointEncoding(t *testing.T) [32]byte {
	t.Helper()
	rng := rand.New(rand.NewSource(0x51bad))
	for attempt := 0; attempt < 1024; attempt++ {
		var encoded [32]byte
		_, _ = rng.Read(encoded[:])
		if _, err := new(edwardsref.Point).SetBytes(encoded[:]); err != nil {
			return encoded
		}
	}
	t.Fatal("failed to generate a deterministic invalid point encoding")
	return [32]byte{}
}

func referenceTorsionPoints(t *testing.T) [X8Lanes]*edwardsref.Point {
	t.Helper()
	var points [X8Lanes]*edwardsref.Point
	for lane, index := range canonicalTorsionIndexes {
		encoded, err := hex.DecodeString(pointTestEncodings[index])
		if err != nil {
			t.Fatal(err)
		}
		points[lane], err = new(edwardsref.Point).SetBytes(encoded)
		if err != nil {
			t.Fatalf("torsion lane %d: %v", lane, err)
		}
	}
	return points
}

func randomMixedReferencePoint(t *testing.T, rng *rand.Rand, torsion *edwardsref.Point) *edwardsref.Point {
	t.Helper()
	var wide [64]byte
	_, _ = rng.Read(wide[:])
	scalar, err := edwardsref.NewScalar().SetUniformBytes(wide[:])
	if err != nil {
		t.Fatal(err)
	}
	prime := new(edwardsref.Point).ScalarBaseMult(scalar)
	return new(edwardsref.Point).Add(prime, torsion)
}

func randomNonUnitElement(t *testing.T, rng *rand.Rand) Element {
	t.Helper()
	var one Element
	one.One()
	for {
		var encoded [32]byte
		_, _ = rng.Read(encoded[:])
		var element Element
		_, _ = element.SetBytes(encoded[:])
		if element.IsZero() == 0 && element.Equal(&one) == 0 {
			return element
		}
	}
}

func assertPointX8Matches(t *testing.T, label string, got *PointX8, want *[X8Lanes]*edwardsref.Point) {
	t.Helper()
	encoded := got.Bytes()
	for lane := 0; lane < X8Lanes; lane++ {
		if !bytes.Equal(encoded[lane][:], want[lane].Bytes()) {
			t.Fatalf("%s lane %d mismatch\ngot  %x\nwant %x", label, lane, encoded[lane], want[lane].Bytes())
		}
		point := got.Lane(lane)
		assertScalarPointInvariant(t, label, &point)
	}
}

func assertPointX4Matches(t *testing.T, label string, got *PointX4, want *[X4Lanes]*edwardsref.Point) {
	t.Helper()
	encoded := got.Bytes()
	for lane := 0; lane < X4Lanes; lane++ {
		if !bytes.Equal(encoded[lane][:], want[lane].Bytes()) {
			t.Fatalf("%s lane %d mismatch\ngot  %x\nwant %x", label, lane, encoded[lane], want[lane].Bytes())
		}
		point := got.Lane(lane)
		assertScalarPointInvariant(t, label, &point)
	}
}

func assertScalarPointInvariant(t *testing.T, label string, p *Point) {
	t.Helper()
	if !IsReduced(p.X.Limbs()) || !IsReduced(p.Y.Limbs()) || !IsReduced(p.Z.Limbs()) || !IsReduced(p.T.Limbs()) {
		t.Fatalf("%s: non-reduced point coordinate", label)
	}
	if p.Z.IsZero() != 0 {
		t.Fatalf("%s: zero projective denominator", label)
	}
	var xy, tz Element
	xy.Multiply(&p.X, &p.Y)
	tz.Multiply(&p.T, &p.Z)
	if xy.Equal(&tz) != 1 {
		t.Fatalf("%s: extended-coordinate T invariant failed", label)
	}
}
