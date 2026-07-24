package r51x5

import (
	"encoding/hex"
	"errors"
	"math/rand"
	"runtime"
	"testing"

	edwardsref "github.com/Overclock-Validator/narya/internal/edwards25519"
)

func TestExperimentalIFMAPointGate(t *testing.T) {
	if ExperimentalIFMAAvailable() {
		return
	}

	identity8 := NewIdentityPointX8()
	out8 := *identity8
	before8 := out8
	if err := ExperimentalIFMAPointAddX8(&out8, identity8, identity8); !errors.Is(err, ErrIFMAUnavailable) {
		t.Fatalf("x8 add error=%v want %v", err, ErrIFMAUnavailable)
	}
	if out8 != before8 {
		t.Fatal("unavailable x8 add changed output")
	}
	if err := ExperimentalIFMAPointDoubleX8(&out8, identity8); !errors.Is(err, ErrIFMAUnavailable) {
		t.Fatalf("x8 double error=%v want %v", err, ErrIFMAUnavailable)
	}
	if out8 != before8 {
		t.Fatal("unavailable x8 double changed output")
	}
	if mask, err := ExperimentalIFMAPointEqualAffineX8(identity8, identity8); mask != 0 || !errors.Is(err, ErrIFMAUnavailable) {
		t.Fatalf("x8 equality=(%02x,%v) want (0,%v)", mask, err, ErrIFMAUnavailable)
	}

	identity4 := NewIdentityPointX4()
	out4 := *identity4
	before4 := out4
	if err := ExperimentalIFMAPointAddX4(&out4, identity4, identity4); !errors.Is(err, ErrIFMAUnavailable) {
		t.Fatalf("x4 add error=%v want %v", err, ErrIFMAUnavailable)
	}
	if out4 != before4 {
		t.Fatal("unavailable x4 add changed output")
	}
	if err := ExperimentalIFMAPointDoubleX4(&out4, identity4); !errors.Is(err, ErrIFMAUnavailable) {
		t.Fatalf("x4 double error=%v want %v", err, ErrIFMAUnavailable)
	}
	if out4 != before4 {
		t.Fatal("unavailable x4 double changed output")
	}
	if mask, err := ExperimentalIFMAPointEqualAffineX4(identity4, identity4); mask != 0 || !errors.Is(err, ErrIFMAUnavailable) {
		t.Fatalf("x4 equality=(%02x,%v) want (0,%v)", mask, err, ErrIFMAUnavailable)
	}
}

func TestExperimentalIFMAPointOperations(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	rng := rand.New(rand.NewSource(0x51_1f4a_9017))
	torsion := referenceTorsionPoints(t)
	for round := 0; round < 128; round++ {
		var aBytes, bBytes [X8Lanes][32]byte
		for lane := 0; lane < X8Lanes; lane++ {
			aRef := randomMixedReferencePoint(t, rng, torsion[(round+lane)%X8Lanes])
			bRef := randomMixedReferencePoint(t, rng, torsion[(round+lane+3)%X8Lanes])
			copy(aBytes[lane][:], aRef.Bytes())
			copy(bBytes[lane][:], bRef.Bytes())
		}

		var affineA, affineB PointX8
		if mask := affineA.SetBytes(&aBytes); mask != 0xff {
			t.Fatalf("round %d: A valid mask=%02x", round, mask)
		}
		if mask := affineB.SetBytes(&bBytes); mask != 0xff {
			t.Fatalf("round %d: B valid mask=%02x", round, mask)
		}
		a := randomProjectiveScaleX8(t, rng, &affineA)
		b := randomProjectiveScaleX8(t, rng, &affineB)
		checkIFMAPointX8X4(t, round, &a, &b, &affineA)

		if round == 0 {
			for active := 0; active < X8Lanes; active++ {
				isolatedA := NewIdentityPointX8()
				isolatedB := NewIdentityPointX8()
				aLane, bLane := a.Lane(active), b.Lane(active)
				isolatedA.SetLane(active, &aLane)
				isolatedB.SetLane(active, &bLane)
				isolatedAffine := NewIdentityPointX8()
				affineLane := affineA.Lane(active)
				isolatedAffine.SetLane(active, &affineLane)
				checkIFMAPointX8X4(t, 10_000+active, isolatedA, isolatedB, isolatedAffine)
			}
		}
	}

	checkIFMAPointInvalidInput(t)
}

func randomProjectiveScaleX8(t *testing.T, rng *rand.Rand, affine *PointX8) PointX8 {
	t.Helper()
	points := affine.Points()
	for lane := range points {
		lambda := randomNonUnitElement(t, rng)
		points[lane].X.Multiply(&points[lane].X, &lambda)
		points[lane].Y.Multiply(&points[lane].Y, &lambda)
		points[lane].Z.Multiply(&points[lane].Z, &lambda)
		points[lane].T.Multiply(&points[lane].T, &lambda)
	}
	var out PointX8
	out.SetPoints(&points)
	return out
}

func checkIFMAPointX8X4(t *testing.T, round int, a, b, affineA *PointX8) {
	t.Helper()

	var wantAdd, wantDouble PointX8
	wantAdd.Add(a, b)
	wantDouble.Double(a)

	var gotAdd, gotDouble PointX8
	if err := ExperimentalIFMAPointAddX8(&gotAdd, a, b); err != nil {
		t.Fatalf("round %d: x8 add: %v", round, err)
	}
	if gotAdd != wantAdd {
		t.Fatalf("round %d: x8 add differs from scalar PointX8", round)
	}
	if err := ExperimentalIFMAPointDoubleX8(&gotDouble, a); err != nil {
		t.Fatalf("round %d: x8 double: %v", round, err)
	}
	if gotDouble != wantDouble {
		t.Fatalf("round %d: x8 double differs from scalar PointX8", round)
	}

	aliasA := *a
	if err := ExperimentalIFMAPointAddX8(&aliasA, &aliasA, b); err != nil || aliasA != wantAdd {
		t.Fatalf("round %d: x8 A-alias add err=%v", round, err)
	}
	aliasB := *b
	if err := ExperimentalIFMAPointAddX8(&aliasB, a, &aliasB); err != nil || aliasB != wantAdd {
		t.Fatalf("round %d: x8 B-alias add err=%v", round, err)
	}
	aliasDouble := *a
	if err := ExperimentalIFMAPointDoubleX8(&aliasDouble, &aliasDouble); err != nil || aliasDouble != wantDouble {
		t.Fatalf("round %d: x8 aliased double err=%v", round, err)
	}

	wantMask := a.EqualAffine(affineA)
	gotMask, err := ExperimentalIFMAPointEqualAffineX8(a, affineA)
	if err != nil || gotMask != wantMask {
		t.Fatalf("round %d: x8 affine equality=(%02x,%v) want=%02x", round, gotMask, err, wantMask)
	}

	// Mutate each affine lane independently. The scalar mask is the oracle so
	// this remains valid even for the exceptional x=0 torsion points.
	for lane := 0; lane < X8Lanes; lane++ {
		mutated := *affineA
		replacement := mutated.Lane(lane)
		replacement.X.Negate(&replacement.X)
		replacement.T.Negate(&replacement.T)
		mutated.SetLane(lane, &replacement)
		wantMask = a.EqualAffine(&mutated)
		gotMask, err = ExperimentalIFMAPointEqualAffineX8(a, &mutated)
		if err != nil || gotMask != wantMask {
			t.Fatalf("round %d lane %d: x8 mutated equality=(%02x,%v) want=%02x", round, lane, gotMask, err, wantMask)
		}
	}

	a4 := splitPointX8(a)
	b4 := splitPointX8(b)
	affineA4 := splitPointX8(affineA)
	wantAdd4 := splitPointX8(&wantAdd)
	wantDouble4 := splitPointX8(&wantDouble)
	for group := 0; group < 2; group++ {
		var gotAdd4, gotDouble4 PointX4
		if err := ExperimentalIFMAPointAddX4(&gotAdd4, &a4[group], &b4[group]); err != nil {
			t.Fatalf("round %d group %d: x4 add: %v", round, group, err)
		}
		if gotAdd4 != wantAdd4[group] {
			t.Fatalf("round %d group %d: x4 add differs from scalar PointX4", round, group)
		}
		if err := ExperimentalIFMAPointDoubleX4(&gotDouble4, &a4[group]); err != nil {
			t.Fatalf("round %d group %d: x4 double: %v", round, group, err)
		}
		if gotDouble4 != wantDouble4[group] {
			t.Fatalf("round %d group %d: x4 double differs from scalar PointX4", round, group)
		}
		aliasA4 := a4[group]
		if err := ExperimentalIFMAPointAddX4(&aliasA4, &aliasA4, &b4[group]); err != nil || aliasA4 != wantAdd4[group] {
			t.Fatalf("round %d group %d: x4 aliased add err=%v", round, group, err)
		}
		aliasDouble4 := a4[group]
		if err := ExperimentalIFMAPointDoubleX4(&aliasDouble4, &aliasDouble4); err != nil || aliasDouble4 != wantDouble4[group] {
			t.Fatalf("round %d group %d: x4 aliased double err=%v", round, group, err)
		}
		wantMask4 := a4[group].EqualAffine(&affineA4[group])
		gotMask4, err := ExperimentalIFMAPointEqualAffineX4(&a4[group], &affineA4[group])
		if err != nil || gotMask4 != wantMask4 {
			t.Fatalf("round %d group %d: x4 equality=(%02x,%v) want=%02x", round, group, gotMask4, err, wantMask4)
		}
	}
}

func splitPointX8(p *PointX8) [2]PointX4 {
	points := p.Points()
	var out [2]PointX4
	for group := range out {
		var half [X4Lanes]Point
		copy(half[:], points[group*X4Lanes:(group+1)*X4Lanes])
		out[group].SetPoints(&half)
	}
	return out
}

func checkIFMAPointInvalidInput(t *testing.T) {
	t.Helper()
	valid8 := *NewIdentityPointX8()
	bad8 := valid8
	bad8.X.limbs[1][7] = 1 << LimbBits
	out8 := valid8
	before8 := out8
	if err := ExperimentalIFMAPointAddX8(&out8, &bad8, &valid8); !errors.Is(err, errIFMAInputRange) || out8 != before8 {
		t.Fatalf("invalid x8 add=(%v, changed=%v)", err, out8 != before8)
	}
	if err := ExperimentalIFMAPointDoubleX8(&out8, &bad8); !errors.Is(err, errIFMAInputRange) || out8 != before8 {
		t.Fatalf("invalid x8 double=(%v, changed=%v)", err, out8 != before8)
	}
	if mask, err := ExperimentalIFMAPointEqualAffineX8(&bad8, &valid8); mask != 0 || !errors.Is(err, errIFMAInputRange) {
		t.Fatalf("invalid x8 equality=(%02x,%v)", mask, err)
	}

	valid4 := *NewIdentityPointX4()
	bad4 := valid4
	bad4.Z.limbs[3][2] = 1 << LimbBits
	out4 := valid4
	before4 := out4
	if err := ExperimentalIFMAPointAddX4(&out4, &valid4, &bad4); !errors.Is(err, errIFMAInputRange) || out4 != before4 {
		t.Fatalf("invalid x4 add=(%v, changed=%v)", err, out4 != before4)
	}
	if err := ExperimentalIFMAPointDoubleX4(&out4, &bad4); !errors.Is(err, errIFMAInputRange) || out4 != before4 {
		t.Fatalf("invalid x4 double=(%v, changed=%v)", err, out4 != before4)
	}
	if mask, err := ExperimentalIFMAPointEqualAffineX4(&valid4, &bad4); mask != 0 || !errors.Is(err, errIFMAInputRange) {
		t.Fatalf("invalid x4 equality=(%02x,%v)", mask, err)
	}
}

func benchmarkMixedPointInputs(b *testing.B) (PointX8, PointX8, [2]PointX4, [2]PointX4) {
	b.Helper()
	generator := edwardsref.NewGeneratorPoint()
	var aBytes, bBytes [X8Lanes][32]byte
	for lane, torsionIndex := range canonicalTorsionIndexes {
		encoded, err := hex.DecodeString(pointTestEncodings[torsionIndex])
		if err != nil {
			b.Fatal(err)
		}
		torsion, err := new(edwardsref.Point).SetBytes(encoded)
		if err != nil {
			b.Fatal(err)
		}
		aPrime := edwardsref.NewIdentityPoint()
		bPrime := edwardsref.NewIdentityPoint()
		for i := 0; i <= lane; i++ {
			aPrime.Add(aPrime, generator)
		}
		for i := 0; i < lane+11; i++ {
			bPrime.Add(bPrime, generator)
		}
		aMixed := new(edwardsref.Point).Add(aPrime, torsion)
		bMixed := new(edwardsref.Point).Add(bPrime, torsion)
		copy(aBytes[lane][:], aMixed.Bytes())
		copy(bBytes[lane][:], bMixed.Bytes())
	}

	var a8, b8 PointX8
	if mask := a8.SetBytes(&aBytes); mask != 0xff {
		b.Fatalf("benchmark A valid mask=%02x", mask)
	}
	if mask := b8.SetBytes(&bBytes); mask != 0xff {
		b.Fatalf("benchmark B valid mask=%02x", mask)
	}
	return a8, b8, splitPointX8(&a8), splitPointX8(&b8)
}

var (
	benchmarkPointX8Sink   PointX8
	benchmarkPointX4Sink   [2]PointX4
	benchmarkPointMaskSink uint8
)

func BenchmarkExperimentalIFMAPointOperations(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	a8, b8, a4, b4 := benchmarkMixedPointInputs(b)

	b.Run("add/x8-zmm-checked", func(b *testing.B) {
		var out PointX8
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := ExperimentalIFMAPointAddX8(&out, &a8, &b8); err != nil {
				b.Fatal(err)
			}
		}
		benchmarkPointX8Sink = out
	})
	b.Run("add/two-x4-ymm-checked", func(b *testing.B) {
		var out [2]PointX4
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for group := range out {
				if err := ExperimentalIFMAPointAddX4(&out[group], &a4[group], &b4[group]); err != nil {
					b.Fatal(err)
				}
			}
		}
		benchmarkPointX4Sink = out
	})
	b.Run("add/scalar-x8", func(b *testing.B) {
		var out PointX8
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			out.Add(&a8, &b8)
		}
		benchmarkPointX8Sink = out
	})

	b.Run("double/x8-zmm-checked", func(b *testing.B) {
		var out PointX8
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := ExperimentalIFMAPointDoubleX8(&out, &a8); err != nil {
				b.Fatal(err)
			}
		}
		benchmarkPointX8Sink = out
	})
	b.Run("double/two-x4-ymm-checked", func(b *testing.B) {
		var out [2]PointX4
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for group := range out {
				if err := ExperimentalIFMAPointDoubleX4(&out[group], &a4[group]); err != nil {
					b.Fatal(err)
				}
			}
		}
		benchmarkPointX4Sink = out
	})
	b.Run("double/scalar-x8", func(b *testing.B) {
		var out PointX8
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			out.Double(&a8)
		}
		benchmarkPointX8Sink = out
	})

	b.Run("equal-affine/x8-zmm-checked", func(b *testing.B) {
		var mask uint8
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			var err error
			mask, err = ExperimentalIFMAPointEqualAffineX8(&a8, &a8)
			if err != nil {
				b.Fatal(err)
			}
		}
		benchmarkPointMaskSink = mask
	})
	b.Run("equal-affine/two-x4-ymm-checked", func(b *testing.B) {
		var mask uint8
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			mask = 0
			for group := range a4 {
				groupMask, err := ExperimentalIFMAPointEqualAffineX4(&a4[group], &a4[group])
				if err != nil {
					b.Fatal(err)
				}
				mask |= groupMask << (group * X4Lanes)
			}
		}
		benchmarkPointMaskSink = mask
	})
}
