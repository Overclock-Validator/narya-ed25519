package r43x6

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"math/rand"
	"testing"

	edwardsref "github.com/Overclock-Validator/narya/internal/edwards25519"
)

func compareDecode2(t *testing.T, label string, aBytes, rBytes []byte) {
	t.Helper()

	var wantA, wantR Point
	_, wantAErr := wantA.SetBytes(aBytes)
	_, wantRErr := wantR.SetBytes(rBytes)
	gotA, gotR, gotAErr, gotRErr := Decode2NoT(aBytes, rBytes)

	if gotAErr != wantAErr {
		t.Fatalf("%s: A error differs: paired=%v independent=%v\nA=%x", label, gotAErr, wantAErr, aBytes)
	}
	if gotRErr != wantRErr {
		t.Fatalf("%s: R error differs: paired=%v independent=%v\nR=%x", label, gotRErr, wantRErr, rBytes)
	}
	if wantAErr == nil {
		if gotA.Equal(&wantA) != 1 {
			t.Fatalf("%s: A point differs\npaired=%x\nindependent=%x", label, gotA.Bytes(), wantA.Bytes())
		}
		if gotA.Z.IsZero() == 1 || gotA.T.IsZero() != wantA.T.IsZero() || !pointCoordinatesReduced(&gotA) {
			t.Fatalf("%s: A extended-coordinate invariant failed", label)
		}
	} else if gotA != (Point{}) {
		t.Fatalf("%s: failed A decode returned a partial point", label)
	}
	if wantRErr == nil {
		if gotR.X.Equal(&wantR.X) != 1 || gotR.Y.Equal(&wantR.Y) != 1 {
			t.Fatalf("%s: compact R coordinates differ", label)
		}
		gotRBytes := gotR.Bytes()
		wantRBytes := wantR.Bytes()
		if gotRBytes != wantRBytes {
			t.Fatalf("%s: compact R encoding differs\npaired=%x\nindependent=%x", label, gotRBytes, wantRBytes)
		}
		if gotAErr == nil && gotA.EqualAffineNoT(&gotR) != wantA.Equal(&wantR) {
			t.Fatalf("%s: compact affine comparison differs", label)
		}
	} else if gotR != (AffinePoint{}) {
		t.Fatalf("%s: failed R decode returned partial coordinates", label)
	}
}

func TestDecode2NoTMatchesIndependentDecoders(t *testing.T) {
	edges := make([][]byte, 0, len(pointEdgeEncodings))
	for _, encodedHex := range pointEdgeEncodings {
		encoded, err := hex.DecodeString(encodedHex)
		if err != nil {
			t.Fatal(err)
		}
		edges = append(edges, encoded)
	}
	for i, a := range edges {
		for j, r := range edges {
			compareDecode2(t, fmt.Sprintf("edge/A=%d/R=%d", i, j), a, r)
		}
	}

	// Length failures are reported independently: a valid counterpart is still
	// decoded exactly as it would be by a separate SetBytes call.
	generator := NewGeneratorPoint().Bytes()
	badLengths := []int{0, 1, 31, 33, 64}
	for _, aLen := range badLengths {
		compareDecode2(t, fmt.Sprintf("bad-A-length/%d", aLen), make([]byte, aLen), generator[:])
	}
	for _, rLen := range badLengths {
		compareDecode2(t, fmt.Sprintf("bad-R-length/%d", rLen), generator[:], make([]byte, rLen))
	}
	for _, aLen := range badLengths {
		for _, rLen := range badLengths {
			compareDecode2(t, fmt.Sprintf("bad-lengths/%d/%d", aLen, rLen), make([]byte, aLen), make([]byte, rLen))
		}
	}

	// This pair locks down permissive negative zero independently in both lane
	// positions.
	negativeZero := make([]byte, 32)
	negativeZero[0] = 1
	negativeZero[31] = 0x80
	compareDecode2(t, "negative-zero/A", negativeZero, generator[:])
	compareDecode2(t, "negative-zero/R", generator[:], negativeZero)

	rng := rand.New(rand.NewSource(0xd3c0de2))
	var bothValid, aInvalid, rInvalid int
	for i := 0; i < 4096; i++ {
		var a, r [32]byte
		_, _ = rng.Read(a[:])
		_, _ = rng.Read(r[:])
		var independentA, independentR Point
		_, ae := independentA.SetBytes(a[:])
		_, re := independentR.SetBytes(r[:])
		switch {
		case ae == nil && re == nil:
			bothValid++
		case ae != nil:
			aInvalid++
		case re != nil:
			rInvalid++
		}
		compareDecode2(t, "random", a[:], r[:])
	}
	if bothValid < 500 || aInvalid < 500 || rInvalid < 500 {
		t.Fatalf("random differential coverage was unbalanced: both=%d a-invalid=%d r-invalid=%d", bothValid, aInvalid, rInvalid)
	}
}

func TestSqrtRatio2MatchesIndependentRawOutputs(t *testing.T) {
	zero := new(Element)
	one := new(Element).One()
	pairs := [][4]Element{
		{*zero, *zero, *zero, *zero},
		{*zero, *one, *one, *zero},
		{*one, *zero, *zero, *one},
		{*one, *one, *one, *one},
	}

	rng := rand.New(rand.NewSource(0x22523d2))
	for len(pairs) < 4100 {
		au, _ := randomElement(t, rng)
		av, _ := randomElement(t, rng)
		ru, _ := randomElement(t, rng)
		rv, _ := randomElement(t, rng)
		pairs = append(pairs, [4]Element{au, av, ru, rv})
	}

	for i, pair := range pairs {
		au, av, ru, rv := pair[0], pair[1], pair[2], pair[3]
		var wantA, wantR Element
		_, wantASquare := wantA.SqrtRatio(&au, &av)
		_, wantRSquare := wantR.SqrtRatio(&ru, &rv)
		var gotA, gotR Element
		gotASquare, gotRSquare := sqrtRatio2(&gotA, &gotR, &au, &ru, &av, &rv)
		if gotASquare != wantASquare || gotA.Equal(&wantA) != 1 {
			t.Fatalf("pair %d: A raw root differs: square=%d/%d got=%x want=%x", i, gotASquare, wantASquare, gotA.Bytes(), wantA.Bytes())
		}
		if gotRSquare != wantRSquare || gotR.Equal(&wantR) != 1 {
			t.Fatalf("pair %d: R raw root differs: square=%d/%d got=%x want=%x", i, gotRSquare, wantRSquare, gotR.Bytes(), wantR.Bytes())
		}
	}
}

type decode2VerifyFixture struct {
	pub [32]byte
	msg []byte
	sig [64]byte
}

func newDecode2VerifyFixture(tb testing.TB, messageSize int) decode2VerifyFixture {
	tb.Helper()
	var seed [ed25519.SeedSize]byte
	for i := range seed {
		seed[i] = byte(i*17 + 3)
	}
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	message := make([]byte, messageSize)
	for i := range message {
		message[i] = byte(i*29 + 11)
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	signature := ed25519.Sign(privateKey, message)
	var fixture decode2VerifyFixture
	copy(fixture.pub[:], publicKey)
	copy(fixture.sig[:], signature)
	fixture.msg = message
	return fixture
}

func decode2Challenge(pub *[32]byte, message, signature []byte) (Scalar, bool) {
	h := sha512.New()
	_, _ = h.Write(signature[:32])
	_, _ = h.Write(pub[:])
	_, _ = h.Write(message)
	var digest [sha512.Size]byte
	h.Sum(digest[:0])
	reduced, err := edwardsref.NewScalar().SetUniformBytes(digest[:])
	if err != nil {
		return Scalar{}, false
	}
	var k Scalar
	_, err = k.SetCanonicalBytes(reduced.Bytes())
	return k, err == nil
}

func verifyDecodeAEncodeQ(f *decode2VerifyFixture) bool {
	var a Point
	if _, err := a.SetBytes(f.pub[:]); err != nil {
		return false
	}
	var s Scalar
	if _, err := s.SetCanonicalBytes(f.sig[32:]); err != nil {
		return false
	}
	k, ok := decode2Challenge(&f.pub, f.msg, f.sig[:])
	if !ok {
		return false
	}
	q := new(Point).VarTimeVerifyMult(&s, &k, &a)
	encodedQ := q.Bytes()
	return bytes.Equal(encodedQ[:], f.sig[:32])
}

func verifyDecode2Projective(f *decode2VerifyFixture) bool {
	a, r, aErr, rErr := Decode2NoT(f.pub[:], f.sig[:32])
	if aErr != nil || rErr != nil {
		return false
	}
	// Direct point equality is equivalent to Encode(Q)==Rbytes only when the
	// supplied R is its decoded point's canonical encoding. Keep the complete
	// reference benchmark predicate-exact even for adversarial mutations.
	canonicalR := r.Bytes()
	if !bytes.Equal(canonicalR[:], f.sig[:32]) {
		return false
	}
	var s Scalar
	if _, err := s.SetCanonicalBytes(f.sig[32:]); err != nil {
		return false
	}
	k, ok := decode2Challenge(&f.pub, f.msg, f.sig[:])
	if !ok {
		return false
	}
	q := new(Point).VarTimeVerifyMult(&s, &k, &a)
	return q.EqualAffineNoT(&r) == 1
}

func TestDecode2CompletePipelineMatchesEncodeReference(t *testing.T) {
	for _, size := range []int{64, 200, 1232} {
		f := newDecode2VerifyFixture(t, size)
		if !verifyDecodeAEncodeQ(&f) || !verifyDecode2Projective(&f) {
			t.Fatalf("valid message size %d failed a complete pipeline", size)
		}
		for _, index := range []int{0, 15, 31, 32, 47, 63} {
			mutated := f
			mutated.sig[index] ^= 1
			if verifyDecode2Projective(&mutated) != verifyDecodeAEncodeQ(&mutated) {
				t.Fatalf("message size %d mutation %d differs", size, index)
			}
		}
	}

	// These self-consistent identity equations discriminate a projective
	// comparator that forgot canonical-R. Both encodings permissively decode
	// to the identity, so an unchecked point comparison would accept, while
	// Encode(Q)==original-R rejects them.
	for _, noncanonicalRHex := range []string{
		"0100000000000000000000000000000000000000000000000000000000000080", // x=0 with sign bit one
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // p+1 alias of y=1
	} {
		var f decode2VerifyFixture
		f.pub[0] = 1 // identity A makes the challenge term vanish.
		f.msg = []byte("canonical-R discriminator")
		rBytes, err := hex.DecodeString(noncanonicalRHex)
		if err != nil {
			t.Fatal(err)
		}
		copy(f.sig[:32], rBytes) // S=0, so Q is the identity.
		if verifyDecodeAEncodeQ(&f) || verifyDecode2Projective(&f) {
			t.Fatalf("noncanonical identity R was accepted: %s", noncanonicalRHex)
		}

		a, r, aErr, rErr := Decode2NoT(f.pub[:], f.sig[:32])
		if aErr != nil || rErr != nil {
			t.Fatalf("discriminator did not permissively decode: A=%v R=%v", aErr, rErr)
		}
		var zero Scalar
		k, ok := decode2Challenge(&f.pub, f.msg, f.sig[:])
		if !ok {
			t.Fatal("challenge reduction failed")
		}
		q := new(Point).VarTimeVerifyMult(&zero, &k, &a)
		if q.EqualAffineNoT(&r) != 1 {
			t.Fatal("canonical-R discriminator does not trigger the broken comparison")
		}
	}
}

func BenchmarkDecode2NoT(b *testing.B) {
	f := newDecode2VerifyFixture(b, 64)
	b.Run("independent", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			var a, r Point
			if _, err := a.SetBytes(f.pub[:]); err != nil {
				b.Fatal(err)
			}
			if _, err := r.SetBytes(f.sig[:32]); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("paired-no-t", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, _, aErr, rErr := Decode2NoT(f.pub[:], f.sig[:32])
			if aErr != nil || rErr != nil {
				b.Fatalf("decode errors: A=%v R=%v", aErr, rErr)
			}
		}
	})
}

func BenchmarkDecode2CompletePipeline(b *testing.B) {
	for _, size := range []int{64, 200, 1232} {
		f := newDecode2VerifyFixture(b, size)
		b.Run(fmt.Sprintf("reference-decodeA-encodeQ/msg=%d", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if !verifyDecodeAEncodeQ(&f) {
					b.Fatal("reference rejected valid signature")
				}
			}
		})
		b.Run(fmt.Sprintf("paired-decode-projective/msg=%d", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if !verifyDecode2Projective(&f) {
					b.Fatal("paired pipeline rejected valid signature")
				}
			}
		})
	}
}
