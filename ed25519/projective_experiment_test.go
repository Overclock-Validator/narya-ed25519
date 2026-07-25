package ed25519

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/Overclock-Validator/narya/internal/edwards25519"
	"github.com/Overclock-Validator/narya/internal/edwards25519/field"
)

// verifyGenericStrictProjective is the complete portable experiment for the
// strict decoded-R pipeline. It deliberately remains test-only: decoding R a
// second time is not expected to pay for itself in the scalar generic backend,
// while a paired IFMA decoder can share the expensive exponentiation. Keeping
// the full candidate here lets benchmarks make that decision rather than
// silently changing the production path on an unrelated architecture.
func verifyGenericStrictProjective(pub *[32]byte, message, sig []byte) bool {
	if len(sig) != 64 || sig[63]&224 != 0 || rejectedByStrict(pub, sig) {
		return false
	}
	if !canonicalREncoding(sig[:32]) {
		return false
	}

	a, err := (&edwards25519.Point{}).SetBytes(pub[:])
	if err != nil {
		return false
	}
	r, err := (&edwards25519.Point{}).SetBytes(sig[:32])
	if err != nil {
		return false
	}

	digest := sha512.New()
	digest.Write(sig[:32])
	digest.Write(pub[:])
	digest.Write(message)
	var hramDigest [sha512.Size]byte
	digest.Sum(hramDigest[:0])
	k, err := edwards25519.NewScalar().SetUniformBytes(hramDigest[:])
	if err != nil {
		return false
	}
	s, err := edwards25519.NewScalar().SetCanonicalBytes(sig[32:])
	if err != nil {
		return false
	}

	minusA := (&edwards25519.Point{}).Negate(a)
	q := (&edwards25519.Point{}).VarTimeDoubleScalarBaseMult(k, minusA, s)
	return q.EqualAffine(r) == 1
}

// affineCoordinateEqual is deliberately unsafe and test-only. It models the
// two tempting broken final comparisons so self-consistent vectors can prove
// that both cross-products in Point.EqualAffine are necessary.
func affineCoordinateEqual(q, affine *edwards25519.Point, compareX bool) int {
	qx, qy, qz, _ := q.ExtendedCoordinates()
	rx, ry, _, _ := affine.ExtendedCoordinates()
	var scaled field.Element
	if compareX {
		scaled.Multiply(rx, qz)
		return qx.Equal(&scaled)
	}
	scaled.Multiply(ry, qz)
	return qy.Equal(&scaled)
}

func scalarFromUint64(t *testing.T, n uint64) *edwards25519.Scalar {
	t.Helper()
	var encoded [32]byte
	binary.LittleEndian.PutUint64(encoded[:8], n)
	s, err := edwards25519.NewScalar().SetCanonicalBytes(encoded[:])
	if err != nil {
		t.Fatalf("scalar %d was not canonical: %v", n, err)
	}
	return s
}

func strictChallenge(t *testing.T, rBytes, aBytes, message []byte) *edwards25519.Scalar {
	t.Helper()
	h := sha512.New()
	_, _ = h.Write(rBytes)
	_, _ = h.Write(aBytes)
	_, _ = h.Write(message)
	var digest [sha512.Size]byte
	h.Sum(digest[:0])
	k, err := edwards25519.NewScalar().SetUniformBytes(digest[:])
	if err != nil {
		t.Fatalf("reduce challenge: %v", err)
	}
	return k
}

func assembleStrictTestSignature(r *edwards25519.Point, s *edwards25519.Scalar) [64]byte {
	var sig [64]byte
	copy(sig[:32], r.Bytes())
	copy(sig[32:], s.Bytes())
	return sig
}

func assertStrictPrecheckDomain(t *testing.T, pub *[32]byte, sig []byte) {
	t.Helper()
	if rejectedByStrict(pub, sig) {
		t.Fatal("self-consistent vector unexpectedly uses a small-order A or R")
	}
	if !canonicalREncoding(sig[:32]) || !canonicalRReference(sig[:32]) {
		t.Fatal("self-consistent coordinate vector unexpectedly uses a noncanonical R")
	}
}

// TestNoncanonicalNonSmallOrderRRequiresCanonicalGateAtEqualityBoundary uses
// an unreduced y+p encoding whose decoded point is not torsion. It isolates
// the exact final-condition divergence: projective point equality succeeds,
// while canonical encoded-Q equality rejects the original bytes. Producing a
// complete self-consistent signature with such an R would require the unknown
// discrete logarithm of one of the very few points with y in [2,18], so the
// verifier-level corpus separately covers self-consistent small-order aliases
// and this test covers the non-small-order equality boundary directly.
func TestNoncanonicalNonSmallOrderRRequiresCanonicalGateAtEqualityBoundary(t *testing.T) {
	var encoded [32]byte
	for index := 1; index < 31; index++ {
		encoded[index] = 0xff
	}
	encoded[31] = 0x7f

	var decoded *edwards25519.Point
	for y := byte(2); y <= 18; y++ {
		encoded[0] = 0xed + y // p+y; no carry for y <= 18.
		candidate, err := (&edwards25519.Point{}).SetBytes(encoded[:])
		if err == nil && !candidate.IsSmallOrder() {
			decoded = candidate
			break
		}
	}
	if decoded == nil {
		t.Fatal("none of the accepted y+p aliases in [p+2,p+18] decoded to a non-small-order point")
	}
	if smallOrderEncoding(encoded[:]) {
		t.Fatalf("non-small-order alias %x matched the strict torsion classifier", encoded)
	}
	if canonicalREncoding(encoded[:]) || canonicalRReference(encoded[:]) {
		t.Fatalf("noncanonical alias %x passed canonical-R validation", encoded)
	}
	if decoded.EqualAffine(decoded) != 1 {
		t.Fatal("projective/affine equality rejected the decoded point itself")
	}
	canonical := decoded.Bytes()
	if bytes.Equal(canonical, encoded[:]) {
		t.Fatal("permissive decoder unexpectedly preserved an unreduced encoding")
	}
	canonicalDecoded, err := (&edwards25519.Point{}).SetBytes(canonical)
	if err != nil || decoded.Equal(canonicalDecoded) != 1 {
		t.Fatalf("canonical re-encoding changed the decoded point: err=%v", err)
	}
}

// TestSelfConsistentVectorRequiresXCrossProduct constructs a signature whose
// equation result is Q=-R. Edwards negation preserves y and negates x, so a
// verifier that checks only Y_Q=y_R*Z_Q accepts while the strict equation and
// the complete projective comparison reject.
func TestSelfConsistentVectorRequiresXCrossProduct(t *testing.T) {
	a := scalarFromUint64(t, 5)
	rScalar := scalarFromUint64(t, 7)
	aPoint := (&edwards25519.Point{}).ScalarBaseMult(a)
	rPoint := (&edwards25519.Point{}).ScalarBaseMult(rScalar)
	rAffine, err := (&edwards25519.Point{}).SetBytes(rPoint.Bytes())
	if err != nil {
		t.Fatalf("decode R: %v", err)
	}
	message := []byte("self-consistent missing-X discriminator")

	var pub [32]byte
	copy(pub[:], aPoint.Bytes())
	k := strictChallenge(t, rPoint.Bytes(), pub[:], message)
	s := (&edwards25519.Scalar{}).Multiply(k, a)
	s.Subtract(s, rScalar) // s = k*a-r, so Q = -R.
	sig := assembleStrictTestSignature(rPoint, s)
	assertStrictPrecheckDomain(t, &pub, sig[:])

	minusA := (&edwards25519.Point{}).Negate(aPoint)
	q := (&edwards25519.Point{}).VarTimeDoubleScalarBaseMult(k, minusA, s)
	minusR := (&edwards25519.Point{}).Negate(rPoint)
	if q.Equal(minusR) != 1 {
		t.Fatal("construction error: Q != -R")
	}
	if affineCoordinateEqual(q, rAffine, false) != 1 {
		t.Fatal("broken Y-only comparison did not accept its discriminator")
	}
	if affineCoordinateEqual(q, rAffine, true) != 0 {
		t.Fatal("X coordinate unexpectedly matched; discriminator is vacuous")
	}
	if q.EqualAffine(rAffine) != 0 {
		t.Fatal("complete projective comparison accepted Q=-R")
	}
	if verifyGenericStrictProjective(&pub, message, sig[:]) || referenceVerifyProfile(DalekStrict, &pub, message, sig[:]) {
		t.Fatal("strict verifier accepted the missing-X discriminator")
	}
}

// TestSelfConsistentVectorRequiresYCrossProduct uses A=[a]B+T2, where T2 is
// the order-two point (0,-1), and grinds an odd challenge. With s=k*a-r this
// gives Q=-R+T2=(x_R,-y_R). A verifier that checks only X_Q=x_R*Z_Q accepts,
// while mixed-order A remains valid under the strict profile.
func TestSelfConsistentVectorRequiresYCrossProduct(t *testing.T) {
	a := scalarFromUint64(t, 5)
	rScalar := scalarFromUint64(t, 7)
	baseA := (&edwards25519.Point{}).ScalarBaseMult(a)
	rPoint := (&edwards25519.Point{}).ScalarBaseMult(rScalar)
	rAffine, err := (&edwards25519.Point{}).SetBytes(rPoint.Bytes())
	if err != nil {
		t.Fatalf("decode R: %v", err)
	}

	orderTwoEncoding, err := hex.DecodeString("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
	if err != nil {
		t.Fatal(err)
	}
	twoTorsion, err := (&edwards25519.Point{}).SetBytes(orderTwoEncoding)
	if err != nil {
		t.Fatalf("decode order-two point: %v", err)
	}
	aPoint := (&edwards25519.Point{}).Add(baseA, twoTorsion)
	var pub [32]byte
	copy(pub[:], aPoint.Bytes())

	var message [8]byte
	var k *edwards25519.Scalar
	for counter := uint64(0); ; counter++ {
		binary.LittleEndian.PutUint64(message[:], counter)
		k = strictChallenge(t, rPoint.Bytes(), pub[:], message[:])
		if k.Bytes()[0]&1 == 1 {
			break
		}
		if counter == 1024 {
			t.Fatal("failed to find an odd challenge")
		}
	}

	s := (&edwards25519.Scalar{}).Multiply(k, a)
	s.Subtract(s, rScalar) // s = k*a-r.
	sig := assembleStrictTestSignature(rPoint, s)
	assertStrictPrecheckDomain(t, &pub, sig[:])

	minusA := (&edwards25519.Point{}).Negate(aPoint)
	q := (&edwards25519.Point{}).VarTimeDoubleScalarBaseMult(k, minusA, s)
	minusR := (&edwards25519.Point{}).Negate(rPoint)
	target := (&edwards25519.Point{}).Add(minusR, twoTorsion)
	if q.Equal(target) != 1 {
		t.Fatal("construction error: Q != -R+T2")
	}
	if affineCoordinateEqual(q, rAffine, true) != 1 {
		t.Fatal("broken X-only comparison did not accept its discriminator")
	}
	if affineCoordinateEqual(q, rAffine, false) != 0 {
		t.Fatal("Y coordinate unexpectedly matched; discriminator is vacuous")
	}
	if q.EqualAffine(rAffine) != 0 {
		t.Fatal("complete projective comparison accepted Q=-R+T2")
	}
	if verifyGenericStrictProjective(&pub, message[:], sig[:]) || referenceVerifyProfile(DalekStrict, &pub, message[:], sig[:]) {
		t.Fatal("strict verifier accepted the missing-Y discriminator")
	}
}

func TestGenericStrictProjectiveMatchesReferenceCorpora(t *testing.T) {
	type encodedVector struct {
		name string
		pub  string
		msg  string
		sig  string
	}
	vectors := make([]encodedVector, 0, len(cctvVectors)+len(wycheproofVectors))
	for _, v := range cctvVectors {
		vectors = append(vectors, encodedVector{fmt.Sprintf("cctv/%d", v.tcID), v.pub, v.msg, v.sig})
	}
	for _, v := range wycheproofVectors {
		vectors = append(vectors, encodedVector{fmt.Sprintf("wycheproof/%d", v.tcID), v.pub, v.msg, v.sig})
	}

	for _, v := range vectors {
		pubBytes, err := hex.DecodeString(v.pub)
		if err != nil || len(pubBytes) != 32 {
			t.Fatalf("%s: invalid public key fixture", v.name)
		}
		msg, err := hex.DecodeString(v.msg)
		if err != nil {
			t.Fatalf("%s: invalid message fixture", v.name)
		}
		sig, err := hex.DecodeString(v.sig)
		if err != nil {
			t.Fatalf("%s: invalid signature fixture", v.name)
		}
		var pub [32]byte
		copy(pub[:], pubBytes)

		got := verifyGenericStrictProjective(&pub, msg, sig)
		want := referenceVerifyProfile(DalekStrict, &pub, msg, sig)
		if got != want {
			t.Fatalf("%s: projective strict=%v reference=%v", v.name, got, want)
		}
	}
}

// BenchmarkGenericStrictFinalEquality compares complete cold verification
// pipelines, not isolated equality primitives. The projective candidate pays
// for decoding R; a future Decode2 IFMA kernel is intended to reduce that
// incremental cost.
func BenchmarkGenericStrictFinalEquality(b *testing.B) {
	for _, size := range benchMsgSizes {
		f := makeFixture(b, size)
		b.Run(fmt.Sprintf("final=encoded-Q/msg=%d", size), func(b *testing.B) {
			g := genericBackend{}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if !g.verify(DalekStrict, &f.pub, f.msg, f.sig, nil) {
					b.Fatal("encoded-Q reference rejected valid signature")
				}
			}
		})
		b.Run(fmt.Sprintf("final=projective-R/msg=%d", size), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if !verifyGenericStrictProjective(&f.pub, f.msg, f.sig) {
					b.Fatal("projective-R candidate rejected valid signature")
				}
			}
		})
	}
}
