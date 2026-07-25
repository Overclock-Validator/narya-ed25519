package r51x5

import (
	"bytes"
	stded25519 "crypto/ed25519"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	edwardsref "github.com/Overclock-Validator/narya/internal/edwards25519"
)

// This file is a same-binary, test-only experiment for the packed singleton
// verifier. The control remains quadStrictVerifierX4.verify: decode only A,
// evaluate the coordinate-parallel DSM, canonically encode Q with an
// inversion, and compare those bytes with the original R bytes.
//
// The candidate fills two independent lanes of the existing x4 decoder with
// A and R. Because the square-root schedule is lane-wise, this retains one
// exponentiation schedule while producing both affine points. After the same
// packed DSM it compares Q with decoded R using both projective cross-products
// in one x4 IFMA multiplication. Production dispatch cannot reach this code.

func quadPairedRStrictBytePrechecksX4(pub *[32]byte, signature []byte, s *[32]byte) bool {
	if pub == nil || len(signature) != stded25519.SignatureSize {
		return false
	}
	copy(s[:], signature[32:])
	if !canonicalScalarBytes(s) ||
		quadEncodesSmallOrderPointX4(pub[:]) ||
		quadEncodesSmallOrderPointX4(signature[:32]) {
		return false
	}
	return quadCanonicalREncodingX4(signature[:32])
}

// verifyPairedRProjective keeps the historical test name while exercising the
// promoted reusable API against the literal encoded-Q control.
func (verifier *quadStrictVerifierX4) verifyPairedRProjective(
	pub *[32]byte,
	message, signature []byte,
) (bool, error) {
	return verifier.ExperimentalPackedStrictVerifierX4.Verify(pub, message, signature)
}

func TestExperimentalCoordinateParallelPairedRProjectiveEqualityX4(t *testing.T) {
	// The helper's scalar model runs on every architecture. Use a genuinely
	// projective Q so an accidental affine-coordinate comparison cannot pass.
	rScalar := quadPairedRScalarFromUint64X4(t, 19)
	rRef := new(edwardsref.Point).ScalarBaseMult(rScalar)
	var r Point
	if _, err := r.SetBytes(rRef.Bytes()); err != nil {
		t.Fatal(err)
	}
	q := r
	var lambda Element
	lambdaBytes := [32]byte{7}
	if _, err := lambda.SetCanonicalBytes(lambdaBytes[:]); err != nil {
		t.Fatal(err)
	}
	q.X.Multiply(&q.X, &lambda)
	q.Y.Multiply(&q.Y, &lambda)
	q.T.Multiply(&q.T, &lambda)
	q.Z.Multiply(&q.Z, &lambda)
	packedQ := new(quadPackedPointX4).setReduced(&q)

	decoded := NewIdentityPointX4()
	decoded.SetLane(1, &r)
	equal, err := quadPackedEqualDecodedAffineLaneX4(packedQ, decoded, 1, quadDSMOperationsX4{})
	if err != nil || !equal {
		t.Fatalf("equal projective/affine points=(%v,%v)", equal, err)
	}

	// -R shares y with R and differs in x. This is the load-bearing missing-X
	// discriminator: a Y-only comparison would accept it.
	negR := r
	negR.X.Negate(&r.X)
	negR.T.Negate(&r.T)
	decoded.SetLane(1, &negR)
	equal, err = quadPackedEqualDecodedAffineLaneX4(packedQ, decoded, 1, quadDSMOperationsX4{})
	if err != nil || equal {
		t.Fatalf("R=-Q discriminator=(%v,%v)", equal, err)
	}

	// Invalid projective Z must fail closed. Without the explicit Z gate, an
	// all-zero uncommitted output satisfies both cross-products as 0=0.
	var zeroQ quadPackedPointX4
	equal, err = quadPackedEqualDecodedAffineLaneX4(&zeroQ, decoded, 1, quadDSMOperationsX4{})
	if err != nil || equal {
		t.Fatalf("zero-Z fail-closed discriminator=(%v,%v)", equal, err)
	}

	// The finalizer owns the checked boundary before its unchecked IFMA
	// multiply. A missing range check would let VPMADD52 truncate this limb.
	outOfRangeQ := *packedQ
	outOfRangeQ.coordinates.limbs[0][0] = ifmaComposableLimbLimit
	equal, err = quadPackedEqualDecodedAffineLaneX4(&outOfRangeQ, decoded, 1, quadDSMOperationsX4{})
	if equal || !errors.Is(err, errIFMAComposableInputRange) {
		t.Fatalf("out-of-range fail-closed discriminator=(%v,%v)", equal, err)
	}

	// Keep x_R and negate y_R (and T_R to preserve the extended-coordinate
	// invariant). X therefore passes while Y fails, directly discriminating a
	// helper that accidentally omits the second cross-product.
	sameXNegY := r
	sameXNegY.Y.Negate(&r.Y)
	sameXNegY.T.Negate(&r.T)
	decoded.SetLane(1, &sameXNegY)
	equal, err = quadPackedEqualDecodedAffineLaneX4(packedQ, decoded, 1, quadDSMOperationsX4{})
	if err != nil || equal {
		t.Fatalf("missing-Y discriminator=(%v,%v)", equal, err)
	}
}

func TestExperimentalCoordinateParallelPairedRCompleteStrictX4(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("AVX-512 IFMA is unavailable")
	}
	verifier, err := newQuadStrictVerifierX4()
	if err != nil {
		t.Fatal(err)
	}
	for _, messageSize := range []int{0, 64, 200, 1232} {
		fixture := newQuadStrictFixtureX4(t, messageSize)
		quadAssertPairedRMatchesLiteralX4(t, verifier, fmt.Sprintf("honest/msg=%d", messageSize), &fixture.pub, fixture.message, fixture.signature, true)

		badMessage := append([]byte(nil), fixture.message...)
		if len(badMessage) == 0 {
			badMessage = []byte{1}
		} else {
			badMessage[len(badMessage)/2] ^= 1
		}
		quadAssertPairedRMatchesLiteralX4(t, verifier, fmt.Sprintf("bad-message/msg=%d", messageSize), &fixture.pub, badMessage, fixture.signature, false)

		badSignature := append([]byte(nil), fixture.signature...)
		badSignature[7] ^= 0x40
		quadAssertPairedRMatchesLiteralX4(t, verifier, fmt.Sprintf("bad-signature/msg=%d", messageSize), &fixture.pub, fixture.message, badSignature, false)
	}

	mixedPub, mixedMessage, mixedSignature := quadPairedRMixedOrderValidVectorX4(t)
	quadAssertPairedRMatchesLiteralX4(t, verifier, "mixed-order", &mixedPub, mixedMessage, mixedSignature, true)

	minusPub, minusMessage, minusSignature := quadPairedRMissingXVectorX4(t)
	quadAssertPairedRMatchesLiteralX4(t, verifier, "missing-X", &minusPub, minusMessage, minusSignature, false)
}

func TestExperimentalPackedStrictVerifierX4APIGate(t *testing.T) {
	verifier, err := NewExperimentalPackedStrictVerifierX4()
	if !ExperimentalIFMAAvailable() {
		if verifier != nil || !errors.Is(err, ErrIFMAUnavailable) {
			t.Fatalf("unavailable constructor=(%p,%v), want (nil,%v)", verifier, err, ErrIFMAUnavailable)
		}
	} else if err != nil || verifier == nil {
		t.Fatalf("available constructor=(%p,%v)", verifier, err)
	}

	var zero ExperimentalPackedStrictVerifierX4
	accepted, verifyErr := zero.Verify(nil, nil, nil)
	if accepted || !errors.Is(verifyErr, errExperimentalPackedStrictVerifierUninitialized) {
		t.Fatalf("zero-value Verify=(%v,%v)", accepted, verifyErr)
	}
}

func TestExperimentalPackedStrictVerifierX4SharesGeneratorTable(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("AVX-512 IFMA unavailable")
	}
	first, err := NewExperimentalPackedStrictVerifierX4()
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewExperimentalPackedStrictVerifierX4()
	if err != nil {
		t.Fatal(err)
	}
	if first.bTable == nil || first.bTable != second.bTable {
		t.Fatal("packed strict verifiers do not share the immutable generator table")
	}
}

func TestExperimentalCoordinateParallelPairedRStrictEdgesX4(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("AVX-512 IFMA is unavailable")
	}
	verifier, err := newQuadStrictVerifierX4()
	if err != nil {
		t.Fatal(err)
	}
	fixture := newQuadStrictFixtureX4(t, 200)

	// Exercise every accepted compressed alias of the seven low-255-bit
	// torsion values under both sign bits, once as A and once as R.
	for index, low := range quadPairedRSmallOrderLow255X4() {
		for sign := byte(0); sign < 2; sign++ {
			encoded := low
			encoded[31] = encoded[31]&0x7f | sign<<7
			if !quadEncodesSmallOrderPointX4(encoded[:]) {
				t.Fatalf("small-order[%d]/sign=%d escaped classifier: %x", index, sign, encoded)
			}
			quadAssertPairedRMatchesLiteralX4(t, verifier, fmt.Sprintf("small-A/%d/%d", index, sign), &encoded, fixture.message, fixture.signature, false)

			sig := append([]byte(nil), fixture.signature...)
			copy(sig[:32], encoded[:])
			quadAssertPairedRMatchesLiteralX4(t, verifier, fmt.Sprintf("small-R/%d/%d", index, sign), &fixture.pub, fixture.message, sig, false)
		}
	}

	noncanonicalA := quadPairedRNoncanonicalDecodablePointX4(t)
	var s [32]byte
	if !quadPairedRStrictBytePrechecksX4(&noncanonicalA, fixture.signature, &s) {
		t.Fatal("strict byte prechecks added a forbidden canonical-A rejection")
	}
	var paired [X4Lanes][32]byte
	paired[0] = noncanonicalA
	copy(paired[1][:], fixture.signature[:32])
	var decoded PointX4
	valid, err := ExperimentalIFMADecodeX4(&decoded, &paired, 0b0011)
	if err != nil || valid&0b0011 != 0b0011 {
		t.Fatalf("noncanonical A did not permissively decode: mask=%x err=%v", valid, err)
	}
	// The fixture signature belongs to another key, so both equations reject;
	// the checks above prove rejection was not caused by canonicalizing A.
	quadAssertPairedRMatchesLiteralX4(t, verifier, "noncanonical-A", &noncanonicalA, fixture.message, fixture.signature, false)

	noncanonicalR := quadPairedRNoncanonicalDecodablePointX4(t)
	sig := append([]byte(nil), fixture.signature...)
	copy(sig[:32], noncanonicalR[:])
	if quadPairedRStrictBytePrechecksX4(&fixture.pub, sig, &s) {
		t.Fatal("noncanonical R escaped the strict byte gate")
	}
	quadAssertPairedRMatchesLiteralX4(t, verifier, "noncanonical-R", &fixture.pub, fixture.message, sig, false)

	undecodableR := quadPairedRUndecodablePointX4(t)
	sig = append([]byte(nil), fixture.signature...)
	copy(sig[:32], undecodableR[:])
	quadAssertPairedRMatchesLiteralX4(t, verifier, "undecodable-R", &fixture.pub, fixture.message, sig, false)
	undecodableA := undecodableR
	quadAssertPairedRMatchesLiteralX4(t, verifier, "undecodable-A", &undecodableA, fixture.message, fixture.signature, false)

	noncanonicalS := append([]byte(nil), fixture.signature...)
	copy(noncanonicalS[32:], scalarOrderBytes[:])
	quadAssertPairedRMatchesLiteralX4(t, verifier, "noncanonical-S", &fixture.pub, fixture.message, noncanonicalS, false)
	quadAssertPairedRMatchesLiteralX4(t, verifier, "nil-A", nil, fixture.message, fixture.signature, false)
	quadAssertPairedRMatchesLiteralX4(t, verifier, "short-signature", &fixture.pub, fixture.message, fixture.signature[:63], false)
	longSignature := append(append([]byte(nil), fixture.signature...), 0)
	quadAssertPairedRMatchesLiteralX4(t, verifier, "long-signature", &fixture.pub, fixture.message, longSignature, false)
}

func TestExperimentalCoordinateParallelPairedRDecodeEveryMaskX4(t *testing.T) {
	fixture := newQuadStrictFixtureX4(t, 64)
	var encoded [X4Lanes][32]byte
	encoded[0] = fixture.pub
	copy(encoded[1][:], fixture.signature[:32])
	encoded[2] = quadPairedRUndecodablePointX4(t)
	encoded[3] = quadPairedRNoncanonicalDecodablePointX4(t)
	for active := 0; active < 1<<X4Lanes; active++ {
		checkIFMADecodeModelX4(t, fmt.Sprintf("paired-active=%x", active), &encoded, uint8(active))
		if ExperimentalIFMAAvailable() {
			var got PointX4
			gotMask, err := ExperimentalIFMADecodeX4(&got, &encoded, uint8(active))
			if err != nil {
				t.Fatal(err)
			}
			want, wantMask := referenceDecodeIFMAX4(&encoded, uint8(active))
			if gotMask != wantMask || got != want {
				t.Fatalf("active=%x hardware mask=%x want=%x or point differs", active, gotMask, wantMask)
			}
		}
	}
}

func TestExperimentalCoordinateParallelPairedRCompleteStrictX4ZeroAllocations(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("AVX-512 IFMA is unavailable")
	}
	verifier, err := newQuadStrictVerifierX4()
	if err != nil {
		t.Fatal(err)
	}
	fixture := newQuadStrictFixtureX4(t, 200)
	if allocations := testing.AllocsPerRun(20, func() {
		accepted, err := verifier.ExperimentalPackedStrictVerifierX4.Verify(&fixture.pub, fixture.message, fixture.signature)
		if err != nil || !accepted {
			panic("r51x5: paired-R packed verifier rejected honest signature")
		}
	}); allocations != 0 {
		t.Fatalf("allocations=%v want 0", allocations)
	}
}

func quadAssertPairedRMatchesLiteralX4(
	t *testing.T,
	verifier *quadStrictVerifierX4,
	label string,
	pub *[32]byte,
	message, signature []byte,
	want bool,
) {
	t.Helper()
	literal, literalErr := verifier.verify(pub, message, signature)
	candidate, candidateErr := verifier.verifyPairedRProjective(pub, message, signature)
	if literalErr != nil || candidateErr != nil || literal != want || candidate != literal {
		t.Fatalf("%s literal=(%v,%v) paired=(%v,%v) want=%v", label, literal, literalErr, candidate, candidateErr, want)
	}
}

func quadPairedRSmallOrderLow255X4() [7][32]byte {
	var values [7][32]byte
	values[1][0] = 1
	values[2][0] = 0xec
	values[3][0] = 0xed
	values[4][0] = 0xee
	for index := 1; index < 31; index++ {
		values[2][index] = 0xff
		values[3][index] = 0xff
		values[4][index] = 0xff
	}
	values[2][31] = 0x7f
	values[3][31] = 0x7f
	values[4][31] = 0x7f
	values[5] = quadSmallOrderAlphaX4
	values[6] = quadSmallOrderNegAlphaX4
	return values
}

func quadPairedRNoncanonicalDecodablePointX4(t *testing.T) [32]byte {
	t.Helper()
	for alias := byte(2); alias <= 18; alias++ {
		candidate := [32]byte{0: 0xed + alias, 31: 0x7f}
		for index := 1; index < 31; index++ {
			candidate[index] = 0xff
		}
		for sign := byte(0); sign < 2; sign++ {
			candidate[31] = 0x7f | sign<<7
			point, err := new(Point).SetBytes(candidate[:])
			if err == nil && !quadEncodesSmallOrderPointX4(candidate[:]) {
				canonical := point.Bytes()
				if !bytes.Equal(canonical[:], candidate[:]) {
					return candidate
				}
			}
		}
	}
	t.Fatal("failed to find a noncanonical decodable non-small-order point")
	return [32]byte{}
}

func quadPairedRUndecodablePointX4(t *testing.T) [32]byte {
	t.Helper()
	for raw := 2; raw < 1<<16; raw++ {
		var candidate [32]byte
		binary.LittleEndian.PutUint16(candidate[:2], uint16(raw))
		if quadEncodesSmallOrderPointX4(candidate[:]) {
			continue
		}
		if _, err := new(Point).SetBytes(candidate[:]); err != nil {
			return candidate
		}
	}
	t.Fatal("failed to find a deterministic invalid compressed point")
	return [32]byte{}
}

func quadPairedRScalarFromUint64X4(t testing.TB, value uint64) *edwardsref.Scalar {
	t.Helper()
	var encoded [32]byte
	binary.LittleEndian.PutUint64(encoded[:8], value)
	scalar, err := edwardsref.NewScalar().SetCanonicalBytes(encoded[:])
	if err != nil {
		t.Fatalf("scalar %d: %v", value, err)
	}
	return scalar
}

func quadPairedRChallengeX4(t testing.TB, rBytes, aBytes, message []byte) *edwardsref.Scalar {
	t.Helper()
	digest := sha512.New()
	_, _ = digest.Write(rBytes)
	_, _ = digest.Write(aBytes)
	_, _ = digest.Write(message)
	var wide [sha512.Size]byte
	digest.Sum(wide[:0])
	k, err := edwardsref.NewScalar().SetUniformBytes(wide[:])
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func quadPairedRSignatureX4(r *edwardsref.Point, s *edwardsref.Scalar) []byte {
	var signature [stded25519.SignatureSize]byte
	copy(signature[:32], r.Bytes())
	copy(signature[32:], s.Bytes())
	return append([]byte(nil), signature[:]...)
}

func quadPairedRMixedOrderValidVectorX4(t *testing.T) ([32]byte, []byte, []byte) {
	t.Helper()
	a := quadPairedRScalarFromUint64X4(t, 5)
	rScalar := quadPairedRScalarFromUint64X4(t, 7)
	torsionEncoding, err := hex.DecodeString("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
	if err != nil {
		t.Fatal(err)
	}
	torsion, err := new(edwardsref.Point).SetBytes(torsionEncoding)
	if err != nil {
		t.Fatal(err)
	}
	A := new(edwardsref.Point).Add(new(edwardsref.Point).ScalarBaseMult(a), torsion)
	R := new(edwardsref.Point).Add(new(edwardsref.Point).ScalarBaseMult(rScalar), torsion)
	var pub [32]byte
	copy(pub[:], A.Bytes())
	var message [8]byte
	var k *edwardsref.Scalar
	for counter := uint64(0); ; counter++ {
		binary.LittleEndian.PutUint64(message[:], counter)
		k = quadPairedRChallengeX4(t, R.Bytes(), pub[:], message[:])
		if k.Bytes()[0]&1 == 1 {
			break
		}
		if counter == 1024 {
			t.Fatal("failed to grind odd mixed-order challenge")
		}
	}
	s := new(edwardsref.Scalar).Multiply(k, a)
	s.Add(s, rScalar)
	return pub, append([]byte(nil), message[:]...), quadPairedRSignatureX4(R, s)
}

func quadPairedRMissingXVectorX4(t *testing.T) ([32]byte, []byte, []byte) {
	t.Helper()
	a := quadPairedRScalarFromUint64X4(t, 5)
	rScalar := quadPairedRScalarFromUint64X4(t, 7)
	A := new(edwardsref.Point).ScalarBaseMult(a)
	R := new(edwardsref.Point).ScalarBaseMult(rScalar)
	var pub [32]byte
	copy(pub[:], A.Bytes())
	message := []byte("packed singleton missing-X discriminator")
	k := quadPairedRChallengeX4(t, R.Bytes(), pub[:], message)
	s := new(edwardsref.Scalar).Multiply(k, a)
	s.Subtract(s, rScalar) // Q=[s]B-[k]A=-R.
	return pub, message, quadPairedRSignatureX4(R, s)
}

var benchmarkQuadPairedRResultX4 bool

func BenchmarkExperimentalCoordinateParallelPairedRComponentsX4(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skip("AVX-512 IFMA is unavailable")
	}
	fixture := newQuadStrictFixtureX4(b, 200)
	verifier, err := newQuadStrictVerifierX4()
	if err != nil {
		b.Fatal(err)
	}
	var encoded [X4Lanes][32]byte
	encoded[0] = fixture.pub
	copy(encoded[1][:], fixture.signature[:32])

	for _, decode := range []struct {
		name   string
		active uint8
	}{
		{"A-only", 0b0001},
		{"paired-A-R", 0b0011},
	} {
		b.Run("decode="+decode.name, func(b *testing.B) {
			b.ReportAllocs()
			var point PointX4
			var mask uint8
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				mask, err = ExperimentalIFMADecodeX4(&point, &encoded, decode.active)
				if err != nil || mask&decode.active != decode.active {
					b.Fatalf("decode mask=%x err=%v", mask, err)
				}
			}
			benchmarkIFMADecodeOneX4Point = point
			benchmarkIFMADecodeOneX4Mask = mask
		})
	}

	// Prepare the identical Q once so this split reports only final-condition
	// cost. Complete-path benchmarks below remain the decision gate.
	var decoded PointX4
	if mask, err := ExperimentalIFMADecodeX4(&decoded, &encoded, 0b0011); err != nil || mask&0b0011 != 0b0011 {
		b.Fatalf("prepare decode mask=%x err=%v", mask, err)
	}
	a := decoded.Lane(0)
	var aTable quadNAFTable5X4
	if err := buildQuadNAFTable5X4(&aTable, &a, verifier.ops); err != nil {
		b.Fatal(err)
	}
	verifier.hash.Reset()
	_, _ = verifier.hash.Write(fixture.signature[:32])
	_, _ = verifier.hash.Write(fixture.pub[:])
	_, _ = verifier.hash.Write(fixture.message)
	verifier.hash.Sum(verifier.digest[:0])
	var wide [X4Lanes][64]byte
	wide[0] = verifier.digest
	var reduced [X4Lanes][32]byte
	if ExperimentalReduceUniformScalarsX4(&reduced, &wide, 1)&1 == 0 {
		b.Fatal("challenge reduction failed")
	}
	var s [32]byte
	copy(s[:], fixture.signature[32:])
	var q quadPackedPointX4
	if usable, err := evaluateQuadNAFVerifyX4(&q, &aTable, verifier.bTable, &s, &reduced[0], verifier.ops); err != nil || !usable {
		b.Fatalf("prepare DSM=(%v,%v)", usable, err)
	}

	b.Run("final=encoded-Q", func(b *testing.B) {
		b.ReportAllocs()
		var accepted bool
		b.ResetTimer()
		for iteration := 0; iteration < b.N; iteration++ {
			quadPackedPointAsLaneZeroX4(&verifier.encodePoints[0], &q)
			verifier.encodeActive[0] = 1
			if err := verifier.encoder.Encode(&verifier.encoded, &verifier.encodePoints, &verifier.encodeActive, 1); err != nil {
				b.Fatal(err)
			}
			accepted = bytes.Equal(verifier.encoded[0][0][:], fixture.signature[:32])
		}
		if !accepted {
			b.Fatal("literal finalizer rejected prepared Q")
		}
		benchmarkQuadPairedRResultX4 = accepted
	})

	b.Run("final=projective-R", func(b *testing.B) {
		b.ReportAllocs()
		var accepted bool
		b.ResetTimer()
		for iteration := 0; iteration < b.N; iteration++ {
			accepted, err = quadPackedEqualDecodedAffineLaneX4(&q, &decoded, 1, verifier.ops)
			if err != nil {
				b.Fatal(err)
			}
		}
		if !accepted {
			b.Fatal("projective finalizer rejected prepared Q")
		}
		benchmarkQuadPairedRResultX4 = accepted
	})
}

func BenchmarkExperimentalCoordinateParallelPairedRCompleteStrictX4(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skip("AVX-512 IFMA is unavailable")
	}
	for _, messageSize := range []int{64, 200, 1232} {
		fixture := newQuadStrictFixtureX4(b, messageSize)
		verifier, err := newQuadStrictVerifierX4()
		if err != nil {
			b.Fatal(err)
		}
		for _, candidate := range []struct {
			name   string
			verify func(*[32]byte, []byte, []byte) (bool, error)
		}{
			{"encoded-Q", verifier.verify},
			{"paired-projective-R", verifier.verifyPairedRProjective},
		} {
			b.Run("final="+candidate.name+"/msg="+quadMessageSizeLabelX4(messageSize), func(b *testing.B) {
				b.ReportAllocs()
				var accepted bool
				var verifyErr error
				b.ResetTimer()
				for iteration := 0; iteration < b.N; iteration++ {
					accepted, verifyErr = candidate.verify(&fixture.pub, fixture.message, fixture.signature)
					if verifyErr != nil || !accepted {
						b.Fatalf("honest signature=(%v,%v)", accepted, verifyErr)
					}
				}
				benchmarkQuadPairedRResultX4 = accepted
			})
		}
	}
}
