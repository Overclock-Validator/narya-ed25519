package r51x5

import (
	"bytes"
	stded25519 "crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"hash"
	"testing"
)

// quadStrictVerifierX4 is a test-only complete singleton gate for the packed
// width-5/width-8 NAF DSM. It deliberately keeps the fixed B table and hash
// object across calls, while every verification pays strict byte checks,
// public-key decompression, challenge hashing/reduction, the cold A table,
// the full DSM, canonical Q encoding, and the final R-byte comparison.
//
// The implementation remains in a test file until the complete-path result
// justifies promoting the packed point representation into ordinary package
// code. Production verification and dispatch cannot reach it.
type quadStrictVerifierX4 struct {
	ops          quadDSMOperationsX4
	bTable       quadNAFTable8X4
	hash         hash.Hash
	digest       [64]byte
	encoder      ExperimentalIFMABatchEncodeWorkspaceX4
	encodePoints [ExperimentalIFMABatchEncodeMaxX4Groups]IFMAPointX4
	encodeActive [ExperimentalIFMABatchEncodeMaxX4Groups]uint8
	encoded      [ExperimentalIFMABatchEncodeMaxX4Groups][X4Lanes][32]byte
}

func newQuadStrictVerifierX4() (*quadStrictVerifierX4, error) {
	var generatorEncoding [32]byte
	generatorEncoding[0] = 0x58
	for index := 1; index < len(generatorEncoding); index++ {
		generatorEncoding[index] = 0x66
	}
	var generator Point
	if _, err := generator.SetBytes(generatorEncoding[:]); err != nil {
		return nil, err
	}
	verifier := &quadStrictVerifierX4{
		ops:  quadDSMOperationsX4{hardware: true},
		hash: sha512.New(),
	}
	if err := buildQuadNAFTable8X4(&verifier.bTable, &generator, verifier.ops); err != nil {
		return nil, err
	}
	return verifier, nil
}

func (verifier *quadStrictVerifierX4) verify(pub *[32]byte, message, signature []byte) (bool, error) {
	if pub == nil || len(signature) != stded25519.SignatureSize {
		return false, nil
	}
	var s [32]byte
	copy(s[:], signature[32:])
	if !canonicalScalarBytes(&s) ||
		quadEncodesSmallOrderPointX4(pub[:]) ||
		quadEncodesSmallOrderPointX4(signature[:32]) ||
		!quadCanonicalRAfterSmallOrderCheckX4(signature[:32]) {
		return false, nil
	}

	var encodedA [X4Lanes][32]byte
	encodedA[0] = *pub
	var decodedA PointX4
	validA, err := ExperimentalIFMADecodeX4(&decodedA, &encodedA, 1)
	if err != nil {
		return false, err
	}
	if validA&1 == 0 {
		return false, nil
	}
	a := decodedA.Lane(0)
	var aTable quadNAFTable5X4
	if err := buildQuadNAFTable5X4(&aTable, &a, verifier.ops); err != nil {
		return false, err
	}

	verifier.hash.Reset()
	_, _ = verifier.hash.Write(signature[:32])
	_, _ = verifier.hash.Write(pub[:])
	_, _ = verifier.hash.Write(message)
	sum := verifier.hash.Sum(verifier.digest[:0])
	if len(sum) != len(verifier.digest) {
		panic("r51x5: SHA-512 returned an invalid digest length")
	}
	var wide [X4Lanes][64]byte
	wide[0] = verifier.digest
	var reduced [X4Lanes][32]byte
	if ExperimentalReduceUniformScalarsX4(&reduced, &wide, 1)&1 == 0 {
		return false, nil
	}

	var q quadPackedPointX4
	usable, err := evaluateQuadNAFVerifyX4(&q, &aTable, &verifier.bTable, &s, &reduced[0], verifier.ops)
	if err != nil || !usable {
		return false, err
	}
	quadPackedPointAsLaneZeroX4(&verifier.encodePoints[0], &q)
	verifier.encodeActive[0] = 1
	if err := verifier.encoder.Encode(&verifier.encoded, &verifier.encodePoints, &verifier.encodeActive, 1); err != nil {
		return false, err
	}
	return bytes.Equal(verifier.encoded[0][0][:], signature[:32]), nil
}

// quadPackedPointAsLaneZeroX4 transposes [X,Y,T,Z] coordinate lanes into one
// active signature lane without a scalar reduction boundary. Inactive lanes
// are valid identity points so the batch encoder's whole-point range check and
// denominator sanitization retain their ordinary contracts.
func quadPackedPointAsLaneZeroX4(out *IFMAPointX4, q *quadPackedPointX4) {
	*out = IFMAPointX4{}
	out.Y.limbs[0] = [X4Lanes]uint64{q.coordinates.limbs[0][1], 1, 1, 1}
	out.Z.limbs[0] = [X4Lanes]uint64{q.coordinates.limbs[0][3], 1, 1, 1}
	out.X.limbs[0][0] = q.coordinates.limbs[0][0]
	out.T.limbs[0][0] = q.coordinates.limbs[0][2]
	for limb := 1; limb < len(q.coordinates.limbs); limb++ {
		out.X.limbs[limb][0] = q.coordinates.limbs[limb][0]
		out.Y.limbs[limb][0] = q.coordinates.limbs[limb][1]
		out.T.limbs[limb][0] = q.coordinates.limbs[limb][2]
		out.Z.limbs[limb][0] = q.coordinates.limbs[limb][3]
	}
}

var (
	quadSmallOrderAlphaX4 = [32]byte{
		0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f,
		0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
		0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6,
		0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a,
	}
	quadSmallOrderNegAlphaX4 = [32]byte{
		0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0,
		0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
		0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39,
		0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05,
	}
)

func quadEncodesSmallOrderPointX4(encoded []byte) bool {
	if len(encoded) != 32 {
		return false
	}
	switch encoded[0] {
	case 0x00, 0x01:
		return quadLow255TailEqualX4(encoded, 0x00, 0x00)
	case 0x26:
		return quadLow255EqualX4(encoded, &quadSmallOrderNegAlphaX4)
	case 0xc7:
		return quadLow255EqualX4(encoded, &quadSmallOrderAlphaX4)
	case 0xec, 0xed, 0xee:
		return quadLow255TailEqualX4(encoded, 0xff, 0x7f)
	default:
		return false
	}
}

func quadLow255TailEqualX4(encoded []byte, middle, last byte) bool {
	diff := (encoded[31] & 0x7f) ^ last
	for index := 1; index < 31; index++ {
		diff |= encoded[index] ^ middle
	}
	return diff == 0
}

func quadLow255EqualX4(encoded []byte, want *[32]byte) bool {
	diff := (encoded[31] & 0x7f) ^ want[31]
	for index := 0; index < 31; index++ {
		diff |= encoded[index] ^ want[index]
	}
	return diff == 0
}

func quadCanonicalRAfterSmallOrderCheckX4(encoded []byte) bool {
	if len(encoded) != 32 {
		return false
	}
	if encoded[31]&0x7f != 0x7f {
		return true
	}
	for index := 30; index > 0; index-- {
		if encoded[index] != 0xff {
			return true
		}
	}
	return encoded[0] < 0xed
}

type quadStrictFixtureX4 struct {
	pub       [32]byte
	message   []byte
	signature []byte
}

func newQuadStrictFixtureX4(tb testing.TB, messageSize int) quadStrictFixtureX4 {
	tb.Helper()
	publicKey, privateKey, err := stded25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	fixture := quadStrictFixtureX4{message: make([]byte, messageSize)}
	copy(fixture.pub[:], publicKey)
	if _, err := rand.Read(fixture.message); err != nil {
		tb.Fatal(err)
	}
	fixture.signature = stded25519.Sign(privateKey, fixture.message)
	return fixture
}

func TestExperimentalCoordinateParallelNAFCompleteStrictX4(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("AVX-512 IFMA is unavailable")
	}
	verifier, err := newQuadStrictVerifierX4()
	if err != nil {
		t.Fatal(err)
	}
	for _, messageSize := range []int{0, 64, 200, 1232} {
		fixture := newQuadStrictFixtureX4(t, messageSize)
		accepted, err := verifier.verify(&fixture.pub, fixture.message, fixture.signature)
		if err != nil || !accepted {
			t.Fatalf("message=%d honest=(%v,%v)", messageSize, accepted, err)
		}

		badMessage := append([]byte(nil), fixture.message...)
		if len(badMessage) == 0 {
			badMessage = []byte{1}
		} else {
			badMessage[len(badMessage)/2] ^= 1
		}
		if accepted, err := verifier.verify(&fixture.pub, badMessage, fixture.signature); err != nil || accepted {
			t.Fatalf("message=%d mutated message=(%v,%v)", messageSize, accepted, err)
		}

		badSignature := append([]byte(nil), fixture.signature...)
		badSignature[7] ^= 0x40
		if accepted, err := verifier.verify(&fixture.pub, fixture.message, badSignature); err != nil || accepted {
			t.Fatalf("message=%d mutated signature=(%v,%v)", messageSize, accepted, err)
		}
	}
}

func TestExperimentalCoordinateParallelNAFCompleteStrictX4Prechecks(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("AVX-512 IFMA is unavailable")
	}
	verifier, err := newQuadStrictVerifierX4()
	if err != nil {
		t.Fatal(err)
	}
	fixture := newQuadStrictFixtureX4(t, 200)

	noncanonicalS := append([]byte(nil), fixture.signature...)
	copy(noncanonicalS[32:], scalarOrderBytes[:])
	if accepted, err := verifier.verify(&fixture.pub, fixture.message, noncanonicalS); err != nil || accepted {
		t.Fatalf("noncanonical S=(%v,%v)", accepted, err)
	}

	smallA := fixture.pub
	smallA = [32]byte{1}
	if accepted, err := verifier.verify(&smallA, fixture.message, fixture.signature); err != nil || accepted {
		t.Fatalf("small-order A=(%v,%v)", accepted, err)
	}

	smallR := append([]byte(nil), fixture.signature...)
	clear(smallR[:32])
	smallR[0] = 1
	if accepted, err := verifier.verify(&fixture.pub, fixture.message, smallR); err != nil || accepted {
		t.Fatalf("small-order R=(%v,%v)", accepted, err)
	}

	noncanonicalR := append([]byte(nil), fixture.signature...)
	for index := 0; index < 32; index++ {
		noncanonicalR[index] = 0xff
	}
	noncanonicalR[31] = 0x7f
	if accepted, err := verifier.verify(&fixture.pub, fixture.message, noncanonicalR); err != nil || accepted {
		t.Fatalf("noncanonical R=(%v,%v)", accepted, err)
	}
}

func TestExperimentalCoordinateParallelNAFCompleteStrictX4ZeroAllocations(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("AVX-512 IFMA is unavailable")
	}
	verifier, err := newQuadStrictVerifierX4()
	if err != nil {
		t.Fatal(err)
	}
	fixture := newQuadStrictFixtureX4(t, 200)
	if allocations := testing.AllocsPerRun(20, func() {
		accepted, err := verifier.verify(&fixture.pub, fixture.message, fixture.signature)
		if err != nil || !accepted {
			panic("r51x5: complete packed verifier rejected honest signature")
		}
	}); allocations != 0 {
		t.Fatalf("allocations=%v want 0", allocations)
	}
}

var benchmarkQuadStrictResultX4 bool

func BenchmarkExperimentalCoordinateParallelNAFCompleteStrictX4(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skip("AVX-512 IFMA is unavailable")
	}
	for _, messageSize := range []int{64, 200, 1232} {
		fixture := newQuadStrictFixtureX4(b, messageSize)
		verifier, err := newQuadStrictVerifierX4()
		if err != nil {
			b.Fatal(err)
		}
		b.Run("msg="+quadMessageSizeLabelX4(messageSize), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			var accepted bool
			var verifyErr error
			for iteration := 0; iteration < b.N; iteration++ {
				accepted, verifyErr = verifier.verify(&fixture.pub, fixture.message, fixture.signature)
				if verifyErr != nil || !accepted {
					b.Fatalf("honest signature=(%v,%v)", accepted, verifyErr)
				}
			}
			benchmarkQuadStrictResultX4 = accepted
		})
	}
}

func quadMessageSizeLabelX4(size int) string {
	switch size {
	case 64:
		return "64"
	case 200:
		return "200"
	case 1232:
		return "1232"
	default:
		panic("r51x5: unexpected benchmark message size")
	}
}
