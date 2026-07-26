package r51x5

import (
	stded25519 "crypto/ed25519"
	"crypto/sha512"
	"errors"
	"hash"
	"sync"
)

var errExperimentalPackedStrictVerifierUninitialized = errors.New("r51x5: experimental packed strict verifier is uninitialized")

// ExperimentalPackedStrictVerifierX4 is a reusable, coordinate-parallel
// singleton verifier for the Dalek strict Ed25519 predicate. Its four IFMA
// lanes hold A, R, and then the X/Y/T/Z coordinates of the DSM accumulator.
// A and R therefore share one lane-parallel square-root schedule, and the
// final equality uses both projective cross-products without an inversion.
//
// The verifier hashes the original compressed R and A bytes, permits a
// noncanonical but decodable A, requires canonical R, rejects pure small-order
// A and R (including accepted aliases), and evaluates [s]B-[k]A with exact
// signed-integer semantics. It is experimental: an explicit r51 adapter may
// consume it, but automatic backend selection remains on the generic path.
//
// A verifier owns mutable hash state and is not safe for concurrent use. Use
// one instance per goroutine. Its zero value is invalid; construct it with
// NewExperimentalPackedStrictVerifierX4.
type ExperimentalPackedStrictVerifierX4 struct {
	ops    quadDSMOperationsX4
	bTable *quadNAFTable8X4
	hash   hash.Hash
	digest [sha512.Size]byte
}

// The generator table is immutable after construction. Sharing it keeps every
// verifier worker on the same 10 KiB read-only working set instead of building
// and retaining an allocator-dependent copy per worker.
var packedStrictGeneratorTableX4 struct {
	once  sync.Once
	table quadNAFTable8X4
	err   error
}

// NewExperimentalPackedStrictVerifierX4 prepares the process-wide generator
// table for one reusable strict singleton verifier. It returns
// ErrIFMAUnavailable when the current machine cannot execute the required
// AVX-512 IFMA/AVX-512VL instructions.
func NewExperimentalPackedStrictVerifierX4() (*ExperimentalPackedStrictVerifierX4, error) {
	if !ExperimentalIFMAAvailable() {
		return nil, ErrIFMAUnavailable
	}

	ops := quadDSMOperationsX4{hardware: true}
	packedStrictGeneratorTableX4.once.Do(func() {
		var generatorEncoding [32]byte
		generatorEncoding[0] = 0x58
		for index := 1; index < len(generatorEncoding); index++ {
			generatorEncoding[index] = 0x66
		}
		var generator Point
		if _, err := generator.SetBytes(generatorEncoding[:]); err != nil {
			packedStrictGeneratorTableX4.err = err
			return
		}
		packedStrictGeneratorTableX4.err = buildQuadNAFTable8X4(&packedStrictGeneratorTableX4.table, &generator, ops)
	})
	if packedStrictGeneratorTableX4.err != nil {
		return nil, packedStrictGeneratorTableX4.err
	}

	return &ExperimentalPackedStrictVerifierX4{
		ops:    ops,
		bTable: &packedStrictGeneratorTableX4.table,
		hash:   sha512.New(),
	}, nil
}

// Verify reports whether signature is valid for message and pub under the
// Dalek strict predicate. It returns arithmetic/platform errors separately
// from ordinary invalid inputs, which return (false, nil).
func (verifier *ExperimentalPackedStrictVerifierX4) Verify(pub *[32]byte, message, signature []byte) (bool, error) {
	if verifier == nil || verifier.hash == nil {
		return false, errExperimentalPackedStrictVerifierUninitialized
	}

	var s [32]byte
	if !packedStrictBytePrechecksX4(pub, signature, &s) {
		return false, nil
	}

	// Lane zero decodes A and lane one decodes R. The decoder performs one
	// square-root schedule across the two live lanes. Keep the original bytes
	// untouched for the challenge hash below.
	var encoded [X4Lanes][32]byte
	encoded[0] = *pub
	copy(encoded[1][:], signature[:32])
	var decoded PointX4
	valid, err := ExperimentalIFMADecodeX4(&decoded, &encoded, 0b0011)
	if err != nil {
		return false, err
	}
	if valid&0b0011 != 0b0011 {
		return false, nil
	}

	a := decoded.Lane(0)
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

	var wide [X4Lanes][sha512.Size]byte
	wide[0] = verifier.digest
	var reduced [X4Lanes][32]byte
	if ExperimentalReduceUniformScalarsX4(&reduced, &wide, 1)&1 == 0 {
		return false, nil
	}

	var q quadPackedPointX4
	usable, err := evaluateQuadNAFVerifyX4(&q, &aTable, verifier.bTable, &s, &reduced[0], verifier.ops)
	if err != nil || !usable {
		return false, err
	}
	return quadPackedEqualDecodedAffineLaneX4(&q, &decoded, 1, verifier.ops)
}

func packedStrictBytePrechecksX4(pub *[32]byte, signature []byte, s *[32]byte) bool {
	if pub == nil || len(signature) != stded25519.SignatureSize {
		return false
	}
	copy(s[:], signature[32:])
	if !canonicalScalarBytes(s) ||
		packedEncodesSmallOrderPointX4(pub[:]) ||
		packedEncodesSmallOrderPointX4(signature[:32]) {
		return false
	}
	// Canonicality independently rejects the x=0/sign-bit-one anomaly; the
	// preceding classifier remains the separate strict small-order policy.
	return packedCanonicalREncodingX4(signature[:32])
}

// quadPackedEqualDecodedAffineLaneX4 compares Q=[X,Y,T,Z] with one decoded
// affine lane using X_Q=x_R*Z_Q and Y_Q=y_R*Z_Q. Both cross-products occupy
// one field multiplication. Canonical reductions make equality modulo p,
// rather than equality of redundant IFMA limb representatives.
func quadPackedEqualDecodedAffineLaneX4(q *quadPackedPointX4, decoded *PointX4, decodedLane int, ops quadDSMOperationsX4) (bool, error) {
	checkLane(decodedLane, X4Lanes)
	if !isIFMAElementX4(&q.coordinates) {
		return false, errIFMAComposableInputRange
	}
	qReduced := q.coordinates.Reduced()
	qz := qReduced.Lane(3)
	if qz.IsZero() != 0 {
		return false, nil
	}

	var affineXY, qZ IFMAElementX4
	for limb := range affineXY.limbs {
		affineXY.limbs[limb][0] = decoded.X.limbs[limb][decodedLane]
		affineXY.limbs[limb][1] = decoded.Y.limbs[limb][decodedLane]
		qZ.limbs[limb][0] = q.coordinates.limbs[limb][3]
		qZ.limbs[limb][1] = q.coordinates.limbs[limb][3]
	}
	var cross IFMAElementX4
	if err := ops.multiply(&cross, &affineXY, &qZ); err != nil {
		return false, err
	}
	crossReduced := cross.Reduced()
	qx, qy := qReduced.Lane(0), qReduced.Lane(1)
	rxZ, ryZ := crossReduced.Lane(0), crossReduced.Lane(1)
	return qx.Equal(&rxZ)&qy.Equal(&ryZ) != 0, nil
}

var (
	packedSmallOrderAlphaX4 = [32]byte{
		0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f,
		0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
		0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6,
		0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a,
	}
	packedSmallOrderNegAlphaX4 = [32]byte{
		0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0,
		0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
		0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39,
		0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05,
	}
)

// ExperimentalEncodesSmallOrderPoint exposes the packed strict small-order
// classifier so another package can assert it against the one the generic
// backend uses.
//
// The two are independent copies of the same fourteen byte strings. Nothing in
// the type system ties them together, so a one-byte edit to either would make
// the generic and r51 backends disagree about which public keys are acceptable,
// which is a consensus split rather than a local bug. This export exists so
// that divergence is caught by a test instead of by a fork.
func ExperimentalEncodesSmallOrderPoint(encoded []byte) bool {
	return packedEncodesSmallOrderPointX4(encoded)
}

func packedEncodesSmallOrderPointX4(encoded []byte) bool {
	if len(encoded) != 32 {
		return false
	}
	switch encoded[0] {
	case 0x00, 0x01:
		return packedLow255TailEqualX4(encoded, 0x00, 0x00)
	case 0x26:
		return packedLow255EqualX4(encoded, &packedSmallOrderNegAlphaX4)
	case 0xc7:
		return packedLow255EqualX4(encoded, &packedSmallOrderAlphaX4)
	case 0xec, 0xed, 0xee:
		return packedLow255TailEqualX4(encoded, 0xff, 0x7f)
	default:
		return false
	}
}

func packedLow255TailEqualX4(encoded []byte, middle, last byte) bool {
	diff := (encoded[31] & 0x7f) ^ last
	for index := 1; index < 31; index++ {
		diff |= encoded[index] ^ middle
	}
	return diff == 0
}

func packedLow255EqualX4(encoded []byte, want *[32]byte) bool {
	diff := (encoded[31] & 0x7f) ^ want[31]
	for index := 0; index < 31; index++ {
		diff |= encoded[index] ^ want[index]
	}
	return diff == 0
}

func packedCanonicalREncodingX4(encoded []byte) bool {
	if len(encoded) != 32 {
		return false
	}
	if !packedLow255LessThanPX4(encoded) {
		return false
	}
	if encoded[31]&0x80 == 0 {
		return true
	}
	if encoded[0] == 0x01 && packedLow255TailEqualX4(encoded, 0x00, 0x00) {
		return false
	}
	if encoded[0] == 0xec && packedLow255TailEqualX4(encoded, 0xff, 0x7f) {
		return false
	}
	return true
}

func packedLow255LessThanPX4(encoded []byte) bool {
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
