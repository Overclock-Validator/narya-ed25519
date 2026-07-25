package ed25519

import (
	"sync/atomic"
)

// Profile selects which acceptance predicate verification enforces.
// It exists because the consensus-correct predicate is versioned: an
// accept/reject flip is a fork, so the semantics are a deliberate
// choice, not an implementation detail.
type Profile uint8

const (
	// DalekStrict is current Solana mainnet transaction semantics
	// (ed25519-dalek 2.x verify_strict, reached via solana-signature):
	// StdlibCompat plus rejection of small-order A and small-order R.
	// This is the default.
	DalekStrict Profile = iota

	// StdlibCompat is exactly crypto/ed25519.Verify: canonical s,
	// permissive A decoding, R re-encoded and byte-compared, and no
	// small-order rejection. Solana accepts a strict subset of this,
	// so StdlibCompat is for differential testing and for callers who
	// explicitly want standard-library behavior — not for verifying
	// mainnet transactions.
	StdlibCompat
)

// A future ZIP215 profile (SIMD-0376, cofactored) can join these only after
// the proposal is accepted and a mainnet feature gate is assigned. Library
// availability is not an activation signal. The change is a slot-activated
// loosening, so it must not become the default before that gate.

var defaultProfile atomic.Uint32 // Profile; zero value == DalekStrict

// SetDefaultProfile sets the profile used by the package-level Verify
// and VerifyBatch and by every Cache. It does not affect VerifyStrict,
// which is always DalekStrict. Intended to be set once at startup. An unknown
// profile is a programmer/configuration error and panics before changing the
// process default; silently treating it as a weaker profile would be unsafe
// for consensus callers.
func SetDefaultProfile(p Profile) {
	if !p.valid() {
		panic("ed25519: unknown verification profile")
	}
	defaultProfile.Store(uint32(p))
}

// DefaultProfile reports the current package-level profile.
func DefaultProfile() Profile { return Profile(defaultProfile.Load()) }

func (p Profile) valid() bool {
	return p == DalekStrict || p == StdlibCompat
}

// rejectedByStrict reports whether the strict profile rejects this
// signature for a reason StdlibCompat does not: a small-order public
// key A, or a small-order signature point R. smallOrderEncoding is an
// exact classification of the encodings that the permissive decoder maps
// to one of the eight small-order points. All other encodings, including
// ones that do not decode, are left for the equation to reject.
func rejectedByStrict(pub *[32]byte, sig []byte) bool {
	if smallOrderEncoding(pub[:]) {
		return true
	}
	if len(sig) == 64 && smallOrderEncoding(sig[:32]) {
		return true
	}
	return false
}

// The permissive Edwards25519 decoder ignores the sign bit and reduces the
// encoded y-coordinate modulo p. Its small-order points therefore have exactly
// these seven low-255-bit encodings: 0, 1, p-1, p, p+1, and the two y values
// of the order-eight points. The sign bit is immaterial for all seven values.
var (
	smallOrderAlpha = [32]byte{
		0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f,
		0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
		0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6,
		0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a,
	}
	smallOrderNegAlpha = [32]byte{
		0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0,
		0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
		0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39,
		0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05,
	}
)

func smallOrderEncoding(b []byte) bool {
	if len(b) != 32 {
		return false
	}

	// The seven values have distinct first bytes, so almost every input exits
	// after this switch without a full 255-bit comparison.
	switch b[0] {
	case 0x00, 0x01:
		return low255TailEqual(b, 0x00, 0x00)
	case 0x26:
		return low255Equal(b, &smallOrderNegAlpha)
	case 0xc7:
		return low255Equal(b, &smallOrderAlpha)
	case 0xec, 0xed, 0xee:
		return low255TailEqual(b, 0xff, 0x7f)
	default:
		return false
	}
}

func low255TailEqual(b []byte, middle, last byte) bool {
	diff := (b[31] & 0x7f) ^ last
	for i := 1; i < 31; i++ {
		diff |= b[i] ^ middle
	}
	return diff == 0
}

func low255Equal(b []byte, want *[32]byte) bool {
	diff := (b[31] & 0x7f) ^ want[31]
	for i := 0; i < 31; i++ {
		diff |= b[i] ^ want[i]
	}
	return diff == 0
}

// canonicalREncoding reports whether r satisfies the decoder-specific byte
// canonicality condition used by strict verification. It is independent of
// small-order rejection: besides requiring low255(r) < p, it rejects the two
// sign-bit-one encodings whose decoded x coordinate is zero (y=1 and y=-1).
//
// Point decoding remains a separate requirement. A reduced byte string that
// is not on the curve can pass this helper and must still fail decoding.
func canonicalREncoding(r []byte) bool {
	if len(r) != 32 {
		return false
	}
	if !low255LessThanP(r) {
		return false
	}
	if r[31]&0x80 == 0 {
		return true
	}
	// On Edwards25519, x=0 iff y=1 or y=-1. Their sign-bit-one forms decode
	// permissively but are not canonical compressed encodings.
	if r[0] == 0x01 && low255TailEqual(r, 0x00, 0x00) {
		return false
	}
	if r[0] == 0xec && low255TailEqual(r, 0xff, 0x7f) {
		return false
	}
	return true
}

// low255LessThanP compares the encoded little-endian y-coordinate with
// p=2^255-19 while ignoring the compressed x-sign bit.
func low255LessThanP(encoded []byte) bool {
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
