package ed25519

import (
	"sync/atomic"

	"github.com/Overclock-Validator/narya/internal/edwards25519"
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

// A future ZIP215 profile (SIMD-0376, cofactored) will join these once
// its feature gate is assigned on mainnet; it is a slot-activated
// loosening, so it must not become the default until then.

var defaultProfile atomic.Uint32 // Profile; zero value == DalekStrict

// SetDefaultProfile sets the profile used by the package-level Verify,
// VerifyBatch, and by any Cache that has not overridden it.
func SetDefaultProfile(p Profile) { defaultProfile.Store(uint32(p)) }

// DefaultProfile reports the current package-level profile.
func DefaultProfile() Profile { return Profile(defaultProfile.Load()) }

// rejectedByStrict reports whether the strict profile rejects this
// signature for a reason StdlibCompat does not: a small-order public
// key A, or a small-order signature point R. Both are decoded exactly
// as ed25519-dalek decodes them (permissive, non-canonical accepted);
// an encoding that does not decode is not small-order here and is left
// for the equation to reject, matching dalek's own ordering of checks.
func rejectedByStrict(pub *[32]byte, sig []byte) bool {
	if smallOrderEncoding(pub[:]) {
		return true
	}
	if len(sig) == 64 && smallOrderEncoding(sig[:32]) {
		return true
	}
	return false
}

func smallOrderEncoding(b []byte) bool {
	var p edwards25519.Point
	if _, err := p.SetBytes(b); err != nil {
		return false
	}
	return p.IsSmallOrder()
}
