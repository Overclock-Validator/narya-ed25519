package ed25519

import (
	"sync/atomic"

	"github.com/Overclock-Validator/narya-ed25519/internal/sigprep"
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

// rules maps a Profile onto the byte-level acceptance policy that the shared
// preparation stage applies. The equation each profile evaluates is chosen by
// the backend; everything decidable from encodings alone lives in the Rules.
func (p Profile) rules() sigprep.Rules {
	switch p {
	case DalekStrict:
		return sigprep.DalekStrict
	case StdlibCompat:
		return sigprep.StdlibCompat
	default:
		panic("ed25519: unknown verification profile")
	}
}

// rejectedByStrict reports whether the strict profile rejects this
// signature for a reason StdlibCompat does not: a small-order public
// key A, or a small-order signature point R. smallOrderEncoding is an
// exact classification of the encodings that the permissive decoder maps
// to one of the eight small-order points. All other encodings, including
// ones that do not decode, are left for the equation to reject.
//
// This is the small-order half of sigprep.DalekStrict only. The canonical-R
// gate is applied separately by backends that compare points instead of
// re-encoding, so it is deliberately not folded in here.
func rejectedByStrict(pub *[32]byte, sig []byte) bool {
	if smallOrderEncoding(pub[:]) {
		return true
	}
	if len(sig) == 64 && smallOrderEncoding(sig[:32]) {
		return true
	}
	return false
}

// The byte-level predicates themselves live in internal/sigprep, which owns the
// whole scalar front half of verification for every backend and every profile.
// These are the in-package spellings.
func smallOrderEncoding(b []byte) bool { return sigprep.SmallOrderEncoding(b) }

func canonicalREncoding(r []byte) bool { return sigprep.CanonicalREncoding(r) }
