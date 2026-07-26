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
	// DalekStrict is current Solana mainnet transaction semantics:
	// StdlibCompat plus rejection of small-order A and small-order R.
	// This is the default.
	//
	// The reference is ed25519-dalek 2.x verify_strict, reached through
	// solana-signature. Naming the version matters, because the two dalek
	// majors differ in the final step: 2.x byte-compares the recomputed R
	// against the signature, which is what this profile does, while 1.x
	// compares decoded points and so accepts a non-canonically encoded R.
	// solana-signature took the 2.x dependency at its own 3.0.0.
	//
	// Verified against agave v4.2.0-beta.1, whose lockfile resolves
	// solana-signature 3.4.1 onto ed25519-dalek 2.2.0. Note that lockfile also
	// contains ed25519-dalek 1.0.1 for other dependents, so reading the version
	// list alone is not enough to establish which one transaction verification
	// reaches.
	//
	// Releases old enough to pin solana-signature 2.x resolve dalek 1.0.1 and
	// are therefore marginally more permissive than this profile about
	// non-canonical R. That divergence is one-directional and is not known to
	// be constructible: the non-canonical y values that decode are either
	// small-order, which both sides reject, or of unknown discrete log, so
	// producing a matching s is not a forgery anyone can perform. Those
	// releases are out of scope here.
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
