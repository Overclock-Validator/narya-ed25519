// Package sigprep is the front half of Ed25519 verification: everything from
// raw bytes up to the reduced challenge scalar, with no curve arithmetic and no
// backend-native representation.
//
// # Why this is a separate stage
//
// Every backend needs the same sequence before it can evaluate anything: check
// the signature length, split it into R and S, reject a non-canonical S, apply
// whatever byte-level gates the predicate demands, and compute
// k = H(R ‖ A ‖ M) mod l. Before this package that sequence was written three
// times, once per backend, each spelled slightly differently and each fused
// into its own verification equation. A predicate change therefore had three
// edit sites and no single place to test.
//
// The split also matters for what comes next. The parts of verification that
// differ between predicates are the byte-level gates and the group equation.
// Everything in between is common. Expressing the gates as data (Rules) rather
// than as a switch on a profile enum means a new predicate contributes a Rules
// value and an equation, and inherits this stage unchanged.
//
// Concretely, for the three predicates that matter to a Solana client:
//
//	                   small-order A   small-order R   canonical R   equation
//	DalekStrict        reject          reject          require       cofactorless
//	StdlibCompat       accept          accept          accept        cofactorless
//	ZIP215             accept          accept          accept        cofactored
//
// StdlibCompat and ZIP215 have identical byte-level rules and differ only in
// the equation, so a cofactored predicate needs no new front-half code at all.
// That is the reason this package can be built and tested now, ahead of any
// decision about whether the cofactored predicate is ever activated.
//
// # What this package deliberately does not own
//
// Point decompression stays with the backends. A decoded point is a
// backend-native representation (an extended point in radix-51 limbs is 160
// bytes; the portable backend's is a different shape entirely), and forcing
// those behind a shared interface would cost more than the duplication it
// removes. See DecodedKeys for the seam a decoded-A cache attaches to.
//
// Scalar reduction of the challenge digest is available here (Reduce) but is
// not mandatory: the vector backends reduce eight digests at once, which is a
// measured win this package must not take away. Those callers use
// ChallengeSegments and reduce the digests themselves.
package sigprep

import (
	"crypto/sha512"

	"github.com/Overclock-Validator/narya-ed25519/internal/edwards25519"
)

// SignatureSize is the length every Ed25519 signature must have.
const SignatureSize = 64

// Rules is the byte-level acceptance policy of a verification predicate: the
// checks that can be decided from the encodings alone, before any curve
// arithmetic. The group equation is not represented here because it is not a
// byte-level decision; see the package comment for how the two compose.
//
// Callers should use one of the predeclared values rather than assembling a
// Rules literal. The fields are exported so the differences between predicates
// are readable at a glance, not so that arbitrary combinations become supported
// configurations.
type Rules struct {
	// RejectSmallOrderA rejects a public key whose encoding decodes to one of
	// the eight small-order points. Without it, a signature verifies under the
	// identity public key for any message, with no private key involved.
	RejectSmallOrderA bool

	// RejectSmallOrderR rejects a signature whose R encoding decodes to a
	// small-order point.
	RejectSmallOrderR bool

	// RequireCanonicalR requires R to be the canonical compressed encoding of
	// its point. A backend that re-encodes its computed R and byte-compares
	// gets this for free; one that compares points must apply it explicitly or
	// it accepts encodings mainnet rejects.
	RequireCanonicalR bool
}

var (
	// DalekStrict is Agave v4 transaction semantics (solana-signature 3.3.0,
	// resolving ed25519-dalek 2.2.0). The Agave v4 Ed25519 precompile is a
	// separate dalek-1.0.1 call path and is not this Rules value's contract.
	DalekStrict = Rules{
		RejectSmallOrderA: true,
		RejectSmallOrderR: true,
		RequireCanonicalR: true,
	}

	// StdlibCompat is exactly crypto/ed25519.Verify: no gate beyond a canonical
	// S, with R settled by re-encoding and byte comparison.
	StdlibCompat = Rules{}

	// ZIP215 is the cofactored predicate proposed for Solana by SIMD-0376.
	// Its byte-level rules are identical to StdlibCompat; only the equation
	// differs. It is declared here because that identity is the load-bearing
	// claim of this package, and a test pins it.
	//
	// This is not an activation signal. SIMD-0376 is in Review and has no
	// mainnet feature gate, and no equation in this repository consumes these
	// rules yet.
	ZIP215 = Rules{}
)

// Prepared is one signature that has passed every byte-level gate, carrying the
// values a group equation needs. It holds no curve points, so it is independent
// of both backend and equation.
type Prepared struct {
	// R is the signature's first half, the encoded commitment point. It is the
	// original bytes: no gate in this package may rewrite it, because it is
	// also hash input.
	R [32]byte

	// S is the signature's second half, guaranteed canonical and less than l.
	S [32]byte

	// K is H(R ‖ A ‖ M) reduced modulo l. Zero unless the value was produced by
	// a function that computes the challenge; Admit and Parse leave it unset.
	K [32]byte
}

// Admit reports whether the byte-level gates accept this signature under rules.
// It performs no hashing, so it is the cheap pre-pass a batch former runs to
// find out which items are worth hashing at all.
//
// A nil public key is rejected. Every bool-returning verification entry point
// in this module fails closed on a missing key, and keeping that here makes the
// behavior backend- and predicate-independent.
func Admit(rules Rules, pub *[32]byte, sig []byte) bool {
	if pub == nil || len(sig) != SignatureSize {
		return false
	}
	if rules.RejectSmallOrderA && SmallOrderEncoding(pub[:]) {
		return false
	}
	if rules.RejectSmallOrderR && SmallOrderEncoding(sig[:32]) {
		return false
	}
	if rules.RequireCanonicalR && !CanonicalREncoding(sig[:32]) {
		return false
	}
	return CanonicalScalarEncoding(sig[32:])
}

// Parse applies the byte-level gates and splits an admitted signature into its
// R and S halves. It does not hash. ok is false exactly when Admit is false.
func Parse(rules Rules, pub *[32]byte, sig []byte) (out Prepared, ok bool) {
	if !Admit(rules, pub, sig) {
		return Prepared{}, false
	}
	copy(out.R[:], sig[:32])
	copy(out.S[:], sig[32:])
	return out, true
}

// ChallengeSegments returns the three hash inputs of k = H(R ‖ A ‖ M) in order.
//
// It exists so the concatenation order is written once. The segments are kept
// separate rather than joined because the multi-buffer hash consumes them that
// way, and because R and A must be hashed as the original byte strings: a
// non-canonical A is accepted by the permissive decoder but must still be
// hashed exactly as it arrived, so no caller may substitute a re-encoded form.
func ChallengeSegments(pub *[32]byte, msg, sig []byte) [3][]byte {
	return [3][]byte{sig[:32], pub[:], msg}
}

// Challenge computes the unreduced 64-byte challenge digest for one signature.
func Challenge(pub *[32]byte, msg, sig []byte) [64]byte {
	h := sha512.New()
	segments := ChallengeSegments(pub, msg, sig)
	for _, segment := range segments {
		_, _ = h.Write(segment)
	}
	var digest [64]byte
	h.Sum(digest[:0])
	return digest
}

// Reducer holds the scratch scalar used to reduce challenge digests, so a hot
// loop reducing many digests allocates nothing. The zero value is ready to use
// and is not safe for concurrent use; keep one per worker.
type Reducer struct {
	scratch *edwards25519.Scalar
}

// Reduce reduces a 64-byte challenge digest modulo l, using the vendored
// Edwards implementation's independently tested wide reduction.
//
// Vector backends reduce whole groups of digests at once and should not call
// this per item; it is the scalar spelling, for single verification and for
// reference paths.
func (r *Reducer) Reduce(digest *[64]byte, out *[32]byte) {
	if r.scratch == nil {
		r.scratch = edwards25519.NewScalar()
	}
	if _, err := r.scratch.SetUniformBytes(digest[:]); err != nil {
		// SetUniformBytes rejects only a wrong input length, which is
		// impossible here. Failing closed keeps the error from becoming a
		// silent zero scalar, which would verify against a forged R.
		panic("sigprep: wide scalar reduction rejected a 64-byte digest")
	}
	r.scratch.BytesInto(out)
}

// Reduce is the one-shot spelling of Reducer.Reduce.
func Reduce(digest *[64]byte) [32]byte {
	var out [32]byte
	var reducer Reducer
	reducer.Reduce(digest, &out)
	return out
}

// Prepare runs the whole scalar front half for one signature: gates, split, and
// reduced challenge. ok is false exactly when Admit is false.
func Prepare(rules Rules, pub *[32]byte, msg, sig []byte) (Prepared, bool) {
	out, ok := Parse(rules, pub, sig)
	if !ok {
		return Prepared{}, false
	}
	digest := Challenge(pub, msg, sig)
	out.K = Reduce(&digest)
	return out, true
}

// DecodedKeys is the seam a decoded-public-key cache attaches to. Nothing in
// this package implements it; it names the shape so the tier has one definition
// rather than one per backend.
//
// The motivation is that decoding A costs a field exponentiation for the square
// root, and a recurring signer pays it on every signature. Retaining the
// decoded point instead is roughly 160 bytes per key for an extended point in
// radix-51 limbs, two orders of magnitude smaller than the per-key comb table,
// with no minimum group width and no requirement that a group be homogeneous.
// Those two constraints are what make the comb tier hard to fill on diverse
// fee-payer traffic, and this tier has neither.
//
// The value type is deliberately backend-native and opaque here: only the
// backend that produced a decoded point can consume it, exactly as with
// PrecomputedKey. Whether this tier pays depends on signer recurrence in real
// traffic, which is unmeasured; this declaration commits to nothing but the
// shape.
type DecodedKeys interface {
	// DecodedA returns the backend-native decoded form of pub, or nil if the
	// key is not retained. A nil return is always safe: the caller decodes.
	DecodedA(pub *[32]byte) any
}
