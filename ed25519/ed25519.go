// Package ed25519 verifies Ed25519 signatures with acceptance behavior
// bit-identical to crypto/ed25519.Verify, accelerated for workloads
// where signers recur: a Cache holds a per-key precomputed table for
// hot public keys, which removes the doubling chain from verification.
// Backends are selected at runtime; the portable one is pure Go over
// the vendored crypto/ed25519 internals, so the two implementations
// agree on every decoding edge case by construction.
//
// Acceptance equality with the standard library is the load-bearing
// contract: in consensus use an accept/reject flip is a fork. It is
// enforced by differential tests across every backend, cached or not.
package ed25519

// Verify reports whether sig is a valid signature of message by pub,
// with the exact acceptance behavior of crypto/ed25519.Verify.
func Verify(pub *[32]byte, message, sig []byte) bool {
	return active().verify(pub, message, sig, nil)
}

// PrecomputedKey accelerates repeated verifications under one public
// key. It is immutable and safe for concurrent use. The representation
// belongs to the backend that built it; a Cache never mixes backends
// because exactly one backend is active per process.
type PrecomputedKey struct {
	raw   [32]byte
	table any   // backend-native table; nil means plain verification
	size  int64 // memory footprint, for Cache accounting
}

// Precompute builds the acceleration table for pub. A non-nil error
// means pub does not decode as a curve point — every Verify against
// such a key returns false — which callers may negative-cache.
func Precompute(pub *[32]byte) (*PrecomputedKey, error) {
	return active().buildPrecomp(pub)
}

// Verify reports whether sig is a valid signature of message by the
// precomputed key, exactly like the package-level Verify.
func (k *PrecomputedKey) Verify(message, sig []byte) bool {
	return active().verify(&k.raw, message, sig, k)
}
