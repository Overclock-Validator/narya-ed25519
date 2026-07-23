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

// Verify reports whether sig is a valid signature of message by pub
// under the default profile (DalekStrict — current Solana mainnet
// transaction semantics).
func Verify(pub *[32]byte, message, sig []byte) bool {
	return verifyOne(active(), pub, message, sig, nil)
}

// verifyOne applies the active profile's strict rejections, then the
// backend's stdlib-semantics equation. Every single-signature entry
// point funnels through here so the profile cannot be bypassed.
func verifyOne(b backend, pub *[32]byte, message, sig []byte, pre *PrecomputedKey) bool {
	if DefaultProfile() == DalekStrict && rejectedByStrict(pub, sig) {
		return false
	}
	return b.verify(pub, message, sig, pre)
}

// VerifyBatch verifies n independent signatures, writing each verdict
// to ok[i]; ok[i] is exactly what Verify(pubs[i], msgs[i], sigs[i])
// would return. The slice lengths must all be equal (the caller
// supplies ok so a hot loop can reuse it). Returns true iff every
// verdict is true. Batching amortizes hashing and decoding; it never
// combines signatures into one equation, so verdicts are per-signature.
func VerifyBatch(pubs []*[32]byte, msgs, sigs [][]byte, ok []bool) bool {
	items := makeItems(pubs, msgs, sigs, ok)
	applyStrictProfile(items)
	active().verifyBatch(items, nil)
	return collect(items, ok)
}

func makeItems(pubs []*[32]byte, msgs, sigs [][]byte, ok []bool) []batchItem {
	if len(pubs) != len(msgs) || len(msgs) != len(sigs) || len(sigs) != len(ok) {
		panic("ed25519: VerifyBatch slice lengths differ")
	}
	items := make([]batchItem, len(pubs))
	for i := range items {
		items[i] = batchItem{pub: pubs[i], msg: msgs[i], sig: sigs[i]}
	}
	return items
}

func collect(items []batchItem, ok []bool) bool {
	all := true
	for i := range items {
		ok[i] = items[i].ok
		all = all && items[i].ok
	}
	return all
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
	return verifyOne(active(), &k.raw, message, sig, k)
}
