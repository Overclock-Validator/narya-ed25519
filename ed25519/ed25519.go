// Package ed25519 verifies Ed25519 signatures under a versioned
// acceptance Profile, accelerated for workloads where signers recur: a
// Cache holds a per-key precomputed table for hot public keys, which
// removes the doubling chain from verification. Backends are selected
// at runtime; the portable one is pure Go over the vendored
// crypto/ed25519 internals, so they agree on every decoding edge case.
//
// The acceptance predicate is the load-bearing contract: in consensus
// use an accept/reject flip is a fork. The default profile, DalekStrict,
// is current Solana mainnet semantics (ed25519-dalek verify_strict);
// StdlibCompat is exactly crypto/ed25519.Verify. Equality with the
// chosen profile is enforced by differential tests across every
// backend, cached or not.
package ed25519

import "errors"

// ErrInvalidPublicKey is returned when a precomputation request does not
// provide a public key. Bool-returning verification APIs fail closed instead.
var ErrInvalidPublicKey = errors.New("ed25519: nil public key")

// Verify reports whether sig is a valid signature of message by pub
// under the default profile (DalekStrict — current Solana mainnet
// transaction semantics).
func Verify(pub *[32]byte, message, sig []byte) bool {
	return verifyOne(active(), DefaultProfile(), pub, message, sig, nil)
}

// VerifyStrict reports whether sig is a valid signature of message by
// pub under DalekStrict semantics, regardless of the package default
// profile. It takes byte slices so it is a drop-in for
// crypto/ed25519.Verify at consensus P2P sites (gossip, shreds,
// repair) that must always reject small-order points; a wrong-length
// pub yields false rather than panicking. Use this rather than Verify
// where the semantics must not depend on mutable global state.
func VerifyStrict(pub, message, sig []byte) bool {
	if len(pub) != 32 {
		return false
	}
	return verifyOne(active(), DalekStrict, (*[32]byte)(pub), message, sig, nil)
}

// verifyOne applies the given profile's shared rejection pre-pass,
// then asks the backend to evaluate that profile's equation. Every
// non-cache single-signature entry point funnels through here so the
// pre-pass cannot be bypassed.
func verifyOne(b backend, profile Profile, pub *[32]byte, message, sig []byte, pre *PrecomputedKey) bool {
	if rejectedByProfile(profile, pub, sig) {
		return false
	}
	return b.verify(profile, pub, message, sig, pre)
}

// VerifyBatch verifies n independent signatures, writing each verdict
// to ok[i]; ok[i] is exactly what Verify(pubs[i], msgs[i], sigs[i])
// would return. The slice lengths must all be equal (the caller supplies ok
// so a hot loop can reuse it). Returns true iff every verdict is true. Batch
// backends may process independent items in parallel, but never combine them
// into one aggregate equation, so verdicts remain per-signature.
func VerifyBatch(pubs []*[32]byte, msgs, sigs [][]byte, ok []bool) bool {
	return verifyBatch(active(), DefaultProfile(), pubs, msgs, sigs, ok, nil)
}

// VerifyBatchStrict verifies n independent signatures under
// DalekStrict semantics, regardless of the package default profile.
// Its inputs, per-item verdicts, return value, and length checks match
// VerifyBatch.
func VerifyBatchStrict(pubs []*[32]byte, msgs, sigs [][]byte, ok []bool) bool {
	return verifyBatch(active(), DalekStrict, pubs, msgs, sigs, ok, nil)
}

func verifyBatch(b backend, profile Profile, pubs []*[32]byte, msgs, sigs [][]byte, ok []bool, lookup func(*[32]byte) *PrecomputedKey) bool {
	checkBatchLengths(pubs, msgs, sigs, ok)
	if lookup == nil {
		if raw, supported := b.(rawBatchBackend); supported {
			return raw.verifyBatchRaw(profile, pubs, msgs, sigs, ok)
		}
	}
	items := makeItemsUnchecked(pubs, msgs, sigs)
	applyProfile(profile, items)
	if lookup != nil {
		for i := range items {
			if !items[i].skip {
				items[i].pre = lookup(items[i].pub)
			}
		}
	}
	b.verifyBatch(profile, items)
	return collect(items, ok)
}

func makeItems(pubs []*[32]byte, msgs, sigs [][]byte, ok []bool) []batchItem {
	checkBatchLengths(pubs, msgs, sigs, ok)
	return makeItemsUnchecked(pubs, msgs, sigs)
}

func makeItemsUnchecked(pubs []*[32]byte, msgs, sigs [][]byte) []batchItem {
	items := make([]batchItem, len(pubs))
	for i := range items {
		items[i] = batchItem{pub: pubs[i], msg: msgs[i], sig: sigs[i]}
	}
	return items
}

func checkBatchLengths(pubs []*[32]byte, msgs, sigs [][]byte, ok []bool) {
	if len(pubs) != len(msgs) || len(msgs) != len(sigs) || len(sigs) != len(ok) {
		panic("ed25519: VerifyBatch slice lengths differ")
	}
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
	if pub == nil {
		return nil, ErrInvalidPublicKey
	}
	return active().buildPrecomp(pub)
}

// Verify reports whether sig is a valid signature of message by the
// precomputed key, exactly like the package-level Verify.
func (k *PrecomputedKey) Verify(message, sig []byte) bool {
	if k == nil {
		return false
	}
	return verifyOne(active(), DefaultProfile(), &k.raw, message, sig, k)
}

// VerifyStrict reports whether sig is valid under DalekStrict semantics,
// regardless of the package default profile. It is the prepared-key analogue
// of VerifyStrict and returns false for a nil receiver.
func (k *PrecomputedKey) VerifyStrict(message, sig []byte) bool {
	if k == nil {
		return false
	}
	return verifyOne(active(), DalekStrict, &k.raw, message, sig, k)
}
