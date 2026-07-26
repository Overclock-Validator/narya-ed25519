// Package sha512mb computes SHA-512 over batches of independent messages.
// Digests are bit-identical to crypto/sha512; the batch API exists so a vector
// kernel can hash several messages at once across SIMD lanes.
//
// The stable surface here — Lanes, Sum512, Sum512Batch — is the portable scalar
// implementation on every platform, including hosts that have the vector
// kernels. It does not dispatch. The AVX2 x4 and AVX-512 x8 kernels live behind
// the hardware-gated Experimental entry points in this package and are reached
// only by a caller that asks for them by width; today that is the forced r51
// verifier backend and nothing else.
//
// That split is deliberate while the kernels are experimental, but it does mean
// a batch hashed through Sum512Batch is a loop over the standard library no
// matter what the CPU supports.
package sha512mb

import "crypto/sha512"

// Lanes reports how many messages the stable batch entry point hashes in
// parallel. It is 1, because Sum512Batch is the portable scalar loop; the
// vector kernels are reached through the Experimental entry points instead.
// Callers should treat any batch size as acceptable rather than grouping work
// to this value.
func Lanes() int { return 1 }

// Sum512 writes SHA-512(parts[0] ‖ parts[1] ‖ …) to out. Taking the
// message in parts lets a verifier hash R ‖ A ‖ M without assembling a
// contiguous buffer.
func Sum512(out *[64]byte, parts ...[]byte) {
	h := sha512.New()
	for _, p := range parts {
		h.Write(p)
	}
	h.Sum(out[:0])
}

// Sum512Batch computes SHA-512 for every message in msgs, where each
// message is the concatenation of its parts, writing the digest to the
// corresponding out entry. len(out) must equal len(msgs); any batch
// size is accepted.
func Sum512Batch(out [][64]byte, msgs [][][]byte) {
	if len(out) != len(msgs) {
		panic("sha512mb: out/msgs length mismatch")
	}
	for i := range msgs {
		Sum512(&out[i], msgs[i]...)
	}
}
