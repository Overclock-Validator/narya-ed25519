// Package sha512mb computes SHA-512 over batches of independent
// messages. Digests are bit-identical to crypto/sha512; the batch API
// exists so a vector kernel can hash Lanes() messages in parallel
// across SIMD lanes. Without one (non-amd64, or CPUs without AVX-512),
// the batch degrades to a loop over the standard library, so the
// package is correct on every platform and the kernel is purely a
// speedup.
package sha512mb

import "crypto/sha512"

// Lanes reports how many messages one batch hashes in parallel.
// Callers should not assume a particular value: it is 1 without a
// vector kernel and 8 with the AVX-512 one.
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
