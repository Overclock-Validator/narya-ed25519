package sha512mb

import (
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"testing"
)

// Hashing is the recurrence-independent part of every verification: k =
// H(R ‖ A ‖ M). This benchmark reports per-message cost for the scalar
// single-stream path (crypto/sha512) against the batch API, so once the
// AVX-512 multi-buffer kernel lands its win over the scalar loop is
// measured here directly. Message sizes span the prefix-only case up to
// the Solana packet cap; the 64-byte R‖A prefix is included.
func BenchmarkHash(b *testing.B) {
	for _, sz := range []int{0, 200, 1232} {
		prefix := make([]byte, 64) // R (32) ‖ A (32)
		msg := make([]byte, sz)
		rand.Read(prefix)
		rand.Read(msg)

		b.Run(fmt.Sprintf("impl=crypto-sha512/msg=%d", sz), func(b *testing.B) {
			var out [64]byte
			for i := 0; i < b.N; i++ {
				h := sha512.New()
				h.Write(prefix)
				h.Write(msg)
				h.Sum(out[:0])
			}
		})

		lanes := Lanes()
		b.Run(fmt.Sprintf("impl=sha512mb-x%d/msg=%d", lanes, sz), func(b *testing.B) {
			out := make([][64]byte, lanes)
			batch := make([][][]byte, lanes)
			for i := range batch {
				batch[i] = [][]byte{prefix, msg}
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				Sum512Batch(out, batch)
			}
			// Per-message, so lanes are comparable to the scalar path.
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*lanes), "ns/msg")
		})
	}
}
