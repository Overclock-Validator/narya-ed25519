package keccakmb

import (
	"crypto/sha3"
	"fmt"
	"testing"
)

// BenchmarkPermute compares eight Keccak-f[1600] permutations: eight calls of
// the scalar reference, the portable x8 loop, and the AVX-512 kernel.
func BenchmarkPermute(b *testing.B) {
	var s StateX8
	b.Run("impl=reference/perms=8", func(b *testing.B) {
		var a [25]uint64
		for b.Loop() {
			for range Lanes {
				permute1(&a)
			}
		}
	})
	b.Run("impl=native-x8/perms=8", func(b *testing.B) {
		if !ExperimentalNativeAvailable() {
			b.Skip("AVX-512 kernel unavailable")
		}
		for b.Loop() {
			permuteX8Native(&s)
		}
	})
}

// BenchmarkHash hashes eight messages per operation with crypto/sha3 and
// with the native batch path. msg=64 is the secp256k1 public-key hash;
// msg=1232 is a full legacy-size Solana transaction; the shake256 rows
// squeeze 1,088 bytes after a 40-byte nonce, the scale of Falcon-512
// hash-to-point.
func BenchmarkHash(b *testing.B) {
	for _, tc := range []struct {
		name   string
		v      Variant
		msg    int
		outLen int
	}{
		{"sha3-256", SHA3_256, 64, 32},
		{"sha3-256", SHA3_256, 1232, 32},
		{"shake256", SHAKE256, 40 + 64, 1088},
		{"shake256", SHAKE256, 40 + 1232, 1088},
	} {
		msgs := make([][][]byte, Lanes)
		out := make([][]byte, Lanes)
		for j := range msgs {
			m := make([]byte, tc.msg)
			m[0] = byte(j)
			msgs[j] = [][]byte{m}
			out[j] = make([]byte, tc.outLen)
		}
		suffix := fmt.Sprintf("%s/msg=%d/out=%d/lanes=8", tc.name, tc.msg, tc.outLen)
		b.Run("impl=stdlib/"+suffix, func(b *testing.B) {
			b.SetBytes(int64(Lanes * tc.msg))
			for b.Loop() {
				for j := range msgs {
					if tc.v == SHA3_256 {
						d := sha3.Sum256(msgs[j][0])
						copy(out[j], d[:])
					} else {
						h := sha3.NewSHAKE256()
						h.Write(msgs[j][0])
						h.Read(out[j])
					}
				}
			}
		})
		// The permutation kernel with the portable Go absorb and squeeze
		// loops, to isolate what the gather absorb and scatter squeeze save.
		b.Run("impl=native-x8-go-sponge/"+suffix, func(b *testing.B) {
			if !ExperimentalNativeAvailable() {
				b.Skip("AVX-512 kernel unavailable")
			}
			b.SetBytes(int64(Lanes * tc.msg))
			var x SpongeX8
			for b.Loop() {
				x.absorb(tc.v, msgs, permuteX8Native)
				x.squeezeInto(out)
			}
		})
		b.Run("impl=native-x8/"+suffix, func(b *testing.B) {
			if !ExperimentalNativeAvailable() {
				b.Skip("AVX-512 kernel unavailable")
			}
			b.SetBytes(int64(Lanes * tc.msg))
			for b.Loop() {
				ExperimentalSumBatch(tc.v, out, msgs)
			}
		})
	}
}
