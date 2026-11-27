// Package keccakmb computes Keccak sponges over batches of independent
// messages. Outputs are bit-identical to crypto/sha3 (SHA3-256, SHAKE128,
// SHAKE256) and to the legacy pre-standard Keccak-256 used by Ethereum and
// the Solana sol_keccak256 syscall and secp256k1 precompile.
//
// The package mirrors sha512mb. The portable entry points are a loop over a
// scalar reference sponge on every platform and never dispatch. The AVX-512
// eight-lane permutation is reached only through the Experimental entry
// points, which report false when the kernel cannot run on this machine.
//
// Consumers in view are the secp256k1 precompile (two legacy Keccak-256
// hashes per signature), the sol_keccak256 syscall, and Falcon (FN-DSA)
// verification, whose hash-to-point step squeezes about 1.1 KB of SHAKE256
// output per signature.
package keccakmb

import "math/bits"

// Lanes is the width of the native multi-buffer permutation.
const Lanes = 8

// roundConstants are the 24 iota constants of Keccak-f[1600]. The assembly
// kernel reads this array directly, so it stays a fixed-size array.
var roundConstants = [24]uint64{
	0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
	0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
	0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
	0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
	0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
	0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
}

// laneOffsets are the byte offsets of the eight lanes of a
// [Lanes][200]byte squeeze buffer. The squeeze kernel scatters through them.
var laneOffsets = [Lanes]uint64{0, 200, 400, 600, 800, 1000, 1200, 1400}

// rhoOffsets[x+5y] is the rho rotation of lane (x, y), from FIPS 202 3.2.2.
var rhoOffsets = [25]uint{
	0, 1, 62, 28, 27,
	36, 44, 6, 55, 20,
	3, 10, 43, 25, 39,
	41, 45, 15, 21, 8,
	18, 2, 61, 56, 14,
}

// permute1 is Keccak-f[1600] written step by step as in FIPS 202 section 3.2,
// indexing lane (x, y) as a[x+5y]. It is the reference the multi-buffer
// kernels are tested against, so it favors clarity over speed.
func permute1(a *[25]uint64) {
	for round := 0; round < 24; round++ {
		// theta
		var c, d [5]uint64
		for x := 0; x < 5; x++ {
			c[x] = a[x] ^ a[x+5] ^ a[x+10] ^ a[x+15] ^ a[x+20]
		}
		for x := 0; x < 5; x++ {
			d[x] = c[(x+4)%5] ^ bits.RotateLeft64(c[(x+1)%5], 1)
		}
		for i := 0; i < 25; i++ {
			a[i] ^= d[i%5]
		}
		// rho and pi: B[y, 2x+3y] = rot(A[x, y], r[x, y])
		var b [25]uint64
		for x := 0; x < 5; x++ {
			for y := 0; y < 5; y++ {
				b[y+5*((2*x+3*y)%5)] = bits.RotateLeft64(a[x+5*y], int(rhoOffsets[x+5*y]))
			}
		}
		// chi
		for y := 0; y < 5; y++ {
			for x := 0; x < 5; x++ {
				a[x+5*y] = b[x+5*y] ^ (^b[(x+1)%5+5*y] & b[(x+2)%5+5*y])
			}
		}
		// iota
		a[0] ^= roundConstants[round]
	}
}

// StateX8 holds eight independent Keccak-f[1600] states, lane-sliced:
// s[i][j] is word i (lane (i%5, i/5)) of instance j. One row is one ZMM
// register in the native kernel.
type StateX8 [25][Lanes]uint64

// permuteX8Generic applies Keccak-f[1600] to each instance of s.
func permuteX8Generic(s *StateX8) {
	for j := 0; j < Lanes; j++ {
		var a [25]uint64
		for i := range a {
			a[i] = s[i][j]
		}
		permute1(&a)
		for i := range a {
			s[i][j] = a[i]
		}
	}
}

// PermuteX8Generic applies Keccak-f[1600] to all eight instances of s with
// the portable reference. It never dispatches.
func PermuteX8Generic(s *StateX8) { permuteX8Generic(s) }

// ExperimentalNativeAvailable reports whether the AVX-512 eight-lane
// permutation can run on this machine.
func ExperimentalNativeAvailable() bool { return nativeX8Available() }

// ExperimentalPermuteX8 applies Keccak-f[1600] to all eight instances of s
// with the AVX-512 kernel. It returns false, leaving s untouched, when that
// kernel is unavailable.
func ExperimentalPermuteX8(s *StateX8) bool {
	if !nativeX8Available() {
		return false
	}
	permuteX8Native(s)
	return true
}
