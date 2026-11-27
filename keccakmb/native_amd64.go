//go:build amd64

package keccakmb

import "golang.org/x/sys/cpu"

// The kernel uses only AVX-512F instructions on ZMM registers: VPTERNLOGQ,
// VPROLQ, VPXORQ, VMOVDQU64, VMOVDQA64 and VPBROADCASTQ.
func nativeX8Available() bool { return cpu.X86.HasAVX512F }

// permuteX8Native applies Keccak-f[1600] to the eight instances of s.
//
//go:noescape
func permuteX8Native(s *StateX8)

// absorbX8Native XORs one block per lane into s and permutes, blocks times.
// Lane j reads words 64-bit words from ptrs[j] + k*strides[j] for block k.
// words must be 17 or 21 and blocks at least 1.
//
//go:noescape
func absorbX8Native(s *StateX8, ptrs *[Lanes]*byte, strides *[Lanes]uint64, words, blocks int)

// squeezeX8Native permutes s first when permute is nonzero, then writes the
// first words 64-bit words of each lane j to out[j]. words must be 17 or 21.
//
//go:noescape
func squeezeX8Native(s *StateX8, out *[Lanes][200]byte, words, permute int)
