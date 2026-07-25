//go:build amd64

package sha512mb

import "golang.org/x/sys/cpu"

func nativeX4Available() bool { return cpu.X86.HasAVX2 }
func nativeX8Available() bool { return cpu.X86.HasAVX512F && cpu.X86.HasAVX512BW }

// nativeCompressX4 applies one SHA-512 compression block to four independent
// states. block is transposed: block[word][lane].
//
//go:noescape
func nativeCompressX4(state *nativeStateX4, block *nativeBlockX4)

// nativeCompressX8 is the AVX-512F/ZMM analogue of nativeCompressX4.
//
//go:noescape
func nativeCompressX8(state *nativeStateX8, block *nativeBlockX8)

// nativeCompressX8Rolling is the rolling-register-schedule candidate.
//
//go:noescape
func nativeCompressX8Rolling(state *nativeStateX8, block *nativeBlockX8)

//go:noescape
func nativeTransposeX8(block *nativeBlockX8, raw *[nativeX8Width][128]byte)

//go:noescape
func nativeTransposePointersX8(block *nativeBlockX8, ptrs *[nativeX8Width]*byte)
