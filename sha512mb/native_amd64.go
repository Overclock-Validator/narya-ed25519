//go:build amd64

package sha512mb

import "golang.org/x/sys/cpu"

func nativeX4Available() bool { return cpu.X86.HasAVX2 }

// nativeX8Available also requires AVX-512VL: nativeCompressVerifierFirstX8Rolling
// loads the 32-byte R and A segments with VMOVDQU64 into a YMM register, which
// has no VEX form and so assembles as EVEX.256. That encoding faults with #UD
// unless VL is present. Every shipping part with AVX-512BW also has VL, so this
// term only matters where CPUID is synthesized, but the exported availability
// helpers promise a kernel that is safe to execute on this machine.
func nativeX8Available() bool {
	return cpu.X86.HasAVX512F && cpu.X86.HasAVX512VL && cpu.X86.HasAVX512BW
}

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

// nativeCompress2X8Expanded is the component gate for interlacing two
// independent x8 SHA-512 waves on a native-512-bit core. Unlike the production
// rolling kernel, it expands both schedules into memory so the sixteen working
// state vectors can remain live together. The experiment decides whether
// latency hidden between the two round chains repays that schedule traffic.
// stateA and stateB must be distinct. Each state may alias its corresponding
// block because both blocks are copied before either state is written.
//
// The two-wave organization is adapted from tape-sha256's Zen 5 AVX-512
// interlace experiment (spool-labs/sha256 commit 39c1fea62015a723f19a2ed9e906926b3be770b8).
// SHA-512 has eight 64-bit lanes per wave rather than SHA-256's sixteen 32-bit
// lanes, so this entry processes sixteen independent messages.
//
//go:noescape
func nativeCompress2X8Expanded(stateA *nativeStateX8, blockA *nativeBlockX8, stateB *nativeStateX8, blockB *nativeBlockX8)

//go:noescape
func nativeTransposeCompressX8Rolling(state *nativeStateX8, ptrs *[nativeX8Width]*byte, initial uint64)

// nativeCompressVerifierFirstX8Rolling initializes state and compresses the
// fixed-layout verifier prefix R[32] || A[32] || message[:64] directly from
// three pointer vectors.
//
//go:noescape
func nativeCompressVerifierFirstX8Rolling(state *nativeStateX8, rPtrs, aPtrs, messagePtrs *[nativeX8Width]*byte)

// nativeCompressFinalX8Rolling compresses the exact SHA-512 final-block shapes
// whose variable prefix contains zero, one, or two complete 64-bit words.
// tail is already transposed and expressed as host uint64 values equal to the
// corresponding big-endian SHA words.
//
//go:noescape
func nativeCompressFinalX8Rolling(state *nativeStateX8, tail *nativeTailX8, tailWords, totalBits uint64)

//go:noescape
func nativeTransposeX8(block *nativeBlockX8, raw *[nativeX8Width][128]byte)

//go:noescape
func nativeTransposePointersX8(block *nativeBlockX8, ptrs *[nativeX8Width]*byte)
