//go:build amd64

#include "textflag.h"
#include "native_amd64_transpose.h"

DATA nativePaddingWord<>+0(SB)/8, $0x8000000000000000
GLOBL nativePaddingWord<>(SB), RODATA|NOPTR, $8

// ROUND8R is the register-schedule SHA-512 round. The eight working words
// rotate through Z0..Z7 by changing macro arguments. W is one of Z16..Z31.
#define ROUND8R(A, B, C, D, E, F, G, H, W, K) \
	VPRORQ $14, E, Z8;                          \
	VPRORQ $18, E, Z9;                          \
	VPXORQ Z9, Z8, Z8;                          \
	VPRORQ $41, E, Z9;                          \
	VPXORQ Z9, Z8, Z8;                          \
	VMOVDQA64 E, Z10;                            \
	VPTERNLOGQ $0xca, G, F, Z10;                 \
	VPADDQ H, Z8, Z8;                           \
	VPADDQ Z10, Z8, Z8;                         \
	VPBROADCASTQ K(BP), Z15;                    \
	VPADDQ Z15, Z8, Z8;                         \
	VPADDQ W, Z8, Z8;                           \
	VPRORQ $28, A, Z9;                          \
	VPRORQ $34, A, Z11;                         \
	VPXORQ Z11, Z9, Z9;                         \
	VPRORQ $39, A, Z11;                         \
	VPXORQ Z11, Z9, Z9;                         \
	VMOVDQA64 A, Z10;                            \
	VPTERNLOGQ $0xe8, C, B, Z10;                 \
	VPADDQ Z10, Z9, Z9;                         \
	VPADDQ Z8, D, D;                            \
	VPADDQ Z9, Z8, H

// EXPAND8 replaces W0 = W[t-16] with W[t]. W1, W9, and W14 are the
// current ring slots for W[t-15], W[t-7], and W[t-2]. Z12..Z15 are scratch;
// ROUND8R overwrites Z15 with the round constant after expansion.
#define EXPAND8(W0, W1, W9, W14)          \
	VPRORQ $1, W1, Z12;                     \
	VPRORQ $8, W1, Z13;                     \
	VPSRLQ $7, W1, Z14;                     \
	VPTERNLOGQ $0x96, Z14, Z13, Z12;        \
	VPRORQ $19, W14, Z13;                   \
	VPRORQ $61, W14, Z14;                   \
	VPSRLQ $6, W14, Z15;                    \
	VPTERNLOGQ $0x96, Z15, Z14, Z13;        \
	VPADDQ Z12, W0, W0;                     \
	VPADDQ W9, W0, W0;                      \
	VPADDQ Z13, W0, W0

// func nativeCompressX8Rolling(state *nativeStateX8, block *nativeBlockX8)
//
// Requires AVX-512F. The sixteen-word SHA-512 message schedule remains in
// Z16..Z31 and is updated as a rolling ring, avoiding the 5 KiB expanded
// schedule and its stack traffic. All block vectors are loaded before state
// is read or written, so state and block may overlap exactly as in the
// reference nativeCompressX8 implementation.
TEXT ·nativeCompressX8Rolling(SB), 0, $0-16
	MOVQ block+8(FP), SI
	VMOVDQU64   0(SI), Z16
	VMOVDQU64  64(SI), Z17
	VMOVDQU64 128(SI), Z18
	VMOVDQU64 192(SI), Z19
	VMOVDQU64 256(SI), Z20
	VMOVDQU64 320(SI), Z21
	VMOVDQU64 384(SI), Z22
	VMOVDQU64 448(SI), Z23
	VMOVDQU64 512(SI), Z24
	VMOVDQU64 576(SI), Z25
	VMOVDQU64 640(SI), Z26
	VMOVDQU64 704(SI), Z27
	VMOVDQU64 768(SI), Z28
	VMOVDQU64 832(SI), Z29
	VMOVDQU64 896(SI), Z30
	VMOVDQU64 960(SI), Z31

	MOVQ state+0(FP), DI
	VMOVDQU64   0(DI), Z0
	VMOVDQU64  64(DI), Z1
	VMOVDQU64 128(DI), Z2
	VMOVDQU64 192(DI), Z3
	VMOVDQU64 256(DI), Z4
	VMOVDQU64 320(DI), Z5
	VMOVDQU64 384(DI), Z6
	VMOVDQU64 448(DI), Z7
	MOVQ $·nativeRoundConstants(SB), BP
	JMP nativeCompressX8RollingRounds<>(SB)

// func nativeTransposeCompressX8Rolling(state *nativeStateX8, ptrs *[nativeX8Width]*byte, initial uint64)
//
// Requires AVX-512F and AVX-512BW. Every pointer must address at least 128
// readable bytes. Input rows are byte-swapped and transposed directly into
// the sixteen-register W ring, avoiding the intermediate 1 KiB nativeBlockX8
// store and reload. All input vectors are loaded before state is written, so
// exact state/input aliasing has the same safe contract as the split path.
TEXT ·nativeTransposeCompressX8Rolling(SB), 0, $0-24
	MOVQ ptrs+8(FP), SI
	MOVQ  0(SI), AX
	MOVQ  8(SI), CX
	MOVQ 16(SI), DX
	MOVQ 24(SI), BX
	MOVQ 32(SI), R8
	MOVQ 40(SI), R9
	MOVQ 48(SI), R10
	MOVQ 56(SI), R11
	VMOVDQU64 ·nativeByteSwapMaskX8(SB), Z31

	VMOVDQU64 0(AX), Z0
	VMOVDQU64 0(CX), Z1
	VMOVDQU64 0(DX), Z2
	VMOVDQU64 0(BX), Z3
	VMOVDQU64 0(R8), Z4
	VMOVDQU64 0(R9), Z5
	VMOVDQU64 0(R10), Z6
	VMOVDQU64 0(R11), Z7
	VPSHUFB Z31, Z0, Z0
	VPSHUFB Z31, Z1, Z1
	VPSHUFB Z31, Z2, Z2
	VPSHUFB Z31, Z3, Z3
	VPSHUFB Z31, Z4, Z4
	VPSHUFB Z31, Z5, Z5
	VPSHUFB Z31, Z6, Z6
	VPSHUFB Z31, Z7, Z7
	TRANSPOSE8(Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z16, Z17, Z18, Z19, Z20, Z21, Z22, Z23, Z8, Z9, Z10, Z11, Z12, Z13, Z14, Z15)

	VMOVDQU64 64(AX), Z0
	VMOVDQU64 64(CX), Z1
	VMOVDQU64 64(DX), Z2
	VMOVDQU64 64(BX), Z3
	VMOVDQU64 64(R8), Z4
	VMOVDQU64 64(R9), Z5
	VMOVDQU64 64(R10), Z6
	VMOVDQU64 64(R11), Z7
	VMOVDQU64 ·nativeByteSwapMaskX8(SB), Z31
	VPSHUFB Z31, Z0, Z0
	VPSHUFB Z31, Z1, Z1
	VPSHUFB Z31, Z2, Z2
	VPSHUFB Z31, Z3, Z3
	VPSHUFB Z31, Z4, Z4
	VPSHUFB Z31, Z5, Z5
	VPSHUFB Z31, Z6, Z6
	VPSHUFB Z31, Z7, Z7
	TRANSPOSE8(Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z24, Z25, Z26, Z27, Z28, Z29, Z30, Z31, Z8, Z9, Z10, Z11, Z12, Z13, Z14, Z15)

	MOVQ state+0(FP), DI
	MOVQ initial+16(FP), SI
	TESTQ SI, SI
	JZ fusedLoadState
	MOVQ $·nativeInitialState(SB), SI
	VPBROADCASTQ   0(SI), Z0
	VPBROADCASTQ   8(SI), Z1
	VPBROADCASTQ  16(SI), Z2
	VPBROADCASTQ  24(SI), Z3
	VPBROADCASTQ  32(SI), Z4
	VPBROADCASTQ  40(SI), Z5
	VPBROADCASTQ  48(SI), Z6
	VPBROADCASTQ  56(SI), Z7
	VMOVDQU64 Z0,   0(DI)
	VMOVDQU64 Z1,  64(DI)
	VMOVDQU64 Z2, 128(DI)
	VMOVDQU64 Z3, 192(DI)
	VMOVDQU64 Z4, 256(DI)
	VMOVDQU64 Z5, 320(DI)
	VMOVDQU64 Z6, 384(DI)
	VMOVDQU64 Z7, 448(DI)
	JMP fusedStateReady
fusedLoadState:
	VMOVDQU64   0(DI), Z0
	VMOVDQU64  64(DI), Z1
	VMOVDQU64 128(DI), Z2
	VMOVDQU64 192(DI), Z3
	VMOVDQU64 256(DI), Z4
	VMOVDQU64 320(DI), Z5
	VMOVDQU64 384(DI), Z6
	VMOVDQU64 448(DI), Z7
fusedStateReady:
	MOVQ $·nativeRoundConstants(SB), BP
	JMP nativeCompressX8RollingRounds<>(SB)

// func nativeCompressFinalX8Rolling(state *nativeStateX8, tail *nativeTailX8, tailWords, totalBits uint64)
//
// Requires AVX-512F. tailWords must be 0, 1, or 2. tail already contains
// the transposed host-uint64 values of the big-endian SHA words. The remaining
// words are the SHA-512 padding bit, zeros, and the 64-bit low message length;
// all supported verifier inputs have a zero high message-length word.
TEXT ·nativeCompressFinalX8Rolling(SB), 0, $0-32
	VPXORQ Z31, Z31, Z31
	VMOVDQA64 Z31, Z16
	VMOVDQA64 Z31, Z17
	VMOVDQA64 Z31, Z18
	VMOVDQA64 Z31, Z19
	VMOVDQA64 Z31, Z20
	VMOVDQA64 Z31, Z21
	VMOVDQA64 Z31, Z22
	VMOVDQA64 Z31, Z23
	VMOVDQA64 Z31, Z24
	VMOVDQA64 Z31, Z25
	VMOVDQA64 Z31, Z26
	VMOVDQA64 Z31, Z27
	VMOVDQA64 Z31, Z28
	VMOVDQA64 Z31, Z29
	VMOVDQA64 Z31, Z30

	MOVQ tail+8(FP), SI
	MOVQ tailWords+16(FP), AX
	CMPQ AX, $0
	JE finalTailZero
	VMOVDQU64 0(SI), Z16
	CMPQ AX, $1
	JE finalTailOne
	VMOVDQU64 64(SI), Z17
	VPBROADCASTQ nativePaddingWord<>(SB), Z18
	JMP finalTailReady
finalTailZero:
	VPBROADCASTQ nativePaddingWord<>(SB), Z16
	JMP finalTailReady
finalTailOne:
	VPBROADCASTQ nativePaddingWord<>(SB), Z17
finalTailReady:
	MOVQ totalBits+24(FP), AX
	VMOVQ AX, X15
	VPBROADCASTQ X15, Z31

	MOVQ state+0(FP), DI
	VMOVDQU64   0(DI), Z0
	VMOVDQU64  64(DI), Z1
	VMOVDQU64 128(DI), Z2
	VMOVDQU64 192(DI), Z3
	VMOVDQU64 256(DI), Z4
	VMOVDQU64 320(DI), Z5
	VMOVDQU64 384(DI), Z6
	VMOVDQU64 448(DI), Z7
	MOVQ $·nativeRoundConstants(SB), BP
	JMP nativeCompressX8RollingRounds<>(SB)

// All public assembly entry points arrive here with W[0..15] in Z16..Z31,
// the current state in Z0..Z7, DI pointing at the original state, and BP
// pointing at the scalar round constants. Tail jumps preserve the Go caller's
// return address, so this shared body returns directly to Go.
TEXT nativeCompressX8RollingRounds<>(SB), NOSPLIT, $0-0

	ROUND8R(Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z16,   0)
	ROUND8R(Z7, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z17,   8)
	ROUND8R(Z6, Z7, Z0, Z1, Z2, Z3, Z4, Z5, Z18,  16)
	ROUND8R(Z5, Z6, Z7, Z0, Z1, Z2, Z3, Z4, Z19,  24)
	ROUND8R(Z4, Z5, Z6, Z7, Z0, Z1, Z2, Z3, Z20,  32)
	ROUND8R(Z3, Z4, Z5, Z6, Z7, Z0, Z1, Z2, Z21,  40)
	ROUND8R(Z2, Z3, Z4, Z5, Z6, Z7, Z0, Z1, Z22,  48)
	ROUND8R(Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z0, Z23,  56)
	ROUND8R(Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z24,  64)
	ROUND8R(Z7, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z25,  72)
	ROUND8R(Z6, Z7, Z0, Z1, Z2, Z3, Z4, Z5, Z26,  80)
	ROUND8R(Z5, Z6, Z7, Z0, Z1, Z2, Z3, Z4, Z27,  88)
	ROUND8R(Z4, Z5, Z6, Z7, Z0, Z1, Z2, Z3, Z28,  96)
	ROUND8R(Z3, Z4, Z5, Z6, Z7, Z0, Z1, Z2, Z29, 104)
	ROUND8R(Z2, Z3, Z4, Z5, Z6, Z7, Z0, Z1, Z30, 112)
	ROUND8R(Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z0, Z31, 120)

	EXPAND8(Z16, Z17, Z25, Z30); ROUND8R(Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z16, 128)
	EXPAND8(Z17, Z18, Z26, Z31); ROUND8R(Z7, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z17, 136)
	EXPAND8(Z18, Z19, Z27, Z16); ROUND8R(Z6, Z7, Z0, Z1, Z2, Z3, Z4, Z5, Z18, 144)
	EXPAND8(Z19, Z20, Z28, Z17); ROUND8R(Z5, Z6, Z7, Z0, Z1, Z2, Z3, Z4, Z19, 152)
	EXPAND8(Z20, Z21, Z29, Z18); ROUND8R(Z4, Z5, Z6, Z7, Z0, Z1, Z2, Z3, Z20, 160)
	EXPAND8(Z21, Z22, Z30, Z19); ROUND8R(Z3, Z4, Z5, Z6, Z7, Z0, Z1, Z2, Z21, 168)
	EXPAND8(Z22, Z23, Z31, Z20); ROUND8R(Z2, Z3, Z4, Z5, Z6, Z7, Z0, Z1, Z22, 176)
	EXPAND8(Z23, Z24, Z16, Z21); ROUND8R(Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z0, Z23, 184)
	EXPAND8(Z24, Z25, Z17, Z22); ROUND8R(Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z24, 192)
	EXPAND8(Z25, Z26, Z18, Z23); ROUND8R(Z7, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z25, 200)
	EXPAND8(Z26, Z27, Z19, Z24); ROUND8R(Z6, Z7, Z0, Z1, Z2, Z3, Z4, Z5, Z26, 208)
	EXPAND8(Z27, Z28, Z20, Z25); ROUND8R(Z5, Z6, Z7, Z0, Z1, Z2, Z3, Z4, Z27, 216)
	EXPAND8(Z28, Z29, Z21, Z26); ROUND8R(Z4, Z5, Z6, Z7, Z0, Z1, Z2, Z3, Z28, 224)
	EXPAND8(Z29, Z30, Z22, Z27); ROUND8R(Z3, Z4, Z5, Z6, Z7, Z0, Z1, Z2, Z29, 232)
	EXPAND8(Z30, Z31, Z23, Z28); ROUND8R(Z2, Z3, Z4, Z5, Z6, Z7, Z0, Z1, Z30, 240)
	EXPAND8(Z31, Z16, Z24, Z29); ROUND8R(Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z0, Z31, 248)

	EXPAND8(Z16, Z17, Z25, Z30); ROUND8R(Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z16, 256)
	EXPAND8(Z17, Z18, Z26, Z31); ROUND8R(Z7, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z17, 264)
	EXPAND8(Z18, Z19, Z27, Z16); ROUND8R(Z6, Z7, Z0, Z1, Z2, Z3, Z4, Z5, Z18, 272)
	EXPAND8(Z19, Z20, Z28, Z17); ROUND8R(Z5, Z6, Z7, Z0, Z1, Z2, Z3, Z4, Z19, 280)
	EXPAND8(Z20, Z21, Z29, Z18); ROUND8R(Z4, Z5, Z6, Z7, Z0, Z1, Z2, Z3, Z20, 288)
	EXPAND8(Z21, Z22, Z30, Z19); ROUND8R(Z3, Z4, Z5, Z6, Z7, Z0, Z1, Z2, Z21, 296)
	EXPAND8(Z22, Z23, Z31, Z20); ROUND8R(Z2, Z3, Z4, Z5, Z6, Z7, Z0, Z1, Z22, 304)
	EXPAND8(Z23, Z24, Z16, Z21); ROUND8R(Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z0, Z23, 312)
	EXPAND8(Z24, Z25, Z17, Z22); ROUND8R(Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z24, 320)
	EXPAND8(Z25, Z26, Z18, Z23); ROUND8R(Z7, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z25, 328)
	EXPAND8(Z26, Z27, Z19, Z24); ROUND8R(Z6, Z7, Z0, Z1, Z2, Z3, Z4, Z5, Z26, 336)
	EXPAND8(Z27, Z28, Z20, Z25); ROUND8R(Z5, Z6, Z7, Z0, Z1, Z2, Z3, Z4, Z27, 344)
	EXPAND8(Z28, Z29, Z21, Z26); ROUND8R(Z4, Z5, Z6, Z7, Z0, Z1, Z2, Z3, Z28, 352)
	EXPAND8(Z29, Z30, Z22, Z27); ROUND8R(Z3, Z4, Z5, Z6, Z7, Z0, Z1, Z2, Z29, 360)
	EXPAND8(Z30, Z31, Z23, Z28); ROUND8R(Z2, Z3, Z4, Z5, Z6, Z7, Z0, Z1, Z30, 368)
	EXPAND8(Z31, Z16, Z24, Z29); ROUND8R(Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z0, Z31, 376)

	EXPAND8(Z16, Z17, Z25, Z30); ROUND8R(Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z16, 384)
	EXPAND8(Z17, Z18, Z26, Z31); ROUND8R(Z7, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z17, 392)
	EXPAND8(Z18, Z19, Z27, Z16); ROUND8R(Z6, Z7, Z0, Z1, Z2, Z3, Z4, Z5, Z18, 400)
	EXPAND8(Z19, Z20, Z28, Z17); ROUND8R(Z5, Z6, Z7, Z0, Z1, Z2, Z3, Z4, Z19, 408)
	EXPAND8(Z20, Z21, Z29, Z18); ROUND8R(Z4, Z5, Z6, Z7, Z0, Z1, Z2, Z3, Z20, 416)
	EXPAND8(Z21, Z22, Z30, Z19); ROUND8R(Z3, Z4, Z5, Z6, Z7, Z0, Z1, Z2, Z21, 424)
	EXPAND8(Z22, Z23, Z31, Z20); ROUND8R(Z2, Z3, Z4, Z5, Z6, Z7, Z0, Z1, Z22, 432)
	EXPAND8(Z23, Z24, Z16, Z21); ROUND8R(Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z0, Z23, 440)
	EXPAND8(Z24, Z25, Z17, Z22); ROUND8R(Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z24, 448)
	EXPAND8(Z25, Z26, Z18, Z23); ROUND8R(Z7, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z25, 456)
	EXPAND8(Z26, Z27, Z19, Z24); ROUND8R(Z6, Z7, Z0, Z1, Z2, Z3, Z4, Z5, Z26, 464)
	EXPAND8(Z27, Z28, Z20, Z25); ROUND8R(Z5, Z6, Z7, Z0, Z1, Z2, Z3, Z4, Z27, 472)
	EXPAND8(Z28, Z29, Z21, Z26); ROUND8R(Z4, Z5, Z6, Z7, Z0, Z1, Z2, Z3, Z28, 480)
	EXPAND8(Z29, Z30, Z22, Z27); ROUND8R(Z3, Z4, Z5, Z6, Z7, Z0, Z1, Z2, Z29, 488)
	EXPAND8(Z30, Z31, Z23, Z28); ROUND8R(Z2, Z3, Z4, Z5, Z6, Z7, Z0, Z1, Z30, 496)
	EXPAND8(Z31, Z16, Z24, Z29); ROUND8R(Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z0, Z31, 504)

	EXPAND8(Z16, Z17, Z25, Z30); ROUND8R(Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z16, 512)
	EXPAND8(Z17, Z18, Z26, Z31); ROUND8R(Z7, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z17, 520)
	EXPAND8(Z18, Z19, Z27, Z16); ROUND8R(Z6, Z7, Z0, Z1, Z2, Z3, Z4, Z5, Z18, 528)
	EXPAND8(Z19, Z20, Z28, Z17); ROUND8R(Z5, Z6, Z7, Z0, Z1, Z2, Z3, Z4, Z19, 536)
	EXPAND8(Z20, Z21, Z29, Z18); ROUND8R(Z4, Z5, Z6, Z7, Z0, Z1, Z2, Z3, Z20, 544)
	EXPAND8(Z21, Z22, Z30, Z19); ROUND8R(Z3, Z4, Z5, Z6, Z7, Z0, Z1, Z2, Z21, 552)
	EXPAND8(Z22, Z23, Z31, Z20); ROUND8R(Z2, Z3, Z4, Z5, Z6, Z7, Z0, Z1, Z22, 560)
	EXPAND8(Z23, Z24, Z16, Z21); ROUND8R(Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z0, Z23, 568)
	EXPAND8(Z24, Z25, Z17, Z22); ROUND8R(Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z24, 576)
	EXPAND8(Z25, Z26, Z18, Z23); ROUND8R(Z7, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z25, 584)
	EXPAND8(Z26, Z27, Z19, Z24); ROUND8R(Z6, Z7, Z0, Z1, Z2, Z3, Z4, Z5, Z26, 592)
	EXPAND8(Z27, Z28, Z20, Z25); ROUND8R(Z5, Z6, Z7, Z0, Z1, Z2, Z3, Z4, Z27, 600)
	EXPAND8(Z28, Z29, Z21, Z26); ROUND8R(Z4, Z5, Z6, Z7, Z0, Z1, Z2, Z3, Z28, 608)
	EXPAND8(Z29, Z30, Z22, Z27); ROUND8R(Z3, Z4, Z5, Z6, Z7, Z0, Z1, Z2, Z29, 616)
	EXPAND8(Z30, Z31, Z23, Z28); ROUND8R(Z2, Z3, Z4, Z5, Z6, Z7, Z0, Z1, Z30, 624)
	EXPAND8(Z31, Z16, Z24, Z29); ROUND8R(Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z0, Z31, 632)

	VPADDQ   0(DI), Z0, Z0
	VPADDQ  64(DI), Z1, Z1
	VPADDQ 128(DI), Z2, Z2
	VPADDQ 192(DI), Z3, Z3
	VPADDQ 256(DI), Z4, Z4
	VPADDQ 320(DI), Z5, Z5
	VPADDQ 384(DI), Z6, Z6
	VPADDQ 448(DI), Z7, Z7
	VMOVDQU64 Z0,   0(DI)
	VMOVDQU64 Z1,  64(DI)
	VMOVDQU64 Z2, 128(DI)
	VMOVDQU64 Z3, 192(DI)
	VMOVDQU64 Z4, 256(DI)
	VMOVDQU64 Z5, 320(DI)
	VMOVDQU64 Z6, 384(DI)
	VMOVDQU64 Z7, 448(DI)
	VZEROUPPER
	RET
