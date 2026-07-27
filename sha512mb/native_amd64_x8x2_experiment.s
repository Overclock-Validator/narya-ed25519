//go:build amd64

#include "textflag.h"

// This file is a component experiment, not a dispatched SHA-512 backend.
//
// The production x8 kernel keeps one 16-word rolling schedule and one SHA-512
// state entirely in ZMM registers. That consumes all 32 architectural vector
// registers: 16 schedule words, 8 state words, and 8 temporaries. A second
// independent state therefore cannot be added without changing where the
// schedule lives.
//
// This experiment makes the opposite trade: expand both 80-word schedules to
// the stack, retain two independent eight-vector states in ZMM registers, and
// alternate one round from wave A with one round from wave B. Zen 5 can issue
// work from B while A's round dependency chain is waiting. The hardware test
// decides whether that latency hiding repays 10 KiB of schedule traffic; no
// theoretical win is assumed.
//
// The organization is adapted from tape-sha256's two-wave Zen 5 kernel:
// https://github.com/spool-labs/sha256/blob/39c1fea62015a723f19a2ed9e906926b3be770b8/src/avx512x2.rs
// SHA-512 uses 64-bit words, hence eight messages per ZMM and sixteen messages
// across the two waves.

// EXPAND2 writes W[t] at 0(P) from the already-expanded words behind P:
//
//   W[t] = sigma1(W[t-2]) + W[t-7] + sigma0(W[t-15]) + W[t-16].
//
// P advances by one 64-byte transposed schedule word after each invocation.
#define EXPAND2(P, S0, S1, S2)       \
	VPRORQ $19, -128(P), S0;           \
	VPRORQ $61, -128(P), S1;           \
	VPXORQ S1, S0, S0;                 \
	VPSRLQ $6, -128(P), S1;            \
	VPXORQ S1, S0, S0;                 \
	VPRORQ $1, -960(P), S1;            \
	VPRORQ $8, -960(P), S2;            \
	VPXORQ S2, S1, S1;                 \
	VPSRLQ $7, -960(P), S2;            \
	VPXORQ S2, S1, S1;                 \
	VPADDQ S1, S0, S0;                 \
	VPADDQ -448(P), S0, S0;            \
	VPADDQ -1024(P), S0, S0;           \
	VMOVDQU64 S0, 0(P)

// ROUND2A and ROUND2B are the same FIPS 180-4 SHA-512 round over disjoint
// register sets. The caller rotates the eight state arguments by name, so no
// state-shuffle instructions are needed. R13/R14 point at the current eight
// schedule words and R12 at the matching scalar round constants.
#define ROUND2A(A, B, C, D, E, F, G, H, W, K) \
	VPRORQ $14, E, Z8;                           \
	VPRORQ $18, E, Z9;                           \
	VPXORQ Z9, Z8, Z8;                           \
	VPRORQ $41, E, Z9;                           \
	VPXORQ Z9, Z8, Z8;                           \
	VMOVDQA64 E, Z10;                            \
	VPTERNLOGQ $0xca, G, F, Z10;                 \
	VPADDQ H, Z8, Z8;                            \
	VPADDQ Z10, Z8, Z8;                          \
	VPBROADCASTQ K(R12), Z15;                    \
	VPADDQ Z15, Z8, Z8;                          \
	VPADDQ W(R13), Z8, Z8;                       \
	VPRORQ $28, A, Z9;                           \
	VPRORQ $34, A, Z11;                          \
	VPXORQ Z11, Z9, Z9;                          \
	VPRORQ $39, A, Z11;                          \
	VPXORQ Z11, Z9, Z9;                          \
	VMOVDQA64 A, Z10;                            \
	VPTERNLOGQ $0xe8, C, B, Z10;                 \
	VPADDQ Z10, Z9, Z9;                          \
	VPADDQ Z8, D, D;                             \
	VPADDQ Z9, Z8, H

#define ROUND2B(A, B, C, D, E, F, G, H, W, K) \
	VPRORQ $14, E, Z24;                          \
	VPRORQ $18, E, Z25;                          \
	VPXORQ Z25, Z24, Z24;                        \
	VPRORQ $41, E, Z25;                          \
	VPXORQ Z25, Z24, Z24;                        \
	VMOVDQA64 E, Z26;                            \
	VPTERNLOGQ $0xca, G, F, Z26;                 \
	VPADDQ H, Z24, Z24;                          \
	VPADDQ Z26, Z24, Z24;                        \
	VPBROADCASTQ K(R12), Z31;                    \
	VPADDQ Z31, Z24, Z24;                        \
	VPADDQ W(R14), Z24, Z24;                     \
	VPRORQ $28, A, Z25;                          \
	VPRORQ $34, A, Z27;                          \
	VPXORQ Z27, Z25, Z25;                        \
	VPRORQ $39, A, Z27;                          \
	VPXORQ Z27, Z25, Z25;                        \
	VMOVDQA64 A, Z26;                            \
	VPTERNLOGQ $0xe8, C, B, Z26;                 \
	VPADDQ Z26, Z25, Z25;                        \
	VPADDQ Z24, D, D;                            \
	VPADDQ Z25, Z24, H

// func nativeCompress2X8Expanded(stateA *nativeStateX8, blockA *nativeBlockX8, stateB *nativeStateX8, blockB *nativeBlockX8)
//
// Requires AVX-512F. stateA and stateB must be distinct. Both complete input
// blocks are copied before either state is read or written, so each state may
// exactly alias its corresponding block.
TEXT ·nativeCompress2X8Expanded(SB), 0, $10240-32
	// Schedule A occupies SP+[0,5120); schedule B occupies SP+[5120,10240).
	MOVQ blockA+8(FP), SI
	LEAQ 0(SP), DI
	MOVQ $16, CX
copyScheduleA:
	VMOVDQU64 0(SI), Z8
	VMOVDQU64 Z8, 0(DI)
	ADDQ $64, SI
	ADDQ $64, DI
	DECQ CX
	JNZ copyScheduleA

	MOVQ blockB+24(FP), SI
	LEAQ 5120(SP), DI
	MOVQ $16, CX
copyScheduleB:
	VMOVDQU64 0(SI), Z8
	VMOVDQU64 Z8, 0(DI)
	ADDQ $64, SI
	ADDQ $64, DI
	DECQ CX
	JNZ copyScheduleB

	// Expand corresponding A/B words next to each other. The chains are
	// independent; an out-of-order core may overlap them even though both use
	// the same scratch registers at their architectural boundaries.
	LEAQ 1024(SP), R13
	LEAQ 6144(SP), R14
	MOVQ $64, CX
expandSchedules2:
	EXPAND2(R13, Z8, Z9, Z10)
	EXPAND2(R14, Z8, Z9, Z10)
	ADDQ $64, R13
	ADDQ $64, R14
	DECQ CX
	JNZ expandSchedules2

	// Keep both working states live. A uses Z0..Z7 and B uses Z16..Z23;
	// their round temporaries occupy disjoint register sets.
	MOVQ stateA+0(FP), AX
	VMOVDQU64   0(AX), Z0
	VMOVDQU64  64(AX), Z1
	VMOVDQU64 128(AX), Z2
	VMOVDQU64 192(AX), Z3
	VMOVDQU64 256(AX), Z4
	VMOVDQU64 320(AX), Z5
	VMOVDQU64 384(AX), Z6
	VMOVDQU64 448(AX), Z7

	MOVQ stateB+16(FP), BX
	VMOVDQU64   0(BX), Z16
	VMOVDQU64  64(BX), Z17
	VMOVDQU64 128(BX), Z18
	VMOVDQU64 192(BX), Z19
	VMOVDQU64 256(BX), Z20
	VMOVDQU64 320(BX), Z21
	VMOVDQU64 384(BX), Z22
	VMOVDQU64 448(BX), Z23

	LEAQ 0(SP), R13
	LEAQ 5120(SP), R14
	MOVQ $·nativeRoundConstants(SB), R12
	MOVQ $10, CX
rounds2x8:
	ROUND2A(Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7,   0,  0)
	ROUND2B(Z16,Z17,Z18,Z19,Z20,Z21,Z22,Z23,   0,  0)
	ROUND2A(Z7, Z0, Z1, Z2, Z3, Z4, Z5, Z6,  64,  8)
	ROUND2B(Z23,Z16,Z17,Z18,Z19,Z20,Z21,Z22,  64,  8)
	ROUND2A(Z6, Z7, Z0, Z1, Z2, Z3, Z4, Z5, 128, 16)
	ROUND2B(Z22,Z23,Z16,Z17,Z18,Z19,Z20,Z21, 128, 16)
	ROUND2A(Z5, Z6, Z7, Z0, Z1, Z2, Z3, Z4, 192, 24)
	ROUND2B(Z21,Z22,Z23,Z16,Z17,Z18,Z19,Z20, 192, 24)
	ROUND2A(Z4, Z5, Z6, Z7, Z0, Z1, Z2, Z3, 256, 32)
	ROUND2B(Z20,Z21,Z22,Z23,Z16,Z17,Z18,Z19, 256, 32)
	ROUND2A(Z3, Z4, Z5, Z6, Z7, Z0, Z1, Z2, 320, 40)
	ROUND2B(Z19,Z20,Z21,Z22,Z23,Z16,Z17,Z18, 320, 40)
	ROUND2A(Z2, Z3, Z4, Z5, Z6, Z7, Z0, Z1, 384, 48)
	ROUND2B(Z18,Z19,Z20,Z21,Z22,Z23,Z16,Z17, 384, 48)
	ROUND2A(Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z0, 448, 56)
	ROUND2B(Z17,Z18,Z19,Z20,Z21,Z22,Z23,Z16, 448, 56)
	ADDQ $512, R13
	ADDQ $512, R14
	ADDQ $64, R12
	DECQ CX
	JNZ rounds2x8

	// Feed forward from the original states and write both results.
	VPADDQ   0(AX), Z0, Z0
	VPADDQ  64(AX), Z1, Z1
	VPADDQ 128(AX), Z2, Z2
	VPADDQ 192(AX), Z3, Z3
	VPADDQ 256(AX), Z4, Z4
	VPADDQ 320(AX), Z5, Z5
	VPADDQ 384(AX), Z6, Z6
	VPADDQ 448(AX), Z7, Z7
	VMOVDQU64 Z0,   0(AX)
	VMOVDQU64 Z1,  64(AX)
	VMOVDQU64 Z2, 128(AX)
	VMOVDQU64 Z3, 192(AX)
	VMOVDQU64 Z4, 256(AX)
	VMOVDQU64 Z5, 320(AX)
	VMOVDQU64 Z6, 384(AX)
	VMOVDQU64 Z7, 448(AX)

	VPADDQ   0(BX), Z16, Z16
	VPADDQ  64(BX), Z17, Z17
	VPADDQ 128(BX), Z18, Z18
	VPADDQ 192(BX), Z19, Z19
	VPADDQ 256(BX), Z20, Z20
	VPADDQ 320(BX), Z21, Z21
	VPADDQ 384(BX), Z22, Z22
	VPADDQ 448(BX), Z23, Z23
	VMOVDQU64 Z16,   0(BX)
	VMOVDQU64 Z17,  64(BX)
	VMOVDQU64 Z18, 128(BX)
	VMOVDQU64 Z19, 192(BX)
	VMOVDQU64 Z20, 256(BX)
	VMOVDQU64 Z21, 320(BX)
	VMOVDQU64 Z22, 384(BX)
	VMOVDQU64 Z23, 448(BX)
	RET
