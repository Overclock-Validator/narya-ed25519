//go:build amd64

#include "textflag.h"

// Transform one raw limb in place. A, B, C, and D are the corresponding
// vectors from the four workspace slots. Outputs reuse them as E, H, F, and G
// respectively. T0/T1 preserve the original A/C values.
#define NIELS_STAGE2_LINEAR(A, B, C, D, P535, T0, T1) \
	VMOVDQA64 A, T0                                   \
	VMOVDQA64 C, T1                                   \
	VPADDQ P535, B, A                                  \
	VPSUBQ T0, A, A                                    \
	VPADDQ T0, B, B                                    \
	VPADDQ D, D, D                                     \
	VPADDQ P535, D, C                                  \
	VPSUBQ T1, C, C                                    \
	VPADDQ T1, D, D

// Carry one non-negative Stage-2 value. Inputs are below 1604*2^51, so each
// carry is at most 1603 and 19*C4 fits wholly in VPMADD52LUQ's low half.
#define NIELS_STAGE2_NORMALIZE_5(IN0, IN1, IN2, IN3, IN4, MASK, C0, C1, C2, C3, C4, FOLD19) \
	VPSRLQ $51, IN0, C0                                                                      \
	VPSRLQ $51, IN1, C1                                                                      \
	VPSRLQ $51, IN2, C2                                                                      \
	VPSRLQ $51, IN3, C3                                                                      \
	VPSRLQ $51, IN4, C4                                                                      \
	VPANDQ MASK, IN0, IN0                                                                    \
	VPANDQ MASK, IN1, IN1                                                                    \
	VPANDQ MASK, IN2, IN2                                                                    \
	VPANDQ MASK, IN3, IN3                                                                    \
	VPANDQ MASK, IN4, IN4                                                                    \
	VPADDQ C0, IN1, IN1                                                                      \
	VPADDQ C1, IN2, IN2                                                                      \
	VPADDQ C2, IN3, IN3                                                                      \
	VPADDQ C3, IN4, IN4                                                                      \
	VPMADD52LUQ C4, FOLD19, IN0

// func ifmaNielsStage2X8(workspace *ifmaNielsStage2WorkspaceX8)
//
// Entry slots are exact raw [A,B,C,D] products. Exit slots are normalized
// [E,F,G,H]. All twenty inputs are resident before any store, which makes the
// in-place state transition explicit and auditable.
TEXT ·ifmaNielsStage2X8(SB), NOSPLIT, $0-8
	MOVQ workspace+0(FP), DI

	// A.
	VMOVDQU64   0(DI), Z0
	VMOVDQU64  64(DI), Z1
	VMOVDQU64 128(DI), Z2
	VMOVDQU64 192(DI), Z3
	VMOVDQU64 256(DI), Z4
	// B.
	VMOVDQU64 320(DI), Z5
	VMOVDQU64 384(DI), Z6
	VMOVDQU64 448(DI), Z7
	VMOVDQU64 512(DI), Z8
	VMOVDQU64 576(DI), Z9
	// C.
	VMOVDQU64 640(DI), Z10
	VMOVDQU64 704(DI), Z11
	VMOVDQU64 768(DI), Z12
	VMOVDQU64 832(DI), Z13
	VMOVDQU64 896(DI), Z14
	// D.
	VMOVDQU64  960(DI), Z15
	VMOVDQU64 1024(DI), Z16
	VMOVDQU64 1088(DI), Z17
	VMOVDQU64 1152(DI), Z18
	VMOVDQU64 1216(DI), Z19

	VPBROADCASTQ ·ifmaNielsStage2Bias535P0(SB), Z20
	VPBROADCASTQ ·ifmaNielsStage2Bias535PN(SB), Z21
	NIELS_STAGE2_LINEAR(Z0, Z5, Z10, Z15, Z20, Z22, Z23)
	NIELS_STAGE2_LINEAR(Z1, Z6, Z11, Z16, Z21, Z22, Z23)
	NIELS_STAGE2_LINEAR(Z2, Z7, Z12, Z17, Z21, Z22, Z23)
	NIELS_STAGE2_LINEAR(Z3, Z8, Z13, Z18, Z21, Z22, Z23)
	NIELS_STAGE2_LINEAR(Z4, Z9, Z14, Z19, Z21, Z22, Z23)

	VPBROADCASTQ ·ifmaNielsStage2Mask51(SB), Z20
	VPBROADCASTQ ·ifmaNielsStage2Fold19(SB), Z21

	// Register mapping after the linear stage: A=E, C=F, D=G, B=H.
	NIELS_STAGE2_NORMALIZE_5(Z0, Z1, Z2, Z3, Z4, Z20, Z22, Z23, Z24, Z25, Z26, Z21)
	NIELS_STAGE2_NORMALIZE_5(Z10, Z11, Z12, Z13, Z14, Z20, Z22, Z23, Z24, Z25, Z26, Z21)
	NIELS_STAGE2_NORMALIZE_5(Z15, Z16, Z17, Z18, Z19, Z20, Z22, Z23, Z24, Z25, Z26, Z21)
	NIELS_STAGE2_NORMALIZE_5(Z5, Z6, Z7, Z8, Z9, Z20, Z22, Z23, Z24, Z25, Z26, Z21)

	// E.
	VMOVDQU64 Z0,   0(DI)
	VMOVDQU64 Z1,  64(DI)
	VMOVDQU64 Z2, 128(DI)
	VMOVDQU64 Z3, 192(DI)
	VMOVDQU64 Z4, 256(DI)
	// F.
	VMOVDQU64 Z10, 320(DI)
	VMOVDQU64 Z11, 384(DI)
	VMOVDQU64 Z12, 448(DI)
	VMOVDQU64 Z13, 512(DI)
	VMOVDQU64 Z14, 576(DI)
	// G.
	VMOVDQU64 Z15, 640(DI)
	VMOVDQU64 Z16, 704(DI)
	VMOVDQU64 Z17, 768(DI)
	VMOVDQU64 Z18, 832(DI)
	VMOVDQU64 Z19, 896(DI)
	// H.
	VMOVDQU64 Z5,   960(DI)
	VMOVDQU64 Z6,  1024(DI)
	VMOVDQU64 Z7,  1088(DI)
	VMOVDQU64 Z8,  1152(DI)
	VMOVDQU64 Z9,  1216(DI)
	VZEROUPPER
	RET

DATA ·ifmaNielsStage2Mask51+0(SB)/8, $0x0007ffffffffffff
GLOBL ·ifmaNielsStage2Mask51(SB), RODATA|NOPTR, $8

DATA ·ifmaNielsStage2Fold19+0(SB)/8, $19
GLOBL ·ifmaNielsStage2Fold19(SB), RODATA|NOPTR, $8

DATA ·ifmaNielsStage2Bias535P0+0(SB)/8, $0x10b7ffffffffd84b
GLOBL ·ifmaNielsStage2Bias535P0(SB), RODATA|NOPTR, $8

DATA ·ifmaNielsStage2Bias535PN+0(SB)/8, $0x10b7fffffffffde9
GLOBL ·ifmaNielsStage2Bias535PN(SB), RODATA|NOPTR, $8
