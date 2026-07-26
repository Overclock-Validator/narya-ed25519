//go:build amd64 && !purego

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

// func ifmaNielsStage2X4(workspace *ifmaNielsStage2WorkspaceX4)
//
// Four-lane widening of the exact x8 arithmetic below. Entry slots contain
// raw [A,B,C] followed by raw-or-u52 D; exit slots are normalized [E,F,G,H].
TEXT ·ifmaNielsStage2X4(SB), NOSPLIT, $0-8
	MOVQ workspace+0(FP), DI

	VMOVDQU64   0(DI), Y0
	VMOVDQU64  32(DI), Y1
	VMOVDQU64  64(DI), Y2
	VMOVDQU64  96(DI), Y3
	VMOVDQU64 128(DI), Y4
	VMOVDQU64 160(DI), Y5
	VMOVDQU64 192(DI), Y6
	VMOVDQU64 224(DI), Y7
	VMOVDQU64 256(DI), Y8
	VMOVDQU64 288(DI), Y9
	VMOVDQU64 320(DI), Y10
	VMOVDQU64 352(DI), Y11
	VMOVDQU64 384(DI), Y12
	VMOVDQU64 416(DI), Y13
	VMOVDQU64 448(DI), Y14
	VMOVDQU64 480(DI), Y15
	VMOVDQU64 512(DI), Y16
	VMOVDQU64 544(DI), Y17
	VMOVDQU64 576(DI), Y18
	VMOVDQU64 608(DI), Y19

	VPBROADCASTQ ·ifmaNielsStage2Bias535P0(SB), Y20
	VPBROADCASTQ ·ifmaNielsStage2Bias535PN(SB), Y21
	NIELS_STAGE2_LINEAR(Y0, Y5, Y10, Y15, Y20, Y22, Y23)
	NIELS_STAGE2_LINEAR(Y1, Y6, Y11, Y16, Y21, Y22, Y23)
	NIELS_STAGE2_LINEAR(Y2, Y7, Y12, Y17, Y21, Y22, Y23)
	NIELS_STAGE2_LINEAR(Y3, Y8, Y13, Y18, Y21, Y22, Y23)
	NIELS_STAGE2_LINEAR(Y4, Y9, Y14, Y19, Y21, Y22, Y23)

	VPBROADCASTQ ·ifmaNielsStage2Mask51(SB), Y20
	VPBROADCASTQ ·ifmaNielsStage2Fold19(SB), Y21
	NIELS_STAGE2_NORMALIZE_5(Y0, Y1, Y2, Y3, Y4, Y20, Y22, Y23, Y24, Y25, Y26, Y21)
	NIELS_STAGE2_NORMALIZE_5(Y10, Y11, Y12, Y13, Y14, Y20, Y22, Y23, Y24, Y25, Y26, Y21)
	NIELS_STAGE2_NORMALIZE_5(Y15, Y16, Y17, Y18, Y19, Y20, Y22, Y23, Y24, Y25, Y26, Y21)
	NIELS_STAGE2_NORMALIZE_5(Y5, Y6, Y7, Y8, Y9, Y20, Y22, Y23, Y24, Y25, Y26, Y21)

	VMOVDQU64 Y0,   0(DI)
	VMOVDQU64 Y1,  32(DI)
	VMOVDQU64 Y2,  64(DI)
	VMOVDQU64 Y3,  96(DI)
	VMOVDQU64 Y4, 128(DI)
	VMOVDQU64 Y10, 160(DI)
	VMOVDQU64 Y11, 192(DI)
	VMOVDQU64 Y12, 224(DI)
	VMOVDQU64 Y13, 256(DI)
	VMOVDQU64 Y14, 288(DI)
	VMOVDQU64 Y15, 320(DI)
	VMOVDQU64 Y16, 352(DI)
	VMOVDQU64 Y17, 384(DI)
	VMOVDQU64 Y18, 416(DI)
	VMOVDQU64 Y19, 448(DI)
	VMOVDQU64 Y5, 480(DI)
	VMOVDQU64 Y6, 512(DI)
	VMOVDQU64 Y7, 544(DI)
	VMOVDQU64 Y8, 576(DI)
	VMOVDQU64 Y9, 608(DI)
	VZEROUPPER
	RET

// func ifmaNielsStage2X8(workspace *ifmaNielsStage2WorkspaceX8)
//
// Entry slots are exact raw [A,B,C] products followed by either a raw D
// product or a composable-u52 D representative. Exit slots are normalized
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
