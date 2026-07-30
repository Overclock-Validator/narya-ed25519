//go:build amd64 && !purego

#include "textflag.h"

// Transform one raw limb in place. A, B, C, and E are the corresponding
// vectors from the four workspace slots. The outputs reuse those registers as
// H, G, F, and E respectively. T is scratch; the bias registers are preserved.
#define DOUBLE_STAGE2_LINEAR(A, B, C, E, P535, P1068, P1069, T) \
	VMOVDQA64 A, T                                                \
	VPSUBQ A, P1069, A                                            \
	VPSUBQ B, A, A                                                \
	VPADDQ P535, B, B                                             \
	VPSUBQ T, B, B                                                \
	VPADDQ C, C, C                                                \
	VMOVDQA64 B, T                                                \
	VPADDQ P1068, T, T                                            \
	VPSUBQ C, T, T                                                \
	VMOVDQA64 T, C                                                \
	VPADDQ E, E, E

// Classical square-trick variant. The fourth raw product is S=(X+Y)^2.
// A becomes H=1069p-A-B before the final instruction, so E=S+H is exactly
// S-A-B modulo p and stays non-negative under the same Stage-2 bounds.
#define DOUBLE_STAGE2_LINEAR_SQUARE_TRICK(A, B, C, E, P535, P1068, P1069, T) \
	VMOVDQA64 A, T                                                               \
	VPSUBQ A, P1069, A                                                           \
	VPSUBQ B, A, A                                                               \
	VPADDQ P535, B, B                                                            \
	VPSUBQ T, B, B                                                               \
	VPADDQ C, C, C                                                               \
	VMOVDQA64 B, T                                                               \
	VPADDQ P1068, T, T                                                           \
	VPSUBQ C, T, T                                                               \
	VMOVDQA64 T, C                                                               \
	VPADDQ A, E, E

// Carry one stage-specific wide value. Inputs are non-negative and below
// 2137*2^51, so every carry is at most 2136. In particular 19*C4 is wholly in
// the low 52-bit half consumed by VPMADD52LUQ. The result is a composable u52
// representative after this one independent pass.
#define DOUBLE_STAGE2_NORMALIZE_5(IN0, IN1, IN2, IN3, IN4, MASK, C0, C1, C2, C3, C4, FOLD19) \
	VPSRLQ $51, IN0, C0                                                                       \
	VPSRLQ $51, IN1, C1                                                                       \
	VPSRLQ $51, IN2, C2                                                                       \
	VPSRLQ $51, IN3, C3                                                                       \
	VPSRLQ $51, IN4, C4                                                                       \
	VPANDQ MASK, IN0, IN0                                                                     \
	VPANDQ MASK, IN1, IN1                                                                     \
	VPANDQ MASK, IN2, IN2                                                                     \
	VPANDQ MASK, IN3, IN3                                                                     \
	VPANDQ MASK, IN4, IN4                                                                     \
	VPADDQ C0, IN1, IN1                                                                       \
	VPADDQ C1, IN2, IN2                                                                       \
	VPADDQ C2, IN3, IN3                                                                       \
	VPADDQ C3, IN4, IN4                                                                       \
	VPMADD52LUQ C4, FOLD19, IN0

#include "double_stage2_x8_body.h"

// func ifmaDoubleStage2X4(workspace *ifmaDoubleStage2WorkspaceX4)
//
// Entry slots are exact raw [A=X^2, B=Y^2, C=Z^2, E=XY] products. Exit slots
// are normalized [E,F,G,H]. The first twenty vector instructions load the
// complete input workspace; no output address is written before all raw values
// are resident in Y0..Y19.
TEXT ·ifmaDoubleStage2X4(SB), NOSPLIT, $0-8
	MOVQ workspace+0(FP), DI

	// Raw A.
	VMOVDQU64   0(DI), Y0
	VMOVDQU64  32(DI), Y1
	VMOVDQU64  64(DI), Y2
	VMOVDQU64  96(DI), Y3
	VMOVDQU64 128(DI), Y4
	// Raw B.
	VMOVDQU64 160(DI), Y5
	VMOVDQU64 192(DI), Y6
	VMOVDQU64 224(DI), Y7
	VMOVDQU64 256(DI), Y8
	VMOVDQU64 288(DI), Y9
	// Raw C=Z^2 (doubling is deliberately deferred to this stage).
	VMOVDQU64 320(DI), Y10
	VMOVDQU64 352(DI), Y11
	VMOVDQU64 384(DI), Y12
	VMOVDQU64 416(DI), Y13
	VMOVDQU64 448(DI), Y14
	// Raw E=X*Y.
	VMOVDQU64 480(DI), Y15
	VMOVDQU64 512(DI), Y16
	VMOVDQU64 544(DI), Y17
	VMOVDQU64 576(DI), Y18
	VMOVDQU64 608(DI), Y19

	VPBROADCASTQ ·ifmaDoubleStage2Bias535P0(SB), Y20
	VPBROADCASTQ ·ifmaDoubleStage2Bias535PN(SB), Y21
	VPBROADCASTQ ·ifmaDoubleStage2Bias1068P0(SB), Y22
	VPBROADCASTQ ·ifmaDoubleStage2Bias1068PN(SB), Y23
	VPBROADCASTQ ·ifmaDoubleStage2Bias1069P0(SB), Y24
	VPBROADCASTQ ·ifmaDoubleStage2Bias1069PN(SB), Y25

	DOUBLE_STAGE2_LINEAR(Y0, Y5, Y10, Y15, Y20, Y22, Y24, Y26)
	DOUBLE_STAGE2_LINEAR(Y1, Y6, Y11, Y16, Y21, Y23, Y25, Y26)
	DOUBLE_STAGE2_LINEAR(Y2, Y7, Y12, Y17, Y21, Y23, Y25, Y26)
	DOUBLE_STAGE2_LINEAR(Y3, Y8, Y13, Y18, Y21, Y23, Y25, Y26)
	DOUBLE_STAGE2_LINEAR(Y4, Y9, Y14, Y19, Y21, Y23, Y25, Y26)

	// The linear stage is complete. Reuse its constants as the normalizer's
	// mask, fold constant, and five carry temporaries.
	VPBROADCASTQ ·ifmaDoubleStage2Mask51(SB), Y20
	VPBROADCASTQ ·ifmaDoubleStage2Fold19(SB), Y21

	// E, F, G, and H are independent; shared scratch registers do not carry
	// information from one coordinate to the next.
	DOUBLE_STAGE2_NORMALIZE_5(Y15, Y16, Y17, Y18, Y19, Y20, Y22, Y23, Y24, Y25, Y26, Y21)
	DOUBLE_STAGE2_NORMALIZE_5(Y10, Y11, Y12, Y13, Y14, Y20, Y22, Y23, Y24, Y25, Y26, Y21)
	DOUBLE_STAGE2_NORMALIZE_5(Y5, Y6, Y7, Y8, Y9, Y20, Y22, Y23, Y24, Y25, Y26, Y21)
	DOUBLE_STAGE2_NORMALIZE_5(Y0, Y1, Y2, Y3, Y4, Y20, Y22, Y23, Y24, Y25, Y26, Y21)

	// Overwrite the workspace in normalized [E,F,G,H] order.
	VMOVDQU64 Y15,   0(DI)
	VMOVDQU64 Y16,  32(DI)
	VMOVDQU64 Y17,  64(DI)
	VMOVDQU64 Y18,  96(DI)
	VMOVDQU64 Y19, 128(DI)
	VMOVDQU64 Y10, 160(DI)
	VMOVDQU64 Y11, 192(DI)
	VMOVDQU64 Y12, 224(DI)
	VMOVDQU64 Y13, 256(DI)
	VMOVDQU64 Y14, 288(DI)
	VMOVDQU64 Y5, 320(DI)
	VMOVDQU64 Y6, 352(DI)
	VMOVDQU64 Y7, 384(DI)
	VMOVDQU64 Y8, 416(DI)
	VMOVDQU64 Y9, 448(DI)
	VMOVDQU64 Y0, 480(DI)
	VMOVDQU64 Y1, 512(DI)
	VMOVDQU64 Y2, 544(DI)
	VMOVDQU64 Y3, 576(DI)
	VMOVDQU64 Y4, 608(DI)
	VZEROUPPER
	RET

// func ifmaDoubleStage2X8(workspace *ifmaDoubleStage2WorkspaceX8)
//
// Native-ZMM widening of the x4 schedule above. Slot and limb offsets double;
// arithmetic order and the proven range bounds are otherwise identical.
TEXT ·ifmaDoubleStage2X8(SB), NOSPLIT, $0-8
	DOUBLE_STAGE2_X8_BODY(workspace+0(FP))
	VZEROUPPER
	RET

// func ifmaDoubleStage2SquareTrickX8(workspace *ifmaDoubleStage2WorkspaceX8)
//
// Test-only fourth-square counterpart. The load, carry, and store schedule is
// deliberately shared with production; only E's final linear instruction
// changes from 2*XY to (X+Y)^2-X^2-Y^2.
TEXT ·ifmaDoubleStage2SquareTrickX8(SB), NOSPLIT, $0-8
	DOUBLE_STAGE2_X8_BODY_WITH_LINEAR(workspace+0(FP), DOUBLE_STAGE2_LINEAR_SQUARE_TRICK)
	VZEROUPPER
	RET

TEXT ·ifmaDoubleStage2SquareTrickPointFinalX8(SB), NOSPLIT, $0-16
	DOUBLE_STAGE2_X8_BODY_WITH_LINEAR(workspace+8(FP), DOUBLE_STAGE2_LINEAR_SQUARE_TRICK)
	JMP ·ifmaPointFinalProductsUncheckedX8(SB)

TEXT ·ifmaDoubleStage2SquareTrickProjectiveFinalX8(SB), NOSPLIT, $0-16
	DOUBLE_STAGE2_X8_BODY_WITH_LINEAR(workspace+8(FP), DOUBLE_STAGE2_LINEAR_SQUARE_TRICK)
	JMP ·ifmaProjectiveFinalProductsUncheckedX8(SB)

// func ifmaDoubleStage2PointFinalX8(out *IFMAPointX8,
//     workspace *ifmaDoubleStage2WorkspaceX8)
//
// Execute the exact standalone Stage-2 body and then tail-enter the existing
// four-product P3 leaf. The two-pointer ABI intentionally matches the final
// leaf: after Stage 2 stores carried E/F/G/H, out+0(FP) and workspace+8(FP)
// are already the final leaf's out and operands arguments. The tail jump
// removes one return/call boundary and one intervening VZEROUPPER; it changes
// no arithmetic instruction or memory representation.
TEXT ·ifmaDoubleStage2PointFinalX8(SB), NOSPLIT, $0-16
	DOUBLE_STAGE2_X8_BODY(workspace+8(FP))
	JMP ·ifmaPointFinalProductsUncheckedX8(SB)

// func ifmaDoubleStage2ProjectiveFinalX8(out *ifmaProjectivePointX8,
//     workspace *ifmaDoubleStage2WorkspaceX8)
//
// P2 counterpart of ifmaDoubleStage2PointFinalX8. The same two-pointer ABI
// tail-enters the independently tested three-product leaf, so an incomplete
// point still cannot acquire a stale T coordinate.
TEXT ·ifmaDoubleStage2ProjectiveFinalX8(SB), NOSPLIT, $0-16
	DOUBLE_STAGE2_X8_BODY(workspace+8(FP))
	JMP ·ifmaProjectiveFinalProductsUncheckedX8(SB)

DATA ·ifmaDoubleStage2Mask51+0(SB)/8, $0x0007ffffffffffff
GLOBL ·ifmaDoubleStage2Mask51(SB), RODATA|NOPTR, $8

DATA ·ifmaDoubleStage2Fold19+0(SB)/8, $19
GLOBL ·ifmaDoubleStage2Fold19(SB), RODATA|NOPTR, $8

DATA ·ifmaDoubleStage2Bias535P0+0(SB)/8, $0x10b7ffffffffd84b
GLOBL ·ifmaDoubleStage2Bias535P0(SB), RODATA|NOPTR, $8

DATA ·ifmaDoubleStage2Bias535PN+0(SB)/8, $0x10b7fffffffffde9
GLOBL ·ifmaDoubleStage2Bias535PN(SB), RODATA|NOPTR, $8

DATA ·ifmaDoubleStage2Bias1068P0+0(SB)/8, $0x215fffffffffb0bc
GLOBL ·ifmaDoubleStage2Bias1068P0(SB), RODATA|NOPTR, $8

DATA ·ifmaDoubleStage2Bias1068PN+0(SB)/8, $0x215ffffffffffbd4
GLOBL ·ifmaDoubleStage2Bias1068PN(SB), RODATA|NOPTR, $8

DATA ·ifmaDoubleStage2Bias1069P0+0(SB)/8, $0x2167ffffffffb0a9
GLOBL ·ifmaDoubleStage2Bias1069P0(SB), RODATA|NOPTR, $8

DATA ·ifmaDoubleStage2Bias1069PN+0(SB)/8, $0x2167fffffffffbd3
GLOBL ·ifmaDoubleStage2Bias1069PN(SB), RODATA|NOPTR, $8
