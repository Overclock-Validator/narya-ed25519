//go:build amd64

#include "textflag.h"

// Each VPMADD52 pair splits a product at bit 52. Since the field radix is
// 2^51, a high half contributes twice its value to the next convolution
// degree. Inputs are strictly below 2^52.
#define SQUARE_MUL_PAIR(X, Y, L, H) \
	VPMADD52LUQ Y, X, L              \
	VPMADD52HUQ Y, X, H

#define SQUARE_CLEAR(R) VPXORQ R, R, R

#define SQUARE_COMBINE_HIGH(H, L) \
	VPSLLQ $1, H, H                 \
	VPADDQ H, L, L

#define SQUARE_FOLD_INTO(LO, HI, T0, T1) \
	VPSLLQ $4, HI, T0                     \
	VPSLLQ $1, HI, T1                     \
	VPADDQ T1, T0, T0                     \
	VPADDQ HI, T0, T0                     \
	VPADDQ T0, LO, LO

// One parallel unsigned carry/fold. The input limbs have exactly the same
// maxima as a general x*x product:
//
//   t0 < 267*2^52 - 456, t1 < 213*2^52 - 366,
//   t2 < 159*2^52 - 276, t3 < 105*2^52 - 186,
//   t4 <  51*2^52 -  96.
//
// Thus every limb is below 2^61, each carry is below 2^10, 19*c4 is exact
// in VPMADD52LUQ, and the outputs are strictly below 2^52.
#define SQUARE_NORMALIZE_5(IN0, IN1, IN2, IN3, IN4, MASK, C0, C1, C2, C3, C4, FOLD19) \
	VPSRLQ $51, IN0, C0                                                           \
	VPSRLQ $51, IN1, C1                                                           \
	VPSRLQ $51, IN2, C2                                                           \
	VPSRLQ $51, IN3, C3                                                           \
	VPSRLQ $51, IN4, C4                                                           \
	VPANDQ MASK, IN0, IN0                                                         \
	VPANDQ MASK, IN1, IN1                                                         \
	VPANDQ MASK, IN2, IN2                                                         \
	VPANDQ MASK, IN3, IN3                                                         \
	VPANDQ MASK, IN4, IN4                                                         \
	VPADDQ C0, IN1, IN1                                                           \
	VPADDQ C1, IN2, IN2                                                           \
	VPADDQ C2, IN3, IN3                                                           \
	VPADDQ C3, IN4, IN4                                                           \
	VPMADD52LUQ C4, FOLD19, IN0

// func ifmaSquareNormalizedExperimentX4(out, x *LimbsX4)
//
// Y0..Y4 contain x0..x4. Y5..Y13 are the low-half accumulators for
// convolution degrees 0..8; Y14..Y22 are their high-half accumulators.
//
// The ten off-diagonal products are accumulated once, their low and high
// contributions are doubled in place, and the five diagonal products are
// then added. This is algebraically and representationally identical to the
// 25-product general multiply with x==y, but uses 15 product pairs (30 IFMA
// instructions) rather than 25 pairs (50 IFMA instructions).
TEXT ·ifmaSquareNormalizedExperimentX4(SB), NOSPLIT, $0-16
	MOVQ out+0(FP), DI
	MOVQ x+8(FP), CX

	// Load every input before any store: exact aliasing is safe.
	VMOVDQU64   0(CX), Y0
	VMOVDQU64  32(CX), Y1
	VMOVDQU64  64(CX), Y2
	VMOVDQU64  96(CX), Y3
	VMOVDQU64 128(CX), Y4

	SQUARE_CLEAR(Y5)
	SQUARE_CLEAR(Y6)
	SQUARE_CLEAR(Y7)
	SQUARE_CLEAR(Y8)
	SQUARE_CLEAR(Y9)
	SQUARE_CLEAR(Y10)
	SQUARE_CLEAR(Y11)
	SQUARE_CLEAR(Y12)
	SQUARE_CLEAR(Y13)
	SQUARE_CLEAR(Y14)
	SQUARE_CLEAR(Y15)
	SQUARE_CLEAR(Y16)
	SQUARE_CLEAR(Y17)
	SQUARE_CLEAR(Y18)
	SQUARE_CLEAR(Y19)
	SQUARE_CLEAR(Y20)
	SQUARE_CLEAR(Y21)
	SQUARE_CLEAR(Y22)

	// The ten unique off-diagonal products.
	SQUARE_MUL_PAIR(Y0, Y1, Y6,  Y15) // degree 1
	SQUARE_MUL_PAIR(Y0, Y2, Y7,  Y16) // degree 2
	SQUARE_MUL_PAIR(Y0, Y3, Y8,  Y17) // degree 3
	SQUARE_MUL_PAIR(Y0, Y4, Y9,  Y18) // degree 4
	SQUARE_MUL_PAIR(Y1, Y2, Y8,  Y17) // degree 3
	SQUARE_MUL_PAIR(Y1, Y3, Y9,  Y18) // degree 4
	SQUARE_MUL_PAIR(Y1, Y4, Y10, Y19) // degree 5
	SQUARE_MUL_PAIR(Y2, Y3, Y10, Y19) // degree 5
	SQUARE_MUL_PAIR(Y2, Y4, Y11, Y20) // degree 6
	SQUARE_MUL_PAIR(Y3, Y4, Y12, Y21) // degree 7

	// Symmetry contributes each off-diagonal product twice. Empty degree-zero
	// and degree-eight cross accumulators need no shifts.
	VPSLLQ $1, Y6,  Y6
	VPSLLQ $1, Y7,  Y7
	VPSLLQ $1, Y8,  Y8
	VPSLLQ $1, Y9,  Y9
	VPSLLQ $1, Y10, Y10
	VPSLLQ $1, Y11, Y11
	VPSLLQ $1, Y12, Y12
	VPSLLQ $1, Y15, Y15
	VPSLLQ $1, Y16, Y16
	VPSLLQ $1, Y17, Y17
	VPSLLQ $1, Y18, Y18
	VPSLLQ $1, Y19, Y19
	VPSLLQ $1, Y20, Y20
	VPSLLQ $1, Y21, Y21

	// The five diagonal products are not doubled.
	SQUARE_MUL_PAIR(Y0, Y0, Y5,  Y14) // degree 0
	SQUARE_MUL_PAIR(Y1, Y1, Y7,  Y16) // degree 2
	SQUARE_MUL_PAIR(Y2, Y2, Y9,  Y18) // degree 4
	SQUARE_MUL_PAIR(Y3, Y3, Y11, Y20) // degree 6
	SQUARE_MUL_PAIR(Y4, Y4, Y13, Y22) // degree 8

	// Convert IFMA's 52-bit split to radix 2^51 coefficients.
	SQUARE_COMBINE_HIGH(Y14, Y6)
	SQUARE_COMBINE_HIGH(Y15, Y7)
	SQUARE_COMBINE_HIGH(Y16, Y8)
	SQUARE_COMBINE_HIGH(Y17, Y9)
	SQUARE_COMBINE_HIGH(Y18, Y10)
	SQUARE_COMBINE_HIGH(Y19, Y11)
	SQUARE_COMBINE_HIGH(Y20, Y12)
	SQUARE_COMBINE_HIGH(Y21, Y13)
	VPSLLQ $1, Y22, Y22

	// Fold degrees 5..9 with 2^255 == 19 (mod p).
	SQUARE_FOLD_INTO(Y5, Y10, Y23, Y24)
	SQUARE_FOLD_INTO(Y6, Y11, Y23, Y24)
	SQUARE_FOLD_INTO(Y7, Y12, Y23, Y24)
	SQUARE_FOLD_INTO(Y8, Y13, Y23, Y24)
	SQUARE_FOLD_INTO(Y9, Y22, Y23, Y24)

	VPBROADCASTQ ·ifmaLimbMask51(SB), Y0
	VPBROADCASTQ ·ifmaFold19(SB), Y15
	SQUARE_NORMALIZE_5(Y5, Y6, Y7, Y8, Y9, Y0, Y10, Y11, Y12, Y13, Y14, Y15)

	VMOVDQU64 Y5,   0(DI)
	VMOVDQU64 Y6,  32(DI)
	VMOVDQU64 Y7,  64(DI)
	VMOVDQU64 Y8,  96(DI)
	VMOVDQU64 Y9, 128(DI)
	VZEROUPPER
	RET
