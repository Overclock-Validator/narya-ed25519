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

// func ifmaSquareNormalizedExperimentX8(out, x *LimbsX8)
//
// Native-ZMM form of the symmetry-aware square above. Register allocation and
// operation order intentionally match x4 so the established exact-u61 and
// carry/fold bounds transfer without a second arithmetic schedule.
TEXT ·ifmaSquareNormalizedExperimentX8(SB), NOSPLIT, $0-16
	MOVQ out+0(FP), DI
	MOVQ x+8(FP), CX

	VMOVDQU64   0(CX), Z0
	VMOVDQU64  64(CX), Z1
	VMOVDQU64 128(CX), Z2
	VMOVDQU64 192(CX), Z3
	VMOVDQU64 256(CX), Z4

	SQUARE_CLEAR(Z5)
	SQUARE_CLEAR(Z6)
	SQUARE_CLEAR(Z7)
	SQUARE_CLEAR(Z8)
	SQUARE_CLEAR(Z9)
	SQUARE_CLEAR(Z10)
	SQUARE_CLEAR(Z11)
	SQUARE_CLEAR(Z12)
	SQUARE_CLEAR(Z13)
	SQUARE_CLEAR(Z14)
	SQUARE_CLEAR(Z15)
	SQUARE_CLEAR(Z16)
	SQUARE_CLEAR(Z17)
	SQUARE_CLEAR(Z18)
	SQUARE_CLEAR(Z19)
	SQUARE_CLEAR(Z20)
	SQUARE_CLEAR(Z21)
	SQUARE_CLEAR(Z22)

	SQUARE_MUL_PAIR(Z0, Z1, Z6,  Z15)
	SQUARE_MUL_PAIR(Z0, Z2, Z7,  Z16)
	SQUARE_MUL_PAIR(Z0, Z3, Z8,  Z17)
	SQUARE_MUL_PAIR(Z0, Z4, Z9,  Z18)
	SQUARE_MUL_PAIR(Z1, Z2, Z8,  Z17)
	SQUARE_MUL_PAIR(Z1, Z3, Z9,  Z18)
	SQUARE_MUL_PAIR(Z1, Z4, Z10, Z19)
	SQUARE_MUL_PAIR(Z2, Z3, Z10, Z19)
	SQUARE_MUL_PAIR(Z2, Z4, Z11, Z20)
	SQUARE_MUL_PAIR(Z3, Z4, Z12, Z21)

	VPSLLQ $1, Z6,  Z6
	VPSLLQ $1, Z7,  Z7
	VPSLLQ $1, Z8,  Z8
	VPSLLQ $1, Z9,  Z9
	VPSLLQ $1, Z10, Z10
	VPSLLQ $1, Z11, Z11
	VPSLLQ $1, Z12, Z12
	VPSLLQ $1, Z15, Z15
	VPSLLQ $1, Z16, Z16
	VPSLLQ $1, Z17, Z17
	VPSLLQ $1, Z18, Z18
	VPSLLQ $1, Z19, Z19
	VPSLLQ $1, Z20, Z20
	VPSLLQ $1, Z21, Z21

	SQUARE_MUL_PAIR(Z0, Z0, Z5,  Z14)
	SQUARE_MUL_PAIR(Z1, Z1, Z7,  Z16)
	SQUARE_MUL_PAIR(Z2, Z2, Z9,  Z18)
	SQUARE_MUL_PAIR(Z3, Z3, Z11, Z20)
	SQUARE_MUL_PAIR(Z4, Z4, Z13, Z22)

	SQUARE_COMBINE_HIGH(Z14, Z6)
	SQUARE_COMBINE_HIGH(Z15, Z7)
	SQUARE_COMBINE_HIGH(Z16, Z8)
	SQUARE_COMBINE_HIGH(Z17, Z9)
	SQUARE_COMBINE_HIGH(Z18, Z10)
	SQUARE_COMBINE_HIGH(Z19, Z11)
	SQUARE_COMBINE_HIGH(Z20, Z12)
	SQUARE_COMBINE_HIGH(Z21, Z13)
	VPSLLQ $1, Z22, Z22

	SQUARE_FOLD_INTO(Z5, Z10, Z23, Z24)
	SQUARE_FOLD_INTO(Z6, Z11, Z23, Z24)
	SQUARE_FOLD_INTO(Z7, Z12, Z23, Z24)
	SQUARE_FOLD_INTO(Z8, Z13, Z23, Z24)
	SQUARE_FOLD_INTO(Z9, Z22, Z23, Z24)

	VPBROADCASTQ ·ifmaLimbMask51(SB), Z0
	VPBROADCASTQ ·ifmaFold19(SB), Z15
	SQUARE_NORMALIZE_5(Z5, Z6, Z7, Z8, Z9, Z0, Z10, Z11, Z12, Z13, Z14, Z15)

	VMOVDQU64 Z5,   0(DI)
	VMOVDQU64 Z6,  64(DI)
	VMOVDQU64 Z7, 128(DI)
	VMOVDQU64 Z8, 192(DI)
	VMOVDQU64 Z9, 256(DI)
	VZEROUPPER
	RET
