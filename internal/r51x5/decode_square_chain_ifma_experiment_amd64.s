//go:build amd64

#include "textflag.h"

#define CHAIN_SQUARE_MUL_PAIR(X, Y, L, H) \
	VPMADD52LUQ Y, X, L                    \
	VPMADD52HUQ Y, X, H

#define CHAIN_SQUARE_CLEAR(R) VPXORQ R, R, R

#define CHAIN_SQUARE_COMBINE_HIGH(H, L) \
	VPSLLQ $1, H, H                       \
	VPADDQ H, L, L

#define CHAIN_SQUARE_FOLD_MUL19(LO, HI, T, FOLD19) \
	VPMULLQ FOLD19, HI, T                         \
	VPADDQ T, LO, LO

#define CHAIN_SQUARE_NORMALIZE_5(IN0, IN1, IN2, IN3, IN4, MASK, C0, C1, C2, C3, C4, FOLD19) \
	VPSRLQ $51, IN0, C0                                                                        \
	VPSRLQ $51, IN1, C1                                                                        \
	VPSRLQ $51, IN2, C2                                                                        \
	VPSRLQ $51, IN3, C3                                                                        \
	VPSRLQ $51, IN4, C4                                                                        \
	VPANDQ MASK, IN0, IN0                                                                      \
	VPANDQ MASK, IN1, IN1                                                                      \
	VPANDQ MASK, IN2, IN2                                                                      \
	VPANDQ MASK, IN3, IN3                                                                      \
	VPANDQ MASK, IN4, IN4                                                                      \
	VPADDQ C0, IN1, IN1                                                                        \
	VPADDQ C1, IN2, IN2                                                                        \
	VPADDQ C2, IN3, IN3                                                                        \
	VPADDQ C3, IN4, IN4                                                                        \
	VPMADD52LUQ C4, FOLD19, IN0

// func ifmaRepeatedSquareNormalizedExperimentX8(out, x *LimbsX8, count int)
//
// Z0..Z4 retain the running field element across every iteration. Z5..Z13
// are low convolution accumulators, Z14..Z22 are high accumulators, Z23 is
// fold scratch, and Z24/Z25 retain the limb mask and fold constant. Nothing
// is stored until the entire dependent chain is complete.
TEXT ·ifmaRepeatedSquareNormalizedExperimentX8(SB), NOSPLIT, $0-24
	MOVQ out+0(FP), DI
	MOVQ x+8(FP), CX
	MOVQ count+16(FP), AX

	VMOVDQU64   0(CX), Z0
	VMOVDQU64  64(CX), Z1
	VMOVDQU64 128(CX), Z2
	VMOVDQU64 192(CX), Z3
	VMOVDQU64 256(CX), Z4
	TESTQ AX, AX
	JE chain_square_store

	VPBROADCASTQ ·ifmaLimbMask51(SB), Z24
	VPBROADCASTQ ·ifmaFold19(SB), Z25

chain_square_loop:
	CHAIN_SQUARE_CLEAR(Z5)
	CHAIN_SQUARE_CLEAR(Z6)
	CHAIN_SQUARE_CLEAR(Z7)
	CHAIN_SQUARE_CLEAR(Z8)
	CHAIN_SQUARE_CLEAR(Z9)
	CHAIN_SQUARE_CLEAR(Z10)
	CHAIN_SQUARE_CLEAR(Z11)
	CHAIN_SQUARE_CLEAR(Z12)
	CHAIN_SQUARE_CLEAR(Z13)
	CHAIN_SQUARE_CLEAR(Z14)
	CHAIN_SQUARE_CLEAR(Z15)
	CHAIN_SQUARE_CLEAR(Z16)
	CHAIN_SQUARE_CLEAR(Z17)
	CHAIN_SQUARE_CLEAR(Z18)
	CHAIN_SQUARE_CLEAR(Z19)
	CHAIN_SQUARE_CLEAR(Z20)
	CHAIN_SQUARE_CLEAR(Z21)
	CHAIN_SQUARE_CLEAR(Z22)

	CHAIN_SQUARE_MUL_PAIR(Z0, Z1, Z6,  Z15)
	CHAIN_SQUARE_MUL_PAIR(Z0, Z2, Z7,  Z16)
	CHAIN_SQUARE_MUL_PAIR(Z0, Z3, Z8,  Z17)
	CHAIN_SQUARE_MUL_PAIR(Z0, Z4, Z9,  Z18)
	CHAIN_SQUARE_MUL_PAIR(Z1, Z2, Z8,  Z17)
	CHAIN_SQUARE_MUL_PAIR(Z1, Z3, Z9,  Z18)
	CHAIN_SQUARE_MUL_PAIR(Z1, Z4, Z10, Z19)
	CHAIN_SQUARE_MUL_PAIR(Z2, Z3, Z10, Z19)
	CHAIN_SQUARE_MUL_PAIR(Z2, Z4, Z11, Z20)
	CHAIN_SQUARE_MUL_PAIR(Z3, Z4, Z12, Z21)

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

	CHAIN_SQUARE_MUL_PAIR(Z0, Z0, Z5,  Z14)
	CHAIN_SQUARE_MUL_PAIR(Z1, Z1, Z7,  Z16)
	CHAIN_SQUARE_MUL_PAIR(Z2, Z2, Z9,  Z18)
	CHAIN_SQUARE_MUL_PAIR(Z3, Z3, Z11, Z20)
	CHAIN_SQUARE_MUL_PAIR(Z4, Z4, Z13, Z22)

	CHAIN_SQUARE_COMBINE_HIGH(Z14, Z6)
	CHAIN_SQUARE_COMBINE_HIGH(Z15, Z7)
	CHAIN_SQUARE_COMBINE_HIGH(Z16, Z8)
	CHAIN_SQUARE_COMBINE_HIGH(Z17, Z9)
	CHAIN_SQUARE_COMBINE_HIGH(Z18, Z10)
	CHAIN_SQUARE_COMBINE_HIGH(Z19, Z11)
	CHAIN_SQUARE_COMBINE_HIGH(Z20, Z12)
	CHAIN_SQUARE_COMBINE_HIGH(Z21, Z13)
	VPSLLQ $1, Z22, Z22

	CHAIN_SQUARE_FOLD_MUL19(Z5, Z10, Z23, Z25)
	CHAIN_SQUARE_FOLD_MUL19(Z6, Z11, Z23, Z25)
	CHAIN_SQUARE_FOLD_MUL19(Z7, Z12, Z23, Z25)
	CHAIN_SQUARE_FOLD_MUL19(Z8, Z13, Z23, Z25)
	CHAIN_SQUARE_FOLD_MUL19(Z9, Z22, Z23, Z25)

	CHAIN_SQUARE_NORMALIZE_5(Z5, Z6, Z7, Z8, Z9, Z24, Z10, Z11, Z12, Z13, Z14, Z25)

	VMOVDQA64 Z5, Z0
	VMOVDQA64 Z6, Z1
	VMOVDQA64 Z7, Z2
	VMOVDQA64 Z8, Z3
	VMOVDQA64 Z9, Z4
	DECQ AX
	JNZ chain_square_loop

chain_square_store:
	VMOVDQU64 Z0,   0(DI)
	VMOVDQU64 Z1,  64(DI)
	VMOVDQU64 Z2, 128(DI)
	VMOVDQU64 Z3, 192(DI)
	VMOVDQU64 Z4, 256(DI)
	VZEROUPPER
	RET
