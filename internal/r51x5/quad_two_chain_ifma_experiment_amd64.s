//go:build amd64 && !purego

#include "textflag.h"

#define TWO_CHAIN_DOUBLE_LINEAR(Q, P, T0, T1, T2, ZERO) \
	VPERMQ    $0x57, Q, T0                             \
	VPERMQ    $0x03, Q, T1                             \
	VPSUBQ    T1, T0, T2                               \
	VPADDQ    T1, T0, T0                               \
	VPSUBQ    T0, ZERO, T1                             \
	VMOVDQU64 T0, K1, T2                               \
	VMOVDQU64 T1, K2, T2                               \
	VPERMQ    $0xaa, Q, T0                             \
	VPSLLQ    $1, T0, T0                               \
	VPSUBQ    T0, T2, K3, T2                          \
	VPADDQ    P, T2, Q

#define TWO_CHAIN_NORMALIZE_5(IN0, IN1, IN2, IN3, IN4, MASK, C0, C1, C2, C3, C4, FOLD19) \
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

#define TWO_CHAIN_MUL_PAIR(X, Y, L, H) \
	VPMADD52LUQ Y, X, L                 \
	VPMADD52HUQ Y, X, H

#define TWO_CHAIN_COMBINE_HIGH(H, L) \
	VPSLLQ $1, H, H                    \
	VPADDQ H, L, L

#define TWO_CHAIN_FOLD_MUL19(LO, HI, T0, FOLD19) \
	VPMULLQ FOLD19, HI, T0                        \
	VPADDQ T0, LO, LO

// Apply [X,Y,T,Z] -> [Y-X,Y+X,T,Z] independently in both 256-bit
// halves. K1 selects X lanes 0/4; K2 selects Y lanes 1/5.
#define TWO_CHAIN_CACHED_ADD_FIRST_LINEAR(Q, P, T0, T1) \
	VPERMQ $0xe5, Q, T0                                  \
	VPERMQ $0x00, Q, T1                                  \
	VPSUBQ T1, T0, K1, T0                                \
	VPADDQ T1, T0, K2, T0                                \
	VPADDQ P, T0, Q

// Apply [A,B,C,D] -> [E,G,H,F] independently in both halves. K1 selects
// E/F (lanes 0/3 and 4/7); K2 selects G/H (lanes 1/2 and 5/6).
#define TWO_CHAIN_CACHED_ADD_LINEAR(Q, P, T0, T1, T2) \
	VPERMQ    $0xdd, Q, T0                              \
	VPERMQ    $0x88, Q, T1                              \
	VPSUBQ    T1, T0, T2                                \
	VPADDQ    T1, T0, T0                                \
	VPXORQ    Q, Q, Q                                   \
	VMOVDQU64 T2, K1, Q                                 \
	VMOVDQU64 T0, K2, Q                                 \
	VPADDQ    P, Q, Q

// func ifmaQuadTwoChainDoubleFirstOperandsUncheckedX8(u, v, q *LimbsX8)
TEXT ·ifmaQuadTwoChainDoubleFirstOperandsUncheckedX8(SB), NOSPLIT, $0-24
	MOVQ u+0(FP), DI
	MOVQ v+8(FP), SI
	MOVQ q+16(FP), CX

	VMOVDQU64   0(CX), Z0
	VMOVDQU64  64(CX), Z1
	VMOVDQU64 128(CX), Z2
	VMOVDQU64 192(CX), Z3
	VMOVDQU64 256(CX), Z4

	// VPERMQ applies the same immediate permutation independently to both
	// 256-bit halves, preserving the two packed point chains.
	VPERMQ $0x34, Z0, Z5
	VPERMQ $0x74, Z0, Z6
	VMOVDQU64 Z5,   0(DI)
	VMOVDQU64 Z6,   0(SI)
	VPERMQ $0x34, Z1, Z5
	VPERMQ $0x74, Z1, Z6
	VMOVDQU64 Z5,  64(DI)
	VMOVDQU64 Z6,  64(SI)
	VPERMQ $0x34, Z2, Z5
	VPERMQ $0x74, Z2, Z6
	VMOVDQU64 Z5, 128(DI)
	VMOVDQU64 Z6, 128(SI)
	VPERMQ $0x34, Z3, Z5
	VPERMQ $0x74, Z3, Z6
	VMOVDQU64 Z5, 192(DI)
	VMOVDQU64 Z6, 192(SI)
	VPERMQ $0x34, Z4, Z5
	VPERMQ $0x74, Z4, Z6
	VMOVDQU64 Z5, 256(DI)
	VMOVDQU64 Z6, 256(SI)
	VZEROUPPER
	RET

// func ifmaQuadTwoChainCachedAddFirstOperandUncheckedX8(out, q *LimbsX8)
TEXT ·ifmaQuadTwoChainCachedAddFirstOperandUncheckedX8(SB), NOSPLIT, $0-16
	MOVQ out+0(FP), DI
	MOVQ q+8(FP), CX

	VMOVDQU64   0(CX), Z0
	VMOVDQU64  64(CX), Z1
	VMOVDQU64 128(CX), Z2
	VMOVDQU64 192(CX), Z3
	VMOVDQU64 256(CX), Z4

	MOVQ $0x11, AX
	KMOVB AX, K1
	MOVQ $0x22, AX
	KMOVB AX, K2
	VPXORQ Z6, Z6, Z6
	VPBROADCASTQ ·ifmaSubBias0(SB), Z5
	VMOVDQU64 Z5, K1, Z6
	TWO_CHAIN_CACHED_ADD_FIRST_LINEAR(Z0, Z6, Z7, Z8)
	VPXORQ Z6, Z6, Z6
	VPBROADCASTQ ·ifmaSubBiasN(SB), Z5
	VMOVDQU64 Z5, K1, Z6
	TWO_CHAIN_CACHED_ADD_FIRST_LINEAR(Z1, Z6, Z7, Z8)
	TWO_CHAIN_CACHED_ADD_FIRST_LINEAR(Z2, Z6, Z7, Z8)
	TWO_CHAIN_CACHED_ADD_FIRST_LINEAR(Z3, Z6, Z7, Z8)
	TWO_CHAIN_CACHED_ADD_FIRST_LINEAR(Z4, Z6, Z7, Z8)

	VPBROADCASTQ ·ifmaLimbMask51(SB), Z5
	VPBROADCASTQ ·ifmaFold19(SB), Z11
	TWO_CHAIN_NORMALIZE_5(Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, Z11)

	VMOVDQU64 Z0,   0(DI)
	VMOVDQU64 Z1,  64(DI)
	VMOVDQU64 Z2, 128(DI)
	VMOVDQU64 Z3, 192(DI)
	VMOVDQU64 Z4, 256(DI)
	VZEROUPPER
	RET

// func ifmaQuadTwoChainCachedAddFinalOperandsUncheckedX8(left, right, products *LimbsX8)
TEXT ·ifmaQuadTwoChainCachedAddFinalOperandsUncheckedX8(SB), NOSPLIT, $0-24
	MOVQ left+0(FP), DI
	MOVQ right+8(FP), SI
	MOVQ products+16(FP), CX

	VMOVDQU64   0(CX), Z0
	VMOVDQU64  64(CX), Z1
	VMOVDQU64 128(CX), Z2
	VMOVDQU64 192(CX), Z3
	VMOVDQU64 256(CX), Z4

	MOVQ $0x99, AX
	KMOVB AX, K1
	MOVQ $0x66, AX
	KMOVB AX, K2
	VPXORQ Z6, Z6, Z6
	VPBROADCASTQ ·ifmaQuadCachedAddBias8P0(SB), Z5
	VMOVDQU64 Z5, K1, Z6
	TWO_CHAIN_CACHED_ADD_LINEAR(Z0, Z6, Z7, Z8, Z9)
	VPXORQ Z6, Z6, Z6
	VPBROADCASTQ ·ifmaQuadCachedAddBias8PN(SB), Z5
	VMOVDQU64 Z5, K1, Z6
	TWO_CHAIN_CACHED_ADD_LINEAR(Z1, Z6, Z7, Z8, Z9)
	TWO_CHAIN_CACHED_ADD_LINEAR(Z2, Z6, Z7, Z8, Z9)
	TWO_CHAIN_CACHED_ADD_LINEAR(Z3, Z6, Z7, Z8, Z9)
	TWO_CHAIN_CACHED_ADD_LINEAR(Z4, Z6, Z7, Z8, Z9)

	VPBROADCASTQ ·ifmaLimbMask51(SB), Z5
	VPBROADCASTQ ·ifmaFold19(SB), Z11
	TWO_CHAIN_NORMALIZE_5(Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, Z11)

	VPERMQ $0xc4, Z0, Z12
	VPERMQ $0x6b, Z0, Z13
	VMOVDQU64 Z12,   0(DI)
	VMOVDQU64 Z13,   0(SI)
	VPERMQ $0xc4, Z1, Z12
	VPERMQ $0x6b, Z1, Z13
	VMOVDQU64 Z12,  64(DI)
	VMOVDQU64 Z13,  64(SI)
	VPERMQ $0xc4, Z2, Z12
	VPERMQ $0x6b, Z2, Z13
	VMOVDQU64 Z12, 128(DI)
	VMOVDQU64 Z13, 128(SI)
	VPERMQ $0xc4, Z3, Z12
	VPERMQ $0x6b, Z3, Z13
	VMOVDQU64 Z12, 192(DI)
	VMOVDQU64 Z13, 192(SI)
	VPERMQ $0xc4, Z4, Z12
	VPERMQ $0x6b, Z4, Z13
	VMOVDQU64 Z12, 256(DI)
	VMOVDQU64 Z13, 256(SI)
	VZEROUPPER
	RET

// func ifmaQuadTwoChainDoubleFinalMultiplyUncheckedX8(out, products *LimbsX8)
TEXT ·ifmaQuadTwoChainDoubleFinalMultiplyUncheckedX8(SB), NOSPLIT, $0-16
	MOVQ out+0(FP), DI
	MOVQ products+8(FP), CX

	VMOVDQU64   0(CX), Z0
	VMOVDQU64  64(CX), Z1
	VMOVDQU64 128(CX), Z2
	VMOVDQU64 192(CX), Z3
	VMOVDQU64 256(CX), Z4

	MOVQ $0x11, AX
	KMOVB AX, K1
	MOVQ $0x44, AX
	KMOVB AX, K2
	MOVQ $0x88, AX
	KMOVB AX, K3
	VMOVDQU64 ·ifmaQuadTwoChainDoubleBias8P0(SB), Z5
	VMOVDQU64 ·ifmaQuadTwoChainDoubleBias8PN(SB), Z6
	VPXORQ Z7, Z7, Z7

	TWO_CHAIN_DOUBLE_LINEAR(Z0, Z5, Z8, Z9, Z10, Z7)
	TWO_CHAIN_DOUBLE_LINEAR(Z1, Z6, Z8, Z9, Z10, Z7)
	TWO_CHAIN_DOUBLE_LINEAR(Z2, Z6, Z8, Z9, Z10, Z7)
	TWO_CHAIN_DOUBLE_LINEAR(Z3, Z6, Z8, Z9, Z10, Z7)
	TWO_CHAIN_DOUBLE_LINEAR(Z4, Z6, Z8, Z9, Z10, Z7)

	VPBROADCASTQ ·ifmaLimbMask51(SB), Z5
	VPBROADCASTQ ·ifmaFold19(SB), Z6
	TWO_CHAIN_NORMALIZE_5(Z0, Z1, Z2, Z3, Z4, Z5, Z7, Z8, Z9, Z10, Z11, Z6)

	VPERMQ $0x6b, Z0, Z5
	VPERMQ $0xc4, Z0, Z0
	VPERMQ $0x6b, Z1, Z6
	VPERMQ $0xc4, Z1, Z1
	VPERMQ $0x6b, Z2, Z7
	VPERMQ $0xc4, Z2, Z2
	VPERMQ $0x6b, Z3, Z8
	VPERMQ $0xc4, Z3, Z3
	VPERMQ $0x6b, Z4, Z9
	VPERMQ $0xc4, Z4, Z4

	VPXORQ Z10, Z10, Z10
	VPXORQ Z11, Z11, Z11
	VPXORQ Z12, Z12, Z12
	VPXORQ Z13, Z13, Z13
	VPXORQ Z14, Z14, Z14
	VPXORQ Z15, Z15, Z15
	VPXORQ Z16, Z16, Z16
	VPXORQ Z17, Z17, Z17
	VPXORQ Z18, Z18, Z18
	VPXORQ Z19, Z19, Z19
	VPXORQ Z20, Z20, Z20
	VPXORQ Z21, Z21, Z21
	VPXORQ Z22, Z22, Z22
	VPXORQ Z23, Z23, Z23
	VPXORQ Z24, Z24, Z24
	VPXORQ Z25, Z25, Z25
	VPXORQ Z26, Z26, Z26
	VPXORQ Z27, Z27, Z27

	TWO_CHAIN_MUL_PAIR(Z0, Z5, Z10, Z19)
	TWO_CHAIN_MUL_PAIR(Z0, Z6, Z11, Z20)
	TWO_CHAIN_MUL_PAIR(Z0, Z7, Z12, Z21)
	TWO_CHAIN_MUL_PAIR(Z0, Z8, Z13, Z22)
	TWO_CHAIN_MUL_PAIR(Z0, Z9, Z14, Z23)
	TWO_CHAIN_MUL_PAIR(Z1, Z5, Z11, Z20)
	TWO_CHAIN_MUL_PAIR(Z1, Z6, Z12, Z21)
	TWO_CHAIN_MUL_PAIR(Z1, Z7, Z13, Z22)
	TWO_CHAIN_MUL_PAIR(Z1, Z8, Z14, Z23)
	TWO_CHAIN_MUL_PAIR(Z1, Z9, Z15, Z24)
	TWO_CHAIN_MUL_PAIR(Z2, Z5, Z12, Z21)
	TWO_CHAIN_MUL_PAIR(Z2, Z6, Z13, Z22)
	TWO_CHAIN_MUL_PAIR(Z2, Z7, Z14, Z23)
	TWO_CHAIN_MUL_PAIR(Z2, Z8, Z15, Z24)
	TWO_CHAIN_MUL_PAIR(Z2, Z9, Z16, Z25)
	TWO_CHAIN_MUL_PAIR(Z3, Z5, Z13, Z22)
	TWO_CHAIN_MUL_PAIR(Z3, Z6, Z14, Z23)
	TWO_CHAIN_MUL_PAIR(Z3, Z7, Z15, Z24)
	TWO_CHAIN_MUL_PAIR(Z3, Z8, Z16, Z25)
	TWO_CHAIN_MUL_PAIR(Z3, Z9, Z17, Z26)
	TWO_CHAIN_MUL_PAIR(Z4, Z5, Z14, Z23)
	TWO_CHAIN_MUL_PAIR(Z4, Z6, Z15, Z24)
	TWO_CHAIN_MUL_PAIR(Z4, Z7, Z16, Z25)
	TWO_CHAIN_MUL_PAIR(Z4, Z8, Z17, Z26)
	TWO_CHAIN_MUL_PAIR(Z4, Z9, Z18, Z27)

	TWO_CHAIN_COMBINE_HIGH(Z19, Z11)
	TWO_CHAIN_COMBINE_HIGH(Z20, Z12)
	TWO_CHAIN_COMBINE_HIGH(Z21, Z13)
	TWO_CHAIN_COMBINE_HIGH(Z22, Z14)
	TWO_CHAIN_COMBINE_HIGH(Z23, Z15)
	TWO_CHAIN_COMBINE_HIGH(Z24, Z16)
	TWO_CHAIN_COMBINE_HIGH(Z25, Z17)
	TWO_CHAIN_COMBINE_HIGH(Z26, Z18)
	VPSLLQ $1, Z27, Z27

	VPBROADCASTQ ·ifmaFold19(SB), Z30
	TWO_CHAIN_FOLD_MUL19(Z10, Z15, Z28, Z30)
	TWO_CHAIN_FOLD_MUL19(Z11, Z16, Z28, Z30)
	TWO_CHAIN_FOLD_MUL19(Z12, Z17, Z28, Z30)
	TWO_CHAIN_FOLD_MUL19(Z13, Z18, Z28, Z30)
	TWO_CHAIN_FOLD_MUL19(Z14, Z27, Z28, Z30)

	VPBROADCASTQ ·ifmaLimbMask51(SB), Z5
	TWO_CHAIN_NORMALIZE_5(Z10, Z11, Z12, Z13, Z14, Z5, Z15, Z16, Z17, Z18, Z19, Z30)

	VMOVDQU64 Z10,   0(DI)
	VMOVDQU64 Z11,  64(DI)
	VMOVDQU64 Z12, 128(DI)
	VMOVDQU64 Z13, 192(DI)
	VMOVDQU64 Z14, 256(DI)
	VZEROUPPER
	RET

DATA ·ifmaQuadTwoChainDoubleBias8P0+0(SB)/8,  $0x0000000000000000
DATA ·ifmaQuadTwoChainDoubleBias8P0+8(SB)/8,  $0x003fffffffffff68
DATA ·ifmaQuadTwoChainDoubleBias8P0+16(SB)/8, $0x003fffffffffff68
DATA ·ifmaQuadTwoChainDoubleBias8P0+24(SB)/8, $0x003fffffffffff68
DATA ·ifmaQuadTwoChainDoubleBias8P0+32(SB)/8, $0x0000000000000000
DATA ·ifmaQuadTwoChainDoubleBias8P0+40(SB)/8, $0x003fffffffffff68
DATA ·ifmaQuadTwoChainDoubleBias8P0+48(SB)/8, $0x003fffffffffff68
DATA ·ifmaQuadTwoChainDoubleBias8P0+56(SB)/8, $0x003fffffffffff68
GLOBL ·ifmaQuadTwoChainDoubleBias8P0(SB), RODATA|NOPTR, $64

DATA ·ifmaQuadTwoChainDoubleBias8PN+0(SB)/8,  $0x0000000000000000
DATA ·ifmaQuadTwoChainDoubleBias8PN+8(SB)/8,  $0x003ffffffffffff8
DATA ·ifmaQuadTwoChainDoubleBias8PN+16(SB)/8, $0x003ffffffffffff8
DATA ·ifmaQuadTwoChainDoubleBias8PN+24(SB)/8, $0x003ffffffffffff8
DATA ·ifmaQuadTwoChainDoubleBias8PN+32(SB)/8, $0x0000000000000000
DATA ·ifmaQuadTwoChainDoubleBias8PN+40(SB)/8, $0x003ffffffffffff8
DATA ·ifmaQuadTwoChainDoubleBias8PN+48(SB)/8, $0x003ffffffffffff8
DATA ·ifmaQuadTwoChainDoubleBias8PN+56(SB)/8, $0x003ffffffffffff8
GLOBL ·ifmaQuadTwoChainDoubleBias8PN(SB), RODATA|NOPTR, $64
