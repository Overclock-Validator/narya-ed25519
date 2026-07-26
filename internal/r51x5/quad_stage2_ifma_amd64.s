//go:build amd64

#include "textflag.h"

// Turn one packed [A,B,C,D] limb into [E,G,H,F]. The lane masks and bias
// vectors are constants; Q is overwritten only after every source lane has
// been selected.
#define QUAD_DOUBLE_LINEAR(Q, P, M0, M2, M3, M123, T0, T1) \
	VPERMQ  $0x57, Q, T0                                  \
	VPANDQ  M0, T0, T1                                    \
	VPADDQ  T1, T0, T0                                    \
	VPANDQ  M2, T0, T1                                    \
	VPSLLQ  $1, T1, T1                                    \
	VPSUBQ  T1, T0, T0                                    \
	VPERMQ  $0xaa, Q, T1                                  \
	VPANDQ  M3, T1, T1                                    \
	VPSLLQ  $1, T1, T1                                    \
	VPSUBQ  T1, T0, T0                                    \
	VPERMQ  $0x00, Q, T1                                  \
	VPANDQ  M123, T1, T1                                  \
	VPSUBQ  T1, T0, T0                                    \
	VPADDQ  P, T0, Q

// Turn one packed [A,B,C,D] limb into [E,G,H,F] for cached addition. M03
// selects the two subtraction lanes, M12 selects the addition lanes, and P
// adds 8p only to E/F.
#define QUAD_CACHED_ADD_LINEAR(Q, P, M03, M12, T0, T1, T2) \
	VPERMQ  $0xdd, Q, T0                                      \
	VPERMQ  $0x88, Q, T1                                      \
	VPSUBQ  T1, T0, T2                                        \
	VPADDQ  T1, T0, T0                                        \
	VPANDQ  M03, T2, T2                                       \
	VPANDQ  M12, T0, T0                                       \
	VPORQ   T2, T0, Q                                         \
	VPADDQ  P, Q, Q

// Turn one packed [X,Y,T,Z] limb into [Y-X,Y+X,T,Z]. P is 4p in lane zero.
#define QUAD_CACHED_ADD_FIRST_LINEAR(Q, P, M0, M1, T0, T1, T2) \
	VPERMQ  $0xe5, Q, T0                                        \
	VPERMQ  $0x00, Q, T1                                        \
	VPANDQ  M0, T1, T2                                          \
	VPSUBQ  T2, T0, T0                                          \
	VPANDQ  M1, T1, T2                                          \
	VPADDQ  T2, T0, T0                                          \
	VPADDQ  P, T0, Q

// Inputs are below 12*2^51, so each carry is at most eleven and 19*C4 fits
// wholly in the low 52-bit half consumed by VPMADD52LUQ.
#define QUAD_DOUBLE_NORMALIZE_5(IN0, IN1, IN2, IN3, IN4, MASK, C0, C1, C2, C3, C4, FOLD19) \
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

// func ifmaQuadDoubleFirstOperandsUncheckedX4(u, v, q *LimbsX4)
TEXT ·ifmaQuadDoubleFirstOperandsUncheckedX4(SB), NOSPLIT, $0-24
	MOVQ u+0(FP), DI
	MOVQ v+8(FP), SI
	MOVQ q+16(FP), CX

	VMOVDQU64   0(CX), Y0
	VMOVDQU64  32(CX), Y1
	VMOVDQU64  64(CX), Y2
	VMOVDQU64  96(CX), Y3
	VMOVDQU64 128(CX), Y4

	VPERMQ $0x34, Y0, Y5
	VPERMQ $0x74, Y0, Y6
	VMOVDQU64 Y5,   0(DI)
	VMOVDQU64 Y6,   0(SI)
	VPERMQ $0x34, Y1, Y5
	VPERMQ $0x74, Y1, Y6
	VMOVDQU64 Y5,  32(DI)
	VMOVDQU64 Y6,  32(SI)
	VPERMQ $0x34, Y2, Y5
	VPERMQ $0x74, Y2, Y6
	VMOVDQU64 Y5,  64(DI)
	VMOVDQU64 Y6,  64(SI)
	VPERMQ $0x34, Y3, Y5
	VPERMQ $0x74, Y3, Y6
	VMOVDQU64 Y5,  96(DI)
	VMOVDQU64 Y6,  96(SI)
	VPERMQ $0x34, Y4, Y5
	VPERMQ $0x74, Y4, Y6
	VMOVDQU64 Y5, 128(DI)
	VMOVDQU64 Y6, 128(SI)
	VZEROUPPER
	RET

// func ifmaQuadCachedAddFirstOperandUncheckedX4(out, q *LimbsX4)
TEXT ·ifmaQuadCachedAddFirstOperandUncheckedX4(SB), NOSPLIT, $0-16
	MOVQ out+0(FP), DI
	MOVQ q+8(FP), CX

	VMOVDQU64   0(CX), Y0
	VMOVDQU64  32(CX), Y1
	VMOVDQU64  64(CX), Y2
	VMOVDQU64  96(CX), Y3
	VMOVDQU64 128(CX), Y4

	VMOVDQU64 ·ifmaQuadLaneMask0(SB), Y5
	VMOVDQU64 ·ifmaQuadLaneMask1(SB), Y6
	VPBROADCASTQ ·ifmaSubBias0(SB), Y7
	VPANDQ Y5, Y7, Y7
	QUAD_CACHED_ADD_FIRST_LINEAR(Y0, Y7, Y5, Y6, Y8, Y9, Y10)
	VPBROADCASTQ ·ifmaSubBiasN(SB), Y7
	VPANDQ Y5, Y7, Y7
	QUAD_CACHED_ADD_FIRST_LINEAR(Y1, Y7, Y5, Y6, Y8, Y9, Y10)
	QUAD_CACHED_ADD_FIRST_LINEAR(Y2, Y7, Y5, Y6, Y8, Y9, Y10)
	QUAD_CACHED_ADD_FIRST_LINEAR(Y3, Y7, Y5, Y6, Y8, Y9, Y10)
	QUAD_CACHED_ADD_FIRST_LINEAR(Y4, Y7, Y5, Y6, Y8, Y9, Y10)

	VPBROADCASTQ ·ifmaLimbMask51(SB), Y5
	VPBROADCASTQ ·ifmaFold19(SB), Y6
	QUAD_DOUBLE_NORMALIZE_5(Y0, Y1, Y2, Y3, Y4, Y5, Y7, Y8, Y9, Y10, Y11, Y6)

	VMOVDQU64 Y0,   0(DI)
	VMOVDQU64 Y1,  32(DI)
	VMOVDQU64 Y2,  64(DI)
	VMOVDQU64 Y3,  96(DI)
	VMOVDQU64 Y4, 128(DI)
	VZEROUPPER
	RET

// func ifmaQuadDoubleFinalOperandsUncheckedX4(left, right, products *LimbsX4)
TEXT ·ifmaQuadDoubleFinalOperandsUncheckedX4(SB), NOSPLIT, $0-24
	MOVQ left+0(FP), DI
	MOVQ right+8(FP), SI
	MOVQ products+16(FP), CX

	VMOVDQU64   0(CX), Y0
	VMOVDQU64  32(CX), Y1
	VMOVDQU64  64(CX), Y2
	VMOVDQU64  96(CX), Y3
	VMOVDQU64 128(CX), Y4

	VMOVDQU64 ·ifmaQuadLaneMask0(SB), Y5
	VMOVDQU64 ·ifmaQuadLaneMask2(SB), Y6
	VMOVDQU64 ·ifmaQuadLaneMask3(SB), Y7
	VMOVDQU64 ·ifmaQuadLaneMask123(SB), Y8
	VMOVDQU64 ·ifmaQuadDoubleBias8P0(SB), Y9
	VMOVDQU64 ·ifmaQuadDoubleBias8PN(SB), Y10

	QUAD_DOUBLE_LINEAR(Y0, Y9,  Y5, Y6, Y7, Y8, Y11, Y12)
	QUAD_DOUBLE_LINEAR(Y1, Y10, Y5, Y6, Y7, Y8, Y11, Y12)
	QUAD_DOUBLE_LINEAR(Y2, Y10, Y5, Y6, Y7, Y8, Y11, Y12)
	QUAD_DOUBLE_LINEAR(Y3, Y10, Y5, Y6, Y7, Y8, Y11, Y12)
	QUAD_DOUBLE_LINEAR(Y4, Y10, Y5, Y6, Y7, Y8, Y11, Y12)

	VPBROADCASTQ ·ifmaLimbMask51(SB), Y5
	VPBROADCASTQ ·ifmaFold19(SB), Y6
	QUAD_DOUBLE_NORMALIZE_5(Y0, Y1, Y2, Y3, Y4, Y5, Y7, Y8, Y9, Y10, Y11, Y6)

	VPERMQ $0xc4, Y0, Y12
	VPERMQ $0x6b, Y0, Y13
	VMOVDQU64 Y12,   0(DI)
	VMOVDQU64 Y13,   0(SI)
	VPERMQ $0xc4, Y1, Y12
	VPERMQ $0x6b, Y1, Y13
	VMOVDQU64 Y12,  32(DI)
	VMOVDQU64 Y13,  32(SI)
	VPERMQ $0xc4, Y2, Y12
	VPERMQ $0x6b, Y2, Y13
	VMOVDQU64 Y12,  64(DI)
	VMOVDQU64 Y13,  64(SI)
	VPERMQ $0xc4, Y3, Y12
	VPERMQ $0x6b, Y3, Y13
	VMOVDQU64 Y12,  96(DI)
	VMOVDQU64 Y13,  96(SI)
	VPERMQ $0xc4, Y4, Y12
	VPERMQ $0x6b, Y4, Y13
	VMOVDQU64 Y12, 128(DI)
	VMOVDQU64 Y13, 128(SI)
	VZEROUPPER
	RET

// func ifmaQuadCachedAddFinalOperandsUncheckedX4(left, right, products *LimbsX4)
TEXT ·ifmaQuadCachedAddFinalOperandsUncheckedX4(SB), NOSPLIT, $0-24
	MOVQ left+0(FP), DI
	MOVQ right+8(FP), SI
	MOVQ products+16(FP), CX

	VMOVDQU64   0(CX), Y0
	VMOVDQU64  32(CX), Y1
	VMOVDQU64  64(CX), Y2
	VMOVDQU64  96(CX), Y3
	VMOVDQU64 128(CX), Y4

	VMOVDQU64 ·ifmaQuadLaneMask03(SB), Y5
	VMOVDQU64 ·ifmaQuadLaneMask12(SB), Y6
	VMOVDQU64 ·ifmaQuadCachedAddBias8P0(SB), Y7
	VMOVDQU64 ·ifmaQuadCachedAddBias8PN(SB), Y8

	QUAD_CACHED_ADD_LINEAR(Y0, Y7, Y5, Y6, Y9, Y10, Y11)
	QUAD_CACHED_ADD_LINEAR(Y1, Y8, Y5, Y6, Y9, Y10, Y11)
	QUAD_CACHED_ADD_LINEAR(Y2, Y8, Y5, Y6, Y9, Y10, Y11)
	QUAD_CACHED_ADD_LINEAR(Y3, Y8, Y5, Y6, Y9, Y10, Y11)
	QUAD_CACHED_ADD_LINEAR(Y4, Y8, Y5, Y6, Y9, Y10, Y11)

	VPBROADCASTQ ·ifmaLimbMask51(SB), Y5
	VPBROADCASTQ ·ifmaFold19(SB), Y6
	QUAD_DOUBLE_NORMALIZE_5(Y0, Y1, Y2, Y3, Y4, Y5, Y7, Y8, Y9, Y10, Y11, Y6)

	VPERMQ $0xc4, Y0, Y12
	VPERMQ $0x6b, Y0, Y13
	VMOVDQU64 Y12,   0(DI)
	VMOVDQU64 Y13,   0(SI)
	VPERMQ $0xc4, Y1, Y12
	VPERMQ $0x6b, Y1, Y13
	VMOVDQU64 Y12,  32(DI)
	VMOVDQU64 Y13,  32(SI)
	VPERMQ $0xc4, Y2, Y12
	VPERMQ $0x6b, Y2, Y13
	VMOVDQU64 Y12,  64(DI)
	VMOVDQU64 Y13,  64(SI)
	VPERMQ $0xc4, Y3, Y12
	VPERMQ $0x6b, Y3, Y13
	VMOVDQU64 Y12,  96(DI)
	VMOVDQU64 Y13,  96(SI)
	VPERMQ $0xc4, Y4, Y12
	VPERMQ $0x6b, Y4, Y13
	VMOVDQU64 Y12, 128(DI)
	VMOVDQU64 Y13, 128(SI)
	VZEROUPPER
	RET

DATA ·ifmaQuadLaneMask0+0(SB)/8, $0xffffffffffffffff
DATA ·ifmaQuadLaneMask0+8(SB)/8, $0x0000000000000000
DATA ·ifmaQuadLaneMask0+16(SB)/8, $0x0000000000000000
DATA ·ifmaQuadLaneMask0+24(SB)/8, $0x0000000000000000
GLOBL ·ifmaQuadLaneMask0(SB), RODATA|NOPTR, $32

DATA ·ifmaQuadLaneMask1+0(SB)/8, $0x0000000000000000
DATA ·ifmaQuadLaneMask1+8(SB)/8, $0xffffffffffffffff
DATA ·ifmaQuadLaneMask1+16(SB)/8, $0x0000000000000000
DATA ·ifmaQuadLaneMask1+24(SB)/8, $0x0000000000000000
GLOBL ·ifmaQuadLaneMask1(SB), RODATA|NOPTR, $32

DATA ·ifmaQuadLaneMask2+0(SB)/8, $0x0000000000000000
DATA ·ifmaQuadLaneMask2+8(SB)/8, $0x0000000000000000
DATA ·ifmaQuadLaneMask2+16(SB)/8, $0xffffffffffffffff
DATA ·ifmaQuadLaneMask2+24(SB)/8, $0x0000000000000000
GLOBL ·ifmaQuadLaneMask2(SB), RODATA|NOPTR, $32

DATA ·ifmaQuadLaneMask3+0(SB)/8, $0x0000000000000000
DATA ·ifmaQuadLaneMask3+8(SB)/8, $0x0000000000000000
DATA ·ifmaQuadLaneMask3+16(SB)/8, $0x0000000000000000
DATA ·ifmaQuadLaneMask3+24(SB)/8, $0xffffffffffffffff
GLOBL ·ifmaQuadLaneMask3(SB), RODATA|NOPTR, $32

DATA ·ifmaQuadLaneMask123+0(SB)/8, $0x0000000000000000
DATA ·ifmaQuadLaneMask123+8(SB)/8, $0xffffffffffffffff
DATA ·ifmaQuadLaneMask123+16(SB)/8, $0xffffffffffffffff
DATA ·ifmaQuadLaneMask123+24(SB)/8, $0xffffffffffffffff
GLOBL ·ifmaQuadLaneMask123(SB), RODATA|NOPTR, $32

DATA ·ifmaQuadLaneMask03+0(SB)/8, $0xffffffffffffffff
DATA ·ifmaQuadLaneMask03+8(SB)/8, $0x0000000000000000
DATA ·ifmaQuadLaneMask03+16(SB)/8, $0x0000000000000000
DATA ·ifmaQuadLaneMask03+24(SB)/8, $0xffffffffffffffff
GLOBL ·ifmaQuadLaneMask03(SB), RODATA|NOPTR, $32

DATA ·ifmaQuadLaneMask12+0(SB)/8, $0x0000000000000000
DATA ·ifmaQuadLaneMask12+8(SB)/8, $0xffffffffffffffff
DATA ·ifmaQuadLaneMask12+16(SB)/8, $0xffffffffffffffff
DATA ·ifmaQuadLaneMask12+24(SB)/8, $0x0000000000000000
GLOBL ·ifmaQuadLaneMask12(SB), RODATA|NOPTR, $32

DATA ·ifmaQuadDoubleBias8P0+0(SB)/8, $0x0000000000000000
DATA ·ifmaQuadDoubleBias8P0+8(SB)/8, $0x003fffffffffff68
DATA ·ifmaQuadDoubleBias8P0+16(SB)/8, $0x003fffffffffff68
DATA ·ifmaQuadDoubleBias8P0+24(SB)/8, $0x003fffffffffff68
GLOBL ·ifmaQuadDoubleBias8P0(SB), RODATA|NOPTR, $32

DATA ·ifmaQuadDoubleBias8PN+0(SB)/8, $0x0000000000000000
DATA ·ifmaQuadDoubleBias8PN+8(SB)/8, $0x003ffffffffffff8
DATA ·ifmaQuadDoubleBias8PN+16(SB)/8, $0x003ffffffffffff8
DATA ·ifmaQuadDoubleBias8PN+24(SB)/8, $0x003ffffffffffff8
GLOBL ·ifmaQuadDoubleBias8PN(SB), RODATA|NOPTR, $32

DATA ·ifmaQuadCachedAddBias8P0+0(SB)/8, $0x003fffffffffff68
DATA ·ifmaQuadCachedAddBias8P0+8(SB)/8, $0x0000000000000000
DATA ·ifmaQuadCachedAddBias8P0+16(SB)/8, $0x0000000000000000
DATA ·ifmaQuadCachedAddBias8P0+24(SB)/8, $0x003fffffffffff68
GLOBL ·ifmaQuadCachedAddBias8P0(SB), RODATA|NOPTR, $32

DATA ·ifmaQuadCachedAddBias8PN+0(SB)/8, $0x003ffffffffffff8
DATA ·ifmaQuadCachedAddBias8PN+8(SB)/8, $0x0000000000000000
DATA ·ifmaQuadCachedAddBias8PN+16(SB)/8, $0x0000000000000000
DATA ·ifmaQuadCachedAddBias8PN+24(SB)/8, $0x003ffffffffffff8
GLOBL ·ifmaQuadCachedAddBias8PN(SB), RODATA|NOPTR, $32
