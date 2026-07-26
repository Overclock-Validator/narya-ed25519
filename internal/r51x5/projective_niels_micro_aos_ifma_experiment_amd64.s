//go:build amd64

#include "textflag.h"

#define MICRO_AOS_TRANSPOSE_4X4(A, B, C, D, T0, T1, T2, T3) \
	VPUNPCKLQDQ B, A, T0                                      \
	VPUNPCKHQDQ B, A, T1                                      \
	VPUNPCKLQDQ D, C, T2                                      \
	VPUNPCKHQDQ D, C, T3                                      \
	VSHUFI64X2 $0x00, T2, T0, A                               \
	VSHUFI64X2 $0x00, T3, T1, B                               \
	VSHUFI64X2 $0x03, T2, T0, C                               \
	VSHUFI64X2 $0x03, T3, T1, D

// Load one limb row from four keys, transpose [Y+X,Y-X,Z,2dT], and store it
// into either the low or high four lanes of the four x8 output coordinates.
#define TRANSPOSE_HALF(OFF, HALF, P0, P1, P2, P3) \
	VMOVDQU64 OFF(P0), Y0                            \
	VMOVDQU64 OFF(P1), Y1                            \
	VMOVDQU64 OFF(P2), Y2                            \
	VMOVDQU64 OFF(P3), Y3                            \
	MICRO_AOS_TRANSPOSE_4X4(Y0, Y1, Y2, Y3, Y4, Y5, Y6, Y7) \
	VMOVDQU64 Y0, (2*OFF+HALF)(AX)                   \
	VMOVDQU64 Y1, (320+2*OFF+HALF)(AX)               \
	VMOVDQU64 Y2, (640+2*OFF+HALF)(AX)               \
	VMOVDQU64 Y3, (960+2*OFF+HALF)(AX)

// func ifmaProjectiveNielsMicroAoSTransposeX8(
//     out *IFMAProjectiveNielsX8,
//     p0, p1, p2, p3, p4, p5, p6, p7 *ifmaProjectiveNielsMicroAoSEntryX8,
// )
TEXT ·ifmaProjectiveNielsMicroAoSTransposeX8(SB), NOSPLIT, $0-72
	MOVQ out+0(FP), AX
	MOVQ p0+8(FP), DI
	MOVQ p1+16(FP), CX
	MOVQ p2+24(FP), BX
	MOVQ p3+32(FP), SI
	MOVQ p4+40(FP), R8
	MOVQ p5+48(FP), R9
	MOVQ p6+56(FP), R10
	MOVQ p7+64(FP), R11

	TRANSPOSE_HALF(0,   0, DI, CX, BX, SI)
	TRANSPOSE_HALF(0,  32, R8, R9, R10, R11)
	TRANSPOSE_HALF(32,  0, DI, CX, BX, SI)
	TRANSPOSE_HALF(32, 32, R8, R9, R10, R11)
	TRANSPOSE_HALF(64,  0, DI, CX, BX, SI)
	TRANSPOSE_HALF(64, 32, R8, R9, R10, R11)
	TRANSPOSE_HALF(96,  0, DI, CX, BX, SI)
	TRANSPOSE_HALF(96, 32, R8, R9, R10, R11)
	TRANSPOSE_HALF(128,  0, DI, CX, BX, SI)
	TRANSPOSE_HALF(128, 32, R8, R9, R10, R11)
	VZEROUPPER
	RET
