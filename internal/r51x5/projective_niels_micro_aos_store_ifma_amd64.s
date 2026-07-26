//go:build amd64

#include "textflag.h"

#define MICRO_AOS_STORE_TRANSPOSE_4X4(A, B, C, D, T0, T1, T2, T3) \
	VPUNPCKLQDQ B, A, T0                                             \
	VPUNPCKHQDQ B, A, T1                                             \
	VPUNPCKLQDQ D, C, T2                                             \
	VPUNPCKHQDQ D, C, T3                                             \
	VSHUFI64X2 $0x00, T2, T0, A                                     \
	VSHUFI64X2 $0x00, T3, T1, B                                     \
	VSHUFI64X2 $0x03, T2, T0, C                                     \
	VSHUFI64X2 $0x03, T3, T1, D

// Transpose one four-lane half for one limb. The positive row is
// [Y+X,Y-X,Z,2dT]; the negative row is [Y-X,Y+X,Z,-2dT]. Each lane owns
// 5120 bytes, each sign owns 2560 bytes, and each entry owns 160 bytes.
#define STORE_HALF(SRC, ROW, HALF, LANEBASE)                         \
	VMOVDQU64 (SRC+HALF)(CX), Y0                                     \
	VMOVDQU64 (320+SRC+HALF)(CX), Y1                                 \
	VMOVDQU64 (640+SRC+HALF)(CX), Y2                                 \
	VMOVDQU64 (960+SRC+HALF)(CX), Y3                                 \
	MICRO_AOS_STORE_TRANSPOSE_4X4(Y0, Y1, Y2, Y3, Y4, Y5, Y6, Y7)  \
	VMOVDQU64 Y0, (LANEBASE+ROW)(DI)                                 \
	VMOVDQU64 Y1, (5120+LANEBASE+ROW)(DI)                            \
	VMOVDQU64 Y2, (10240+LANEBASE+ROW)(DI)                           \
	VMOVDQU64 Y3, (15360+LANEBASE+ROW)(DI)                           \
	VMOVDQU64 (320+SRC+HALF)(CX), Y0                                 \
	VMOVDQU64 (SRC+HALF)(CX), Y1                                     \
	VMOVDQU64 (640+SRC+HALF)(CX), Y2                                 \
	VMOVDQU64 (SRC+HALF)(DX), Y3                                    \
	MICRO_AOS_STORE_TRANSPOSE_4X4(Y0, Y1, Y2, Y3, Y4, Y5, Y6, Y7)  \
	VMOVDQU64 Y0, (2560+LANEBASE+ROW)(DI)                            \
	VMOVDQU64 Y1, (7680+LANEBASE+ROW)(DI)                            \
	VMOVDQU64 Y2, (12800+LANEBASE+ROW)(DI)                           \
	VMOVDQU64 Y3, (17920+LANEBASE+ROW)(DI)

// func ifmaProjectiveNielsPreSignedMicroAoSStoreTransposeX8(
//     table *ifmaProjectiveNielsPreSignedMicroAoSTableX8,
//     entry uint64,
//     point *IFMAProjectiveNielsX8,
//     negativeT2D *IFMAElementX8,
// )
TEXT ·ifmaProjectiveNielsPreSignedMicroAoSStoreTransposeX8(SB), NOSPLIT, $0-32
	MOVQ table+0(FP), AX
	MOVQ entry+8(FP), BX
	MOVQ point+16(FP), CX
	MOVQ negativeT2D+24(FP), DX

	// DI addresses lane zero, positive sign, selected entry.
	LEAQ (BX)(BX*4), BX
	SHLQ $5, BX
	LEAQ (AX)(BX*1), DI

	STORE_HALF(0,   0,   0, 0)
	STORE_HALF(0,   0,  32, 20480)
	STORE_HALF(64,  32,  0, 0)
	STORE_HALF(64,  32, 32, 20480)
	STORE_HALF(128, 64,  0, 0)
	STORE_HALF(128, 64, 32, 20480)
	STORE_HALF(192, 96,  0, 0)
	STORE_HALF(192, 96, 32, 20480)
	STORE_HALF(256, 128,  0, 0)
	STORE_HALF(256, 128, 32, 20480)
	VZEROUPPER
	RET
