//go:build amd64 && !purego

#include "textflag.h"

// Transpose four [X,Y,Z,T] rows into [X0..X3], [Y0..Y3], [Z0..Z3],
// [T0..T3]. A..D are overwritten only after T0..T3 hold every unpacked
// source pair.
#define MICRO_AOS_TRANSPOSE_4X4(A, B, C, D, T0, T1, T2, T3) \
	VPUNPCKLQDQ B, A, T0                                      \
	VPUNPCKHQDQ B, A, T1                                      \
	VPUNPCKLQDQ D, C, T2                                      \
	VPUNPCKHQDQ D, C, T3                                      \
	/* For VL=256, immediate 0 selects both low 128-bit halves, */ \
	/* while immediate 3 selects both high 128-bit halves. */     \
	VSHUFI64X2 $0x00, T2, T0, A                               \
	VSHUFI64X2 $0x00, T3, T1, B                               \
	VSHUFI64X2 $0x03, T2, T0, C                               \
	VSHUFI64X2 $0x03, T3, T1, D

// func ifmaMicroAoSTransposeSelectExperimentX4(
//     out *IFMAPointX4,
//     p0, p1, p2, p3 *ifmaMicroAoSPointEntryExperiment,
// )
//
// Each source is 160 bytes: five 32-byte limb rows in [X,Y,Z,T] order.
// IFMAPointX4 is four 160-byte coordinates in [X,Y,Z,T] order, with five
// [lane0..lane3] rows per coordinate.
TEXT ·ifmaMicroAoSTransposeSelectExperimentX4(SB), NOSPLIT, $0-40
	MOVQ out+0(FP), AX
	MOVQ p0+8(FP), DI
	MOVQ p1+16(FP), CX
	MOVQ p2+24(FP), BX
	MOVQ p3+32(FP), SI

	// Load all twenty vectors before the first store. Besides keeping the
	// load stream contiguous within each key, this makes exact overlap with
	// the 640-byte output safe.
	VMOVDQU64   0(DI), Y0
	VMOVDQU64   0(CX), Y1
	VMOVDQU64   0(BX), Y2
	VMOVDQU64   0(SI), Y3
	VMOVDQU64  32(DI), Y4
	VMOVDQU64  32(CX), Y5
	VMOVDQU64  32(BX), Y6
	VMOVDQU64  32(SI), Y7
	VMOVDQU64  64(DI), Y8
	VMOVDQU64  64(CX), Y9
	VMOVDQU64  64(BX), Y10
	VMOVDQU64  64(SI), Y11
	VMOVDQU64  96(DI), Y12
	VMOVDQU64  96(CX), Y13
	VMOVDQU64  96(BX), Y14
	VMOVDQU64  96(SI), Y15
	VMOVDQU64 128(DI), Y16
	VMOVDQU64 128(CX), Y17
	VMOVDQU64 128(BX), Y18
	VMOVDQU64 128(SI), Y19

	MICRO_AOS_TRANSPOSE_4X4(Y0,  Y1,  Y2,  Y3,  Y20, Y21, Y22, Y23)
	MICRO_AOS_TRANSPOSE_4X4(Y4,  Y5,  Y6,  Y7,  Y20, Y21, Y22, Y23)
	MICRO_AOS_TRANSPOSE_4X4(Y8,  Y9,  Y10, Y11, Y20, Y21, Y22, Y23)
	MICRO_AOS_TRANSPOSE_4X4(Y12, Y13, Y14, Y15, Y20, Y21, Y22, Y23)
	MICRO_AOS_TRANSPOSE_4X4(Y16, Y17, Y18, Y19, Y20, Y21, Y22, Y23)

	// X limbs.
	VMOVDQU64 Y0,    0(AX)
	VMOVDQU64 Y4,   32(AX)
	VMOVDQU64 Y8,   64(AX)
	VMOVDQU64 Y12,  96(AX)
	VMOVDQU64 Y16, 128(AX)
	// Y limbs.
	VMOVDQU64 Y1,  160(AX)
	VMOVDQU64 Y5,  192(AX)
	VMOVDQU64 Y9,  224(AX)
	VMOVDQU64 Y13, 256(AX)
	VMOVDQU64 Y17, 288(AX)
	// Z limbs.
	VMOVDQU64 Y2,  320(AX)
	VMOVDQU64 Y6,  352(AX)
	VMOVDQU64 Y10, 384(AX)
	VMOVDQU64 Y14, 416(AX)
	VMOVDQU64 Y18, 448(AX)
	// T limbs.
	VMOVDQU64 Y3,  480(AX)
	VMOVDQU64 Y7,  512(AX)
	VMOVDQU64 Y11, 544(AX)
	VMOVDQU64 Y15, 576(AX)
	VMOVDQU64 Y19, 608(AX)
	VZEROUPPER
	RET
