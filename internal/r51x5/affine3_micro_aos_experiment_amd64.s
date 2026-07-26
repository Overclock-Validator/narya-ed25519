//go:build amd64

#include "textflag.h"

#define AFFINE3_TRANSPOSE_4X4(A, B, C, D, T0, T1, T2, T3) \
	VPUNPCKLQDQ B, A, T0                                      \
	VPUNPCKHQDQ B, A, T1                                      \
	VPUNPCKLQDQ D, C, T2                                      \
	VPUNPCKHQDQ D, C, T3                                      \
	VSHUFI64X2 $0x00, T2, T0, A                               \
	VSHUFI64X2 $0x00, T3, T1, B                               \
	VSHUFI64X2 $0x03, T2, T0, C                               \
	VSHUFI64X2 $0x03, T3, T1, D

#define AFFINE3_TRANSPOSE_8X3_ROW(SRC, YP0, YP1, YM0, YM1, T0, T1) \
	VMOVDQU64.Z SRC(DI),  K1, Y0                                  \
	VMOVDQU64.Z SRC(CX),  K1, Y1                                  \
	VMOVDQU64.Z SRC(BX),  K1, Y2                                  \
	VMOVDQU64.Z SRC(SI),  K1, Y3                                  \
	VMOVDQU64.Z SRC(R9),  K1, Y4                                  \
	VMOVDQU64.Z SRC(R10), K1, Y5                                  \
	VMOVDQU64.Z SRC(R11), K1, Y6                                  \
	VMOVDQU64.Z SRC(R12), K1, Y7                                  \
	AFFINE3_TRANSPOSE_4X4(Y0, Y1, Y2, Y3, Y8, Y9, Y10, Y11)      \
	AFFINE3_TRANSPOSE_4X4(Y4, Y5, Y6, Y7, Y12, Y13, Y14, Y15)    \
	VMOVDQU64 Y0, YP0(AX)                                         \
	VMOVDQU64 Y4, YP1(AX)                                         \
	VMOVDQU64 Y1, YM0(AX)                                         \
	VMOVDQU64 Y5, YM1(AX)                                         \
	VMOVDQU64 Y2, T0(AX)                                          \
	VMOVDQU64 Y6, T1(AX)

// Each source is exactly 120 bytes: five 24-byte rows. K1 masks off the
// fourth qword, so the final row load cannot read beyond the entry. All twenty
// sources are loaded before the first store, preserving exact overlap safety.
TEXT ·ifmaAffine3MicroAoSTransposeSelectExperimentX4(SB), NOSPLIT, $0-40
	MOVQ out+0(FP), AX
	MOVQ p0+8(FP), DI
	MOVQ p1+16(FP), CX
	MOVQ p2+24(FP), BX
	MOVQ p3+32(FP), SI
	MOVQ $7, R8
	KMOVB R8, K1

	VMOVDQU64.Z   0(DI), K1, Y0
	VMOVDQU64.Z   0(CX), K1, Y1
	VMOVDQU64.Z   0(BX), K1, Y2
	VMOVDQU64.Z   0(SI), K1, Y3
	VMOVDQU64.Z  24(DI), K1, Y4
	VMOVDQU64.Z  24(CX), K1, Y5
	VMOVDQU64.Z  24(BX), K1, Y6
	VMOVDQU64.Z  24(SI), K1, Y7
	VMOVDQU64.Z  48(DI), K1, Y8
	VMOVDQU64.Z  48(CX), K1, Y9
	VMOVDQU64.Z  48(BX), K1, Y10
	VMOVDQU64.Z  48(SI), K1, Y11
	VMOVDQU64.Z  72(DI), K1, Y12
	VMOVDQU64.Z  72(CX), K1, Y13
	VMOVDQU64.Z  72(BX), K1, Y14
	VMOVDQU64.Z  72(SI), K1, Y15
	VMOVDQU64.Z  96(DI), K1, Y16
	VMOVDQU64.Z  96(CX), K1, Y17
	VMOVDQU64.Z  96(BX), K1, Y18
	VMOVDQU64.Z  96(SI), K1, Y19

	AFFINE3_TRANSPOSE_4X4(Y0,  Y1,  Y2,  Y3,  Y20, Y21, Y22, Y23)
	AFFINE3_TRANSPOSE_4X4(Y4,  Y5,  Y6,  Y7,  Y20, Y21, Y22, Y23)
	AFFINE3_TRANSPOSE_4X4(Y8,  Y9,  Y10, Y11, Y20, Y21, Y22, Y23)
	AFFINE3_TRANSPOSE_4X4(Y12, Y13, Y14, Y15, Y20, Y21, Y22, Y23)
	AFFINE3_TRANSPOSE_4X4(Y16, Y17, Y18, Y19, Y20, Y21, Y22, Y23)

	VMOVDQU64 Y0,    0(AX)
	VMOVDQU64 Y4,   32(AX)
	VMOVDQU64 Y8,   64(AX)
	VMOVDQU64 Y12,  96(AX)
	VMOVDQU64 Y16, 128(AX)
	VMOVDQU64 Y1,  160(AX)
	VMOVDQU64 Y5,  192(AX)
	VMOVDQU64 Y9,  224(AX)
	VMOVDQU64 Y13, 256(AX)
	VMOVDQU64 Y17, 288(AX)
	VMOVDQU64 Y2,  320(AX)
	VMOVDQU64 Y6,  352(AX)
	VMOVDQU64 Y10, 384(AX)
	VMOVDQU64 Y14, 416(AX)
	VMOVDQU64 Y18, 448(AX)
	VZEROUPPER
	RET

// Process one 24-byte limb row at a time so the eight sources plus transpose
// scratch stay below the 32-register YMM file. Each masked load reads exactly
// three qwords; in particular the row at offset 96 cannot cross the 120-byte
// source boundary. Sources and output are deliberately non-aliasing.
TEXT ·ifmaAffine3MicroAoSTransposeSelectExperimentX8(SB), NOSPLIT, $0-72
	MOVQ out+0(FP), AX
	MOVQ p0+8(FP), DI
	MOVQ p1+16(FP), CX
	MOVQ p2+24(FP), BX
	MOVQ p3+32(FP), SI
	MOVQ p4+40(FP), R9
	MOVQ p5+48(FP), R10
	MOVQ p6+56(FP), R11
	MOVQ p7+64(FP), R12
	MOVQ $7, R8
	KMOVB R8, K1

	AFFINE3_TRANSPOSE_8X3_ROW(0,   0,  32, 320, 352, 640, 672)
	AFFINE3_TRANSPOSE_8X3_ROW(24, 64,  96, 384, 416, 704, 736)
	AFFINE3_TRANSPOSE_8X3_ROW(48, 128, 160, 448, 480, 768, 800)
	AFFINE3_TRANSPOSE_8X3_ROW(72, 192, 224, 512, 544, 832, 864)
	AFFINE3_TRANSPOSE_8X3_ROW(96, 256, 288, 576, 608, 896, 928)

	VZEROUPPER
	RET
