//go:build amd64

#include "textflag.h"

// Four independent SHA-512 streams are stored one per uint64 lane. The
// working variables stay in Y0..Y7. ROUND writes new a into old h and new e
// into old d, so rotating the macro arguments avoids seven register moves per
// round; after eight rounds the physical register mapping returns to Y0..Y7.
#define ROUND(A, B, C, D, E, F, G, H, W, K) \
	VPSRLQ $14, E, Y8;                         \
	VPSLLQ $50, E, Y9;                         \
	VPXOR  Y9, Y8, Y8;                         \
	VPSRLQ $18, E, Y9;                         \
	VPXOR  Y9, Y8, Y8;                         \
	VPSLLQ $46, E, Y9;                         \
	VPXOR  Y9, Y8, Y8;                         \
	VPSRLQ $41, E, Y9;                         \
	VPXOR  Y9, Y8, Y8;                         \
	VPSLLQ $23, E, Y9;                         \
	VPXOR  Y9, Y8, Y8;                         \
	VPAND  F, E, Y10;                          \
	VPANDN G, E, Y11;                          \
	VPXOR  Y11, Y10, Y10;                      \
	VPADDQ H, Y8, Y8;                          \
	VPADDQ Y10, Y8, Y8;                        \
	VPBROADCASTQ K(BP), Y15;                   \
	VPADDQ Y15, Y8, Y8;                        \
	VPADDQ W(BX), Y8, Y8;                      \
	VPSRLQ $28, A, Y9;                         \
	VPSLLQ $36, A, Y11;                        \
	VPXOR  Y11, Y9, Y9;                        \
	VPSRLQ $34, A, Y11;                        \
	VPXOR  Y11, Y9, Y9;                        \
	VPSLLQ $30, A, Y11;                        \
	VPXOR  Y11, Y9, Y9;                        \
	VPSRLQ $39, A, Y11;                        \
	VPXOR  Y11, Y9, Y9;                        \
	VPSLLQ $25, A, Y11;                        \
	VPXOR  Y11, Y9, Y9;                        \
	VPXOR  B, A, Y10;                          \
	VPAND  C, Y10, Y10;                        \
	VPAND  B, A, Y11;                          \
	VPXOR  Y11, Y10, Y10;                      \
	VPADDQ Y10, Y9, Y9;                        \
	VPADDQ Y8, D, D;                           \
	VPADDQ Y9, Y8, H

#define ROUND8(A, B, C, D, E, F, G, H, W, K) \
	VPRORQ $14, E, Z8;                          \
	VPRORQ $18, E, Z9;                          \
	VPXORQ Z9, Z8, Z8;                          \
	VPRORQ $41, E, Z9;                          \
	VPXORQ Z9, Z8, Z8;                          \
	VPANDQ F, E, Z10;                           \
	VPANDNQ G, E, Z11;                          \
	VPXORQ Z11, Z10, Z10;                       \
	VPADDQ H, Z8, Z8;                           \
	VPADDQ Z10, Z8, Z8;                         \
	VPBROADCASTQ K(BP), Z15;                    \
	VPADDQ Z15, Z8, Z8;                         \
	VPADDQ W(BX), Z8, Z8;                       \
	VPRORQ $28, A, Z9;                          \
	VPRORQ $34, A, Z11;                         \
	VPXORQ Z11, Z9, Z9;                         \
	VPRORQ $39, A, Z11;                         \
	VPXORQ Z11, Z9, Z9;                         \
	VPXORQ B, A, Z10;                           \
	VPANDQ C, Z10, Z10;                         \
	VPANDQ B, A, Z11;                           \
	VPXORQ Z11, Z10, Z10;                       \
	VPADDQ Z10, Z9, Z9;                         \
	VPADDQ Z8, D, D;                            \
	VPADDQ Z9, Z8, H

// func nativeCompressX4(state *nativeStateX4, block *nativeBlockX4)
//
// Requires AVX2. state is [8][4]uint64 and block is [16][4]uint64, both
// transposed by message lane. The 80-vector schedule occupies the stack
// frame. state and block may overlap: all 16 block vectors are copied to the
// stack before state is loaded or written.
TEXT ·nativeCompressX4(SB), 0, $2560-16
	MOVQ block+8(FP), SI
	LEAQ 0(SP), BX
	MOVQ $16, CX

copy_words:
	VMOVDQU (SI), Y8
	VMOVDQU Y8, (BX)
	ADDQ $32, SI
	ADDQ $32, BX
	DECQ CX
	JNZ copy_words

	// Expand W[16..79] in vector lanes.
	LEAQ 512(SP), BX
	MOVQ $64, CX

expand_schedule:
	// sigma1(W[t-2]) = ROTR19 ^ ROTR61 ^ SHR6.
	VMOVDQU -64(BX), Y8
	VPSRLQ $19, Y8, Y9
	VPSLLQ $45, Y8, Y10
	VPXOR Y10, Y9, Y9
	VPSRLQ $61, Y8, Y10
	VPXOR Y10, Y9, Y9
	VPSLLQ $3, Y8, Y10
	VPXOR Y10, Y9, Y9
	VPSRLQ $6, Y8, Y10
	VPXOR Y10, Y9, Y9

	// sigma0(W[t-15]) = ROTR1 ^ ROTR8 ^ SHR7.
	VMOVDQU -480(BX), Y8
	VPSRLQ $1, Y8, Y10
	VPSLLQ $63, Y8, Y11
	VPXOR Y11, Y10, Y10
	VPSRLQ $8, Y8, Y11
	VPXOR Y11, Y10, Y10
	VPSLLQ $56, Y8, Y11
	VPXOR Y11, Y10, Y10
	VPSRLQ $7, Y8, Y11
	VPXOR Y11, Y10, Y10

	VPADDQ Y10, Y9, Y9
	VPADDQ -224(BX), Y9, Y9
	VPADDQ -512(BX), Y9, Y9
	VMOVDQU Y9, (BX)
	ADDQ $32, BX
	DECQ CX
	JNZ expand_schedule

	MOVQ state+0(FP), DI
	VMOVDQU   0(DI), Y0
	VMOVDQU  32(DI), Y1
	VMOVDQU  64(DI), Y2
	VMOVDQU  96(DI), Y3
	VMOVDQU 128(DI), Y4
	VMOVDQU 160(DI), Y5
	VMOVDQU 192(DI), Y6
	VMOVDQU 224(DI), Y7
	LEAQ 0(SP), BX
	MOVQ $·nativeRoundConstants(SB), BP

	ROUND(Y0, Y1, Y2, Y3, Y4, Y5, Y6, Y7,    0,   0)
	ROUND(Y7, Y0, Y1, Y2, Y3, Y4, Y5, Y6,   32,   8)
	ROUND(Y6, Y7, Y0, Y1, Y2, Y3, Y4, Y5,   64,  16)
	ROUND(Y5, Y6, Y7, Y0, Y1, Y2, Y3, Y4,   96,  24)
	ROUND(Y4, Y5, Y6, Y7, Y0, Y1, Y2, Y3,  128,  32)
	ROUND(Y3, Y4, Y5, Y6, Y7, Y0, Y1, Y2,  160,  40)
	ROUND(Y2, Y3, Y4, Y5, Y6, Y7, Y0, Y1,  192,  48)
	ROUND(Y1, Y2, Y3, Y4, Y5, Y6, Y7, Y0,  224,  56)
	ROUND(Y0, Y1, Y2, Y3, Y4, Y5, Y6, Y7,  256,  64)
	ROUND(Y7, Y0, Y1, Y2, Y3, Y4, Y5, Y6,  288,  72)
	ROUND(Y6, Y7, Y0, Y1, Y2, Y3, Y4, Y5,  320,  80)
	ROUND(Y5, Y6, Y7, Y0, Y1, Y2, Y3, Y4,  352,  88)
	ROUND(Y4, Y5, Y6, Y7, Y0, Y1, Y2, Y3,  384,  96)
	ROUND(Y3, Y4, Y5, Y6, Y7, Y0, Y1, Y2,  416, 104)
	ROUND(Y2, Y3, Y4, Y5, Y6, Y7, Y0, Y1,  448, 112)
	ROUND(Y1, Y2, Y3, Y4, Y5, Y6, Y7, Y0,  480, 120)
	ROUND(Y0, Y1, Y2, Y3, Y4, Y5, Y6, Y7,  512, 128)
	ROUND(Y7, Y0, Y1, Y2, Y3, Y4, Y5, Y6,  544, 136)
	ROUND(Y6, Y7, Y0, Y1, Y2, Y3, Y4, Y5,  576, 144)
	ROUND(Y5, Y6, Y7, Y0, Y1, Y2, Y3, Y4,  608, 152)
	ROUND(Y4, Y5, Y6, Y7, Y0, Y1, Y2, Y3,  640, 160)
	ROUND(Y3, Y4, Y5, Y6, Y7, Y0, Y1, Y2,  672, 168)
	ROUND(Y2, Y3, Y4, Y5, Y6, Y7, Y0, Y1,  704, 176)
	ROUND(Y1, Y2, Y3, Y4, Y5, Y6, Y7, Y0,  736, 184)
	ROUND(Y0, Y1, Y2, Y3, Y4, Y5, Y6, Y7,  768, 192)
	ROUND(Y7, Y0, Y1, Y2, Y3, Y4, Y5, Y6,  800, 200)
	ROUND(Y6, Y7, Y0, Y1, Y2, Y3, Y4, Y5,  832, 208)
	ROUND(Y5, Y6, Y7, Y0, Y1, Y2, Y3, Y4,  864, 216)
	ROUND(Y4, Y5, Y6, Y7, Y0, Y1, Y2, Y3,  896, 224)
	ROUND(Y3, Y4, Y5, Y6, Y7, Y0, Y1, Y2,  928, 232)
	ROUND(Y2, Y3, Y4, Y5, Y6, Y7, Y0, Y1,  960, 240)
	ROUND(Y1, Y2, Y3, Y4, Y5, Y6, Y7, Y0,  992, 248)
	ROUND(Y0, Y1, Y2, Y3, Y4, Y5, Y6, Y7, 1024, 256)
	ROUND(Y7, Y0, Y1, Y2, Y3, Y4, Y5, Y6, 1056, 264)
	ROUND(Y6, Y7, Y0, Y1, Y2, Y3, Y4, Y5, 1088, 272)
	ROUND(Y5, Y6, Y7, Y0, Y1, Y2, Y3, Y4, 1120, 280)
	ROUND(Y4, Y5, Y6, Y7, Y0, Y1, Y2, Y3, 1152, 288)
	ROUND(Y3, Y4, Y5, Y6, Y7, Y0, Y1, Y2, 1184, 296)
	ROUND(Y2, Y3, Y4, Y5, Y6, Y7, Y0, Y1, 1216, 304)
	ROUND(Y1, Y2, Y3, Y4, Y5, Y6, Y7, Y0, 1248, 312)
	ROUND(Y0, Y1, Y2, Y3, Y4, Y5, Y6, Y7, 1280, 320)
	ROUND(Y7, Y0, Y1, Y2, Y3, Y4, Y5, Y6, 1312, 328)
	ROUND(Y6, Y7, Y0, Y1, Y2, Y3, Y4, Y5, 1344, 336)
	ROUND(Y5, Y6, Y7, Y0, Y1, Y2, Y3, Y4, 1376, 344)
	ROUND(Y4, Y5, Y6, Y7, Y0, Y1, Y2, Y3, 1408, 352)
	ROUND(Y3, Y4, Y5, Y6, Y7, Y0, Y1, Y2, 1440, 360)
	ROUND(Y2, Y3, Y4, Y5, Y6, Y7, Y0, Y1, 1472, 368)
	ROUND(Y1, Y2, Y3, Y4, Y5, Y6, Y7, Y0, 1504, 376)
	ROUND(Y0, Y1, Y2, Y3, Y4, Y5, Y6, Y7, 1536, 384)
	ROUND(Y7, Y0, Y1, Y2, Y3, Y4, Y5, Y6, 1568, 392)
	ROUND(Y6, Y7, Y0, Y1, Y2, Y3, Y4, Y5, 1600, 400)
	ROUND(Y5, Y6, Y7, Y0, Y1, Y2, Y3, Y4, 1632, 408)
	ROUND(Y4, Y5, Y6, Y7, Y0, Y1, Y2, Y3, 1664, 416)
	ROUND(Y3, Y4, Y5, Y6, Y7, Y0, Y1, Y2, 1696, 424)
	ROUND(Y2, Y3, Y4, Y5, Y6, Y7, Y0, Y1, 1728, 432)
	ROUND(Y1, Y2, Y3, Y4, Y5, Y6, Y7, Y0, 1760, 440)
	ROUND(Y0, Y1, Y2, Y3, Y4, Y5, Y6, Y7, 1792, 448)
	ROUND(Y7, Y0, Y1, Y2, Y3, Y4, Y5, Y6, 1824, 456)
	ROUND(Y6, Y7, Y0, Y1, Y2, Y3, Y4, Y5, 1856, 464)
	ROUND(Y5, Y6, Y7, Y0, Y1, Y2, Y3, Y4, 1888, 472)
	ROUND(Y4, Y5, Y6, Y7, Y0, Y1, Y2, Y3, 1920, 480)
	ROUND(Y3, Y4, Y5, Y6, Y7, Y0, Y1, Y2, 1952, 488)
	ROUND(Y2, Y3, Y4, Y5, Y6, Y7, Y0, Y1, 1984, 496)
	ROUND(Y1, Y2, Y3, Y4, Y5, Y6, Y7, Y0, 2016, 504)
	ROUND(Y0, Y1, Y2, Y3, Y4, Y5, Y6, Y7, 2048, 512)
	ROUND(Y7, Y0, Y1, Y2, Y3, Y4, Y5, Y6, 2080, 520)
	ROUND(Y6, Y7, Y0, Y1, Y2, Y3, Y4, Y5, 2112, 528)
	ROUND(Y5, Y6, Y7, Y0, Y1, Y2, Y3, Y4, 2144, 536)
	ROUND(Y4, Y5, Y6, Y7, Y0, Y1, Y2, Y3, 2176, 544)
	ROUND(Y3, Y4, Y5, Y6, Y7, Y0, Y1, Y2, 2208, 552)
	ROUND(Y2, Y3, Y4, Y5, Y6, Y7, Y0, Y1, 2240, 560)
	ROUND(Y1, Y2, Y3, Y4, Y5, Y6, Y7, Y0, 2272, 568)
	ROUND(Y0, Y1, Y2, Y3, Y4, Y5, Y6, Y7, 2304, 576)
	ROUND(Y7, Y0, Y1, Y2, Y3, Y4, Y5, Y6, 2336, 584)
	ROUND(Y6, Y7, Y0, Y1, Y2, Y3, Y4, Y5, 2368, 592)
	ROUND(Y5, Y6, Y7, Y0, Y1, Y2, Y3, Y4, 2400, 600)
	ROUND(Y4, Y5, Y6, Y7, Y0, Y1, Y2, Y3, 2432, 608)
	ROUND(Y3, Y4, Y5, Y6, Y7, Y0, Y1, Y2, 2464, 616)
	ROUND(Y2, Y3, Y4, Y5, Y6, Y7, Y0, Y1, 2496, 624)
	ROUND(Y1, Y2, Y3, Y4, Y5, Y6, Y7, Y0, 2528, 632)

	VPADDQ   0(DI), Y0, Y0
	VPADDQ  32(DI), Y1, Y1
	VPADDQ  64(DI), Y2, Y2
	VPADDQ  96(DI), Y3, Y3
	VPADDQ 128(DI), Y4, Y4
	VPADDQ 160(DI), Y5, Y5
	VPADDQ 192(DI), Y6, Y6
	VPADDQ 224(DI), Y7, Y7
	VMOVDQU Y0,   0(DI)
	VMOVDQU Y1,  32(DI)
	VMOVDQU Y2,  64(DI)
	VMOVDQU Y3,  96(DI)
	VMOVDQU Y4, 128(DI)
	VMOVDQU Y5, 160(DI)
	VMOVDQU Y6, 192(DI)
	VMOVDQU Y7, 224(DI)
	VZEROUPPER
	RET

// func nativeCompressX8(state *nativeStateX8, block *nativeBlockX8)
//
// Requires AVX-512F. This is a true eight-stream ZMM schedule, not two calls
// to nativeCompressX4. Zen 4 implements 512-bit operations over its 256-bit
// datapaths, so complete benchmarks must decide between this kernel and two
// x4 groups. state and block may overlap because the complete block is copied
// to the stack before state is loaded or written.
TEXT ·nativeCompressX8(SB), 0, $5120-16
	MOVQ block+8(FP), SI
	LEAQ 0(SP), BX
	MOVQ $16, CX

copy_words_x8:
	VMOVDQU64 (SI), Z8
	VMOVDQU64 Z8, (BX)
	ADDQ $64, SI
	ADDQ $64, BX
	DECQ CX
	JNZ copy_words_x8

	LEAQ 1024(SP), BX
	MOVQ $64, CX

expand_schedule_x8:
	VMOVDQU64 -128(BX), Z8
	VPRORQ $19, Z8, Z9
	VPRORQ $61, Z8, Z10
	VPXORQ Z10, Z9, Z9
	VPSRLQ $6, Z8, Z10
	VPXORQ Z10, Z9, Z9

	VMOVDQU64 -960(BX), Z8
	VPRORQ $1, Z8, Z10
	VPRORQ $8, Z8, Z11
	VPXORQ Z11, Z10, Z10
	VPSRLQ $7, Z8, Z11
	VPXORQ Z11, Z10, Z10

	VPADDQ Z10, Z9, Z9
	VPADDQ -448(BX), Z9, Z9
	VPADDQ -1024(BX), Z9, Z9
	VMOVDQU64 Z9, (BX)
	ADDQ $64, BX
	DECQ CX
	JNZ expand_schedule_x8

	MOVQ state+0(FP), DI
	VMOVDQU64   0(DI), Z0
	VMOVDQU64  64(DI), Z1
	VMOVDQU64 128(DI), Z2
	VMOVDQU64 192(DI), Z3
	VMOVDQU64 256(DI), Z4
	VMOVDQU64 320(DI), Z5
	VMOVDQU64 384(DI), Z6
	VMOVDQU64 448(DI), Z7
	LEAQ 0(SP), BX
	MOVQ $·nativeRoundConstants(SB), BP

	ROUND8(Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7,    0,   0)
	ROUND8(Z7, Z0, Z1, Z2, Z3, Z4, Z5, Z6,   64,   8)
	ROUND8(Z6, Z7, Z0, Z1, Z2, Z3, Z4, Z5,  128,  16)
	ROUND8(Z5, Z6, Z7, Z0, Z1, Z2, Z3, Z4,  192,  24)
	ROUND8(Z4, Z5, Z6, Z7, Z0, Z1, Z2, Z3,  256,  32)
	ROUND8(Z3, Z4, Z5, Z6, Z7, Z0, Z1, Z2,  320,  40)
	ROUND8(Z2, Z3, Z4, Z5, Z6, Z7, Z0, Z1,  384,  48)
	ROUND8(Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z0,  448,  56)
	ROUND8(Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7,  512,  64)
	ROUND8(Z7, Z0, Z1, Z2, Z3, Z4, Z5, Z6,  576,  72)
	ROUND8(Z6, Z7, Z0, Z1, Z2, Z3, Z4, Z5,  640,  80)
	ROUND8(Z5, Z6, Z7, Z0, Z1, Z2, Z3, Z4,  704,  88)
	ROUND8(Z4, Z5, Z6, Z7, Z0, Z1, Z2, Z3,  768,  96)
	ROUND8(Z3, Z4, Z5, Z6, Z7, Z0, Z1, Z2,  832, 104)
	ROUND8(Z2, Z3, Z4, Z5, Z6, Z7, Z0, Z1,  896, 112)
	ROUND8(Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z0,  960, 120)
	ROUND8(Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, 1024, 128)
	ROUND8(Z7, Z0, Z1, Z2, Z3, Z4, Z5, Z6, 1088, 136)
	ROUND8(Z6, Z7, Z0, Z1, Z2, Z3, Z4, Z5, 1152, 144)
	ROUND8(Z5, Z6, Z7, Z0, Z1, Z2, Z3, Z4, 1216, 152)
	ROUND8(Z4, Z5, Z6, Z7, Z0, Z1, Z2, Z3, 1280, 160)
	ROUND8(Z3, Z4, Z5, Z6, Z7, Z0, Z1, Z2, 1344, 168)
	ROUND8(Z2, Z3, Z4, Z5, Z6, Z7, Z0, Z1, 1408, 176)
	ROUND8(Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z0, 1472, 184)
	ROUND8(Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, 1536, 192)
	ROUND8(Z7, Z0, Z1, Z2, Z3, Z4, Z5, Z6, 1600, 200)
	ROUND8(Z6, Z7, Z0, Z1, Z2, Z3, Z4, Z5, 1664, 208)
	ROUND8(Z5, Z6, Z7, Z0, Z1, Z2, Z3, Z4, 1728, 216)
	ROUND8(Z4, Z5, Z6, Z7, Z0, Z1, Z2, Z3, 1792, 224)
	ROUND8(Z3, Z4, Z5, Z6, Z7, Z0, Z1, Z2, 1856, 232)
	ROUND8(Z2, Z3, Z4, Z5, Z6, Z7, Z0, Z1, 1920, 240)
	ROUND8(Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z0, 1984, 248)
	ROUND8(Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, 2048, 256)
	ROUND8(Z7, Z0, Z1, Z2, Z3, Z4, Z5, Z6, 2112, 264)
	ROUND8(Z6, Z7, Z0, Z1, Z2, Z3, Z4, Z5, 2176, 272)
	ROUND8(Z5, Z6, Z7, Z0, Z1, Z2, Z3, Z4, 2240, 280)
	ROUND8(Z4, Z5, Z6, Z7, Z0, Z1, Z2, Z3, 2304, 288)
	ROUND8(Z3, Z4, Z5, Z6, Z7, Z0, Z1, Z2, 2368, 296)
	ROUND8(Z2, Z3, Z4, Z5, Z6, Z7, Z0, Z1, 2432, 304)
	ROUND8(Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z0, 2496, 312)
	ROUND8(Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, 2560, 320)
	ROUND8(Z7, Z0, Z1, Z2, Z3, Z4, Z5, Z6, 2624, 328)
	ROUND8(Z6, Z7, Z0, Z1, Z2, Z3, Z4, Z5, 2688, 336)
	ROUND8(Z5, Z6, Z7, Z0, Z1, Z2, Z3, Z4, 2752, 344)
	ROUND8(Z4, Z5, Z6, Z7, Z0, Z1, Z2, Z3, 2816, 352)
	ROUND8(Z3, Z4, Z5, Z6, Z7, Z0, Z1, Z2, 2880, 360)
	ROUND8(Z2, Z3, Z4, Z5, Z6, Z7, Z0, Z1, 2944, 368)
	ROUND8(Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z0, 3008, 376)
	ROUND8(Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, 3072, 384)
	ROUND8(Z7, Z0, Z1, Z2, Z3, Z4, Z5, Z6, 3136, 392)
	ROUND8(Z6, Z7, Z0, Z1, Z2, Z3, Z4, Z5, 3200, 400)
	ROUND8(Z5, Z6, Z7, Z0, Z1, Z2, Z3, Z4, 3264, 408)
	ROUND8(Z4, Z5, Z6, Z7, Z0, Z1, Z2, Z3, 3328, 416)
	ROUND8(Z3, Z4, Z5, Z6, Z7, Z0, Z1, Z2, 3392, 424)
	ROUND8(Z2, Z3, Z4, Z5, Z6, Z7, Z0, Z1, 3456, 432)
	ROUND8(Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z0, 3520, 440)
	ROUND8(Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, 3584, 448)
	ROUND8(Z7, Z0, Z1, Z2, Z3, Z4, Z5, Z6, 3648, 456)
	ROUND8(Z6, Z7, Z0, Z1, Z2, Z3, Z4, Z5, 3712, 464)
	ROUND8(Z5, Z6, Z7, Z0, Z1, Z2, Z3, Z4, 3776, 472)
	ROUND8(Z4, Z5, Z6, Z7, Z0, Z1, Z2, Z3, 3840, 480)
	ROUND8(Z3, Z4, Z5, Z6, Z7, Z0, Z1, Z2, 3904, 488)
	ROUND8(Z2, Z3, Z4, Z5, Z6, Z7, Z0, Z1, 3968, 496)
	ROUND8(Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z0, 4032, 504)
	ROUND8(Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, 4096, 512)
	ROUND8(Z7, Z0, Z1, Z2, Z3, Z4, Z5, Z6, 4160, 520)
	ROUND8(Z6, Z7, Z0, Z1, Z2, Z3, Z4, Z5, 4224, 528)
	ROUND8(Z5, Z6, Z7, Z0, Z1, Z2, Z3, Z4, 4288, 536)
	ROUND8(Z4, Z5, Z6, Z7, Z0, Z1, Z2, Z3, 4352, 544)
	ROUND8(Z3, Z4, Z5, Z6, Z7, Z0, Z1, Z2, 4416, 552)
	ROUND8(Z2, Z3, Z4, Z5, Z6, Z7, Z0, Z1, 4480, 560)
	ROUND8(Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z0, 4544, 568)
	ROUND8(Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, 4608, 576)
	ROUND8(Z7, Z0, Z1, Z2, Z3, Z4, Z5, Z6, 4672, 584)
	ROUND8(Z6, Z7, Z0, Z1, Z2, Z3, Z4, Z5, 4736, 592)
	ROUND8(Z5, Z6, Z7, Z0, Z1, Z2, Z3, Z4, 4800, 600)
	ROUND8(Z4, Z5, Z6, Z7, Z0, Z1, Z2, Z3, 4864, 608)
	ROUND8(Z3, Z4, Z5, Z6, Z7, Z0, Z1, Z2, 4928, 616)
	ROUND8(Z2, Z3, Z4, Z5, Z6, Z7, Z0, Z1, 4992, 624)
	ROUND8(Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z0, 5056, 632)

	VPADDQ   0(DI), Z0, Z0
	VPADDQ  64(DI), Z1, Z1
	VPADDQ 128(DI), Z2, Z2
	VPADDQ 192(DI), Z3, Z3
	VPADDQ 256(DI), Z4, Z4
	VPADDQ 320(DI), Z5, Z5
	VPADDQ 384(DI), Z6, Z6
	VPADDQ 448(DI), Z7, Z7
	VMOVDQU64 Z0,   0(DI)
	VMOVDQU64 Z1,  64(DI)
	VMOVDQU64 Z2, 128(DI)
	VMOVDQU64 Z3, 192(DI)
	VMOVDQU64 Z4, 256(DI)
	VMOVDQU64 Z5, 320(DI)
	VMOVDQU64 Z6, 384(DI)
	VMOVDQU64 Z7, 448(DI)
	VZEROUPPER
	RET
