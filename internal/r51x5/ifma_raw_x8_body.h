// MUL_RAW_X8_BODY multiplies the five u52 limbs addressed by CX and BX and
// stores the exact folded-u61 product through DI. It deliberately omits
// VZEROUPPER and RET so several independent products can share one assembly
// transition. AX and DX remain untouched for compound leaves to retain their
// output and argument-block bases across expansions.
//
// This is a source-level factoring of ifmaMulRawX8, not a new arithmetic
// schedule. MUL_PAIR, CLEAR, COMBINE_HIGH, and FOLD_STORE are defined by the
// including assembly file; the single-product and four-product entry points
// expand this identical body.
#define MUL_RAW_X8_BODY \
	VMOVDQU64   0(CX), Z0  \
	VMOVDQU64  64(CX), Z1  \
	VMOVDQU64 128(CX), Z2  \
	VMOVDQU64 192(CX), Z3  \
	VMOVDQU64 256(CX), Z4  \
	VMOVDQU64   0(BX), Z5  \
	VMOVDQU64  64(BX), Z6  \
	VMOVDQU64 128(BX), Z7  \
	VMOVDQU64 192(BX), Z8  \
	VMOVDQU64 256(BX), Z9  \
	CLEAR(Z10)             \
	CLEAR(Z11)             \
	CLEAR(Z12)             \
	CLEAR(Z13)             \
	CLEAR(Z14)             \
	CLEAR(Z15)             \
	CLEAR(Z16)             \
	CLEAR(Z17)             \
	CLEAR(Z18)             \
	CLEAR(Z19)             \
	CLEAR(Z20)             \
	CLEAR(Z21)             \
	CLEAR(Z22)             \
	CLEAR(Z23)             \
	CLEAR(Z24)             \
	CLEAR(Z25)             \
	CLEAR(Z26)             \
	CLEAR(Z27)             \
	MUL_PAIR(Z0, Z5, Z10, Z19) \
	MUL_PAIR(Z0, Z6, Z11, Z20) \
	MUL_PAIR(Z0, Z7, Z12, Z21) \
	MUL_PAIR(Z0, Z8, Z13, Z22) \
	MUL_PAIR(Z0, Z9, Z14, Z23) \
	MUL_PAIR(Z1, Z5, Z11, Z20) \
	MUL_PAIR(Z1, Z6, Z12, Z21) \
	MUL_PAIR(Z1, Z7, Z13, Z22) \
	MUL_PAIR(Z1, Z8, Z14, Z23) \
	MUL_PAIR(Z1, Z9, Z15, Z24) \
	MUL_PAIR(Z2, Z5, Z12, Z21) \
	MUL_PAIR(Z2, Z6, Z13, Z22) \
	MUL_PAIR(Z2, Z7, Z14, Z23) \
	MUL_PAIR(Z2, Z8, Z15, Z24) \
	MUL_PAIR(Z2, Z9, Z16, Z25) \
	MUL_PAIR(Z3, Z5, Z13, Z22) \
	MUL_PAIR(Z3, Z6, Z14, Z23) \
	MUL_PAIR(Z3, Z7, Z15, Z24) \
	MUL_PAIR(Z3, Z8, Z16, Z25) \
	MUL_PAIR(Z3, Z9, Z17, Z26) \
	MUL_PAIR(Z4, Z5, Z14, Z23) \
	MUL_PAIR(Z4, Z6, Z15, Z24) \
	MUL_PAIR(Z4, Z7, Z16, Z25) \
	MUL_PAIR(Z4, Z8, Z17, Z26) \
	MUL_PAIR(Z4, Z9, Z18, Z27) \
	COMBINE_HIGH(Z19, Z11)      \
	COMBINE_HIGH(Z20, Z12)      \
	COMBINE_HIGH(Z21, Z13)      \
	COMBINE_HIGH(Z22, Z14)      \
	COMBINE_HIGH(Z23, Z15)      \
	COMBINE_HIGH(Z24, Z16)      \
	COMBINE_HIGH(Z25, Z17)      \
	COMBINE_HIGH(Z26, Z18)      \
	VPSLLQ $1, Z27, Z27         \
	FOLD_STORE(Z10, Z15, Z28, Z29,   0) \
	FOLD_STORE(Z11, Z16, Z28, Z29,  64) \
	FOLD_STORE(Z12, Z17, Z28, Z29, 128) \
	FOLD_STORE(Z13, Z18, Z28, Z29, 192) \
	FOLD_STORE(Z14, Z27, Z28, Z29, 256)

// Expand four independent raw products from the common nine-pointer Go ABI0
// signature. Keeping argument loads here as well as MUL_RAW_X8_BODY means the
// raw-only, double-Stage-2, and Niels-Stage-2 leaves cannot drift in their
// product order. The caller chooses only the continuation after this macro.
#define FOUR_RAW_PRODUCTS_X8_BODY \
	MOVQ out+0(FP), AX      \
	MOVQ AX, DI             \
	MOVQ x0+8(FP), CX       \
	MOVQ y0+16(FP), BX      \
	MUL_RAW_X8_BODY         \
	LEAQ 320(AX), DI        \
	MOVQ x1+24(FP), CX      \
	MOVQ y1+32(FP), BX      \
	MUL_RAW_X8_BODY         \
	LEAQ 640(AX), DI        \
	MOVQ x2+40(FP), CX      \
	MOVQ y2+48(FP), BX      \
	MUL_RAW_X8_BODY         \
	LEAQ 960(AX), DI        \
	MOVQ x3+56(FP), CX      \
	MOVQ y3+64(FP), BX      \
	MUL_RAW_X8_BODY

// Three raw products followed by one already-composable D slot is the affine
// cached/Niels shape used by fixed-base addition. D is copied bit-for-bit into
// the fourth workspace slot after the raw multipliers are finished, so the
// same Niels Stage-2 provenance contract remains valid.
#define THREE_RAW_PRODUCTS_AND_D_X8_BODY \
	MOVQ out+0(FP), AX         \
	MOVQ AX, DI                \
	MOVQ x0+8(FP), CX          \
	MOVQ y0+16(FP), BX         \
	MUL_RAW_X8_BODY            \
	LEAQ 320(AX), DI           \
	MOVQ x1+24(FP), CX         \
	MOVQ y1+32(FP), BX         \
	MUL_RAW_X8_BODY            \
	LEAQ 640(AX), DI           \
	MOVQ x2+40(FP), CX         \
	MOVQ y2+48(FP), BX         \
	MUL_RAW_X8_BODY            \
	MOVQ d+56(FP), CX          \
	VMOVDQU64   0(CX), Z0      \
	VMOVDQU64  64(CX), Z1      \
	VMOVDQU64 128(CX), Z2      \
	VMOVDQU64 192(CX), Z3      \
	VMOVDQU64 256(CX), Z4      \
	VMOVDQU64 Z0,  960(AX)     \
	VMOVDQU64 Z1, 1024(AX)     \
	VMOVDQU64 Z2, 1088(AX)     \
	VMOVDQU64 Z3, 1152(AX)     \
	VMOVDQU64 Z4, 1216(AX)
