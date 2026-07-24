//go:build amd64

#include "textflag.h"

// VPMADD52 splits each at-most-52x52-bit product at bit 52. If the product has low half
// l and high half h, then product = l + 2*h*2^51. Low halves are accumulated
// at convolution degree i+j and high halves at degree i+j+1. The high
// accumulators are doubled only after all 25 products have been added.
#define MUL_PAIR(X, Y, L, H) \
	VPMADD52LUQ Y, X, L       \
	VPMADD52HUQ Y, X, H

#define CLEAR(R) VPXORQ R, R, R

#define COMBINE_HIGH(H, L) \
	VPSLLQ $1, H, H          \
	VPADDQ H, L, L

// Set T0 = LO + 19*HI and store one folded radix-2^51 coefficient. This uses
// shifts and adds so the kernel depends only on AVX-512F/VL plus IFMA.
#define FOLD_STORE(LO, HI, T0, T1, OFF) \
	VPSLLQ $4, HI, T0                     \
	VPSLLQ $1, HI, T1                     \
	VPADDQ T1, T0, T0                     \
	VPADDQ HI, T0, T0                     \
	VPADDQ LO, T0, T0                     \
	VMOVDQU64 T0, OFF(DI)

// func ifmaMulRawX8(out *IFMAProductX8, x, y *LimbsX8)
//
// Inputs are eight independent radix-2^51 representations whose limbs are
// each below 2^52. Output is an exact folded representation of each product
// modulo p; every output limb is below 2^61 but is not carried or canonical.
// All inputs are loaded before output is written, so the raw kernel tolerates
// overlapping storage even though the typed Go wrapper does not rely on it.
TEXT ·ifmaMulRawX8(SB), NOSPLIT, $0-24
	MOVQ out+0(FP), DI
	MOVQ x+8(FP), CX
	MOVQ y+16(FP), BX

	VMOVDQU64   0(CX), Z0
	VMOVDQU64  64(CX), Z1
	VMOVDQU64 128(CX), Z2
	VMOVDQU64 192(CX), Z3
	VMOVDQU64 256(CX), Z4
	VMOVDQU64   0(BX), Z5
	VMOVDQU64  64(BX), Z6
	VMOVDQU64 128(BX), Z7
	VMOVDQU64 192(BX), Z8
	VMOVDQU64 256(BX), Z9

	// Z10..Z18 hold low halves for degrees 0..8. Z19..Z27 hold
	// high halves for degrees 1..9.
	CLEAR(Z10)
	CLEAR(Z11)
	CLEAR(Z12)
	CLEAR(Z13)
	CLEAR(Z14)
	CLEAR(Z15)
	CLEAR(Z16)
	CLEAR(Z17)
	CLEAR(Z18)
	CLEAR(Z19)
	CLEAR(Z20)
	CLEAR(Z21)
	CLEAR(Z22)
	CLEAR(Z23)
	CLEAR(Z24)
	CLEAR(Z25)
	CLEAR(Z26)
	CLEAR(Z27)

	MUL_PAIR(Z0, Z5, Z10, Z19)
	MUL_PAIR(Z0, Z6, Z11, Z20)
	MUL_PAIR(Z0, Z7, Z12, Z21)
	MUL_PAIR(Z0, Z8, Z13, Z22)
	MUL_PAIR(Z0, Z9, Z14, Z23)
	MUL_PAIR(Z1, Z5, Z11, Z20)
	MUL_PAIR(Z1, Z6, Z12, Z21)
	MUL_PAIR(Z1, Z7, Z13, Z22)
	MUL_PAIR(Z1, Z8, Z14, Z23)
	MUL_PAIR(Z1, Z9, Z15, Z24)
	MUL_PAIR(Z2, Z5, Z12, Z21)
	MUL_PAIR(Z2, Z6, Z13, Z22)
	MUL_PAIR(Z2, Z7, Z14, Z23)
	MUL_PAIR(Z2, Z8, Z15, Z24)
	MUL_PAIR(Z2, Z9, Z16, Z25)
	MUL_PAIR(Z3, Z5, Z13, Z22)
	MUL_PAIR(Z3, Z6, Z14, Z23)
	MUL_PAIR(Z3, Z7, Z15, Z24)
	MUL_PAIR(Z3, Z8, Z16, Z25)
	MUL_PAIR(Z3, Z9, Z17, Z26)
	MUL_PAIR(Z4, Z5, Z14, Z23)
	MUL_PAIR(Z4, Z6, Z15, Z24)
	MUL_PAIR(Z4, Z7, Z16, Z25)
	MUL_PAIR(Z4, Z8, Z17, Z26)
	MUL_PAIR(Z4, Z9, Z18, Z27)

	COMBINE_HIGH(Z19, Z11)
	COMBINE_HIGH(Z20, Z12)
	COMBINE_HIGH(Z21, Z13)
	COMBINE_HIGH(Z22, Z14)
	COMBINE_HIGH(Z23, Z15)
	COMBINE_HIGH(Z24, Z16)
	COMBINE_HIGH(Z25, Z17)
	COMBINE_HIGH(Z26, Z18)
	VPSLLQ $1, Z27, Z27

	// Fold degrees 5..9 with 2^255 = 19 (mod p).
	FOLD_STORE(Z10, Z15, Z28, Z29,   0)
	FOLD_STORE(Z11, Z16, Z28, Z29,  64)
	FOLD_STORE(Z12, Z17, Z28, Z29, 128)
	FOLD_STORE(Z13, Z18, Z28, Z29, 192)
	FOLD_STORE(Z14, Z27, Z28, Z29, 256)

	VZEROUPPER
	RET

// func ifmaMulRawX4(out *IFMAProductX4, x, y *LimbsX4)
//
// This is intentionally a real four-lane AVX-512VL schedule using YMM
// registers, not a masked execution of the ZMM kernel. It has the same field
// and u61 output contracts as ifmaMulRawX8.
TEXT ·ifmaMulRawX4(SB), NOSPLIT, $0-24
	MOVQ out+0(FP), DI
	MOVQ x+8(FP), CX
	MOVQ y+16(FP), BX

	VMOVDQU64   0(CX), Y0
	VMOVDQU64  32(CX), Y1
	VMOVDQU64  64(CX), Y2
	VMOVDQU64  96(CX), Y3
	VMOVDQU64 128(CX), Y4
	VMOVDQU64   0(BX), Y5
	VMOVDQU64  32(BX), Y6
	VMOVDQU64  64(BX), Y7
	VMOVDQU64  96(BX), Y8
	VMOVDQU64 128(BX), Y9

	CLEAR(Y10)
	CLEAR(Y11)
	CLEAR(Y12)
	CLEAR(Y13)
	CLEAR(Y14)
	CLEAR(Y15)
	CLEAR(Y16)
	CLEAR(Y17)
	CLEAR(Y18)
	CLEAR(Y19)
	CLEAR(Y20)
	CLEAR(Y21)
	CLEAR(Y22)
	CLEAR(Y23)
	CLEAR(Y24)
	CLEAR(Y25)
	CLEAR(Y26)
	CLEAR(Y27)

	MUL_PAIR(Y0, Y5, Y10, Y19)
	MUL_PAIR(Y0, Y6, Y11, Y20)
	MUL_PAIR(Y0, Y7, Y12, Y21)
	MUL_PAIR(Y0, Y8, Y13, Y22)
	MUL_PAIR(Y0, Y9, Y14, Y23)
	MUL_PAIR(Y1, Y5, Y11, Y20)
	MUL_PAIR(Y1, Y6, Y12, Y21)
	MUL_PAIR(Y1, Y7, Y13, Y22)
	MUL_PAIR(Y1, Y8, Y14, Y23)
	MUL_PAIR(Y1, Y9, Y15, Y24)
	MUL_PAIR(Y2, Y5, Y12, Y21)
	MUL_PAIR(Y2, Y6, Y13, Y22)
	MUL_PAIR(Y2, Y7, Y14, Y23)
	MUL_PAIR(Y2, Y8, Y15, Y24)
	MUL_PAIR(Y2, Y9, Y16, Y25)
	MUL_PAIR(Y3, Y5, Y13, Y22)
	MUL_PAIR(Y3, Y6, Y14, Y23)
	MUL_PAIR(Y3, Y7, Y15, Y24)
	MUL_PAIR(Y3, Y8, Y16, Y25)
	MUL_PAIR(Y3, Y9, Y17, Y26)
	MUL_PAIR(Y4, Y5, Y14, Y23)
	MUL_PAIR(Y4, Y6, Y15, Y24)
	MUL_PAIR(Y4, Y7, Y16, Y25)
	MUL_PAIR(Y4, Y8, Y17, Y26)
	MUL_PAIR(Y4, Y9, Y18, Y27)

	COMBINE_HIGH(Y19, Y11)
	COMBINE_HIGH(Y20, Y12)
	COMBINE_HIGH(Y21, Y13)
	COMBINE_HIGH(Y22, Y14)
	COMBINE_HIGH(Y23, Y15)
	COMBINE_HIGH(Y24, Y16)
	COMBINE_HIGH(Y25, Y17)
	COMBINE_HIGH(Y26, Y18)
	VPSLLQ $1, Y27, Y27

	FOLD_STORE(Y10, Y15, Y28, Y29,   0)
	FOLD_STORE(Y11, Y16, Y28, Y29,  32)
	FOLD_STORE(Y12, Y17, Y28, Y29,  64)
	FOLD_STORE(Y13, Y18, Y28, Y29,  96)
	FOLD_STORE(Y14, Y27, Y28, Y29, 128)

	VZEROUPPER
	RET
