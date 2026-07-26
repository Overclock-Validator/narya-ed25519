//go:build amd64 && !purego

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

// Fold HI into LO in registers using 2^255 = 19 (mod p). T0 and T1 may not
// alias LO or HI. This is the register-resident counterpart of FOLD_STORE.
#define FOLD_INTO(LO, HI, T0, T1) \
	VPSLLQ $4, HI, T0              \
	VPSLLQ $1, HI, T1              \
	VPADDQ T1, T0, T0              \
	VPADDQ HI, T0, T0              \
	VPADDQ T0, LO, LO

// AVX-512DQ can fold an already combined coefficient with one full-width
// 64-bit multiply. The proven pre-fold bounds keep 19*HI below 2^64, so the
// low-64-bit VPMULLQ result is the exact integer product. This is an
// experimental alternative to the shift/add schedule above.
#define FOLD_INTO_MUL19(LO, HI, T0, FOLD19) \
	VPMULLQ FOLD19, HI, T0                    \
	VPADDQ T0, LO, LO

// Carry a vector of five folded radix-2^51 coefficients. IN0..IN4 are each
// below 2^61. MASK contains 2^51-1 and FOLD19 contains 19. C0..C4 receive
// the five independent carry-outs from the original limbs. The result has
// limb zero below 2^51+19*1024 and every other limb below 2^51+1024, hence
// every output remains a valid u52 VPMADD52 multiplicand.
//
// The VPMADD52LUQ is exact here: C4 < 2^10, so 19*C4 fits entirely in the
// low 52-bit half selected by the instruction.
#define NORMALIZE_5(IN0, IN1, IN2, IN3, IN4, MASK, C0, C1, C2, C3, C4, FOLD19) \
	VPSRLQ $51, IN0, C0                                                    \
	VPSRLQ $51, IN1, C1                                                    \
	VPSRLQ $51, IN2, C2                                                    \
	VPSRLQ $51, IN3, C3                                                    \
	VPSRLQ $51, IN4, C4                                                    \
	VPANDQ MASK, IN0, IN0                                                  \
	VPANDQ MASK, IN1, IN1                                                  \
	VPANDQ MASK, IN2, IN2                                                  \
	VPANDQ MASK, IN3, IN3                                                  \
	VPANDQ MASK, IN4, IN4                                                  \
	VPADDQ C0, IN1, IN1                                                    \
	VPADDQ C1, IN2, IN2                                                    \
	VPADDQ C2, IN3, IN3                                                    \
	VPADDQ C3, IN4, IN4                                                    \
	VPMADD52LUQ C4, FOLD19, IN0

// Multiply the u52 values addressed by CX and BX and store one normalized
// u52 result through DI. The four-point-final-product leaf below expands this
// body four times so the independent Edwards output products share one
// Go/assembly transition and one VZEROUPPER. AX and DX are deliberately not
// touched: that leaf keeps its output and operand bases there between bodies.
#define MUL_NORMALIZED_X8_BODY \
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
	VPBROADCASTQ ·ifmaFold19(SB), Z30 \
	FOLD_INTO_MUL19(Z10, Z15, Z28, Z30) \
	FOLD_INTO_MUL19(Z11, Z16, Z28, Z30) \
	FOLD_INTO_MUL19(Z12, Z17, Z28, Z30) \
	FOLD_INTO_MUL19(Z13, Z18, Z28, Z30) \
	FOLD_INTO_MUL19(Z14, Z27, Z28, Z30) \
	VPBROADCASTQ ·ifmaLimbMask51(SB), Z5 \
	NORMALIZE_5(Z10, Z11, Z12, Z13, Z14, Z5, Z15, Z16, Z17, Z18, Z19, Z30) \
	VMOVDQU64 Z10,   0(DI)      \
	VMOVDQU64 Z11,  64(DI)      \
	VMOVDQU64 Z12, 128(DI)      \
	VMOVDQU64 Z13, 192(DI)      \
	VMOVDQU64 Z14, 256(DI)

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

// func ifmaMulNormalizedUncheckedX8(out, x, y *LimbsX8)
//
// Fused form of ifmaMulRawX8 followed by ifmaNormalizeProductUncheckedX8.
// The exact folded u61 product never touches memory. All ten input vectors are
// loaded before any output store, so out may alias x or y.
TEXT ·ifmaMulNormalizedUncheckedX8(SB), NOSPLIT, $0-24
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

	// cpufeat.IFMA already requires AVX-512DQ. The combined high
	// coefficients are below 2^56, so VPMULLQ by 19 is exact and removes
	// fourteen shift/add instructions from the hot multiply.
	VPBROADCASTQ ·ifmaFold19(SB), Z30
	FOLD_INTO_MUL19(Z10, Z15, Z28, Z30)
	FOLD_INTO_MUL19(Z11, Z16, Z28, Z30)
	FOLD_INTO_MUL19(Z12, Z17, Z28, Z30)
	FOLD_INTO_MUL19(Z13, Z18, Z28, Z30)
	FOLD_INTO_MUL19(Z14, Z27, Z28, Z30)

	VPBROADCASTQ ·ifmaLimbMask51(SB), Z5
	NORMALIZE_5(Z10, Z11, Z12, Z13, Z14, Z5, Z15, Z16, Z17, Z18, Z19, Z30)

	VMOVDQU64 Z10,   0(DI)
	VMOVDQU64 Z11,  64(DI)
	VMOVDQU64 Z12, 128(DI)
	VMOVDQU64 Z13, 192(DI)
	VMOVDQU64 Z14, 256(DI)
	VZEROUPPER
	RET

// func ifmaPointFinalProductsUncheckedX8(out *IFMAPointX8, operands *IFMAProductX8)
//
// operands points to four consecutive carried-u52 slots in E,F,G,H order.
// The leaf computes (E*F, G*H, F*G, E*H) into out.X/Y/Z/T. The current point
// formulas keep operands in separate workspace storage, so aliasing is neither
// required nor supported. Each multiplication is representation-identical to
// ifmaMulNormalizedUncheckedX8; the only optimization is sharing the call
// boundary and final VZEROUPPER across four independent products.
TEXT ·ifmaPointFinalProductsUncheckedX8(SB), NOSPLIT, $0-16
	MOVQ out+0(FP), AX
	MOVQ operands+8(FP), DX

	// X = E*F.
	MOVQ AX, DI
	MOVQ DX, CX
	LEAQ 320(DX), BX
	MUL_NORMALIZED_X8_BODY

	// Y = G*H.
	LEAQ 320(AX), DI
	LEAQ 640(DX), CX
	LEAQ 960(DX), BX
	MUL_NORMALIZED_X8_BODY

	// T = E*H.
	LEAQ 960(AX), DI
	MOVQ DX, CX
	LEAQ 960(DX), BX
	MUL_NORMALIZED_X8_BODY

	// Z = F*G.
	LEAQ 640(AX), DI
	LEAQ 320(DX), CX
	LEAQ 640(DX), BX
	MUL_NORMALIZED_X8_BODY

	VZEROUPPER
	RET

// func ifmaMulNormalizedMul19ExperimentX8(out, x, y *LimbsX8)
//
// Exact copy of the fused x8 multiply above except that the five radix folds
// use AVX-512DQ VPMULLQ by 19. The combined high coefficients are below 2^56,
// so their products by 19 remain exact unsigned 64-bit integers.
TEXT ·ifmaMulNormalizedMul19ExperimentX8(SB), NOSPLIT, $0-24
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

	VPBROADCASTQ ·ifmaFold19(SB), Z30
	FOLD_INTO_MUL19(Z10, Z15, Z28, Z30)
	FOLD_INTO_MUL19(Z11, Z16, Z28, Z30)
	FOLD_INTO_MUL19(Z12, Z17, Z28, Z30)
	FOLD_INTO_MUL19(Z13, Z18, Z28, Z30)
	FOLD_INTO_MUL19(Z14, Z27, Z28, Z30)

	VPBROADCASTQ ·ifmaLimbMask51(SB), Z5
	VPBROADCASTQ ·ifmaFold19(SB), Z20
	NORMALIZE_5(Z10, Z11, Z12, Z13, Z14, Z5, Z15, Z16, Z17, Z18, Z19, Z20)

	VMOVDQU64 Z10,   0(DI)
	VMOVDQU64 Z11,  64(DI)
	VMOVDQU64 Z12, 128(DI)
	VMOVDQU64 Z13, 192(DI)
	VMOVDQU64 Z14, 256(DI)
	VZEROUPPER
	RET

// func ifmaMulNormalizedUncheckedX4(out, x, y *LimbsX4)
//
// AVX-512VL/YMM fused multiply-normalize. This is a dedicated four-lane
// schedule, not a masked ZMM call.
TEXT ·ifmaMulNormalizedUncheckedX4(SB), NOSPLIT, $0-24
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

	FOLD_INTO(Y10, Y15, Y28, Y29)
	FOLD_INTO(Y11, Y16, Y28, Y29)
	FOLD_INTO(Y12, Y17, Y28, Y29)
	FOLD_INTO(Y13, Y18, Y28, Y29)
	FOLD_INTO(Y14, Y27, Y28, Y29)

	VPBROADCASTQ ·ifmaLimbMask51(SB), Y5
	VPBROADCASTQ ·ifmaFold19(SB), Y20
	NORMALIZE_5(Y10, Y11, Y12, Y13, Y14, Y5, Y15, Y16, Y17, Y18, Y19, Y20)

	VMOVDQU64 Y10,   0(DI)
	VMOVDQU64 Y11,  32(DI)
	VMOVDQU64 Y12,  64(DI)
	VMOVDQU64 Y13,  96(DI)
	VMOVDQU64 Y14, 128(DI)
	VZEROUPPER
	RET

// func ifmaNormalizeProductUncheckedX8(out *LimbsX8, x *IFMAProductX8)
//
// This is an internal proven-range primitive. Unlike the scalar reference it
// does not scan for malformed u61 inputs; callers may enter it only after the
// raw multiply or formula operations whose bounds establish that contract.
TEXT ·ifmaNormalizeProductUncheckedX8(SB), NOSPLIT, $0-16
	MOVQ out+0(FP), DI
	MOVQ x+8(FP), CX

	VMOVDQU64   0(CX), Z0
	VMOVDQU64  64(CX), Z1
	VMOVDQU64 128(CX), Z2
	VMOVDQU64 192(CX), Z3
	VMOVDQU64 256(CX), Z4
	VPBROADCASTQ ·ifmaLimbMask51(SB), Z5
	VPBROADCASTQ ·ifmaFold19(SB), Z11

	NORMALIZE_5(Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, Z11)

	VMOVDQU64 Z0,   0(DI)
	VMOVDQU64 Z1,  64(DI)
	VMOVDQU64 Z2, 128(DI)
	VMOVDQU64 Z3, 192(DI)
	VMOVDQU64 Z4, 256(DI)
	VZEROUPPER
	RET

// func ifmaNormalizeProductUncheckedX4(out *LimbsX4, x *IFMAProductX4)
TEXT ·ifmaNormalizeProductUncheckedX4(SB), NOSPLIT, $0-16
	MOVQ out+0(FP), DI
	MOVQ x+8(FP), CX

	VMOVDQU64   0(CX), Y0
	VMOVDQU64  32(CX), Y1
	VMOVDQU64  64(CX), Y2
	VMOVDQU64  96(CX), Y3
	VMOVDQU64 128(CX), Y4
	VPBROADCASTQ ·ifmaLimbMask51(SB), Y5
	VPBROADCASTQ ·ifmaFold19(SB), Y11

	NORMALIZE_5(Y0, Y1, Y2, Y3, Y4, Y5, Y6, Y7, Y8, Y9, Y10, Y11)

	VMOVDQU64 Y0,   0(DI)
	VMOVDQU64 Y1,  32(DI)
	VMOVDQU64 Y2,  64(DI)
	VMOVDQU64 Y3,  96(DI)
	VMOVDQU64 Y4, 128(DI)
	VZEROUPPER
	RET

// func ifmaAddNormalizedUncheckedX8(out, x, y *LimbsX8)
TEXT ·ifmaAddNormalizedUncheckedX8(SB), NOSPLIT, $0-24
	MOVQ out+0(FP), DI
	MOVQ x+8(FP), CX
	MOVQ y+16(FP), BX

	VMOVDQU64   0(CX), Z0
	VMOVDQU64  64(CX), Z1
	VMOVDQU64 128(CX), Z2
	VMOVDQU64 192(CX), Z3
	VMOVDQU64 256(CX), Z4
	VPADDQ   0(BX), Z0, Z0
	VPADDQ  64(BX), Z1, Z1
	VPADDQ 128(BX), Z2, Z2
	VPADDQ 192(BX), Z3, Z3
	VPADDQ 256(BX), Z4, Z4
	VPBROADCASTQ ·ifmaLimbMask51(SB), Z5
	VPBROADCASTQ ·ifmaFold19(SB), Z11
	NORMALIZE_5(Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, Z11)
	VMOVDQU64 Z0,   0(DI)
	VMOVDQU64 Z1,  64(DI)
	VMOVDQU64 Z2, 128(DI)
	VMOVDQU64 Z3, 192(DI)
	VMOVDQU64 Z4, 256(DI)
	VZEROUPPER
	RET

// func ifmaSubtractNormalizedUncheckedX8(out, x, y *LimbsX8)
TEXT ·ifmaSubtractNormalizedUncheckedX8(SB), NOSPLIT, $0-24
	MOVQ out+0(FP), DI
	MOVQ x+8(FP), CX
	MOVQ y+16(FP), BX

	VMOVDQU64   0(CX), Z0
	VMOVDQU64  64(CX), Z1
	VMOVDQU64 128(CX), Z2
	VMOVDQU64 192(CX), Z3
	VMOVDQU64 256(CX), Z4
	VPBROADCASTQ ·ifmaSubBias0(SB), Z9
	VPBROADCASTQ ·ifmaSubBiasN(SB), Z10
	VPADDQ Z9, Z0, Z0
	VPADDQ Z10, Z1, Z1
	VPADDQ Z10, Z2, Z2
	VPADDQ Z10, Z3, Z3
	VPADDQ Z10, Z4, Z4
	VPSUBQ   0(BX), Z0, Z0
	VPSUBQ  64(BX), Z1, Z1
	VPSUBQ 128(BX), Z2, Z2
	VPSUBQ 192(BX), Z3, Z3
	VPSUBQ 256(BX), Z4, Z4
	VPBROADCASTQ ·ifmaLimbMask51(SB), Z5
	VPBROADCASTQ ·ifmaFold19(SB), Z11
	NORMALIZE_5(Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, Z11)
	VMOVDQU64 Z0,   0(DI)
	VMOVDQU64 Z1,  64(DI)
	VMOVDQU64 Z2, 128(DI)
	VMOVDQU64 Z3, 192(DI)
	VMOVDQU64 Z4, 256(DI)
	VZEROUPPER
	RET

// func ifmaNegateNormalizedUncheckedX8(out, x *LimbsX8)
TEXT ·ifmaNegateNormalizedUncheckedX8(SB), NOSPLIT, $0-16
	MOVQ out+0(FP), DI
	MOVQ x+8(FP), CX

	VPBROADCASTQ ·ifmaSubBias0(SB), Z0
	VPBROADCASTQ ·ifmaSubBiasN(SB), Z1
	VMOVDQA64 Z1, Z2
	VMOVDQA64 Z1, Z3
	VMOVDQA64 Z1, Z4
	VPSUBQ   0(CX), Z0, Z0
	VPSUBQ  64(CX), Z1, Z1
	VPSUBQ 128(CX), Z2, Z2
	VPSUBQ 192(CX), Z3, Z3
	VPSUBQ 256(CX), Z4, Z4
	VPBROADCASTQ ·ifmaLimbMask51(SB), Z5
	VPBROADCASTQ ·ifmaFold19(SB), Z11
	NORMALIZE_5(Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, Z11)
	VMOVDQU64 Z0,   0(DI)
	VMOVDQU64 Z1,  64(DI)
	VMOVDQU64 Z2, 128(DI)
	VMOVDQU64 Z3, 192(DI)
	VMOVDQU64 Z4, 256(DI)
	VZEROUPPER
	RET

// func ifmaAddNormalizedUncheckedX4(out, x, y *LimbsX4)
TEXT ·ifmaAddNormalizedUncheckedX4(SB), NOSPLIT, $0-24
	MOVQ out+0(FP), DI
	MOVQ x+8(FP), CX
	MOVQ y+16(FP), BX

	VMOVDQU64   0(CX), Y0
	VMOVDQU64  32(CX), Y1
	VMOVDQU64  64(CX), Y2
	VMOVDQU64  96(CX), Y3
	VMOVDQU64 128(CX), Y4
	VPADDQ   0(BX), Y0, Y0
	VPADDQ  32(BX), Y1, Y1
	VPADDQ  64(BX), Y2, Y2
	VPADDQ  96(BX), Y3, Y3
	VPADDQ 128(BX), Y4, Y4
	VPBROADCASTQ ·ifmaLimbMask51(SB), Y5
	VPBROADCASTQ ·ifmaFold19(SB), Y11
	NORMALIZE_5(Y0, Y1, Y2, Y3, Y4, Y5, Y6, Y7, Y8, Y9, Y10, Y11)
	VMOVDQU64 Y0,   0(DI)
	VMOVDQU64 Y1,  32(DI)
	VMOVDQU64 Y2,  64(DI)
	VMOVDQU64 Y3,  96(DI)
	VMOVDQU64 Y4, 128(DI)
	VZEROUPPER
	RET

// func ifmaSubtractNormalizedUncheckedX4(out, x, y *LimbsX4)
TEXT ·ifmaSubtractNormalizedUncheckedX4(SB), NOSPLIT, $0-24
	MOVQ out+0(FP), DI
	MOVQ x+8(FP), CX
	MOVQ y+16(FP), BX

	VMOVDQU64   0(CX), Y0
	VMOVDQU64  32(CX), Y1
	VMOVDQU64  64(CX), Y2
	VMOVDQU64  96(CX), Y3
	VMOVDQU64 128(CX), Y4
	VPBROADCASTQ ·ifmaSubBias0(SB), Y9
	VPBROADCASTQ ·ifmaSubBiasN(SB), Y10
	VPADDQ Y9, Y0, Y0
	VPADDQ Y10, Y1, Y1
	VPADDQ Y10, Y2, Y2
	VPADDQ Y10, Y3, Y3
	VPADDQ Y10, Y4, Y4
	VPSUBQ   0(BX), Y0, Y0
	VPSUBQ  32(BX), Y1, Y1
	VPSUBQ  64(BX), Y2, Y2
	VPSUBQ  96(BX), Y3, Y3
	VPSUBQ 128(BX), Y4, Y4
	VPBROADCASTQ ·ifmaLimbMask51(SB), Y5
	VPBROADCASTQ ·ifmaFold19(SB), Y11
	NORMALIZE_5(Y0, Y1, Y2, Y3, Y4, Y5, Y6, Y7, Y8, Y9, Y10, Y11)
	VMOVDQU64 Y0,   0(DI)
	VMOVDQU64 Y1,  32(DI)
	VMOVDQU64 Y2,  64(DI)
	VMOVDQU64 Y3,  96(DI)
	VMOVDQU64 Y4, 128(DI)
	VZEROUPPER
	RET

// func ifmaNegateNormalizedUncheckedX4(out, x *LimbsX4)
TEXT ·ifmaNegateNormalizedUncheckedX4(SB), NOSPLIT, $0-16
	MOVQ out+0(FP), DI
	MOVQ x+8(FP), CX

	VPBROADCASTQ ·ifmaSubBias0(SB), Y0
	VPBROADCASTQ ·ifmaSubBiasN(SB), Y1
	VMOVDQA64 Y1, Y2
	VMOVDQA64 Y1, Y3
	VMOVDQA64 Y1, Y4
	VPSUBQ   0(CX), Y0, Y0
	VPSUBQ  32(CX), Y1, Y1
	VPSUBQ  64(CX), Y2, Y2
	VPSUBQ  96(CX), Y3, Y3
	VPSUBQ 128(CX), Y4, Y4
	VPBROADCASTQ ·ifmaLimbMask51(SB), Y5
	VPBROADCASTQ ·ifmaFold19(SB), Y11
	NORMALIZE_5(Y0, Y1, Y2, Y3, Y4, Y5, Y6, Y7, Y8, Y9, Y10, Y11)
	VMOVDQU64 Y0,   0(DI)
	VMOVDQU64 Y1,  32(DI)
	VMOVDQU64 Y2,  64(DI)
	VMOVDQU64 Y3,  96(DI)
	VMOVDQU64 Y4, 128(DI)
	VZEROUPPER
	RET

// func ifmaConditionalNegateNormalizedUncheckedX4(out, x *LimbsX4, negativeMask uint8)
//
// Every input limb is loaded before the first store, so out may alias x. The
// public mask selects biased subtraction lane by lane. The blended value then
// takes the same carry/fold path as the portable implementation, including for
// unselected lanes.
TEXT ·ifmaConditionalNegateNormalizedUncheckedX4(SB), NOSPLIT, $0-17
	MOVQ    out+0(FP), DI
	MOVQ    x+8(FP), CX
	MOVBQZX negativeMask+16(FP), AX
	KMOVB   AX, K1

	VMOVDQU64   0(CX), Y0
	VMOVDQU64  32(CX), Y1
	VMOVDQU64  64(CX), Y2
	VMOVDQU64  96(CX), Y3
	VMOVDQU64 128(CX), Y4

	VPBROADCASTQ ·ifmaSubBias0(SB), Y12
	VPBROADCASTQ ·ifmaSubBiasN(SB), Y13
	VMOVDQA64 Y13, Y14
	VMOVDQA64 Y13, Y15
	VMOVDQA64 Y13, Y16
	VPSUBQ Y0, Y12, Y12
	VPSUBQ Y1, Y13, Y13
	VPSUBQ Y2, Y14, Y14
	VPSUBQ Y3, Y15, Y15
	VPSUBQ Y4, Y16, Y16

	VMOVDQU64 Y12, K1, Y0
	VMOVDQU64 Y13, K1, Y1
	VMOVDQU64 Y14, K1, Y2
	VMOVDQU64 Y15, K1, Y3
	VMOVDQU64 Y16, K1, Y4

	VPBROADCASTQ ·ifmaLimbMask51(SB), Y5
	VPBROADCASTQ ·ifmaFold19(SB), Y11
	NORMALIZE_5(Y0, Y1, Y2, Y3, Y4, Y5, Y6, Y7, Y8, Y9, Y10, Y11)
	VMOVDQU64 Y0,   0(DI)
	VMOVDQU64 Y1,  32(DI)
	VMOVDQU64 Y2,  64(DI)
	VMOVDQU64 Y3,  96(DI)
	VMOVDQU64 Y4, 128(DI)
	VZEROUPPER
	RET

// func ifmaConditionalNegateNormalizedUncheckedX8(out, x *LimbsX8, negativeMask uint8)
//
// Native-width counterpart of the x4 leaf above. Every input limb is loaded
// before the first store, so exact out==x aliasing is safe. K1 selects the
// biased subtraction result for each of the eight public lanes; both selected
// and unselected lanes then take the same one-pass carry/fold normalization.
TEXT ·ifmaConditionalNegateNormalizedUncheckedX8(SB), NOSPLIT, $0-17
	MOVQ    out+0(FP), DI
	MOVQ    x+8(FP), CX
	MOVBQZX negativeMask+16(FP), AX
	KMOVB   AX, K1

	VMOVDQU64   0(CX), Z0
	VMOVDQU64  64(CX), Z1
	VMOVDQU64 128(CX), Z2
	VMOVDQU64 192(CX), Z3
	VMOVDQU64 256(CX), Z4

	VPBROADCASTQ ·ifmaSubBias0(SB), Z12
	VPBROADCASTQ ·ifmaSubBiasN(SB), Z13
	VMOVDQA64 Z13, Z14
	VMOVDQA64 Z13, Z15
	VMOVDQA64 Z13, Z16
	VPSUBQ Z0, Z12, Z12
	VPSUBQ Z1, Z13, Z13
	VPSUBQ Z2, Z14, Z14
	VPSUBQ Z3, Z15, Z15
	VPSUBQ Z4, Z16, Z16

	VMOVDQU64 Z12, K1, Z0
	VMOVDQU64 Z13, K1, Z1
	VMOVDQU64 Z14, K1, Z2
	VMOVDQU64 Z15, K1, Z3
	VMOVDQU64 Z16, K1, Z4

	VPBROADCASTQ ·ifmaLimbMask51(SB), Z5
	VPBROADCASTQ ·ifmaFold19(SB), Z11
	NORMALIZE_5(Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, Z11)
	VMOVDQU64 Z0,   0(DI)
	VMOVDQU64 Z1,  64(DI)
	VMOVDQU64 Z2, 128(DI)
	VMOVDQU64 Z3, 192(DI)
	VMOVDQU64 Z4, 256(DI)
	VZEROUPPER
	RET

DATA ·ifmaLimbMask51+0(SB)/8, $0x0007ffffffffffff
GLOBL ·ifmaLimbMask51(SB), RODATA|NOPTR, $8

DATA ·ifmaFold19+0(SB)/8, $19
GLOBL ·ifmaFold19(SB), RODATA|NOPTR, $8

DATA ·ifmaSubBias0+0(SB)/8, $0x001fffffffffffb4
GLOBL ·ifmaSubBias0(SB), RODATA|NOPTR, $8

DATA ·ifmaSubBiasN+0(SB)/8, $0x001ffffffffffffc
GLOBL ·ifmaSubBiasN(SB), RODATA|NOPTR, $8
