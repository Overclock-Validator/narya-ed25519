//go:build amd64

#include "textflag.h"

// MUL_ROW broadcasts x[XOFF], computes its six products with y using IFMA,
// splits each product at bit 52, shifts the high half to radix-2^43, and adds
// both halves to coefficients C0 through C6. Coefficients fit in uint64 for
// reduced inputs.
#define MUL_ROW(XOFF, C0, C1, C2, C3, C4, C5, C6) \
	VPBROADCASTQ XOFF(CX), Z3                           \
	VPXORQ       Z1, Z1, Z1                             \
	VPXORQ       Z2, Z2, Z2                             \
	VPMADD52LUQ  Z0, Z3, Z1                             \
	VPMADD52HUQ  Z0, Z3, Z2                             \
	VPSLLQ       $9, Z2, Z2                             \
	VMOVDQU64    Z1, 64(SP)                             \
	VMOVDQU64    Z2, 128(SP)                            \
	MOVQ  64(SP), AX; ADDQ AX, C0(SP)                   \
	MOVQ  72(SP), AX; ADDQ AX, C1(SP)                   \
	MOVQ  80(SP), AX; ADDQ AX, C2(SP)                   \
	MOVQ  88(SP), AX; ADDQ AX, C3(SP)                   \
	MOVQ  96(SP), AX; ADDQ AX, C4(SP)                   \
	MOVQ 104(SP), AX; ADDQ AX, C5(SP)                   \
	MOVQ 128(SP), AX; ADDQ AX, C1(SP)                   \
	MOVQ 136(SP), AX; ADDQ AX, C2(SP)                   \
	MOVQ 144(SP), AX; ADDQ AX, C3(SP)                   \
	MOVQ 152(SP), AX; ADDQ AX, C4(SP)                   \
	MOVQ 160(SP), AX; ADDQ AX, C5(SP)                   \
	MOVQ 168(SP), AX; ADDQ AX, C6(SP)

// func ifmaMulRaw(out, x, y *Limbs)
//
// Inputs: reduced (limbs 0-4 u43, limb 5 u40, integer < p).
// Output: unreduced u47 after the Firedancer unsigned fold.
// Requires: AVX-512F and AVX-512IFMA; the Go wrapper enforces cpufeat.IFMA.
TEXT ·ifmaMulRaw(SB), NOSPLIT, $320-24
	MOVQ out+0(FP), DI
	MOVQ x+8(FP), CX
	MOVQ y+16(FP), BX

	// Build a zero-padded eight-lane y vector without reading past Limbs.
	MOVQ  0(BX), AX; MOVQ AX,  0(SP)
	MOVQ  8(BX), AX; MOVQ AX,  8(SP)
	MOVQ 16(BX), AX; MOVQ AX, 16(SP)
	MOVQ 24(BX), AX; MOVQ AX, 24(SP)
	MOVQ 32(BX), AX; MOVQ AX, 32(SP)
	MOVQ 40(BX), AX; MOVQ AX, 40(SP)
	MOVQ $0, 48(SP)
	MOVQ $0, 56(SP)
	VMOVDQU64 0(SP), Z0

	// Clear the twelve radix-2^43 convolution coefficients.
	VPXORQ Z4, Z4, Z4
	VMOVDQU64 Z4, 192(SP)
	VMOVDQU64 Z4, 256(SP)

	MUL_ROW( 0, 192, 200, 208, 216, 224, 232, 240)
	MUL_ROW( 8, 200, 208, 216, 224, 232, 240, 248)
	MUL_ROW(16, 208, 216, 224, 232, 240, 248, 256)
	MUL_ROW(24, 216, 224, 232, 240, 248, 256, 264)
	MUL_ROW(32, 224, 232, 240, 248, 256, 264, 272)
	MUL_ROW(40, 232, 240, 248, 256, 264, 272, 280)

	// Fold coefficients 6..11 by 2^(43*6) = 2^258 = 152 (mod p).
	MOVQ 240(SP), AX; IMUL3Q $152, AX, AX; ADDQ 192(SP), AX; MOVQ AX,  0(SP)
	MOVQ 248(SP), AX; IMUL3Q $152, AX, AX; ADDQ 200(SP), AX; MOVQ AX,  8(SP)
	MOVQ 256(SP), AX; IMUL3Q $152, AX, AX; ADDQ 208(SP), AX; MOVQ AX, 16(SP)
	MOVQ 264(SP), AX; IMUL3Q $152, AX, AX; ADDQ 216(SP), AX; MOVQ AX, 24(SP)
	MOVQ 272(SP), AX; IMUL3Q $152, AX, AX; ADDQ 224(SP), AX; MOVQ AX, 32(SP)
	MOVQ 280(SP), AX; IMUL3Q $152, AX, AX; ADDQ 232(SP), AX; MOVQ AX, 40(SP)

	// Firedancer fold_unsigned: one parallel carry approximation maps the
	// unsigned multiplication result into the composable u47 range.
	MOVQ $0x7ffffffffff, R15 // 2^43-1
	MOVQ $0xffffffffff, R14  // 2^40-1

	MOVQ  0(SP), AX
	ANDQ R15, AX
	MOVQ 40(SP), R8
	SHRQ $40, R8
	IMUL3Q $19, R8, R8
	ADDQ R8, AX
	MOVQ AX, 0(DI)

	MOVQ  8(SP), AX
	ANDQ R15, AX
	MOVQ  0(SP), R8
	SHRQ $43, R8
	ADDQ R8, AX
	MOVQ AX, 8(DI)

	MOVQ 16(SP), AX
	ANDQ R15, AX
	MOVQ  8(SP), R8
	SHRQ $43, R8
	ADDQ R8, AX
	MOVQ AX, 16(DI)

	MOVQ 24(SP), AX
	ANDQ R15, AX
	MOVQ 16(SP), R8
	SHRQ $43, R8
	ADDQ R8, AX
	MOVQ AX, 24(DI)

	MOVQ 32(SP), AX
	ANDQ R15, AX
	MOVQ 24(SP), R8
	SHRQ $43, R8
	ADDQ R8, AX
	MOVQ AX, 32(DI)

	MOVQ 40(SP), AX
	ANDQ R14, AX
	MOVQ 32(SP), R8
	SHRQ $43, R8
	ADDQ R8, AX
	MOVQ AX, 40(DI)

	VZEROUPPER
	RET
