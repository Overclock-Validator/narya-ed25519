package r51x5

import (
	"encoding/binary"
	"math/bits"

	"github.com/Overclock-Validator/narya-ed25519/internal/cpufeat"
)

// scalarBarrettMu is floor(2^512/l), where l is the prime order of the
// Edwards25519 basepoint. Limbs are little-endian in radix 2^64.
//
// The reduction below is deliberately independent of the signed radix-2^21
// ref10 schedule used by edwards25519.Scalar.SetUniformBytes. Keeping an
// independently derived fixed-width implementation makes differential tests
// capable of finding transcription errors in either implementation.
var scalarBarrettMu = [5]uint64{
	0xed9ce5a30a2c131b,
	0x2106215d086329a7,
	0xffffffffffffffeb,
	0xffffffffffffffff,
	0x000000000000000f,
}

var scalarOrderWords = [5]uint64{
	0x5812631a5cf5d3ed,
	0x14def9dea2f79cd6,
	0x0000000000000000,
	0x1000000000000000,
	0x0000000000000000,
}

// ExperimentalReduceUniformScalarsX4 reduces active 64-byte little-endian
// integers modulo the Ed25519 group order. It consumes the lane-major layout
// emitted by sha512mb and writes canonical 32-byte scalar encodings to
// caller-owned storage without allocating.
//
// Inactive outputs are zeroed. The returned mask is active with bits outside
// the four-lane width removed. This experiment is not used by production
// dispatch.
func ExperimentalReduceUniformScalarsX4(out *[X4Lanes][32]byte, in *[X4Lanes][64]byte, active uint8) uint8 {
	*out = [X4Lanes][32]byte{}
	active &= (1 << X4Lanes) - 1
	for lane := 0; lane < X4Lanes; lane++ {
		if active&(1<<lane) != 0 {
			reduceUniformScalar(&out[lane], &in[lane])
		}
	}
	return active
}

// ExperimentalReduceUniformScalarsX8 is the eight-lane counterpart of
// ExperimentalReduceUniformScalarsX4.
func ExperimentalReduceUniformScalarsX8(out *[X8Lanes][32]byte, in *[X8Lanes][64]byte, active uint8) uint8 {
	if cpufeat.PreferNativeScalarReduceX8IFMA() {
		if reduced, ok := reduceUniformScalarsIFMAX8(out, in, active); ok {
			return reduced
		}
	}
	return reduceUniformScalarsScalarX8(out, in, active)
}

// reduceUniformScalarsScalarX8 is the portable lane-serial oracle and fallback
// for ExperimentalReduceUniformScalarsX8. Keep it directly callable by the
// native differential so the candidate can never accidentally compare against
// itself through the exported dispatch seam.
func reduceUniformScalarsScalarX8(out *[X8Lanes][32]byte, in *[X8Lanes][64]byte, active uint8) uint8 {
	*out = [X8Lanes][32]byte{}
	for lane := 0; lane < X8Lanes; lane++ {
		if active&(1<<lane) != 0 {
			reduceUniformScalar(&out[lane], &in[lane])
		}
	}
	return active
}

// reduceUniformScalar is a fixed-array radix-2^21 reduction. Its constants
// encode 2^252 = -27742317777372353535851937790883648493 (mod l), in the
// same public-domain schedule used by ref10. It is kept compact with fixed
// loops so the x4/x8 wrappers remain auditable and allocation-free.
func reduceUniformScalar(out *[32]byte, in *[64]byte) {
	const mask21 = int64(1<<21 - 1)
	var s [24]int64
	s[0] = mask21 & scalarLoad3(in[:])
	s[1] = mask21 & (scalarLoad4(in[2:]) >> 5)
	s[2] = mask21 & (scalarLoad3(in[5:]) >> 2)
	s[3] = mask21 & (scalarLoad4(in[7:]) >> 7)
	s[4] = mask21 & (scalarLoad4(in[10:]) >> 4)
	s[5] = mask21 & (scalarLoad3(in[13:]) >> 1)
	s[6] = mask21 & (scalarLoad4(in[15:]) >> 6)
	s[7] = mask21 & (scalarLoad3(in[18:]) >> 3)
	s[8] = mask21 & scalarLoad3(in[21:])
	s[9] = mask21 & (scalarLoad4(in[23:]) >> 5)
	s[10] = mask21 & (scalarLoad3(in[26:]) >> 2)
	s[11] = mask21 & (scalarLoad4(in[28:]) >> 7)
	s[12] = mask21 & (scalarLoad4(in[31:]) >> 4)
	s[13] = mask21 & (scalarLoad3(in[34:]) >> 1)
	s[14] = mask21 & (scalarLoad4(in[36:]) >> 6)
	s[15] = mask21 & (scalarLoad3(in[39:]) >> 3)
	s[16] = mask21 & scalarLoad3(in[42:])
	s[17] = mask21 & (scalarLoad4(in[44:]) >> 5)
	s[18] = mask21 & (scalarLoad3(in[47:]) >> 2)
	s[19] = mask21 & (scalarLoad4(in[49:]) >> 7)
	s[20] = mask21 & (scalarLoad4(in[52:]) >> 4)
	s[21] = mask21 & (scalarLoad3(in[55:]) >> 1)
	s[22] = mask21 & (scalarLoad4(in[57:]) >> 6)
	s[23] = scalarLoad4(in[60:]) >> 3

	for i := 23; i >= 18; i-- {
		foldScalarRadix21(&s, i)
	}
	carryScalarRadix21Rounded(&s, 6, 16)
	carryScalarRadix21Rounded(&s, 7, 15)

	for i := 17; i >= 12; i-- {
		foldScalarRadix21(&s, i)
	}
	carryScalarRadix21Rounded(&s, 0, 10)
	carryScalarRadix21Rounded(&s, 1, 11)

	foldScalarRadix21(&s, 12)
	carryScalarRadix21(&s, 0, 11)
	foldScalarRadix21(&s, 12)
	carryScalarRadix21(&s, 0, 10)

	out[0] = byte(s[0])
	out[1] = byte(s[0] >> 8)
	out[2] = byte((s[0] >> 16) | (s[1] << 5))
	out[3] = byte(s[1] >> 3)
	out[4] = byte(s[1] >> 11)
	out[5] = byte((s[1] >> 19) | (s[2] << 2))
	out[6] = byte(s[2] >> 6)
	out[7] = byte((s[2] >> 14) | (s[3] << 7))
	out[8] = byte(s[3] >> 1)
	out[9] = byte(s[3] >> 9)
	out[10] = byte((s[3] >> 17) | (s[4] << 4))
	out[11] = byte(s[4] >> 4)
	out[12] = byte(s[4] >> 12)
	out[13] = byte((s[4] >> 20) | (s[5] << 1))
	out[14] = byte(s[5] >> 7)
	out[15] = byte((s[5] >> 15) | (s[6] << 6))
	out[16] = byte(s[6] >> 2)
	out[17] = byte(s[6] >> 10)
	out[18] = byte((s[6] >> 18) | (s[7] << 3))
	out[19] = byte(s[7] >> 5)
	out[20] = byte(s[7] >> 13)
	out[21] = byte(s[8])
	out[22] = byte(s[8] >> 8)
	out[23] = byte((s[8] >> 16) | (s[9] << 5))
	out[24] = byte(s[9] >> 3)
	out[25] = byte(s[9] >> 11)
	out[26] = byte((s[9] >> 19) | (s[10] << 2))
	out[27] = byte(s[10] >> 6)
	out[28] = byte((s[10] >> 14) | (s[11] << 7))
	out[29] = byte(s[11] >> 1)
	out[30] = byte(s[11] >> 9)
	out[31] = byte(s[11] >> 17)
}

func scalarLoad3(in []byte) int64 {
	return int64(in[0]) | int64(in[1])<<8 | int64(in[2])<<16
}

func scalarLoad4(in []byte) int64 {
	return scalarLoad3(in) | int64(in[3])<<24
}

func foldScalarRadix21(s *[24]int64, high int) {
	x := s[high]
	low := high - 12
	s[low] += x * 666643
	s[low+1] += x * 470296
	s[low+2] += x * 654183
	s[low+3] -= x * 997805
	s[low+4] += x * 136657
	s[low+5] -= x * 683901
	s[high] = 0
}

func carryScalarRadix21Rounded(s *[24]int64, first, last int) {
	for i := first; i <= last; i += 2 {
		carry := (s[i] + (1 << 20)) >> 21
		s[i+1] += carry
		s[i] -= carry << 21
	}
}

func carryScalarRadix21(s *[24]int64, first, last int) {
	for i := first; i <= last; i++ {
		carry := s[i] >> 21
		s[i+1] += carry
		s[i] -= carry << 21
	}
}

// reduceUniformScalarBarrett is a structurally independent test oracle and
// alternative candidate. It applies Barrett reduction with b=2^64 and k=4:
//
//	q1 = floor(x / b^(k-1))
//	q3 = floor(q1 * floor(b^(2k)/l) / b^(k+1))
//	r  = x - q3*l (mod b^(k+1))
//
// For x < b^(2k), the Barrett bound leaves r < 3*l, so two conditional
// subtractions produce the unique representative in [0,l). All temporaries
// have fixed size and remain on the caller's stack.
func reduceUniformScalarBarrett(out *[32]byte, in *[64]byte) {
	var x [8]uint64
	for i := range x {
		x[i] = binary.LittleEndian.Uint64(in[i*8:])
	}

	q1 := [5]uint64{x[3], x[4], x[5], x[6], x[7]}
	var q2 [10]uint64
	mul5x5(&q2, &q1, &scalarBarrettMu)
	q3 := [5]uint64{q2[5], q2[6], q2[7], q2[8], q2[9]}

	var r2 [5]uint64
	mul5x5Low(&r2, &q3, &scalarOrderWords)
	r := [5]uint64{x[0], x[1], x[2], x[3], x[4]}
	var borrow uint64
	for i := range r {
		r[i], borrow = bits.Sub64(r[i], r2[i], borrow)
	}
	// Discarding borrow is addition of b^(k+1), as prescribed by Barrett
	// reduction when the residue subtraction is negative.
	conditionalSubtractScalarOrder(&r)
	conditionalSubtractScalarOrder(&r)

	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint64(out[i*8:], r[i])
	}
}

func mul5x5(out *[10]uint64, x, y *[5]uint64) {
	*out = [10]uint64{}
	for i := 0; i < 5; i++ {
		for j := 0; j < 5; j++ {
			hi, lo := bits.Mul64(x[i], y[j])
			add128x10(out, i+j, lo, hi)
		}
	}
}

// mul5x5Low returns x*y modulo 2^320.
func mul5x5Low(out *[5]uint64, x, y *[5]uint64) {
	*out = [5]uint64{}
	for i := 0; i < 5; i++ {
		for j := 0; i+j < 5; j++ {
			hi, lo := bits.Mul64(x[i], y[j])
			add128x5Low(out, i+j, lo, hi)
		}
	}
}

func add128x10(out *[10]uint64, index int, lo, hi uint64) {
	var carry uint64
	out[index], carry = bits.Add64(out[index], lo, 0)
	out[index+1], carry = bits.Add64(out[index+1], hi, carry)
	for i := index + 2; i < len(out); i++ {
		out[i], carry = bits.Add64(out[i], 0, carry)
	}
}

func add128x5Low(out *[5]uint64, index int, lo, hi uint64) {
	var carry uint64
	out[index], carry = bits.Add64(out[index], lo, 0)
	if index+1 == len(out) {
		return
	}
	out[index+1], carry = bits.Add64(out[index+1], hi, carry)
	for i := index + 2; i < len(out); i++ {
		out[i], carry = bits.Add64(out[i], 0, carry)
	}
}

func conditionalSubtractScalarOrder(x *[5]uint64) {
	var reduced [5]uint64
	var borrow uint64
	for i := range x {
		reduced[i], borrow = bits.Sub64(x[i], scalarOrderWords[i], borrow)
	}
	// borrow is one exactly when x < l. Select reduced otherwise.
	keepOriginal := uint64(0) - borrow
	for i := range x {
		x[i] = (x[i] & keepOriginal) | (reduced[i] &^ keepOriginal)
	}
}
