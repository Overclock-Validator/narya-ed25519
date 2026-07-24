package r51x5

import (
	"encoding/binary"
	"math/bits"
)

const heeaBaseSplitBit = 128

// ExperimentalHEEABaseSplitB128X4 prepares the second fixed base used by the
// HEEA split equation. This is setup work: callers should retain the result
// rather than performing 128 doublings for every verification.
//
// The equation helper relies on B having order L. It deliberately does not
// cofactor-clear or otherwise change B.
func ExperimentalHEEABaseSplitB128X4(out, B *PointX4) *PointX4 {
	*out = *B
	for doubling := 0; doubling < heeaBaseSplitBit; doubling++ {
		out.Double(out)
	}
	return out
}

// ExperimentalHEEABaseSplitB128X8 is the eight-lane counterpart of
// ExperimentalHEEABaseSplitB128X4.
func ExperimentalHEEABaseSplitB128X8(out, B *PointX8) *PointX8 {
	*out = *B
	for doubling := 0; doubling < heeaBaseSplitBit; doubling++ {
		out.Double(out)
	}
	return out
}

// ExperimentalHEEABaseSplitEquationX4 evaluates
//
//	[tau*s]B - [tau]R - [epsilon*rho]A
//
// by reducing only tau*s modulo L, splitting that canonical scalar at bit
// 128, and evaluating the four terms with bases B, [2^128]B, R, and A.
// B128 must have been derived from B lane-wise. B must have order L; R and A
// may contain torsion, so their signed coefficients are never reduced.
//
// Invalid epsilon values and basepoint products wider than the fixed 512-bit
// reducer can represent are removed from the returned usable mask. They are
// baseline-fallback lanes, not truncated equations. Inactive and unusable
// output lanes are identities. This research helper is not used by production
// dispatch.
func ExperimentalHEEABaseSplitEquationX4(out *PointX4, B, B128, R, A *PointX4, s, tau, rho *[X4Lanes]SignedMagnitude, epsilon *[X4Lanes]int8, radixBits uint, active uint8) uint8 {
	usable := active & 0x0f
	var bases [QSMTerms]PointX4
	bases[0], bases[1], bases[2], bases[3] = *B, *B128, *R, *A
	var coefficients QSMScalarsX4
	var reduced [X4Lanes][32]byte
	for lane := 0; lane < X4Lanes; lane++ {
		laneMask := uint8(1 << lane)
		if usable&laneMask == 0 {
			continue
		}
		if epsilon[lane] != -1 && epsilon[lane] != 1 {
			usable &^= laneMask
			continue
		}
		if !heeaReduceSignedProduct(&reduced[lane], tau[lane], s[lane]) {
			usable &^= laneMask
			continue
		}
		coefficients[0][lane] = heeaSignedMagnitudeView(reduced[lane][:16], false)
		coefficients[1][lane] = heeaSignedMagnitudeView(reduced[lane][16:], false)
		coefficients[2][lane] = heeaSignedMagnitudeTimesSignView(tau[lane], -1)
		coefficients[3][lane] = heeaSignedMagnitudeTimesSignView(rho[lane], -int(epsilon[lane]))
	}
	QSMX4(out, &bases, &coefficients, radixBits, usable)
	return usable
}

// ExperimentalHEEABaseSplitEquationX8 is the eight-lane counterpart of
// ExperimentalHEEABaseSplitEquationX4.
func ExperimentalHEEABaseSplitEquationX8(out *PointX8, B, B128, R, A *PointX8, s, tau, rho *[X8Lanes]SignedMagnitude, epsilon *[X8Lanes]int8, radixBits uint, active uint8) uint8 {
	usable := active
	var bases [QSMTerms]PointX8
	bases[0], bases[1], bases[2], bases[3] = *B, *B128, *R, *A
	var coefficients QSMScalarsX8
	var reduced [X8Lanes][32]byte
	for lane := 0; lane < X8Lanes; lane++ {
		laneMask := uint8(1 << lane)
		if usable&laneMask == 0 {
			continue
		}
		if epsilon[lane] != -1 && epsilon[lane] != 1 {
			usable &^= laneMask
			continue
		}
		if !heeaReduceSignedProduct(&reduced[lane], tau[lane], s[lane]) {
			usable &^= laneMask
			continue
		}
		coefficients[0][lane] = heeaSignedMagnitudeView(reduced[lane][:16], false)
		coefficients[1][lane] = heeaSignedMagnitudeView(reduced[lane][16:], false)
		coefficients[2][lane] = heeaSignedMagnitudeTimesSignView(tau[lane], -1)
		coefficients[3][lane] = heeaSignedMagnitudeTimesSignView(rho[lane], -int(epsilon[lane]))
	}
	QSMX8(out, &bases, &coefficients, radixBits, usable)
	return usable
}

// heeaReduceSignedProduct returns x*y modulo L as a canonical little-endian
// scalar. The magnitude multiplication and reduction use fixed caller-owned
// storage. The fixed reducer is the same independently differential-tested
// Barrett primitive used by the SHA-512-to-scalar experiment.
//
// A false return means the exact unsigned product needs more than 512 bits.
// HEEA's admitted tau*s products are around 389 bits; wider research inputs
// must fall back rather than being silently truncated.
func heeaReduceSignedProduct(out *[32]byte, x, y SignedMagnitude) bool {
	*out = [32]byte{}
	if x.Sign() == 0 || y.Sign() == 0 {
		return true
	}
	if x.BitLen()+y.BitLen() > 512 || len(x.magnitude) > 64 || len(y.magnitude) > 64 {
		return false
	}

	var xWords, yWords, product [8]uint64
	heeaLoadMagnitudeWords(&xWords, x.magnitude)
	heeaLoadMagnitudeWords(&yWords, y.magnitude)
	xCount := (len(x.magnitude) + 7) / 8
	yCount := (len(y.magnitude) + 7) / 8
	for i := 0; i < xCount; i++ {
		for j := 0; j < yCount; j++ {
			hi, lo := bits.Mul64(xWords[i], yWords[j])
			if !heeaAdd128(&product, i+j, lo, hi) {
				return false
			}
		}
	}

	var wide [64]byte
	for i := range product {
		binary.LittleEndian.PutUint64(wide[i*8:], product[i])
	}
	reduceUniformScalar(out, &wide)
	if x.negative != y.negative {
		heeaNegateCanonicalScalar(out)
	}
	return true
}

func heeaLoadMagnitudeWords(out *[8]uint64, magnitude []byte) {
	*out = [8]uint64{}
	for i, value := range magnitude {
		out[i>>3] |= uint64(value) << uint((i&7)*8)
	}
}

func heeaAdd128(out *[8]uint64, index int, lo, hi uint64) bool {
	if index >= len(out) {
		return lo == 0 && hi == 0
	}
	var carry uint64
	out[index], carry = bits.Add64(out[index], lo, 0)
	index++
	if index == len(out) {
		return hi == 0 && carry == 0
	}
	out[index], carry = bits.Add64(out[index], hi, carry)
	for index++; carry != 0 && index < len(out); index++ {
		out[index], carry = bits.Add64(out[index], 0, carry)
	}
	return carry == 0
}

func heeaNegateCanonicalScalar(x *[32]byte) {
	var nonzero byte
	for _, value := range x {
		nonzero |= value
	}
	if nonzero == 0 {
		return
	}
	var borrow uint64
	for i := 0; i < 4; i++ {
		value := binary.LittleEndian.Uint64(x[i*8:])
		value, borrow = bits.Sub64(scalarOrderWords[i], value, borrow)
		binary.LittleEndian.PutUint64(x[i*8:], value)
	}
	if borrow != 0 {
		panic("r51x5: reduced HEEA basepoint coefficient exceeded L")
	}
}

// heeaSignedMagnitudeView borrows magnitude for the duration of one QSM call.
// QSM treats coefficients as immutable. This avoids a redundant copy while
// retaining SignedMagnitude's normalized representation.
func heeaSignedMagnitudeView(magnitude []byte, negative bool) SignedMagnitude {
	end := len(magnitude)
	for end > 0 && magnitude[end-1] == 0 {
		end--
	}
	if end == 0 {
		return SignedMagnitude{}
	}
	return SignedMagnitude{magnitude: magnitude[:end], negative: negative}
}

func heeaSignedMagnitudeTimesSignView(x SignedMagnitude, sign int) SignedMagnitude {
	if sign != -1 && sign != 1 {
		panic("r51x5: HEEA coefficient sign must be -1 or +1")
	}
	if x.Sign() == 0 {
		return SignedMagnitude{}
	}
	negative := x.negative
	if sign < 0 {
		negative = !negative
	}
	return SignedMagnitude{magnitude: x.magnitude, negative: negative}
}
