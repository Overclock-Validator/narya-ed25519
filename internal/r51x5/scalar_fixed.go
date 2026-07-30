package r51x5

const maxFixedScalarRounds = 64

var scalarOrderBytes = [32]byte{
	0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
	0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
}

// FixedRadixDigitsX4 stores the ordinary 32-byte Ed25519 scalar schedule in
// caller-owned fixed storage. Unlike RadixDigitsX4 it cannot represent HEEA's
// wider exact integers, but it performs no slice allocation and is the right
// handoff for S and the reduced challenge k in the ordinary verifier.
type FixedRadixDigitsX4 struct {
	rounds    [maxFixedScalarRounds]RadixRoundX4
	count     uint8
	radixBits uint8
}

// FixedRadixDigitsX8 is the eight-lane counterpart of FixedRadixDigitsX4.
type FixedRadixDigitsX8 struct {
	rounds    [maxFixedScalarRounds]RadixRoundX8
	count     uint8
	radixBits uint8
}

// RoundCount reports the fixed number of rounds for the selected radix: 64
// for radix 16, 51 for radix 32, and 43 for radix 64.
func (d *FixedRadixDigitsX4) RoundCount() int { return int(d.count) }

// RoundCount is the eight-lane counterpart of FixedRadixDigitsX4.RoundCount.
func (d *FixedRadixDigitsX8) RoundCount() int { return int(d.count) }

// RadixBits reports four for radix 16, five for radix 32, or six for radix 64.
func (d *FixedRadixDigitsX4) RadixBits() uint { return uint(d.radixBits) }

// RadixBits is the eight-lane counterpart of FixedRadixDigitsX4.RadixBits.
func (d *FixedRadixDigitsX8) RadixBits() uint { return uint(d.radixBits) }

// Round returns the round-major public digit record at index. It panics for an
// out-of-range index.
func (d *FixedRadixDigitsX4) Round(index int) *RadixRoundX4 {
	if index < 0 || index >= int(d.count) {
		panic("r51x5: fixed x4 scalar round out of range")
	}
	return &d.rounds[index]
}

// Round is the eight-lane counterpart of FixedRadixDigitsX4.Round.
func (d *FixedRadixDigitsX8) Round(index int) *RadixRoundX8 {
	if index < 0 || index >= int(d.count) {
		panic("r51x5: fixed x8 scalar round out of range")
	}
	return &d.rounds[index]
}

// RecodeCanonicalScalarsX4 recodes active canonical scalar encodings into
// fixed round-major storage. negativeMask applies an exact integer sign after
// recoding. The returned mask contains active lanes whose input is less than
// the group order; invalid and inactive lanes remain all-zero digits.
func RecodeCanonicalScalarsX4(out *FixedRadixDigitsX4, scalars *[X4Lanes][32]byte, negativeMask, active uint8, radixBits uint) uint8 {
	*out = FixedRadixDigitsX4{}
	out.count = uint8(fixedScalarRoundCount(radixBits))
	out.radixBits = uint8(radixBits)
	active &= 0x0f
	var valid uint8
	for lane := 0; lane < X4Lanes; lane++ {
		laneMask := uint8(1 << lane)
		if active&laneMask == 0 || !canonicalScalarBytes(&scalars[lane]) {
			continue
		}
		valid |= laneMask
		recodeFixedScalarX4(out, lane, &scalars[lane], negativeMask&laneMask != 0)
	}
	return valid
}

// RecodeCanonicalScalarsX8 is the eight-lane counterpart of
// RecodeCanonicalScalarsX4.
func RecodeCanonicalScalarsX8(out *FixedRadixDigitsX8, scalars *[X8Lanes][32]byte, negativeMask, active uint8, radixBits uint) uint8 {
	*out = FixedRadixDigitsX8{}
	out.count = uint8(fixedScalarRoundCount(radixBits))
	out.radixBits = uint8(radixBits)
	var valid uint8
	for lane := 0; lane < X8Lanes; lane++ {
		laneMask := uint8(1 << lane)
		if active&laneMask == 0 || !canonicalScalarBytes(&scalars[lane]) {
			continue
		}
		valid |= laneMask
	}

	// Build the round-major representation in round-major order. Besides
	// matching the consumer's layout, this computes the public bit offset once
	// per round instead of once per lane and keeps the current output record
	// hot while all eight lane digits are installed.
	half := int16(1) << (out.radixBits - 1)
	var carries [X8Lanes]int16
	for round := 0; round < int(out.count); round++ {
		bit := round * int(out.radixBits)
		for lane := 0; lane < X8Lanes; lane++ {
			laneMask := uint8(1 << lane)
			if valid&laneMask == 0 {
				continue
			}
			digit := int16(fixedScalarBits(&scalars[lane], bit, uint(out.radixBits))) + carries[lane]
			// The extracted digit is nonnegative and the incoming carry is
			// zero or one. Division by this power-of-two radix is therefore
			// exactly a shift, without an IDIV in the per-lane inner loop.
			carries[lane] = (digit + half) >> out.radixBits
			digit -= carries[lane] << out.radixBits
			if negativeMask&laneMask != 0 {
				digit = -digit
			}
			setRadixRoundDigitX8(&out.rounds[round], lane, int8(digit))
		}
	}
	for lane := 0; lane < X8Lanes; lane++ {
		if carries[lane] != 0 {
			panic("r51x5: canonical x8 scalar exceeded fixed recoding width")
		}
	}
	return valid
}

// recodeCanonicalNegatedRadix32FullX8 specializes the registered cold x8
// variable-base regime: eight active scalars, radix 32, and a negative sign on
// every lane. All eight inputs are still checked for canonicality. Any failure
// re-enters the generic recoder, preserving its exact per-lane fail-closed
// output. The all-valid loop assigns every field in each used round directly,
// removing dynamic-radix, active-lane, and sign branches from the hot path.
func recodeCanonicalNegatedRadix32FullX8(out *FixedRadixDigitsX8, scalars *[X8Lanes][32]byte) uint8 {
	for lane := 0; lane < X8Lanes; lane++ {
		if !canonicalScalarBytes(&scalars[lane]) {
			return RecodeCanonicalScalarsX8(out, scalars, 0xff, 0xff, 5)
		}
	}

	*out = FixedRadixDigitsX8{}
	out.count = 51
	out.radixBits = 5
	var carries [X8Lanes]int16
	for round := 0; round < 51; round++ {
		bit := round * 5
		byteIndex := bit >> 3
		shift := uint(bit & 7)
		record := &out.rounds[round]
		var nonzeroMask, negativeMask uint8
		for lane := 0; lane < X8Lanes; lane++ {
			word := uint16(scalars[lane][byteIndex])
			if byteIndex < 31 {
				word |= uint16(scalars[lane][byteIndex+1]) << 8
			}
			digit := int16((word>>shift)&31) + carries[lane]
			carries[lane] = (digit + 16) >> 5
			digit -= carries[lane] << 5
			digit = -digit
			laneMask := uint8(1 << lane)
			if digit < 0 {
				record.Magnitude[lane] = uint8(-digit)
				negativeMask |= laneMask
			} else {
				record.Magnitude[lane] = uint8(digit)
			}
			if digit != 0 {
				nonzeroMask |= laneMask
			}
		}
		record.NonzeroMask = nonzeroMask
		record.NegativeMask = negativeMask
	}
	for lane := 0; lane < X8Lanes; lane++ {
		if carries[lane] != 0 {
			panic("r51x5: canonical x8 scalar exceeded fixed recoding width")
		}
	}
	return 0xff
}

func recodeCanonicalScalarsRadix32X8(
	out *FixedRadixDigitsX8,
	scalars *[X8Lanes][32]byte,
	negativeMask, active uint8,
) uint8 {
	if active == 0xff && negativeMask == 0xff {
		return recodeCanonicalNegatedRadix32FullX8(out, scalars)
	}
	return RecodeCanonicalScalarsX8(out, scalars, negativeMask, active, 5)
}

func fixedScalarRoundCount(radixBits uint) int {
	switch radixBits {
	case 4:
		return 64
	case 5:
		return 51
	case 6:
		return 43
	default:
		panic("r51x5: fixed scalar radix must be 16, 32, or 64")
	}
}

func canonicalScalarBytes(x *[32]byte) bool {
	for i := len(x) - 1; i >= 0; i-- {
		if x[i] < scalarOrderBytes[i] {
			return true
		}
		if x[i] > scalarOrderBytes[i] {
			return false
		}
	}
	return false
}

func recodeFixedScalarX4(out *FixedRadixDigitsX4, lane int, scalar *[32]byte, negative bool) {
	carry := int16(0)
	half := int16(1) << (out.radixBits - 1)
	for round := 0; round < int(out.count); round++ {
		digit := int16(fixedScalarBits(scalar, round*int(out.radixBits), uint(out.radixBits))) + carry
		carry = (digit + half) >> out.radixBits
		digit -= carry << out.radixBits
		if negative {
			digit = -digit
		}
		setRadixRoundDigitX4(&out.rounds[round], lane, int8(digit))
	}
	if carry != 0 {
		panic("r51x5: canonical x4 scalar exceeded fixed recoding width")
	}
}

func fixedScalarBits(scalar *[32]byte, bit int, width uint) uint16 {
	// This extractor reads at most 16 source bits. Its callers restrict width
	// so shift+width never exceeds 16 (fixed scalar: 4/5/6; fixed comb:
	// 4/5/8). A future wider recoder must use a three-byte or wider extractor.
	byteIndex := bit >> 3
	shift := uint(bit & 7)
	word := uint16(scalar[byteIndex])
	if byteIndex+1 < len(scalar) {
		word |= uint16(scalar[byteIndex+1]) << 8
	}
	return (word >> shift) & uint16((1<<width)-1)
}
