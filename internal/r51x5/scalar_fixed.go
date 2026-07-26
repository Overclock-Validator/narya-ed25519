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
		recodeFixedScalarX8(out, lane, &scalars[lane], negativeMask&laneMask != 0)
	}
	return valid
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

// fixedScalarWindowReader extracts consecutive little-endian windows from one
// 32-byte scalar. At widths 4..6, fewer than width bits remain after each
// extraction, so adding the next byte keeps buffer below 14 live bits. The
// final radix-32/radix-64 window is zero-extended past bit 255, matching the
// former two-byte random-access extractor without an out-of-bounds load.
type fixedScalarWindowReader struct {
	scalar *[32]byte
	buffer uint16
	bits   uint8
	next   uint8
}

func (reader *fixedScalarWindowReader) window(width uint8) uint16 {
	for reader.bits < width {
		if int(reader.next) < len(reader.scalar) {
			reader.buffer |= uint16(reader.scalar[reader.next]) << reader.bits
		}
		reader.next++
		reader.bits += 8
	}
	value := reader.buffer & uint16((1<<width)-1)
	reader.buffer >>= width
	reader.bits -= width
	return value
}

func recodeFixedScalarX4(out *FixedRadixDigitsX4, lane int, scalar *[32]byte, negative bool) {
	carry := int16(0)
	radix := int16(1 << out.radixBits)
	half := radix >> 1
	reader := fixedScalarWindowReader{scalar: scalar}
	for round := 0; round < int(out.count); round++ {
		digit := int16(reader.window(out.radixBits)) + carry
		carry = (digit + half) / radix
		digit -= carry * radix
		if negative {
			digit = -digit
		}
		setRadixRoundDigitX4(&out.rounds[round], lane, int8(digit))
	}
	if carry != 0 {
		panic("r51x5: canonical x4 scalar exceeded fixed recoding width")
	}
}

func recodeFixedScalarX8(out *FixedRadixDigitsX8, lane int, scalar *[32]byte, negative bool) {
	carry := int16(0)
	radix := int16(1 << out.radixBits)
	half := radix >> 1
	reader := fixedScalarWindowReader{scalar: scalar}
	for round := 0; round < int(out.count); round++ {
		digit := int16(reader.window(out.radixBits)) + carry
		carry = (digit + half) / radix
		digit -= carry * radix
		if negative {
			digit = -digit
		}
		setRadixRoundDigitX8(&out.rounds[round], lane, int8(digit))
	}
	if carry != 0 {
		panic("r51x5: canonical x8 scalar exceeded fixed recoding width")
	}
}
