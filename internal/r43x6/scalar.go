package r43x6

import (
	"encoding/binary"
	"errors"
)

var errNonCanonicalScalar = errors.New("r43x6: non-canonical scalar encoding")

var scalarOrder = [32]byte{
	0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
	0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
}

// Scalar is a canonical integer modulo the Ed25519 group order. It exists only
// to drive the correctness-reference scalar multiplication path.
type Scalar struct {
	bytes [32]byte
}

// SetCanonicalBytes sets s from its canonical 32-byte little-endian encoding.
// The receiver is unchanged on failure.
func (s *Scalar) SetCanonicalBytes(in []byte) (*Scalar, error) {
	if len(in) != 32 || !lessLittleEndian(in, scalarOrder[:]) {
		return nil, errNonCanonicalScalar
	}
	var encoded [32]byte
	copy(encoded[:], in)
	s.bytes = encoded
	return s, nil
}

// Bytes returns s's canonical encoding.
func (s *Scalar) Bytes() [32]byte { return s.bytes }

func lessLittleEndian(x, y []byte) bool {
	for i := len(x) - 1; i >= 0; i-- {
		if x[i] < y[i] {
			return true
		}
		if x[i] > y[i] {
			return false
		}
	}
	return false
}

func (s *Scalar) nonAdjacentForm(width uint) [256]int8 {
	if width < 2 || width > 8 {
		panic("r43x6: NAF width must be between 2 and 8")
	}
	var naf [256]int8
	var words [5]uint64
	for i := 0; i < 4; i++ {
		words[i] = binary.LittleEndian.Uint64(s.bytes[i*8:])
	}

	w := uint64(1 << width)
	mask := w - 1
	for pos, carry := uint(0), uint64(0); pos < 256; {
		word := pos / 64
		bit := pos % 64
		var bitBuffer uint64
		if bit < 64-width {
			bitBuffer = words[word] >> bit
		} else {
			bitBuffer = words[word]>>bit | words[word+1]<<(64-bit)
		}
		window := carry + bitBuffer&mask
		if window&1 == 0 {
			pos++
			continue
		}
		if window < w/2 {
			carry = 0
			naf[pos] = int8(window)
		} else {
			carry = 1
			naf[pos] = int8(window) - int8(w)
		}
		pos += width
	}
	return naf
}
