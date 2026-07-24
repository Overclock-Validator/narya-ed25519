package r51x5

import (
	"encoding/binary"
	"errors"
)

const (
	// LimbBits is the radix exponent used by the five-limb representation.
	LimbBits = 51
	// IFMAMultiplicandBits is the maximum documented input width of each
	// unsigned VPMADD52 multiplicand limb. This is not Element's range.
	IFMAMultiplicandBits = 52

	limbMask = uint64(1<<LimbBits) - 1
)

var (
	errInvalidLength = errors.New("r51x5: invalid field encoding length")
	errNonCanonical  = errors.New("r51x5: non-canonical field encoding")

	modulusLimbs = Limbs{
		1<<LimbBits - 19,
		limbMask,
		limbMask,
		limbMask,
		limbMask,
	}
)

// Limbs is a little-endian radix-2^51 representation.
type Limbs [5]uint64

// Element is a uniquely reduced field element. Its zero value is zero.
type Element struct {
	limbs Limbs
}

// New returns a new zero element.
func New() *Element { return &Element{} }

// Set sets z = x and returns z.
func (z *Element) Set(x *Element) *Element {
	z.limbs = x.limbs
	return z
}

// Zero sets z = 0 and returns z.
func (z *Element) Zero() *Element {
	z.limbs = Limbs{}
	return z
}

// One sets z = 1 and returns z.
func (z *Element) One() *Element {
	z.limbs = Limbs{1}
	return z
}

// Limbs returns a copy of z's reduced limbs.
func (z *Element) Limbs() Limbs { return z.limbs }

// SetBytes decodes a permissive 32-byte little-endian field element. Bit 255
// is ignored and the low 255 bits are reduced modulo p. The receiver is
// unchanged on a length mismatch.
func (z *Element) SetBytes(in []byte) (*Element, error) {
	if len(in) != 32 {
		return nil, errInvalidLength
	}
	l := unpackLow255(in)
	if compareLimbs(l, modulusLimbs) >= 0 {
		l = subtractLimbs(l, modulusLimbs)
	}
	z.limbs = l
	return z, nil
}

// SetCanonicalBytes decodes a canonical 32-byte little-endian field element.
// It rejects bit 255, integers at least p, and length mismatches. The receiver
// is unchanged on failure.
func (z *Element) SetCanonicalBytes(in []byte) (*Element, error) {
	if len(in) != 32 || in[31]&0x80 != 0 {
		return nil, errNonCanonical
	}
	l := unpackLow255(in)
	if compareLimbs(l, modulusLimbs) >= 0 {
		return nil, errNonCanonical
	}
	z.limbs = l
	return z, nil
}

// FromCanonicalBytes returns the canonical field element encoded by in.
func FromCanonicalBytes(in []byte) (Element, error) {
	var z Element
	_, err := z.SetCanonicalBytes(in)
	return z, err
}

func unpackLow255(in []byte) Limbs {
	w0 := binary.LittleEndian.Uint64(in[0:8])
	w1 := binary.LittleEndian.Uint64(in[8:16])
	w2 := binary.LittleEndian.Uint64(in[16:24])
	w3 := binary.LittleEndian.Uint64(in[24:32])
	return Limbs{
		w0 & limbMask,
		(w0>>51 | w1<<13) & limbMask,
		(w1>>38 | w2<<26) & limbMask,
		(w2>>25 | w3<<39) & limbMask,
		(w3 >> 12) & limbMask,
	}
}

// Bytes returns z's unique canonical 32-byte little-endian encoding.
func (z *Element) Bytes() [32]byte {
	l := z.limbs
	w0 := l[0] | l[1]<<51
	w1 := l[1]>>13 | l[2]<<38
	w2 := l[2]>>26 | l[3]<<25
	w3 := l[3]>>39 | l[4]<<12

	var out [32]byte
	binary.LittleEndian.PutUint64(out[0:8], w0)
	binary.LittleEndian.PutUint64(out[8:16], w1)
	binary.LittleEndian.PutUint64(out[16:24], w2)
	binary.LittleEndian.PutUint64(out[24:32], w3)
	return out
}

// IsReduced reports whether l is the unique radix-2^51 representation of an
// integer in [0,p).
func IsReduced(l Limbs) bool {
	for _, x := range l {
		if x >= 1<<LimbBits {
			return false
		}
	}
	return compareLimbs(l, modulusLimbs) < 0
}

// IsIFMAMultiplicand reports whether every limb is less than 2^52. It does
// not imply that the limbs form a reduced or even carried field element.
func IsIFMAMultiplicand(l Limbs) bool {
	for _, x := range l {
		if x >= 1<<IFMAMultiplicandBits {
			return false
		}
	}
	return true
}

func compareLimbs(x, y Limbs) int {
	for i := len(x) - 1; i >= 0; i-- {
		if x[i] < y[i] {
			return -1
		}
		if x[i] > y[i] {
			return 1
		}
	}
	return 0
}

// subtractLimbs returns x-y. It requires x >= y and canonical limb widths;
// x may equal p.
func subtractLimbs(x, y Limbs) Limbs {
	var z Limbs
	var borrow uint64
	for i := range z {
		subtrahend := y[i] + borrow
		if x[i] >= subtrahend {
			z[i] = x[i] - subtrahend
			borrow = 0
		} else {
			z[i] = (1 << LimbBits) + x[i] - subtrahend
			borrow = 1
		}
	}
	return z
}
