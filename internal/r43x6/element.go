package r43x6

import (
	"encoding/binary"
	"errors"
)

const (
	LimbBits        = 43
	TopLimbBits     = 40
	UnreducedBits   = 47
	UnsignedBits    = 62
	UnpackedTopBits = 41

	limbMask = uint64(1<<LimbBits) - 1
	topMask  = uint64(1<<TopLimbBits) - 1
)

var errNonCanonical = errors.New("r43x6: non-canonical field encoding")
var errInvalidLength = errors.New("r43x6: invalid field encoding length")

// Limbs is a little-endian radix-2^43 representation. Range predicates below
// identify which Firedancer contract a value satisfies. Arithmetic uses
// Element so that loose values cannot accidentally cross an API boundary.
type Limbs [6]uint64

var (
	modulusLimbs = Limbs{
		1<<LimbBits - 19,
		limbMask, limbMask, limbMask, limbMask,
		topMask,
	}
	twiceModulusLimbs = Limbs{
		1<<LimbBits - 38,
		limbMask, limbMask, limbMask, limbMask,
		1<<UnpackedTopBits - 1,
	}
)

// Element is a uniquely reduced field element. The zero value is zero and is
// valid. Its limbs are private so every exported arithmetic operation can
// guarantee a reduced result.
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

// SetBytes decodes a permissive 32-byte little-endian field element. It
// ignores bit 255 and reduces the remaining integer modulo p, matching the
// field decoding used by Go and dalek-style Edwards25519 point decoders. The
// receiver is unchanged on a length mismatch.
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
// It rejects values at least p, values with bit 255 set, and length mismatches.
// The receiver is unchanged on failure.
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

func unpackLow255(in []byte) Limbs {
	w0 := binary.LittleEndian.Uint64(in[0:8])
	w1 := binary.LittleEndian.Uint64(in[8:16])
	w2 := binary.LittleEndian.Uint64(in[16:24])
	w3 := binary.LittleEndian.Uint64(in[24:32])
	return Limbs{
		w0 & limbMask,
		(w0>>43 | w1<<21) & limbMask,
		(w1>>22 | w2<<42) & limbMask,
		(w2 >> 1) & limbMask,
		(w2>>44 | w3<<20) & limbMask,
		(w3 >> 23) & topMask,
	}
}

// FromCanonicalBytes returns the field element encoded by in.
func FromCanonicalBytes(in []byte) (Element, error) {
	var z Element
	_, err := z.SetCanonicalBytes(in)
	return z, err
}

// Bytes returns z's unique canonical 32-byte little-endian encoding.
func (z *Element) Bytes() [32]byte {
	l := z.limbs
	w0 := l[0] | l[1]<<43
	w1 := l[1]>>21 | l[2]<<22
	w2 := l[2]>>42 | l[3]<<1 | l[4]<<44
	w3 := l[4]>>20 | l[5]<<23

	var out [32]byte
	binary.LittleEndian.PutUint64(out[0:8], w0)
	binary.LittleEndian.PutUint64(out[8:16], w1)
	binary.LittleEndian.PutUint64(out[16:24], w2)
	binary.LittleEndian.PutUint64(out[24:32], w3)
	return out
}

// IsUnsigned reports whether l satisfies Firedancer's unsigned range.
func IsUnsigned(l Limbs) bool {
	for _, x := range l {
		if x >= 1<<UnsignedBits {
			return false
		}
	}
	return true
}

// IsUnreduced reports whether l satisfies Firedancer's u47 range.
func IsUnreduced(l Limbs) bool {
	for _, x := range l {
		if x >= 1<<UnreducedBits {
			return false
		}
	}
	return true
}

// IsUnpacked reports whether l has five 43-bit limbs and one 41-bit top limb.
func IsUnpacked(l Limbs) bool {
	for i := 0; i < 5; i++ {
		if l[i] >= 1<<LimbBits {
			return false
		}
	}
	return l[5] < 1<<UnpackedTopBits
}

// IsNearlyReduced reports whether l is unpacked and represents an integer
// smaller than 2p.
func IsNearlyReduced(l Limbs) bool {
	return IsUnpacked(l) && compareLimbs(l, twiceModulusLimbs) < 0
}

// IsReduced reports whether l is the unique representation of an integer in
// [0,p).
func IsReduced(l Limbs) bool {
	for i := 0; i < 5; i++ {
		if l[i] >= 1<<LimbBits {
			return false
		}
	}
	return l[5] < 1<<TopLimbBits && compareLimbs(l, modulusLimbs) < 0
}

func compareLimbs(x, y Limbs) int {
	for i := 5; i >= 0; i-- {
		if x[i] < y[i] {
			return -1
		}
		if x[i] > y[i] {
			return 1
		}
	}
	return 0
}
