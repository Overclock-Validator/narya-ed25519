package r51x5

import "errors"

var (
	errInvalidPointLength = errors.New("r51x5: invalid point encoding length")
	errInvalidPoint       = errors.New("r51x5: invalid point encoding")

	// Reduced radix-2^51 Edwards25519 constants. curve2D is derived through
	// the scalar field oracle so the relationship cannot drift.
	curveD = Element{limbs: Limbs{
		929955233495203,
		466365720129213,
		1662059464998953,
		2033849074728123,
		1442794654840575,
	}}
	curve2D = Element{limbs: Limbs{
		1859910466990425,
		932731440258426,
		1072319116312658,
		1815898335770999,
		633789495995903,
	}}
	sqrtM1 = Element{limbs: Limbs{
		1718705420411056,
		234908883556509,
		2233514472574048,
		2117202627021982,
		765476049583133,
	}}
)

// Point is a scalar extended-coordinate Edwards25519 point used only to pack,
// unpack, and inspect lanes in the correctness-first PointX4/PointX8 models.
// Every coordinate is reduced and satisfies x=X/Z, y=Y/Z, and xy=T/Z.
// The zero value is not a valid point.
type Point struct {
	X Element
	Y Element
	Z Element
	T Element
}

// NewIdentityPoint returns the neutral point (0,1,1,0).
func NewIdentityPoint() *Point {
	p := new(Point)
	p.Y.One()
	p.Z.One()
	return p
}

// Set sets p=q and returns p.
func (p *Point) Set(q *Point) *Point {
	*p = *q
	return p
}

// SetBytes decodes an Edwards25519 point with the permissive Go/dalek field
// semantics: the low 255 y bits are reduced modulo p and x=0 is accepted with
// either sign bit. The receiver is unchanged on failure.
func (p *Point) SetBytes(in []byte) (*Point, error) {
	if len(in) != 32 {
		return nil, errInvalidPointLength
	}

	var y Element
	if _, err := y.SetBytes(in); err != nil {
		return nil, errInvalidPointLength
	}
	var y2, u, v, one Element
	one.One()
	y2.Square(&y)
	u.Subtract(&y2, &one)
	v.Multiply(&y2, &curveD)
	v.Add(&v, &one)

	var x Element
	if sqrtRatio(&x, &u, &v) == 0 {
		return nil, errInvalidPoint
	}
	requestedSign := int(in[31] >> 7)
	if x.IsNegative() != requestedSign {
		x.Negate(&x)
	}

	var decoded Point
	decoded.X.Set(&x)
	decoded.Y.Set(&y)
	decoded.Z.One()
	decoded.T.Multiply(&x, &y)
	*p = decoded
	return p, nil
}

// Bytes returns p's unique canonical compressed Edwards25519 encoding.
func (p *Point) Bytes() [32]byte {
	var zInv, x, y Element
	zInv.Invert(&p.Z)
	x.Multiply(&p.X, &zInv)
	y.Multiply(&p.Y, &zInv)
	out := y.Bytes()
	out[31] |= byte(x.IsNegative() << 7)
	return out
}

// Equal returns 1 when p and q represent the same projective point.
func (p *Point) Equal(q *Point) int {
	var pxqz, qxpz, pyqz, qypz Element
	pxqz.Multiply(&p.X, &q.Z)
	qxpz.Multiply(&q.X, &p.Z)
	pyqz.Multiply(&p.Y, &q.Z)
	qypz.Multiply(&q.Y, &p.Z)
	return pxqz.Equal(&qxpz) & pyqz.Equal(&qypz)
}

// IsIdentity returns 1 when p is the neutral point.
func (p *Point) IsIdentity() int {
	return p.X.IsZero() & p.Y.Equal(&p.Z)
}

func pow22523(z, x *Element) *Element {
	base := *x
	var x2, x9, x11 Element
	x2.Square(&base)
	x9.repeatedSquareMultiply(&x2, &base, 2)
	x11.Multiply(&x9, &x2)

	var x5, x10, x20, x40, x50, x100, x200, x250 Element
	x5.repeatedSquareMultiply(&x11, &x9, 1)
	x10.repeatedSquareMultiply(&x5, &x5, 5)
	x20.repeatedSquareMultiply(&x10, &x10, 10)
	x40.repeatedSquareMultiply(&x20, &x20, 20)
	x50.repeatedSquareMultiply(&x40, &x10, 10)
	x100.repeatedSquareMultiply(&x50, &x50, 50)
	x200.repeatedSquareMultiply(&x100, &x100, 100)
	x250.repeatedSquareMultiply(&x200, &x50, 50)
	return z.repeatedSquareMultiply(&x250, &base, 2)
}

// sqrtRatio returns one and writes the nonnegative square root of u/v when
// the ratio is square. It uses the same deterministic root rule as the
// vendored Edwards25519 decoder.
func sqrtRatio(z, u, v *Element) int {
	var uv, pow, r Element
	uv.Multiply(u, v)
	pow22523(&pow, &uv)
	r.Multiply(u, &pow)

	var r2, check, negU, negUSqrtM1 Element
	r2.Square(&r)
	check.Multiply(v, &r2)
	negU.Negate(u)
	negUSqrtM1.Multiply(&negU, &sqrtM1)

	correct := check.Equal(u)
	flipped := check.Equal(&negU)
	flippedI := check.Equal(&negUSqrtM1)
	if flipped|flippedI != 0 {
		r.Multiply(&r, &sqrtM1)
	}
	if r.IsNegative() != 0 {
		r.Negate(&r)
	}
	z.Set(&r)
	return correct | flipped
}

func broadcastX4(x *Element) ElementX4 {
	var elements [X4Lanes]Element
	for lane := range elements {
		elements[lane] = *x
	}
	var result ElementX4
	result.SetElements(&elements)
	return result
}

func broadcastX8(x *Element) ElementX8 {
	var elements [X8Lanes]Element
	for lane := range elements {
		elements[lane] = *x
	}
	var result ElementX8
	result.SetElements(&elements)
	return result
}
