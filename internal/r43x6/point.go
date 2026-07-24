package r43x6

import "errors"

var (
	errInvalidPointLength = errors.New("r43x6: invalid point encoding length")
	errInvalidPoint       = errors.New("r43x6: invalid point encoding")
)

// Point is an Edwards25519 point in extended projective coordinates. Every
// coordinate is a reduced Element and satisfies x=X/Z, y=Y/Z, and xy=T/Z.
// The zero value is not a valid point; use NewIdentityPoint, SetBytes, or a
// group operation to initialize one.
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

// NewGeneratorPoint returns the RFC 8032 Edwards25519 generator.
func NewGeneratorPoint() *Point {
	encoded := [32]byte{
		0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
		0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
		0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
		0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
	}
	p, err := new(Point).SetBytes(encoded[:])
	if err != nil {
		panic("r43x6: internal generator encoding is invalid")
	}
	return p
}

// Set sets p = q and returns p.
func (p *Point) Set(q *Point) *Point {
	*p = *q
	return p
}

// SetBytes decodes an Edwards25519 point with the permissive Go/dalek field
// semantics: the low 255 bits are reduced modulo p and an x=0 point is
// accepted with either sign bit. The receiver is unchanged on failure.
//
// A future paired decoder must retain two independent Pow22523 chains for A
// and R. They may be instruction-interleaved or vectorized, but their field
// inputs and roots cannot be arithmetically combined.
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
	if _, wasSquare := x.SqrtRatio(&u, &v); wasSquare == 0 {
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

// Bytes returns the unique canonical RFC 8032 compressed encoding of p.
func (p *Point) Bytes() [32]byte {
	var zInv, x, y Element
	zInv.Invert(&p.Z)
	x.Multiply(&p.X, &zInv)
	y.Multiply(&p.Y, &zInv)
	out := y.Bytes()
	out[31] |= byte(x.IsNegative() << 7)
	return out
}

// Add sets p = a+b and returns p. Inputs and output may alias.
func (p *Point) Add(a, b *Point) *Point {
	aa, bb := *a, *b
	var yMinusX1, yPlusX1, yMinusX2, yPlusX2 Element
	yMinusX1.Subtract(&aa.Y, &aa.X)
	yPlusX1.Add(&aa.Y, &aa.X)
	yMinusX2.Subtract(&bb.Y, &bb.X)
	yPlusX2.Add(&bb.Y, &bb.X)

	var A, B, C, D, E, F, G, H Element
	A.Multiply(&yMinusX1, &yMinusX2)
	B.Multiply(&yPlusX1, &yPlusX2)
	C.Multiply(&aa.T, &bb.T)
	C.Multiply(&C, &curve2D)
	D.Multiply(&aa.Z, &bb.Z)
	D.Add(&D, &D)
	E.Subtract(&B, &A)
	F.Subtract(&D, &C)
	G.Add(&D, &C)
	H.Add(&B, &A)

	var result Point
	result.X.Multiply(&E, &F)
	result.Y.Multiply(&G, &H)
	result.T.Multiply(&E, &H)
	result.Z.Multiply(&F, &G)
	*p = result
	return p
}

// Subtract sets p = a-b and returns p. Inputs and output may alias.
func (p *Point) Subtract(a, b *Point) *Point {
	var negB Point
	negB.Negate(b)
	return p.Add(a, &negB)
}

// Negate sets p = -q and returns p. Input and output may alias.
func (p *Point) Negate(q *Point) *Point {
	qq := *q
	p.X.Negate(&qq.X)
	p.Y.Set(&qq.Y)
	p.Z.Set(&qq.Z)
	p.T.Negate(&qq.T)
	return p
}

// Double sets p = 2q and returns p. Input and output may alias.
func (p *Point) Double(q *Point) *Point {
	qq := *q
	var A, B, C, D, E, F, G, H, xPlusY Element
	A.Square(&qq.X)
	B.Square(&qq.Y)
	C.Square(&qq.Z)
	C.Add(&C, &C)
	D.Negate(&A)
	xPlusY.Add(&qq.X, &qq.Y)
	E.Square(&xPlusY)
	E.Subtract(&E, &A)
	E.Subtract(&E, &B)
	G.Add(&D, &B)
	F.Subtract(&G, &C)
	H.Subtract(&D, &B)

	var result Point
	result.X.Multiply(&E, &F)
	result.Y.Multiply(&G, &H)
	result.T.Multiply(&E, &H)
	result.Z.Multiply(&F, &G)
	*p = result
	return p
}

// MultByCofactor sets p = 8q and returns p.
func (p *Point) MultByCofactor(q *Point) *Point {
	p.Double(q)
	p.Double(p)
	p.Double(p)
	return p
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

// EqualAffine compares p with q using two cross-products. q must have Z=1,
// as points returned by SetBytes do.
func (p *Point) EqualAffine(q *Point) int {
	var qxpz, qypz Element
	qxpz.Multiply(&q.X, &p.Z)
	qypz.Multiply(&q.Y, &p.Z)
	return p.X.Equal(&qxpz) & p.Y.Equal(&qypz)
}

// IsIdentity returns 1 when p is the neutral point.
func (p *Point) IsIdentity() int {
	return p.Equal(NewIdentityPoint())
}
