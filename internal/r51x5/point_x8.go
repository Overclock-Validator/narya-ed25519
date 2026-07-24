package r51x5

// PointX8 stores eight independent extended-coordinate Edwards25519 points in
// [coordinate][limb][lane] form. Operations are lane-independent scalar
// references and make no SIMD performance claim. Its zero value is not a
// valid set of points.
type PointX8 struct {
	X ElementX8
	Y ElementX8
	Z ElementX8
	T ElementX8
}

// NewIdentityPointX8 returns eight neutral points.
func NewIdentityPointX8() *PointX8 {
	var one Element
	one.One()
	ones := broadcastX8(&one)
	return &PointX8{Y: ones, Z: ones}
}

// Set sets p=q and returns p.
func (p *PointX8) Set(q *PointX8) *PointX8 {
	*p = *q
	return p
}

// SetPoints packs eight scalar points into p and returns p.
func (p *PointX8) SetPoints(points *[X8Lanes]Point) *PointX8 {
	for lane := range points {
		p.SetLane(lane, &points[lane])
	}
	return p
}

// Points returns all eight lanes as scalar extended-coordinate points.
func (p *PointX8) Points() [X8Lanes]Point {
	var points [X8Lanes]Point
	for lane := range points {
		points[lane] = p.Lane(lane)
	}
	return points
}

// Lane returns a copy of one scalar point.
func (p *PointX8) Lane(lane int) Point {
	checkLane(lane, X8Lanes)
	return Point{
		X: p.X.Lane(lane),
		Y: p.Y.Lane(lane),
		Z: p.Z.Lane(lane),
		T: p.T.Lane(lane),
	}
}

// SetLane copies q into lane and returns p.
func (p *PointX8) SetLane(lane int, q *Point) *PointX8 {
	checkLane(lane, X8Lanes)
	p.X.SetLane(lane, &q.X)
	p.Y.SetLane(lane, &q.Y)
	p.Z.SetLane(lane, &q.Z)
	p.T.SetLane(lane, &q.T)
	return p
}

// SetBytes permissively decodes eight compressed points. Its result mask has
// bit i set exactly when lane i decoded successfully. Invalid lanes are set to
// the identity so no invalid coordinates enter later group operations.
func (p *PointX8) SetBytes(in *[X8Lanes][32]byte) uint8 {
	result := NewIdentityPointX8()
	var valid uint8
	for lane := range in {
		var decoded Point
		if _, err := decoded.SetBytes(in[lane][:]); err == nil {
			result.SetLane(lane, &decoded)
			valid |= 1 << lane
		}
	}
	*p = *result
	return valid
}

// Bytes returns the canonical compressed encoding of each lane.
func (p *PointX8) Bytes() [X8Lanes][32]byte {
	var out [X8Lanes][32]byte
	for lane := range out {
		point := p.Lane(lane)
		out[lane] = point.Bytes()
	}
	return out
}

// Add sets p=a+b lane-wise and returns p. Inputs and output may alias.
func (p *PointX8) Add(a, b *PointX8) *PointX8 {
	aa, bb := *a, *b
	var yMinusX1, yPlusX1, yMinusX2, yPlusX2 ElementX8
	yMinusX1.Subtract(&aa.Y, &aa.X)
	yPlusX1.Add(&aa.Y, &aa.X)
	yMinusX2.Subtract(&bb.Y, &bb.X)
	yPlusX2.Add(&bb.Y, &bb.X)

	var A, B, C, D, E, F, G, H ElementX8
	A.Multiply(&yMinusX1, &yMinusX2)
	B.Multiply(&yPlusX1, &yPlusX2)
	C.Multiply(&aa.T, &bb.T)
	twoD := broadcastX8(&curve2D)
	C.Multiply(&C, &twoD)
	D.Multiply(&aa.Z, &bb.Z)
	D.Add(&D, &D)
	E.Subtract(&B, &A)
	F.Subtract(&D, &C)
	G.Add(&D, &C)
	H.Add(&B, &A)

	var result PointX8
	result.X.Multiply(&E, &F)
	result.Y.Multiply(&G, &H)
	result.T.Multiply(&E, &H)
	result.Z.Multiply(&F, &G)
	*p = result
	return p
}

// Subtract sets p=a-b lane-wise and returns p.
func (p *PointX8) Subtract(a, b *PointX8) *PointX8 {
	var negB PointX8
	negB.Negate(b)
	return p.Add(a, &negB)
}

// Negate sets p=-q lane-wise and returns p.
func (p *PointX8) Negate(q *PointX8) *PointX8 {
	qq := *q
	p.X.Negate(&qq.X)
	p.Y = qq.Y
	p.Z = qq.Z
	p.T.Negate(&qq.T)
	return p
}

// Double sets p=2q lane-wise and returns p.
func (p *PointX8) Double(q *PointX8) *PointX8 {
	qq := *q
	var A, B, C, D, E, F, G, H, xPlusY ElementX8
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

	var result PointX8
	result.X.Multiply(&E, &F)
	result.Y.Multiply(&G, &H)
	result.T.Multiply(&E, &H)
	result.Z.Multiply(&F, &G)
	*p = result
	return p
}

// Equal returns a mask whose bit i is set exactly when lane i represents the
// same projective point in p and q.
func (p *PointX8) Equal(q *PointX8) uint8 {
	var pxqz, qxpz, pyqz, qypz ElementX8
	pxqz.Multiply(&p.X, &q.Z)
	qxpz.Multiply(&q.X, &p.Z)
	pyqz.Multiply(&p.Y, &q.Z)
	qypz.Multiply(&q.Y, &p.Z)
	var mask uint8
	for lane := 0; lane < X8Lanes; lane++ {
		x1, x2 := pxqz.Lane(lane), qxpz.Lane(lane)
		y1, y2 := pyqz.Lane(lane), qypz.Lane(lane)
		if x1.Equal(&x2)&y1.Equal(&y2) != 0 {
			mask |= 1 << lane
		}
	}
	return mask
}

// EqualAffine compares p with affine q (all q.Z lanes must equal one) using
// both projective cross-products and returns an equality mask.
func (p *PointX8) EqualAffine(q *PointX8) uint8 {
	var qxpz, qypz ElementX8
	qxpz.Multiply(&q.X, &p.Z)
	qypz.Multiply(&q.Y, &p.Z)
	var mask uint8
	for lane := 0; lane < X8Lanes; lane++ {
		px, py := p.X.Lane(lane), p.Y.Lane(lane)
		qx, qy := qxpz.Lane(lane), qypz.Lane(lane)
		if px.Equal(&qx)&py.Equal(&qy) != 0 {
			mask |= 1 << lane
		}
	}
	return mask
}

// EqualCompactAffine compares p with the compact affine representation
// returned by Decode2NoTX8. Both projective cross-products are required: an
// x-only or y-only comparison does not uniquely identify an Edwards point.
func (p *PointX8) EqualCompactAffine(q *AffinePointX8) uint8 {
	var qxpz, qypz ElementX8
	qxpz.Multiply(&q.X, &p.Z)
	qypz.Multiply(&q.Y, &p.Z)
	return equalMaskX8(&p.X, &qxpz) & equalMaskX8(&p.Y, &qypz)
}

// IsIdentity returns a mask whose bit i is set exactly when lane i is the
// neutral point.
func (p *PointX8) IsIdentity() uint8 {
	var mask uint8
	for lane := 0; lane < X8Lanes; lane++ {
		x, y, z := p.X.Lane(lane), p.Y.Lane(lane), p.Z.Lane(lane)
		if x.IsZero()&y.Equal(&z) != 0 {
			mask |= 1 << lane
		}
	}
	return mask
}
