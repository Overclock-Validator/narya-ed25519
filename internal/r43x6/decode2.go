package r43x6

// AffinePoint is the compact output used for a decoded verification R. Its
// coordinates are reduced affine x and y values; unlike Point it deliberately
// has no Z or T coordinate.
//
// Keeping R in this form avoids both the x*y multiplication needed to build T
// and the inversion needed to encode a computed projective point at the end
// of strict verification.
type AffinePoint struct {
	X Element
	Y Element
}

// Bytes returns the unique canonical RFC 8032 compressed encoding of p.
func (p *AffinePoint) Bytes() [32]byte {
	out := p.Y.Bytes()
	out[31] |= byte(p.X.IsNegative() << 7)
	return out
}

// EqualAffineNoT compares p with an affine point using both projective cross
// products. The affine input is assumed to have implicit Z=1.
func (p *Point) EqualAffineNoT(q *AffinePoint) int {
	var qxpz, qypz Element
	qxpz.Multiply(&q.X, &p.Z)
	qypz.Multiply(&q.Y, &p.Z)
	return p.X.Equal(&qxpz) & p.Y.Equal(&qypz)
}

// Decode2NoT permissively decodes A and R together. A is returned as a full
// extended point, while R is returned as compact affine (x,y) coordinates.
// The two error results are independent and exactly match the success/failure
// result of calling Point.SetBytes on aBytes and rBytes separately, including
// acceptance of noncanonical y encodings and the x=0, sign-bit-one encoding.
//
// On the common 32-byte path, the two simplified square-root-ratio
// exponentiations remain mathematically independent but are interleaved at
// every stage. In particular, this function does not use a product-root
// shortcut: such a shortcut cannot recover both roots with the required
// deterministic signs for all quartic classes.
func Decode2NoT(aBytes, rBytes []byte) (a Point, r AffinePoint, aErr, rErr error) {
	if len(aBytes) != 32 || len(rBytes) != 32 {
		return decode2NoTUncommonLengths(aBytes, rBytes)
	}

	var ay, ry Element
	_, _ = ay.SetBytes(aBytes)
	_, _ = ry.SetBytes(rBytes)

	var ay2, ry2 Element
	square2(&ay2, &ry2, &ay, &ry)

	var one Element
	one.One()
	var au, ru Element
	au.Subtract(&ay2, &one)
	ru.Subtract(&ry2, &one)
	var av, rv Element
	av.Multiply(&ay2, &curveD)
	rv.Multiply(&ry2, &curveD)
	av.Add(&av, &one)
	rv.Add(&rv, &one)

	var ax, rx Element
	aSquare, rSquare := sqrtRatio2(&ax, &rx, &au, &ru, &av, &rv)
	if ax.IsNegative() != int(aBytes[31]>>7) {
		ax.Negate(&ax)
	}
	if rx.IsNegative() != int(rBytes[31]>>7) {
		rx.Negate(&rx)
	}

	if aSquare != 0 {
		a.X.Set(&ax)
		a.Y.Set(&ay)
		a.Z.One()
		a.T.Multiply(&ax, &ay)
	} else {
		aErr = errInvalidPoint
	}
	if rSquare != 0 {
		r.X.Set(&rx)
		r.Y.Set(&ry)
	} else {
		rErr = errInvalidPoint
	}
	return a, r, aErr, rErr
}

// decode2NoTUncommonLengths preserves independent decoder outcomes without
// complicating the paired hot path. This path is only used for API misuse;
// verification always supplies two fixed-width encodings.
func decode2NoTUncommonLengths(aBytes, rBytes []byte) (a Point, r AffinePoint, aErr, rErr error) {
	if len(aBytes) != 32 {
		aErr = errInvalidPointLength
	} else {
		var decoded Point
		if _, aErr = decoded.SetBytes(aBytes); aErr == nil {
			a = decoded
		}
	}

	if len(rBytes) != 32 {
		rErr = errInvalidPointLength
	} else {
		var decoded Point
		if _, rErr = decoded.SetBytes(rBytes); rErr == nil {
			r.X.Set(&decoded.X)
			r.Y.Set(&decoded.Y)
		}
	}
	return a, r, aErr, rErr
}

// sqrtRatio2 applies the same simplified formula as Element.SqrtRatio to two
// independent ratios:
//
//	r = u * (u*v)^((p-5)/8)
//
// Each operation on the A chain is immediately followed by the corresponding
// operation on the R chain, exposing instruction-level parallelism without
// changing either chain's inputs or output selection.
func sqrtRatio2(az, rz, au, ru, av, rv *Element) (aWasSquare, rWasSquare int) {
	var auv, ruv Element
	auv.Multiply(au, av)
	ruv.Multiply(ru, rv)

	var apow, rpow Element
	pow22523Pair(&apow, &rpow, &auv, &ruv)
	var ar, rr Element
	ar.Multiply(au, &apow)
	rr.Multiply(ru, &rpow)

	var ar2, rr2 Element
	square2(&ar2, &rr2, &ar, &rr)
	var acheck, rcheck Element
	acheck.Multiply(av, &ar2)
	rcheck.Multiply(rv, &rr2)

	var anegU, rnegU Element
	anegU.Negate(au)
	rnegU.Negate(ru)
	var anegUSqrtM1, rnegUSqrtM1 Element
	anegUSqrtM1.Multiply(&anegU, &sqrtM1)
	rnegUSqrtM1.Multiply(&rnegU, &sqrtM1)

	acorrect := acheck.Equal(au)
	rcorrect := rcheck.Equal(ru)
	aflipped := acheck.Equal(&anegU)
	rflipped := rcheck.Equal(&rnegU)
	aflippedI := acheck.Equal(&anegUSqrtM1)
	rflippedI := rcheck.Equal(&rnegUSqrtM1)
	if aflipped|aflippedI != 0 {
		ar.Multiply(&ar, &sqrtM1)
	}
	if rflipped|rflippedI != 0 {
		rr.Multiply(&rr, &sqrtM1)
	}
	if ar.IsNegative() != 0 {
		ar.Negate(&ar)
	}
	if rr.IsNegative() != 0 {
		rr.Negate(&rr)
	}
	az.Set(&ar)
	rz.Set(&rr)
	return acorrect | aflipped, rcorrect | rflipped
}

func pow22523Pair(az, rz, ax, rx *Element) {
	abase, rbase := *ax, *rx
	var ax2, rx2 Element
	square2(&ax2, &rx2, &abase, &rbase)

	var ax9, rx9 Element
	repeatedSquareMultiply2(&ax9, &rx9, &ax2, &rx2, &abase, &rbase, 2)
	var ax11, rx11 Element
	ax11.Multiply(&ax9, &ax2)
	rx11.Multiply(&rx9, &rx2)

	var ax5, rx5, ax10, rx10, ax20, rx20, ax40, rx40 Element
	repeatedSquareMultiply2(&ax5, &rx5, &ax11, &rx11, &ax9, &rx9, 1)
	repeatedSquareMultiply2(&ax10, &rx10, &ax5, &rx5, &ax5, &rx5, 5)
	repeatedSquareMultiply2(&ax20, &rx20, &ax10, &rx10, &ax10, &rx10, 10)
	repeatedSquareMultiply2(&ax40, &rx40, &ax20, &rx20, &ax20, &rx20, 20)

	var ax50, rx50, ax100, rx100, ax200, rx200, ax250, rx250 Element
	repeatedSquareMultiply2(&ax50, &rx50, &ax40, &rx40, &ax10, &rx10, 10)
	repeatedSquareMultiply2(&ax100, &rx100, &ax50, &rx50, &ax50, &rx50, 50)
	repeatedSquareMultiply2(&ax200, &rx200, &ax100, &rx100, &ax100, &rx100, 100)
	repeatedSquareMultiply2(&ax250, &rx250, &ax200, &rx200, &ax50, &rx50, 50)
	repeatedSquareMultiply2(az, rz, &ax250, &rx250, &abase, &rbase, 2)
}

func square2(az, rz, ax, rx *Element) {
	az.Square(ax)
	rz.Square(rx)
}

func repeatedSquareMultiply2(az, rz, ax, rx, ay, ry *Element, count int) {
	az.Set(ax)
	rz.Set(rx)
	for i := 0; i < count; i++ {
		az.Square(az)
		rz.Square(rz)
	}
	az.Multiply(az, ay)
	rz.Multiply(rz, ry)
}
