package r51x5

// AffinePointX4 stores four compact affine points. It intentionally omits Z
// and T: strict verification only needs xR and yR for the final projective
// cross-products.
type AffinePointX4 struct {
	X ElementX4
	Y ElementX4
}

// AffinePointX8 is the eight-lane counterpart of AffinePointX4.
type AffinePointX8 struct {
	X ElementX8
	Y ElementX8
}

// Decode2NoTX4 permissively decodes four independent (A,R) pairs in lockstep.
// active selects input lanes. Inactive or invalid A lanes are returned as the
// identity; inactive or invalid R lanes are zeroed. aValid and rValid report
// the two decoder outcomes independently and are always subsets of active.
//
// This is a representation and scheduling reference. Its ElementX4 methods
// are currently scalar lane oracles; a future IFMA decoder can preserve this
// exact API and predicate while replacing the field operations.
func Decode2NoTX4(a *PointX4, r *AffinePointX4, aBytes, rBytes *[X4Lanes][32]byte, active uint8) (aValid, rValid uint8) {
	active &= 0x0f
	ay := decodeY4(aBytes, active)
	ry := decodeY4(rBytes, active)

	one := broadcastX4(new(Element).One())
	d := broadcastX4(&curveD)
	var ay2, ry2, au, ru, av, rv ElementX4
	ay2.Square(&ay)
	ry2.Square(&ry)
	au.Subtract(&ay2, &one)
	ru.Subtract(&ry2, &one)
	av.Multiply(&ay2, &d)
	rv.Multiply(&ry2, &d)
	av.Add(&av, &one)
	rv.Add(&rv, &one)

	var ax, rx ElementX4
	aValid, rValid = sqrtRatioPairX4(&ax, &rx, &au, &ru, &av, &rv)
	aValid &= active
	rValid &= active
	applyEncodedSignsX4(&ax, &rx, aBytes, rBytes, active)

	aResult := PointX4{Y: one, Z: one}
	var rResult AffinePointX4
	zero := ElementX4{}
	decodeSelectX4(&aResult.X, &zero, &ax, aValid)
	decodeSelectX4(&aResult.Y, &one, &ay, aValid)
	var at ElementX4
	at.Multiply(&ax, &ay)
	decodeSelectX4(&aResult.T, &zero, &at, aValid)
	decodeSelectX4(&rResult.X, &zero, &rx, rValid)
	decodeSelectX4(&rResult.Y, &zero, &ry, rValid)
	*a, *r = aResult, rResult
	return aValid, rValid
}

// Decode2NoTX8 is the eight-lane counterpart of Decode2NoTX4.
func Decode2NoTX8(a *PointX8, r *AffinePointX8, aBytes, rBytes *[X8Lanes][32]byte, active uint8) (aValid, rValid uint8) {
	ay := decodeY8(aBytes, active)
	ry := decodeY8(rBytes, active)

	one := broadcastX8(new(Element).One())
	d := broadcastX8(&curveD)
	var ay2, ry2, au, ru, av, rv ElementX8
	ay2.Square(&ay)
	ry2.Square(&ry)
	au.Subtract(&ay2, &one)
	ru.Subtract(&ry2, &one)
	av.Multiply(&ay2, &d)
	rv.Multiply(&ry2, &d)
	av.Add(&av, &one)
	rv.Add(&rv, &one)

	var ax, rx ElementX8
	aValid, rValid = sqrtRatioPairX8(&ax, &rx, &au, &ru, &av, &rv)
	aValid &= active
	rValid &= active
	applyEncodedSignsX8(&ax, &rx, aBytes, rBytes, active)

	aResult := PointX8{Y: one, Z: one}
	var rResult AffinePointX8
	zero := ElementX8{}
	decodeSelectX8(&aResult.X, &zero, &ax, aValid)
	decodeSelectX8(&aResult.Y, &one, &ay, aValid)
	var at ElementX8
	at.Multiply(&ax, &ay)
	decodeSelectX8(&aResult.T, &zero, &at, aValid)
	decodeSelectX8(&rResult.X, &zero, &rx, rValid)
	decodeSelectX8(&rResult.Y, &zero, &ry, rValid)
	*a, *r = aResult, rResult
	return aValid, rValid
}

func decodeY4(in *[X4Lanes][32]byte, active uint8) ElementX4 {
	var values [X4Lanes]Element
	for lane := range values {
		if active&(1<<lane) != 0 {
			_, _ = values[lane].SetBytes(in[lane][:])
		} else {
			values[lane].One()
		}
	}
	var out ElementX4
	out.SetElements(&values)
	return out
}

func decodeY8(in *[X8Lanes][32]byte, active uint8) ElementX8 {
	var values [X8Lanes]Element
	for lane := range values {
		if active&(1<<lane) != 0 {
			_, _ = values[lane].SetBytes(in[lane][:])
		} else {
			values[lane].One()
		}
	}
	var out ElementX8
	out.SetElements(&values)
	return out
}

func sqrtRatioPairX4(az, rz, au, ru, av, rv *ElementX4) (aSquare, rSquare uint8) {
	var auv, ruv, apow, rpow, ar, rr ElementX4
	auv.Multiply(au, av)
	ruv.Multiply(ru, rv)
	pow22523PairX4(&apow, &rpow, &auv, &ruv)
	ar.Multiply(au, &apow)
	rr.Multiply(ru, &rpow)

	var ar2, rr2, acheck, rcheck, anegU, rnegU ElementX4
	ar2.Square(&ar)
	rr2.Square(&rr)
	acheck.Multiply(av, &ar2)
	rcheck.Multiply(rv, &rr2)
	anegU.Negate(au)
	rnegU.Negate(ru)
	rootI := broadcastX4(&sqrtM1)
	var anegUI, rnegUI ElementX4
	anegUI.Multiply(&anegU, &rootI)
	rnegUI.Multiply(&rnegU, &rootI)

	acorrect := equalMaskX4(&acheck, au)
	rcorrect := equalMaskX4(&rcheck, ru)
	aflipped := equalMaskX4(&acheck, &anegU)
	rflipped := equalMaskX4(&rcheck, &rnegU)
	aflippedI := equalMaskX4(&acheck, &anegUI)
	rflippedI := equalMaskX4(&rcheck, &rnegUI)
	var arI, rrI ElementX4
	arI.Multiply(&ar, &rootI)
	rrI.Multiply(&rr, &rootI)
	decodeSelectX4(&ar, &ar, &arI, aflipped|aflippedI)
	decodeSelectX4(&rr, &rr, &rrI, rflipped|rflippedI)
	conditionalNegateX4(&ar, negativeMaskX4(&ar))
	conditionalNegateX4(&rr, negativeMaskX4(&rr))
	az.limbs = ar.limbs
	rz.limbs = rr.limbs
	return acorrect | aflipped, rcorrect | rflipped
}

func sqrtRatioPairX8(az, rz, au, ru, av, rv *ElementX8) (aSquare, rSquare uint8) {
	var auv, ruv, apow, rpow, ar, rr ElementX8
	auv.Multiply(au, av)
	ruv.Multiply(ru, rv)
	pow22523PairX8(&apow, &rpow, &auv, &ruv)
	ar.Multiply(au, &apow)
	rr.Multiply(ru, &rpow)

	var ar2, rr2, acheck, rcheck, anegU, rnegU ElementX8
	ar2.Square(&ar)
	rr2.Square(&rr)
	acheck.Multiply(av, &ar2)
	rcheck.Multiply(rv, &rr2)
	anegU.Negate(au)
	rnegU.Negate(ru)
	rootI := broadcastX8(&sqrtM1)
	var anegUI, rnegUI ElementX8
	anegUI.Multiply(&anegU, &rootI)
	rnegUI.Multiply(&rnegU, &rootI)

	acorrect := equalMaskX8(&acheck, au)
	rcorrect := equalMaskX8(&rcheck, ru)
	aflipped := equalMaskX8(&acheck, &anegU)
	rflipped := equalMaskX8(&rcheck, &rnegU)
	aflippedI := equalMaskX8(&acheck, &anegUI)
	rflippedI := equalMaskX8(&rcheck, &rnegUI)
	var arI, rrI ElementX8
	arI.Multiply(&ar, &rootI)
	rrI.Multiply(&rr, &rootI)
	decodeSelectX8(&ar, &ar, &arI, aflipped|aflippedI)
	decodeSelectX8(&rr, &rr, &rrI, rflipped|rflippedI)
	conditionalNegateX8(&ar, negativeMaskX8(&ar))
	conditionalNegateX8(&rr, negativeMaskX8(&rr))
	az.limbs = ar.limbs
	rz.limbs = rr.limbs
	return acorrect | aflipped, rcorrect | rflipped
}

func pow22523PairX4(az, rz, ax, rx *ElementX4) {
	abase, rbase := *ax, *rx
	var ax2, rx2, ax9, rx9, ax11, rx11 ElementX4
	ax2.Square(&abase)
	rx2.Square(&rbase)
	repeatedSquareMultiplyPairX4(&ax9, &rx9, &ax2, &rx2, &abase, &rbase, 2)
	ax11.Multiply(&ax9, &ax2)
	rx11.Multiply(&rx9, &rx2)

	var ax5, rx5, ax10, rx10, ax20, rx20, ax40, rx40 ElementX4
	repeatedSquareMultiplyPairX4(&ax5, &rx5, &ax11, &rx11, &ax9, &rx9, 1)
	repeatedSquareMultiplyPairX4(&ax10, &rx10, &ax5, &rx5, &ax5, &rx5, 5)
	repeatedSquareMultiplyPairX4(&ax20, &rx20, &ax10, &rx10, &ax10, &rx10, 10)
	repeatedSquareMultiplyPairX4(&ax40, &rx40, &ax20, &rx20, &ax20, &rx20, 20)
	var ax50, rx50, ax100, rx100, ax200, rx200, ax250, rx250 ElementX4
	repeatedSquareMultiplyPairX4(&ax50, &rx50, &ax40, &rx40, &ax10, &rx10, 10)
	repeatedSquareMultiplyPairX4(&ax100, &rx100, &ax50, &rx50, &ax50, &rx50, 50)
	repeatedSquareMultiplyPairX4(&ax200, &rx200, &ax100, &rx100, &ax100, &rx100, 100)
	repeatedSquareMultiplyPairX4(&ax250, &rx250, &ax200, &rx200, &ax50, &rx50, 50)
	repeatedSquareMultiplyPairX4(az, rz, &ax250, &rx250, &abase, &rbase, 2)
}

func pow22523PairX8(az, rz, ax, rx *ElementX8) {
	abase, rbase := *ax, *rx
	var ax2, rx2, ax9, rx9, ax11, rx11 ElementX8
	ax2.Square(&abase)
	rx2.Square(&rbase)
	repeatedSquareMultiplyPairX8(&ax9, &rx9, &ax2, &rx2, &abase, &rbase, 2)
	ax11.Multiply(&ax9, &ax2)
	rx11.Multiply(&rx9, &rx2)

	var ax5, rx5, ax10, rx10, ax20, rx20, ax40, rx40 ElementX8
	repeatedSquareMultiplyPairX8(&ax5, &rx5, &ax11, &rx11, &ax9, &rx9, 1)
	repeatedSquareMultiplyPairX8(&ax10, &rx10, &ax5, &rx5, &ax5, &rx5, 5)
	repeatedSquareMultiplyPairX8(&ax20, &rx20, &ax10, &rx10, &ax10, &rx10, 10)
	repeatedSquareMultiplyPairX8(&ax40, &rx40, &ax20, &rx20, &ax20, &rx20, 20)
	var ax50, rx50, ax100, rx100, ax200, rx200, ax250, rx250 ElementX8
	repeatedSquareMultiplyPairX8(&ax50, &rx50, &ax40, &rx40, &ax10, &rx10, 10)
	repeatedSquareMultiplyPairX8(&ax100, &rx100, &ax50, &rx50, &ax50, &rx50, 50)
	repeatedSquareMultiplyPairX8(&ax200, &rx200, &ax100, &rx100, &ax100, &rx100, 100)
	repeatedSquareMultiplyPairX8(&ax250, &rx250, &ax200, &rx200, &ax50, &rx50, 50)
	repeatedSquareMultiplyPairX8(az, rz, &ax250, &rx250, &abase, &rbase, 2)
}

func repeatedSquareMultiplyPairX4(az, rz, ax, rx, ay, ry *ElementX4, count int) {
	az.limbs, rz.limbs = ax.limbs, rx.limbs
	for i := 0; i < count; i++ {
		az.Square(az)
		rz.Square(rz)
	}
	az.Multiply(az, ay)
	rz.Multiply(rz, ry)
}

func repeatedSquareMultiplyPairX8(az, rz, ax, rx, ay, ry *ElementX8, count int) {
	az.limbs, rz.limbs = ax.limbs, rx.limbs
	for i := 0; i < count; i++ {
		az.Square(az)
		rz.Square(rz)
	}
	az.Multiply(az, ay)
	rz.Multiply(rz, ry)
}

func applyEncodedSignsX4(ax, rx *ElementX4, aBytes, rBytes *[X4Lanes][32]byte, active uint8) {
	var aSigns, rSigns uint8
	for lane := 0; lane < X4Lanes; lane++ {
		if active&(1<<lane) != 0 {
			aSigns |= (aBytes[lane][31] >> 7) << lane
			rSigns |= (rBytes[lane][31] >> 7) << lane
		}
	}
	conditionalNegateX4(ax, (negativeMaskX4(ax)^aSigns)&active)
	conditionalNegateX4(rx, (negativeMaskX4(rx)^rSigns)&active)
}

func applyEncodedSignsX8(ax, rx *ElementX8, aBytes, rBytes *[X8Lanes][32]byte, active uint8) {
	var aSigns, rSigns uint8
	for lane := 0; lane < X8Lanes; lane++ {
		if active&(1<<lane) != 0 {
			aSigns |= (aBytes[lane][31] >> 7) << lane
			rSigns |= (rBytes[lane][31] >> 7) << lane
		}
	}
	conditionalNegateX8(ax, (negativeMaskX8(ax)^aSigns)&active)
	conditionalNegateX8(rx, (negativeMaskX8(rx)^rSigns)&active)
}

func equalMaskX4(x, y *ElementX4) uint8 {
	var mask uint8
	for lane := 0; lane < X4Lanes; lane++ {
		var diff uint64
		for limb := 0; limb < 5; limb++ {
			diff |= x.limbs[limb][lane] ^ y.limbs[limb][lane]
		}
		mask |= uint8(zeroBit(diff)) << lane
	}
	return mask
}

func equalMaskX8(x, y *ElementX8) uint8 {
	var mask uint8
	for lane := 0; lane < X8Lanes; lane++ {
		var diff uint64
		for limb := 0; limb < 5; limb++ {
			diff |= x.limbs[limb][lane] ^ y.limbs[limb][lane]
		}
		mask |= uint8(zeroBit(diff)) << lane
	}
	return mask
}

func negativeMaskX4(x *ElementX4) uint8 {
	var mask uint8
	for lane := 0; lane < X4Lanes; lane++ {
		mask |= uint8(x.limbs[0][lane]&1) << lane
	}
	return mask
}

func negativeMaskX8(x *ElementX8) uint8 {
	var mask uint8
	for lane := 0; lane < X8Lanes; lane++ {
		mask |= uint8(x.limbs[0][lane]&1) << lane
	}
	return mask
}

func conditionalNegateX4(x *ElementX4, mask uint8) {
	var neg ElementX4
	neg.Negate(x)
	decodeSelectX4(x, x, &neg, mask)
}

func conditionalNegateX8(x *ElementX8, mask uint8) {
	var neg ElementX8
	neg.Negate(x)
	decodeSelectX8(x, x, &neg, mask)
}

func decodeSelectX4(out, x, y *ElementX4, mask uint8) {
	for lane := 0; lane < X4Lanes; lane++ {
		selectMask := uint64(0) - uint64((mask>>lane)&1)
		for limb := 0; limb < 5; limb++ {
			out.limbs[limb][lane] = x.limbs[limb][lane] ^ (selectMask & (x.limbs[limb][lane] ^ y.limbs[limb][lane]))
		}
	}
}

func decodeSelectX8(out, x, y *ElementX8, mask uint8) {
	for lane := 0; lane < X8Lanes; lane++ {
		selectMask := uint64(0) - uint64((mask>>lane)&1)
		for limb := 0; limb < 5; limb++ {
			out.limbs[limb][lane] = x.limbs[limb][lane] ^ (selectMask & (x.limbs[limb][lane] ^ y.limbs[limb][lane]))
		}
	}
}
