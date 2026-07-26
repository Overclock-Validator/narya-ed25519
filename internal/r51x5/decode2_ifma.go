package r51x5

// decode2IFMAOpsX4 binds the paired decompression schedule either to the
// hardware IFMA multiplier or to the reduced lane model. uncheckedInputs is
// enabled only after the external-to-composable boundary has been scanned;
// raw products remain normalized under their proven u61 bound. failAt is used
// only by the checked/model test paths to prove atomic output commits.
type decode2IFMAOpsX4 struct {
	hardware        bool
	uncheckedInputs bool
	failAt          int
	calls           int
}

// decode2IFMAOpsX8 is the eight-lane analogue of decode2IFMAOpsX4.
type decode2IFMAOpsX8 struct {
	hardware        bool
	uncheckedInputs bool
	failAt          int
	calls           int
}

// ExperimentalIFMADecode2NoTX4 permissively decodes four independent (A,R)
// pairs with the composable r51 IFMA field schedule. It returns the same
// masks and reduced output buffers as Decode2NoTX4. The hardware schedule is
// experimental and is never selected by production dispatch.
//
// The receiver buffers are unchanged on error. In particular, calling this
// function without the complete AVX-512 IFMA feature set returns
// ErrIFMAUnavailable without touching a or r.
func ExperimentalIFMADecode2NoTX4(a *PointX4, r *AffinePointX4, aBytes, rBytes *[X4Lanes][32]byte, active uint8) (aValid, rValid uint8, err error) {
	if !ExperimentalIFMAAvailable() {
		return 0, 0, ErrIFMAUnavailable
	}
	ops := decode2IFMAOpsX4{hardware: true, uncheckedInputs: true}
	return decode2NoTIFMAX4(a, r, aBytes, rBytes, active, &ops, true)
}

// ExperimentalIFMADecode2NoTX8 is the eight-lane counterpart of
// ExperimentalIFMADecode2NoTX4.
func ExperimentalIFMADecode2NoTX8(a *PointX8, r *AffinePointX8, aBytes, rBytes *[X8Lanes][32]byte, active uint8) (aValid, rValid uint8, err error) {
	if !ExperimentalIFMAAvailable() {
		return 0, 0, ErrIFMAUnavailable
	}
	ops := decode2IFMAOpsX8{hardware: true, uncheckedInputs: true}
	return decode2NoTIFMAX8(a, r, aBytes, rBytes, active, &ops, true)
}

// decode2NoTIFMAModelX4 executes the exact paired schedule through the reduced
// lane oracle. Keeping this in the non-test implementation lets every target
// exercise the schedule without ever executing unsupported instructions.
func decode2NoTIFMAModelX4(a *PointX4, r *AffinePointX4, aBytes, rBytes *[X4Lanes][32]byte, active uint8) (aValid, rValid uint8, err error) {
	ops := decode2IFMAOpsX4{}
	return decode2NoTIFMAX4(a, r, aBytes, rBytes, active, &ops, true)
}

// decode2NoTIFMAModelX8 is the eight-lane schedule oracle.
func decode2NoTIFMAModelX8(a *PointX8, r *AffinePointX8, aBytes, rBytes *[X8Lanes][32]byte, active uint8) (aValid, rValid uint8, err error) {
	ops := decode2IFMAOpsX8{}
	return decode2NoTIFMAX8(a, r, aBytes, rBytes, active, &ops, true)
}

func decode2NoTIFMAX4(a *PointX4, r *AffinePointX4, aBytes, rBytes *[X4Lanes][32]byte, active uint8, ops *decode2IFMAOpsX4, interleaved bool) (aValid, rValid uint8, err error) {
	active &= 0x0f
	ayReduced := decodeY4(aBytes, active)
	ryReduced := decodeY4(rBytes, active)
	oneReduced := broadcastX4(new(Element).One())
	dReduced := broadcastX4(&curveD)

	var ay, ry, one, d IFMAElementX4
	ay.SetReduced(&ayReduced)
	ry.SetReduced(&ryReduced)
	one.SetReduced(&oneReduced)
	d.SetReduced(&dReduced)
	if err = ops.validatePairImports(&ay, &ry, &one, &d); err != nil {
		return 0, 0, err
	}

	var ay2, ry2, au, ru, av, rv IFMAElementX4
	if err = ops.mul(&ay2, &ay, &ay); err != nil {
		return 0, 0, err
	}
	if err = ops.mul(&ry2, &ry, &ry); err != nil {
		return 0, 0, err
	}
	au.Subtract(&ay2, &one)
	ru.Subtract(&ry2, &one)
	if err = ops.mul(&av, &ay2, &d); err != nil {
		return 0, 0, err
	}
	if err = ops.mul(&rv, &ry2, &d); err != nil {
		return 0, 0, err
	}
	av.Add(&av, &one)
	rv.Add(&rv, &one)

	var ax, rx ElementX4
	if aValid, rValid, err = sqrtRatioPairIFMAX4(&ax, &rx, &au, &ru, &av, &rv, ops, interleaved); err != nil {
		return 0, 0, err
	}
	aValid &= active
	rValid &= active
	applyEncodedSignsX4(&ax, &rx, aBytes, rBytes, active)

	// Root classification and sign selection above are the first canonical
	// boundary. Compute T through the same composable multiplier, then reduce
	// once more before committing the public reduced point representation.
	var axIFMA, ayIFMA, atIFMA IFMAElementX4
	axIFMA.SetReduced(&ax)
	ayIFMA.SetReduced(&ayReduced)
	if err = ops.mul(&atIFMA, &axIFMA, &ayIFMA); err != nil {
		return 0, 0, err
	}
	at := atIFMA.Reduced()

	aResult := PointX4{Y: oneReduced, Z: oneReduced}
	var rResult AffinePointX4
	zero := ElementX4{}
	decodeSelectX4(&aResult.X, &zero, &ax, aValid)
	decodeSelectX4(&aResult.Y, &oneReduced, &ayReduced, aValid)
	decodeSelectX4(&aResult.T, &zero, &at, aValid)
	decodeSelectX4(&rResult.X, &zero, &rx, rValid)
	decodeSelectX4(&rResult.Y, &zero, &ryReduced, rValid)
	*a, *r = aResult, rResult
	return aValid, rValid, nil
}

func decode2NoTIFMAX8(a *PointX8, r *AffinePointX8, aBytes, rBytes *[X8Lanes][32]byte, active uint8, ops *decode2IFMAOpsX8, interleaved bool) (aValid, rValid uint8, err error) {
	ayReduced := decodeY8(aBytes, active)
	ryReduced := decodeY8(rBytes, active)
	oneReduced := broadcastX8(new(Element).One())
	dReduced := broadcastX8(&curveD)

	var ay, ry, one, d IFMAElementX8
	ay.SetReduced(&ayReduced)
	ry.SetReduced(&ryReduced)
	one.SetReduced(&oneReduced)
	d.SetReduced(&dReduced)
	if err = ops.validatePairImports(&ay, &ry, &one, &d); err != nil {
		return 0, 0, err
	}

	var ay2, ry2, au, ru, av, rv IFMAElementX8
	if err = ops.mul(&ay2, &ay, &ay); err != nil {
		return 0, 0, err
	}
	if err = ops.mul(&ry2, &ry, &ry); err != nil {
		return 0, 0, err
	}
	au.Subtract(&ay2, &one)
	ru.Subtract(&ry2, &one)
	if err = ops.mul(&av, &ay2, &d); err != nil {
		return 0, 0, err
	}
	if err = ops.mul(&rv, &ry2, &d); err != nil {
		return 0, 0, err
	}
	av.Add(&av, &one)
	rv.Add(&rv, &one)

	var ax, rx ElementX8
	if aValid, rValid, err = sqrtRatioPairIFMAX8(&ax, &rx, &au, &ru, &av, &rv, ops, interleaved); err != nil {
		return 0, 0, err
	}
	aValid &= active
	rValid &= active
	applyEncodedSignsX8(&ax, &rx, aBytes, rBytes, active)

	var axIFMA, ayIFMA, atIFMA IFMAElementX8
	axIFMA.SetReduced(&ax)
	ayIFMA.SetReduced(&ayReduced)
	if err = ops.mul(&atIFMA, &axIFMA, &ayIFMA); err != nil {
		return 0, 0, err
	}
	at := atIFMA.Reduced()

	aResult := PointX8{Y: oneReduced, Z: oneReduced}
	var rResult AffinePointX8
	zero := ElementX8{}
	decodeSelectX8(&aResult.X, &zero, &ax, aValid)
	decodeSelectX8(&aResult.Y, &oneReduced, &ayReduced, aValid)
	decodeSelectX8(&aResult.T, &zero, &at, aValid)
	decodeSelectX8(&rResult.X, &zero, &rx, rValid)
	decodeSelectX8(&rResult.Y, &zero, &ryReduced, rValid)
	*a, *r = aResult, rResult
	return aValid, rValid, nil
}

// decode2NoTIFMAIndependentX4 is the hardware/model benchmark control. Unlike
// decode2NoTIFMAX4, it completes the entire A decoder before starting R. It
// deliberately remains internal: only the interleaved schedule is a candidate
// API, while this path exists to make the Ryzen scheduling comparison honest.
func decode2NoTIFMAIndependentX4(a *PointX4, r *AffinePointX4, aBytes, rBytes *[X4Lanes][32]byte, active uint8, ops *decode2IFMAOpsX4) (aValid, rValid uint8, err error) {
	active &= 0x0f
	var ax, ay, rx, ry ElementX4
	if aValid, err = decodeOneIFMAX4(&ax, &ay, aBytes, active, ops); err != nil {
		return 0, 0, err
	}
	if rValid, err = decodeOneIFMAX4(&rx, &ry, rBytes, active, ops); err != nil {
		return 0, 0, err
	}

	var axIFMA, ayIFMA, atIFMA IFMAElementX4
	axIFMA.SetReduced(&ax)
	ayIFMA.SetReduced(&ay)
	if err = ops.mul(&atIFMA, &axIFMA, &ayIFMA); err != nil {
		return 0, 0, err
	}
	at := atIFMA.Reduced()
	one := broadcastX4(new(Element).One())
	zero := ElementX4{}
	aResult := PointX4{Y: one, Z: one}
	var rResult AffinePointX4
	decodeSelectX4(&aResult.X, &zero, &ax, aValid)
	decodeSelectX4(&aResult.Y, &one, &ay, aValid)
	decodeSelectX4(&aResult.T, &zero, &at, aValid)
	decodeSelectX4(&rResult.X, &zero, &rx, rValid)
	decodeSelectX4(&rResult.Y, &zero, &ry, rValid)
	*a, *r = aResult, rResult
	return aValid, rValid, nil
}

// decode2NoTIFMAIndependentX8 is the eight-lane benchmark control.
func decode2NoTIFMAIndependentX8(a *PointX8, r *AffinePointX8, aBytes, rBytes *[X8Lanes][32]byte, active uint8, ops *decode2IFMAOpsX8) (aValid, rValid uint8, err error) {
	var ax, ay, rx, ry ElementX8
	if aValid, err = decodeOneIFMAX8(&ax, &ay, aBytes, active, ops); err != nil {
		return 0, 0, err
	}
	if rValid, err = decodeOneIFMAX8(&rx, &ry, rBytes, active, ops); err != nil {
		return 0, 0, err
	}

	var axIFMA, ayIFMA, atIFMA IFMAElementX8
	axIFMA.SetReduced(&ax)
	ayIFMA.SetReduced(&ay)
	if err = ops.mul(&atIFMA, &axIFMA, &ayIFMA); err != nil {
		return 0, 0, err
	}
	at := atIFMA.Reduced()
	one := broadcastX8(new(Element).One())
	zero := ElementX8{}
	aResult := PointX8{Y: one, Z: one}
	var rResult AffinePointX8
	decodeSelectX8(&aResult.X, &zero, &ax, aValid)
	decodeSelectX8(&aResult.Y, &one, &ay, aValid)
	decodeSelectX8(&aResult.T, &zero, &at, aValid)
	decodeSelectX8(&rResult.X, &zero, &rx, rValid)
	decodeSelectX8(&rResult.Y, &zero, &ry, rValid)
	*a, *r = aResult, rResult
	return aValid, rValid, nil
}

func decodeOneIFMAX4(x, y *ElementX4, in *[X4Lanes][32]byte, active uint8, ops *decode2IFMAOpsX4) (valid uint8, err error) {
	active &= 0x0f
	yReduced := decodeY4(in, active)
	oneReduced := broadcastX4(new(Element).One())
	dReduced := broadcastX4(&curveD)
	var yy, one, d, y2, u, v IFMAElementX4
	yy.SetReduced(&yReduced)
	one.SetReduced(&oneReduced)
	d.SetReduced(&dReduced)
	if err = ops.validateOneImports(&yy, &one, &d); err != nil {
		return 0, err
	}
	if err = ops.mul(&y2, &yy, &yy); err != nil {
		return 0, err
	}
	u.Subtract(&y2, &one)
	if err = ops.mul(&v, &y2, &d); err != nil {
		return 0, err
	}
	v.Add(&v, &one)
	var root ElementX4
	if valid, err = sqrtRatioIFMAX4(&root, &u, &v, ops); err != nil {
		return 0, err
	}
	valid &= active
	conditionalNegateX4(&root, (negativeMaskX4(&root)^encodedSignMaskX4(in, active))&active)
	*x, *y = root, yReduced
	return valid, nil
}

func decodeOneIFMAX8(x, y *ElementX8, in *[X8Lanes][32]byte, active uint8, ops *decode2IFMAOpsX8) (valid uint8, err error) {
	yReduced := decodeY8(in, active)
	oneReduced := broadcastX8(new(Element).One())
	dReduced := broadcastX8(&curveD)
	var yy, one, d, y2, u, v IFMAElementX8
	yy.SetReduced(&yReduced)
	one.SetReduced(&oneReduced)
	d.SetReduced(&dReduced)
	if err = ops.validateOneImports(&yy, &one, &d); err != nil {
		return 0, err
	}
	if err = ops.mul(&y2, &yy, &yy); err != nil {
		return 0, err
	}
	u.Subtract(&y2, &one)
	if err = ops.mul(&v, &y2, &d); err != nil {
		return 0, err
	}
	v.Add(&v, &one)
	var root ElementX8
	if valid, err = sqrtRatioIFMAX8(&root, &u, &v, ops); err != nil {
		return 0, err
	}
	valid &= active
	conditionalNegateX8(&root, (negativeMaskX8(&root)^encodedSignMaskX8(in, active))&active)
	*x, *y = root, yReduced
	return valid, nil
}

func sqrtRatioIFMAX4(z *ElementX4, u, v *IFMAElementX4, ops *decode2IFMAOpsX4) (square uint8, err error) {
	var uv, pow, root IFMAElementX4
	if err = ops.mul(&uv, u, v); err != nil {
		return 0, err
	}
	if err = pow22523IFMAX4(&pow, &uv, ops); err != nil {
		return 0, err
	}
	if err = ops.mul(&root, u, &pow); err != nil {
		return 0, err
	}
	var root2, check, negU IFMAElementX4
	if err = ops.mul(&root2, &root, &root); err != nil {
		return 0, err
	}
	if err = ops.mul(&check, v, &root2); err != nil {
		return 0, err
	}
	negU.Negate(u)
	rootIReduced := broadcastX4(&sqrtM1)
	var rootI, negUI IFMAElementX4
	rootI.SetReduced(&rootIReduced)
	if err = ops.mul(&negUI, &negU, &rootI); err != nil {
		return 0, err
	}
	checkReduced, uReduced := check.Reduced(), u.Reduced()
	negUReduced, negUIReduced := negU.Reduced(), negUI.Reduced()
	correct := equalMaskX4(&checkReduced, &uReduced)
	flipped := equalMaskX4(&checkReduced, &negUReduced)
	flippedI := equalMaskX4(&checkReduced, &negUIReduced)
	var rootTimesI IFMAElementX4
	if err = ops.mul(&rootTimesI, &root, &rootI); err != nil {
		return 0, err
	}
	decodeSelectIFMAX4(&root, &root, &rootTimesI, flipped|flippedI)
	rootReduced := root.Reduced()
	conditionalNegateX4(&rootReduced, negativeMaskX4(&rootReduced))
	*z = rootReduced
	return correct | flipped, nil
}

func sqrtRatioIFMAX8(z *ElementX8, u, v *IFMAElementX8, ops *decode2IFMAOpsX8) (square uint8, err error) {
	var uv, pow, root IFMAElementX8
	if err = ops.mul(&uv, u, v); err != nil {
		return 0, err
	}
	if err = pow22523IFMAX8(&pow, &uv, ops); err != nil {
		return 0, err
	}
	if err = ops.mul(&root, u, &pow); err != nil {
		return 0, err
	}
	var root2, check, negU IFMAElementX8
	if err = ops.mul(&root2, &root, &root); err != nil {
		return 0, err
	}
	if err = ops.mul(&check, v, &root2); err != nil {
		return 0, err
	}
	negU.Negate(u)
	rootIReduced := broadcastX8(&sqrtM1)
	var rootI, negUI IFMAElementX8
	rootI.SetReduced(&rootIReduced)
	if err = ops.mul(&negUI, &negU, &rootI); err != nil {
		return 0, err
	}
	checkReduced, uReduced := check.Reduced(), u.Reduced()
	negUReduced, negUIReduced := negU.Reduced(), negUI.Reduced()
	correct := equalMaskX8(&checkReduced, &uReduced)
	flipped := equalMaskX8(&checkReduced, &negUReduced)
	flippedI := equalMaskX8(&checkReduced, &negUIReduced)
	var rootTimesI IFMAElementX8
	if err = ops.mul(&rootTimesI, &root, &rootI); err != nil {
		return 0, err
	}
	decodeSelectIFMAX8(&root, &root, &rootTimesI, flipped|flippedI)
	rootReduced := root.Reduced()
	conditionalNegateX8(&rootReduced, negativeMaskX8(&rootReduced))
	*z = rootReduced
	return correct | flipped, nil
}

func encodedSignMaskX4(in *[X4Lanes][32]byte, active uint8) uint8 {
	var signs uint8
	for lane := 0; lane < X4Lanes; lane++ {
		if active&(1<<lane) != 0 {
			signs |= (in[lane][31] >> 7) << lane
		}
	}
	return signs
}

func encodedSignMaskX8(in *[X8Lanes][32]byte, active uint8) uint8 {
	var signs uint8
	for lane := 0; lane < X8Lanes; lane++ {
		if active&(1<<lane) != 0 {
			signs |= (in[lane][31] >> 7) << lane
		}
	}
	return signs
}

func sqrtRatioPairIFMAX4(az, rz *ElementX4, au, ru, av, rv *IFMAElementX4, ops *decode2IFMAOpsX4, interleaved bool) (aSquare, rSquare uint8, err error) {
	var auv, ruv, apow, rpow, ar, rr IFMAElementX4
	if err = ops.mul(&auv, au, av); err != nil {
		return 0, 0, err
	}
	if err = ops.mul(&ruv, ru, rv); err != nil {
		return 0, 0, err
	}
	if interleaved {
		err = pow22523PairIFMAX4(&apow, &rpow, &auv, &ruv, ops)
	} else {
		err = pow22523IFMAX4(&apow, &auv, ops)
		if err == nil {
			err = pow22523IFMAX4(&rpow, &ruv, ops)
		}
	}
	if err != nil {
		return 0, 0, err
	}
	if err = ops.mul(&ar, au, &apow); err != nil {
		return 0, 0, err
	}
	if err = ops.mul(&rr, ru, &rpow); err != nil {
		return 0, 0, err
	}

	var ar2, rr2, acheck, rcheck, anegU, rnegU IFMAElementX4
	if err = ops.mul(&ar2, &ar, &ar); err != nil {
		return 0, 0, err
	}
	if err = ops.mul(&rr2, &rr, &rr); err != nil {
		return 0, 0, err
	}
	if err = ops.mul(&acheck, av, &ar2); err != nil {
		return 0, 0, err
	}
	if err = ops.mul(&rcheck, rv, &rr2); err != nil {
		return 0, 0, err
	}
	anegU.Negate(au)
	rnegU.Negate(ru)
	rootIReduced := broadcastX4(&sqrtM1)
	var rootI, anegUI, rnegUI IFMAElementX4
	rootI.SetReduced(&rootIReduced)
	if err = ops.mul(&anegUI, &anegU, &rootI); err != nil {
		return 0, 0, err
	}
	if err = ops.mul(&rnegUI, &rnegU, &rootI); err != nil {
		return 0, 0, err
	}

	acheckReduced, rcheckReduced := acheck.Reduced(), rcheck.Reduced()
	auReduced, ruReduced := au.Reduced(), ru.Reduced()
	anegUReduced, rnegUReduced := anegU.Reduced(), rnegU.Reduced()
	anegUIReduced, rnegUIReduced := anegUI.Reduced(), rnegUI.Reduced()
	acorrect := equalMaskX4(&acheckReduced, &auReduced)
	rcorrect := equalMaskX4(&rcheckReduced, &ruReduced)
	aflipped := equalMaskX4(&acheckReduced, &anegUReduced)
	rflipped := equalMaskX4(&rcheckReduced, &rnegUReduced)
	aflippedI := equalMaskX4(&acheckReduced, &anegUIReduced)
	rflippedI := equalMaskX4(&rcheckReduced, &rnegUIReduced)

	var arI, rrI IFMAElementX4
	if err = ops.mul(&arI, &ar, &rootI); err != nil {
		return 0, 0, err
	}
	if err = ops.mul(&rrI, &rr, &rootI); err != nil {
		return 0, 0, err
	}
	decodeSelectIFMAX4(&ar, &ar, &arI, aflipped|aflippedI)
	decodeSelectIFMAX4(&rr, &rr, &rrI, rflipped|rflippedI)
	arReduced, rrReduced := ar.Reduced(), rr.Reduced()
	conditionalNegateX4(&arReduced, negativeMaskX4(&arReduced))
	conditionalNegateX4(&rrReduced, negativeMaskX4(&rrReduced))
	*az, *rz = arReduced, rrReduced
	return acorrect | aflipped, rcorrect | rflipped, nil
}

func sqrtRatioPairIFMAX8(az, rz *ElementX8, au, ru, av, rv *IFMAElementX8, ops *decode2IFMAOpsX8, interleaved bool) (aSquare, rSquare uint8, err error) {
	var auv, ruv, apow, rpow, ar, rr IFMAElementX8
	if err = ops.mul(&auv, au, av); err != nil {
		return 0, 0, err
	}
	if err = ops.mul(&ruv, ru, rv); err != nil {
		return 0, 0, err
	}
	if interleaved {
		err = pow22523PairIFMAX8(&apow, &rpow, &auv, &ruv, ops)
	} else {
		err = pow22523IFMAX8(&apow, &auv, ops)
		if err == nil {
			err = pow22523IFMAX8(&rpow, &ruv, ops)
		}
	}
	if err != nil {
		return 0, 0, err
	}
	if err = ops.mul(&ar, au, &apow); err != nil {
		return 0, 0, err
	}
	if err = ops.mul(&rr, ru, &rpow); err != nil {
		return 0, 0, err
	}

	var ar2, rr2, acheck, rcheck, anegU, rnegU IFMAElementX8
	if err = ops.mul(&ar2, &ar, &ar); err != nil {
		return 0, 0, err
	}
	if err = ops.mul(&rr2, &rr, &rr); err != nil {
		return 0, 0, err
	}
	if err = ops.mul(&acheck, av, &ar2); err != nil {
		return 0, 0, err
	}
	if err = ops.mul(&rcheck, rv, &rr2); err != nil {
		return 0, 0, err
	}
	anegU.Negate(au)
	rnegU.Negate(ru)
	rootIReduced := broadcastX8(&sqrtM1)
	var rootI, anegUI, rnegUI IFMAElementX8
	rootI.SetReduced(&rootIReduced)
	if err = ops.mul(&anegUI, &anegU, &rootI); err != nil {
		return 0, 0, err
	}
	if err = ops.mul(&rnegUI, &rnegU, &rootI); err != nil {
		return 0, 0, err
	}

	acheckReduced, rcheckReduced := acheck.Reduced(), rcheck.Reduced()
	auReduced, ruReduced := au.Reduced(), ru.Reduced()
	anegUReduced, rnegUReduced := anegU.Reduced(), rnegU.Reduced()
	anegUIReduced, rnegUIReduced := anegUI.Reduced(), rnegUI.Reduced()
	acorrect := equalMaskX8(&acheckReduced, &auReduced)
	rcorrect := equalMaskX8(&rcheckReduced, &ruReduced)
	aflipped := equalMaskX8(&acheckReduced, &anegUReduced)
	rflipped := equalMaskX8(&rcheckReduced, &rnegUReduced)
	aflippedI := equalMaskX8(&acheckReduced, &anegUIReduced)
	rflippedI := equalMaskX8(&rcheckReduced, &rnegUIReduced)

	var arI, rrI IFMAElementX8
	if err = ops.mul(&arI, &ar, &rootI); err != nil {
		return 0, 0, err
	}
	if err = ops.mul(&rrI, &rr, &rootI); err != nil {
		return 0, 0, err
	}
	decodeSelectIFMAX8(&ar, &ar, &arI, aflipped|aflippedI)
	decodeSelectIFMAX8(&rr, &rr, &rrI, rflipped|rflippedI)
	arReduced, rrReduced := ar.Reduced(), rr.Reduced()
	conditionalNegateX8(&arReduced, negativeMaskX8(&arReduced))
	conditionalNegateX8(&rrReduced, negativeMaskX8(&rrReduced))
	*az, *rz = arReduced, rrReduced
	return acorrect | aflipped, rcorrect | rflipped, nil
}

func pow22523PairIFMAX4(az, rz, ax, rx *IFMAElementX4, ops *decode2IFMAOpsX4) error {
	abase, rbase := *ax, *rx
	var ax2, rx2, ax9, rx9, ax11, rx11 IFMAElementX4
	if err := ops.mul(&ax2, &abase, &abase); err != nil {
		return err
	}
	if err := ops.mul(&rx2, &rbase, &rbase); err != nil {
		return err
	}
	if err := repeatedSquareMultiplyPairIFMAX4(&ax9, &rx9, &ax2, &rx2, &abase, &rbase, 2, ops); err != nil {
		return err
	}
	if err := ops.mul(&ax11, &ax9, &ax2); err != nil {
		return err
	}
	if err := ops.mul(&rx11, &rx9, &rx2); err != nil {
		return err
	}

	var ax5, rx5, ax10, rx10, ax20, rx20, ax40, rx40 IFMAElementX4
	if err := repeatedSquareMultiplyPairIFMAX4(&ax5, &rx5, &ax11, &rx11, &ax9, &rx9, 1, ops); err != nil {
		return err
	}
	if err := repeatedSquareMultiplyPairIFMAX4(&ax10, &rx10, &ax5, &rx5, &ax5, &rx5, 5, ops); err != nil {
		return err
	}
	if err := repeatedSquareMultiplyPairIFMAX4(&ax20, &rx20, &ax10, &rx10, &ax10, &rx10, 10, ops); err != nil {
		return err
	}
	if err := repeatedSquareMultiplyPairIFMAX4(&ax40, &rx40, &ax20, &rx20, &ax20, &rx20, 20, ops); err != nil {
		return err
	}
	var ax50, rx50, ax100, rx100, ax200, rx200, ax250, rx250 IFMAElementX4
	if err := repeatedSquareMultiplyPairIFMAX4(&ax50, &rx50, &ax40, &rx40, &ax10, &rx10, 10, ops); err != nil {
		return err
	}
	if err := repeatedSquareMultiplyPairIFMAX4(&ax100, &rx100, &ax50, &rx50, &ax50, &rx50, 50, ops); err != nil {
		return err
	}
	if err := repeatedSquareMultiplyPairIFMAX4(&ax200, &rx200, &ax100, &rx100, &ax100, &rx100, 100, ops); err != nil {
		return err
	}
	if err := repeatedSquareMultiplyPairIFMAX4(&ax250, &rx250, &ax200, &rx200, &ax50, &rx50, 50, ops); err != nil {
		return err
	}
	return repeatedSquareMultiplyPairIFMAX4(az, rz, &ax250, &rx250, &abase, &rbase, 2, ops)
}

func pow22523PairIFMAX8(az, rz, ax, rx *IFMAElementX8, ops *decode2IFMAOpsX8) error {
	abase, rbase := *ax, *rx
	var ax2, rx2, ax9, rx9, ax11, rx11 IFMAElementX8
	if err := ops.mul(&ax2, &abase, &abase); err != nil {
		return err
	}
	if err := ops.mul(&rx2, &rbase, &rbase); err != nil {
		return err
	}
	if err := repeatedSquareMultiplyPairIFMAX8(&ax9, &rx9, &ax2, &rx2, &abase, &rbase, 2, ops); err != nil {
		return err
	}
	if err := ops.mul(&ax11, &ax9, &ax2); err != nil {
		return err
	}
	if err := ops.mul(&rx11, &rx9, &rx2); err != nil {
		return err
	}

	var ax5, rx5, ax10, rx10, ax20, rx20, ax40, rx40 IFMAElementX8
	if err := repeatedSquareMultiplyPairIFMAX8(&ax5, &rx5, &ax11, &rx11, &ax9, &rx9, 1, ops); err != nil {
		return err
	}
	if err := repeatedSquareMultiplyPairIFMAX8(&ax10, &rx10, &ax5, &rx5, &ax5, &rx5, 5, ops); err != nil {
		return err
	}
	if err := repeatedSquareMultiplyPairIFMAX8(&ax20, &rx20, &ax10, &rx10, &ax10, &rx10, 10, ops); err != nil {
		return err
	}
	if err := repeatedSquareMultiplyPairIFMAX8(&ax40, &rx40, &ax20, &rx20, &ax20, &rx20, 20, ops); err != nil {
		return err
	}
	var ax50, rx50, ax100, rx100, ax200, rx200, ax250, rx250 IFMAElementX8
	if err := repeatedSquareMultiplyPairIFMAX8(&ax50, &rx50, &ax40, &rx40, &ax10, &rx10, 10, ops); err != nil {
		return err
	}
	if err := repeatedSquareMultiplyPairIFMAX8(&ax100, &rx100, &ax50, &rx50, &ax50, &rx50, 50, ops); err != nil {
		return err
	}
	if err := repeatedSquareMultiplyPairIFMAX8(&ax200, &rx200, &ax100, &rx100, &ax100, &rx100, 100, ops); err != nil {
		return err
	}
	if err := repeatedSquareMultiplyPairIFMAX8(&ax250, &rx250, &ax200, &rx200, &ax50, &rx50, 50, ops); err != nil {
		return err
	}
	return repeatedSquareMultiplyPairIFMAX8(az, rz, &ax250, &rx250, &abase, &rbase, 2, ops)
}

func pow22523IFMAX4(z, x *IFMAElementX4, ops *decode2IFMAOpsX4) error {
	base := *x
	var x2, x9, x11 IFMAElementX4
	if err := ops.mul(&x2, &base, &base); err != nil {
		return err
	}
	if err := repeatedSquareMultiplyIFMAX4(&x9, &x2, &base, 2, ops); err != nil {
		return err
	}
	if err := ops.mul(&x11, &x9, &x2); err != nil {
		return err
	}
	var x5, x10, x20, x40, x50, x100, x200, x250 IFMAElementX4
	if err := repeatedSquareMultiplyIFMAX4(&x5, &x11, &x9, 1, ops); err != nil {
		return err
	}
	if err := repeatedSquareMultiplyIFMAX4(&x10, &x5, &x5, 5, ops); err != nil {
		return err
	}
	if err := repeatedSquareMultiplyIFMAX4(&x20, &x10, &x10, 10, ops); err != nil {
		return err
	}
	if err := repeatedSquareMultiplyIFMAX4(&x40, &x20, &x20, 20, ops); err != nil {
		return err
	}
	if err := repeatedSquareMultiplyIFMAX4(&x50, &x40, &x10, 10, ops); err != nil {
		return err
	}
	if err := repeatedSquareMultiplyIFMAX4(&x100, &x50, &x50, 50, ops); err != nil {
		return err
	}
	if err := repeatedSquareMultiplyIFMAX4(&x200, &x100, &x100, 100, ops); err != nil {
		return err
	}
	if err := repeatedSquareMultiplyIFMAX4(&x250, &x200, &x50, 50, ops); err != nil {
		return err
	}
	return repeatedSquareMultiplyIFMAX4(z, &x250, &base, 2, ops)
}

func pow22523IFMAX8(z, x *IFMAElementX8, ops *decode2IFMAOpsX8) error {
	base := *x
	var x2, x9, x11 IFMAElementX8
	if err := ops.mul(&x2, &base, &base); err != nil {
		return err
	}
	if err := repeatedSquareMultiplyIFMAX8(&x9, &x2, &base, 2, ops); err != nil {
		return err
	}
	if err := ops.mul(&x11, &x9, &x2); err != nil {
		return err
	}
	var x5, x10, x20, x40, x50, x100, x200, x250 IFMAElementX8
	if err := repeatedSquareMultiplyIFMAX8(&x5, &x11, &x9, 1, ops); err != nil {
		return err
	}
	if err := repeatedSquareMultiplyIFMAX8(&x10, &x5, &x5, 5, ops); err != nil {
		return err
	}
	if err := repeatedSquareMultiplyIFMAX8(&x20, &x10, &x10, 10, ops); err != nil {
		return err
	}
	if err := repeatedSquareMultiplyIFMAX8(&x40, &x20, &x20, 20, ops); err != nil {
		return err
	}
	if err := repeatedSquareMultiplyIFMAX8(&x50, &x40, &x10, 10, ops); err != nil {
		return err
	}
	if err := repeatedSquareMultiplyIFMAX8(&x100, &x50, &x50, 50, ops); err != nil {
		return err
	}
	if err := repeatedSquareMultiplyIFMAX8(&x200, &x100, &x100, 100, ops); err != nil {
		return err
	}
	if err := repeatedSquareMultiplyIFMAX8(&x250, &x200, &x50, 50, ops); err != nil {
		return err
	}
	return repeatedSquareMultiplyIFMAX8(z, &x250, &base, 2, ops)
}

func repeatedSquareMultiplyPairIFMAX4(az, rz, ax, rx, ay, ry *IFMAElementX4, count int, ops *decode2IFMAOpsX4) error {
	*az, *rz = *ax, *rx
	for i := 0; i < count; i++ {
		if err := ops.mul(az, az, az); err != nil {
			return err
		}
		if err := ops.mul(rz, rz, rz); err != nil {
			return err
		}
	}
	if err := ops.mul(az, az, ay); err != nil {
		return err
	}
	return ops.mul(rz, rz, ry)
}

func repeatedSquareMultiplyPairIFMAX8(az, rz, ax, rx, ay, ry *IFMAElementX8, count int, ops *decode2IFMAOpsX8) error {
	*az, *rz = *ax, *rx
	for i := 0; i < count; i++ {
		if err := ops.mul(az, az, az); err != nil {
			return err
		}
		if err := ops.mul(rz, rz, rz); err != nil {
			return err
		}
	}
	if err := ops.mul(az, az, ay); err != nil {
		return err
	}
	return ops.mul(rz, rz, ry)
}

func repeatedSquareMultiplyIFMAX4(z, x, y *IFMAElementX4, count int, ops *decode2IFMAOpsX4) error {
	// The unchecked hardware decoder has already validated its u52 import
	// boundary. Keep the dependent square run in registers; the final multiply
	// remains separate because its second operand changes at each addition-chain
	// boundary. Checked/fault-injection and portable schedules retain the common
	// per-operation path below.
	if ops.hardware && ops.uncheckedInputs {
		ifmaRepeatedSquareNormalizedX4(&z.limbs, &x.limbs, count)
	} else {
		*z = *x
		for i := 0; i < count; i++ {
			if err := ops.mul(z, z, z); err != nil {
				return err
			}
		}
	}
	return ops.mul(z, z, y)
}

func repeatedSquareMultiplyIFMAX8(z, x, y *IFMAElementX8, count int, ops *decode2IFMAOpsX8) error {
	// See the x4 counterpart for the range and fault-injection boundary.
	if ops.hardware && ops.uncheckedInputs {
		ifmaRepeatedSquareNormalizedX8(&z.limbs, &x.limbs, count)
	} else {
		*z = *x
		for i := 0; i < count; i++ {
			if err := ops.mul(z, z, z); err != nil {
				return err
			}
		}
	}
	return ops.mul(z, z, y)
}

func (ops *decode2IFMAOpsX4) mul(out, x, y *IFMAElementX4) error {
	if ops.hardware && ops.uncheckedInputs {
		return ifmaMultiplyComposableUncheckedX4(out, x, y)
	}
	ops.calls++
	if ops.failAt != 0 && ops.calls == ops.failAt {
		return errIFMAOutputRange
	}
	if !ops.uncheckedInputs && (!isIFMAElementX4(x) || !isIFMAElementX4(y)) {
		return errIFMAComposableInputRange
	}
	if ops.hardware {
		return ifmaMultiplyComposableUncheckedX4(out, x, y)
	}
	xReduced, yReduced := x.Reduced(), y.Reduced()
	var product ElementX4
	product.Multiply(&xReduced, &yReduced)
	out.SetReduced(&product)
	return nil
}

func (ops *decode2IFMAOpsX8) mul(out, x, y *IFMAElementX8) error {
	if ops.hardware && ops.uncheckedInputs {
		return ifmaMultiplyComposableUncheckedX8(out, x, y)
	}
	ops.calls++
	if ops.failAt != 0 && ops.calls == ops.failAt {
		return errIFMAOutputRange
	}
	if !ops.uncheckedInputs && (!isIFMAElementX8(x) || !isIFMAElementX8(y)) {
		return errIFMAComposableInputRange
	}
	if ops.hardware {
		return ifmaMultiplyComposableUncheckedX8(out, x, y)
	}
	xReduced, yReduced := x.Reduced(), y.Reduced()
	var product ElementX8
	product.Multiply(&xReduced, &yReduced)
	out.SetReduced(&product)
	return nil
}

// validatePairImports scans the external-to-composable boundary once before
// an unchecked hardware schedule begins. The reduced lane model and the
// legacy checked hardware benchmark retain per-multiply scans instead.
func (ops *decode2IFMAOpsX4) validatePairImports(y0, y1, one, d *IFMAElementX4) error {
	if !ops.uncheckedInputs {
		return nil
	}
	if !isIFMAElementX4(y0) || !isIFMAElementX4(y1) || !isIFMAElementX4(one) || !isIFMAElementX4(d) {
		return errIFMAComposableInputRange
	}
	return nil
}

func (ops *decode2IFMAOpsX8) validatePairImports(y0, y1, one, d *IFMAElementX8) error {
	if !ops.uncheckedInputs {
		return nil
	}
	if !isIFMAElementX8(y0) || !isIFMAElementX8(y1) || !isIFMAElementX8(one) || !isIFMAElementX8(d) {
		return errIFMAComposableInputRange
	}
	return nil
}

func (ops *decode2IFMAOpsX4) validateOneImports(y, one, d *IFMAElementX4) error {
	if !ops.uncheckedInputs {
		return nil
	}
	if !isIFMAElementX4(y) || !isIFMAElementX4(one) || !isIFMAElementX4(d) {
		return errIFMAComposableInputRange
	}
	return nil
}

func (ops *decode2IFMAOpsX8) validateOneImports(y, one, d *IFMAElementX8) error {
	if !ops.uncheckedInputs {
		return nil
	}
	if !isIFMAElementX8(y) || !isIFMAElementX8(one) || !isIFMAElementX8(d) {
		return errIFMAComposableInputRange
	}
	return nil
}

func decodeSelectIFMAX4(out, x, y *IFMAElementX4, mask uint8) {
	for lane := 0; lane < X4Lanes; lane++ {
		selectMask := uint64(0) - uint64((mask>>lane)&1)
		for limb := 0; limb < 5; limb++ {
			out.limbs[limb][lane] = x.limbs[limb][lane] ^ (selectMask & (x.limbs[limb][lane] ^ y.limbs[limb][lane]))
		}
	}
}

func decodeSelectIFMAX8(out, x, y *IFMAElementX8, mask uint8) {
	for lane := 0; lane < X8Lanes; lane++ {
		selectMask := uint64(0) - uint64((mask>>lane)&1)
		for limb := 0; limb < 5; limb++ {
			out.limbs[limb][lane] = x.limbs[limb][lane] ^ (selectMask & (x.limbs[limb][lane] ^ y.limbs[limb][lane]))
		}
	}
}
