package r51x5

import "math/bits"

// ifmaLooseLaneModel is the scalar oracle for one VPMADD52-style radix-51
// product. It intentionally mirrors the low/high 52-bit split used by the
// assembly rather than using the package's ordinary field multiplication.
func ifmaLooseLaneModel(x, y Limbs) Limbs {
	const mask52 = uint64(1<<52) - 1
	var low, high [9]uint64
	for i := range x {
		for j := range y {
			hi, lo := bits.Mul64(x[i], y[j])
			degree := i + j
			low[degree] += lo & mask52
			high[degree] += lo>>52 | hi<<12
		}
	}

	var coefficients [10]uint64
	for degree := range low {
		coefficients[degree] += low[degree]
		coefficients[degree+1] += 2 * high[degree]
	}
	return Limbs{
		coefficients[0] + 19*coefficients[5],
		coefficients[1] + 19*coefficients[6],
		coefficients[2] + 19*coefficients[7],
		coefficients[3] + 19*coefficients[8],
		coefficients[4] + 19*coefficients[9],
	}
}

func modelMultiplyComposableX8(out, x, y *IFMAElementX8) error {
	if !isIFMAElementX8(x) || !isIFMAElementX8(y) {
		return errIFMAComposableInputRange
	}
	var raw IFMAProductX8
	for lane := 0; lane < X8Lanes; lane++ {
		var xl, yl Limbs
		for limb := range xl {
			xl[limb] = x.limbs[limb][lane]
			yl[limb] = y.limbs[limb][lane]
		}
		product := ifmaLooseLaneModel(xl, yl)
		for limb := range product {
			raw[limb][lane] = product[limb]
		}
	}
	normalized, ok := normalizeIFMAProductX8(&raw)
	if !ok {
		return errIFMAOutputRange
	}
	out.limbs = normalized
	return nil
}

func modelMultiplyComposableX4(out, x, y *IFMAElementX4) error {
	if !isIFMAElementX4(x) || !isIFMAElementX4(y) {
		return errIFMAComposableInputRange
	}
	var raw IFMAProductX4
	for lane := 0; lane < X4Lanes; lane++ {
		var xl, yl Limbs
		for limb := range xl {
			xl[limb] = x.limbs[limb][lane]
			yl[limb] = y.limbs[limb][lane]
		}
		product := ifmaLooseLaneModel(xl, yl)
		for limb := range product {
			raw[limb][lane] = product[limb]
		}
	}
	normalized, ok := normalizeIFMAProductX4(&raw)
	if !ok {
		return errIFMAOutputRange
	}
	out.limbs = normalized
	return nil
}
