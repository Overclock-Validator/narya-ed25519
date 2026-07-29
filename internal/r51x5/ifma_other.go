//go:build !amd64 || purego

package r51x5

const nativeIFMAKernelsBuilt = false

func ifmaMulRawX8(out *IFMAProductX8, x, y *LimbsX8) {
	panic("r51x5: unreachable x8 IFMA call on non-amd64")
}

func ifmaFourRawProductsUncheckedX8(
	out *IFMAProductX8,
	x0, y0, x1, y1, x2, y2, x3, y3 *LimbsX8,
) {
	panic("r51x5: unreachable x8 four-product IFMA call on non-amd64")
}

func ifmaFourRawProductsDoubleStage2UncheckedX8(
	out *IFMAProductX8,
	x0, y0, x1, y1, x2, y2, x3, y3 *LimbsX8,
) {
	panic("r51x5: unreachable x8 four-product double-Stage-2 IFMA call on non-amd64")
}

func ifmaFourRawProductsNielsStage2UncheckedX8(
	out *IFMAProductX8,
	x0, y0, x1, y1, x2, y2, x3, y3 *LimbsX8,
) {
	panic("r51x5: unreachable x8 four-product Niels-Stage-2 IFMA call on non-amd64")
}

func ifmaThreeRawProductsNielsStage2UncheckedX8(
	out *IFMAProductX8,
	x0, y0, x1, y1, x2, y2, d *LimbsX8,
) {
	panic("r51x5: unreachable x8 three-product Niels-Stage-2 IFMA call on non-amd64")
}

func ifmaMulRawX4(out *IFMAProductX4, x, y *LimbsX4) {
	panic("r51x5: unreachable x4 IFMA call on non-amd64")
}

func ifmaMulNormalizedUncheckedX8(out, x, y *LimbsX8) {
	panic("r51x5: unreachable x8 fused IFMA call on non-amd64")
}

func ifmaPointFinalProductsUncheckedX8(out *IFMAPointX8, operands *IFMAProductX8) {
	panic("r51x5: unreachable x8 final-product IFMA call on non-amd64")
}

func ifmaMulNormalizedMul19ExperimentX8(out, x, y *LimbsX8) {
	ifmaMulNormalizedUncheckedX8(out, x, y)
}

func ifmaMulNormalizedUncheckedX4(out, x, y *LimbsX4) {
	panic("r51x5: unreachable x4 fused IFMA call on non-amd64")
}

func ifmaNormalizeProductUncheckedX8(out *LimbsX8, x *IFMAProductX8) {
	normalized, ok := normalizeIFMAProductX8(x)
	if !ok {
		panic("r51x5: internal x8 composable range invariant violated")
	}
	*out = normalized
}

func ifmaNormalizeProductUncheckedX4(out *LimbsX4, x *IFMAProductX4) {
	normalized, ok := normalizeIFMAProductX4(x)
	if !ok {
		panic("r51x5: internal x4 composable range invariant violated")
	}
	*out = normalized
}

func ifmaAddNormalizedUncheckedX8(out, x, y *LimbsX8) {
	var raw IFMAProductX8
	for limb := range raw {
		for lane := range raw[limb] {
			raw[limb][lane] = x[limb][lane] + y[limb][lane]
		}
	}
	ifmaNormalizeProductUncheckedX8(out, &raw)
}

func ifmaSubtractNormalizedUncheckedX8(out, x, y *LimbsX8) {
	var raw IFMAProductX8
	for limb := range raw {
		bias := ifmaSubtractionBias(limb)
		for lane := range raw[limb] {
			raw[limb][lane] = x[limb][lane] + bias - y[limb][lane]
		}
	}
	ifmaNormalizeProductUncheckedX8(out, &raw)
}

func ifmaNegateNormalizedUncheckedX8(out, x *LimbsX8) {
	var raw IFMAProductX8
	for limb := range raw {
		bias := ifmaSubtractionBias(limb)
		for lane := range raw[limb] {
			raw[limb][lane] = bias - x[limb][lane]
		}
	}
	ifmaNormalizeProductUncheckedX8(out, &raw)
}

func ifmaAddNormalizedUncheckedX4(out, x, y *LimbsX4) {
	var raw IFMAProductX4
	for limb := range raw {
		for lane := range raw[limb] {
			raw[limb][lane] = x[limb][lane] + y[limb][lane]
		}
	}
	ifmaNormalizeProductUncheckedX4(out, &raw)
}

func ifmaSubtractNormalizedUncheckedX4(out, x, y *LimbsX4) {
	var raw IFMAProductX4
	for limb := range raw {
		bias := ifmaSubtractionBias(limb)
		for lane := range raw[limb] {
			raw[limb][lane] = x[limb][lane] + bias - y[limb][lane]
		}
	}
	ifmaNormalizeProductUncheckedX4(out, &raw)
}

func ifmaNegateNormalizedUncheckedX4(out, x *LimbsX4) {
	var raw IFMAProductX4
	for limb := range raw {
		bias := ifmaSubtractionBias(limb)
		for lane := range raw[limb] {
			raw[limb][lane] = bias - x[limb][lane]
		}
	}
	ifmaNormalizeProductUncheckedX4(out, &raw)
}

func ifmaConditionalNegateNormalizedUncheckedX4(out, x *LimbsX4, negativeMask uint8) {
	var raw IFMAProductX4
	for limb := range raw {
		bias := ifmaSubtractionBias(limb)
		for lane := range raw[limb] {
			if negativeMask&(1<<lane) != 0 {
				raw[limb][lane] = bias - x[limb][lane]
			} else {
				raw[limb][lane] = x[limb][lane]
			}
		}
	}
	ifmaNormalizeProductUncheckedX4(out, &raw)
}

func ifmaConditionalNegateNormalizedUncheckedX8(out, x *LimbsX8, negativeMask uint8) {
	var raw IFMAProductX8
	for limb := range raw {
		bias := ifmaSubtractionBias(limb)
		for lane := range raw[limb] {
			if negativeMask&(1<<lane) != 0 {
				raw[limb][lane] = bias - x[limb][lane]
			} else {
				raw[limb][lane] = x[limb][lane]
			}
		}
	}
	ifmaNormalizeProductUncheckedX8(out, &raw)
}
