package r51x5

const (
	// IFMAProductLimbBits bounds each folded coefficient emitted when the raw
	// multiplication kernel consumes composable limbs below 2^52. The five
	// input limbs produce convolution coefficients with respective term
	// weights 1,4,7,10,13,14,11,8,5,2 after the 52-to-51-bit split. Folding
	// degrees five through nine therefore gives weights
	//
	//	267, 213, 159, 105, 51.
	//
	// Every source term is below 2^52, so the largest folded coefficient is
	// below 267*2^52, which is strictly below 2^61. The assembly accumulators
	// and their shift/add folds consequently cannot overflow uint64.
	IFMAProductLimbBits = 61

	// IFMALooseLimbBits bounds each limb emitted by the experimental x4/x8
	// multiplication kernels. The kernels require reduced radix-2^51 inputs.
	// Their folded output represents the product modulo p, but it is neither
	// carried nor canonical and MUST NOT be used as another IFMA multiplicand.
	//
	// For two inputs below 2^51, every LUQ term is below 2^52 and every
	// HUQ term is below 2^50. After moving HUQ to the next radix-2^51 degree
	// by doubling it, a convolution coefficient is below
	//
	//	5*2^52 + 2*5*2^50 = 15*2^51 < 2^55.
	//
	// Folding coefficients five through nine by 2^255 = 19 therefore leaves
	// every output limb below 20*2^55 < 2^60.
	IFMALooseLimbBits = 60

	ifmaProductLimbLimit = uint64(1) << IFMAProductLimbBits
	ifmaLooseLimbLimit   = uint64(1) << IFMALooseLimbBits
)

// IFMAProductX4 is the exact folded output storage of the raw four-lane
// kernel. For multiplicand limbs below 2^52, every output limb is below
// 2^61. It must be carry-normalized before it is used as another
// multiplicand.
type IFMAProductX4 [5][X4Lanes]uint64

// IFMAProductX8 is the eight-lane analogue of IFMAProductX4.
type IFMAProductX8 [5][X8Lanes]uint64

// IFMALooseX4 is the non-composable [limb][lane] output of the experimental
// four-lane IFMA multiplication kernel. Each limb is less than 2^60 and each
// lane represents the product modulo p in radix 2^51.
type IFMALooseX4 [5][X4Lanes]uint64

// IFMALooseX8 is the non-composable [limb][lane] output of the experimental
// eight-lane IFMA multiplication kernel. Each limb is less than 2^60 and each
// lane represents the product modulo p in radix 2^51.
type IFMALooseX8 [5][X8Lanes]uint64

func isIFMAProductX4(x IFMAProductX4) bool {
	for limb := range x {
		for lane := range x[limb] {
			if x[limb][lane] >= ifmaProductLimbLimit {
				return false
			}
		}
	}
	return true
}

func isIFMAProductX8(x IFMAProductX8) bool {
	for limb := range x {
		for lane := range x[limb] {
			if x[limb][lane] >= ifmaProductLimbLimit {
				return false
			}
		}
	}
	return true
}

// IsIFMALooseX4 reports whether every raw limb satisfies the kernel's u60
// output bound. It does not imply that the value is carried or canonical.
func IsIFMALooseX4(x IFMALooseX4) bool {
	for limb := range x {
		for lane := range x[limb] {
			if x[limb][lane] >= ifmaLooseLimbLimit {
				return false
			}
		}
	}
	return true
}

// IsIFMALooseX8 reports whether every raw limb satisfies the kernel's u60
// output bound. It does not imply that the value is carried or canonical.
func IsIFMALooseX8(x IFMALooseX8) bool {
	for limb := range x {
		for lane := range x[limb] {
			if x[limb][lane] >= ifmaLooseLimbLimit {
				return false
			}
		}
	}
	return true
}

func reduceIFMALooseX4(x *IFMALooseX4) (LimbsX4, bool) {
	if !IsIFMALooseX4(*x) {
		return LimbsX4{}, false
	}
	var out LimbsX4
	for lane := 0; lane < X4Lanes; lane++ {
		var accum [5]uint128
		for limb := range accum {
			accum[limb].lo = x[limb][lane]
		}
		reduced := reduceAccumulators(&accum)
		for limb := range reduced {
			out[limb][lane] = reduced[limb]
		}
	}
	return out, true
}

func reduceIFMALooseX8(x *IFMALooseX8) (LimbsX8, bool) {
	if !IsIFMALooseX8(*x) {
		return LimbsX8{}, false
	}
	var out LimbsX8
	for lane := 0; lane < X8Lanes; lane++ {
		var accum [5]uint128
		for limb := range accum {
			accum[limb].lo = x[limb][lane]
		}
		reduced := reduceAccumulators(&accum)
		for limb := range reduced {
			out[limb][lane] = reduced[limb]
		}
	}
	return out, true
}
