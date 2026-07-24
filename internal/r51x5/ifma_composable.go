package r51x5

import "errors"

const (
	// IFMAComposableLimbBits is the exclusive per-limb width accepted by
	// VPMADD52 and maintained by IFMAElementX4/X8. These values are bounded
	// representatives modulo p; they are deliberately not canonical.
	IFMAComposableLimbBits = 52

	ifmaComposableLimbLimit = uint64(1) << IFMAComposableLimbBits
	ifmaFoldCarryMax        = uint64(1) << 10
	ifmaPostCarryLimb0Limit = uint64(1)<<LimbBits + 19*ifmaFoldCarryMax
)

var errIFMAComposableInputRange = errors.New("r51x5: composable IFMA input is outside u52")

// IFMAElementX4 holds four bounded, non-canonical field representatives.
// Every limb is below 2^52. Its zero value is valid, and its fields are
// private so construction and arithmetic preserve the multiplicand bound.
type IFMAElementX4 struct {
	limbs LimbsX4
}

// IFMAElementX8 is the eight-lane analogue of IFMAElementX4.
type IFMAElementX8 struct {
	limbs LimbsX8
}

// SetReduced imports four canonical lanes into the composable domain.
func (z *IFMAElementX4) SetReduced(x *ElementX4) *IFMAElementX4 {
	z.limbs = x.limbs
	return z
}

// SetReduced imports eight canonical lanes into the composable domain.
func (z *IFMAElementX8) SetReduced(x *ElementX8) *IFMAElementX8 {
	z.limbs = x.limbs
	return z
}

// Limbs returns a copy of the composable four-lane representation.
func (z *IFMAElementX4) Limbs() LimbsX4 { return z.limbs }

// Limbs returns a copy of the composable eight-lane representation.
func (z *IFMAElementX8) Limbs() LimbsX8 { return z.limbs }

// Reduced canonically reduces all four lanes. This is a boundary operation,
// not part of the composable point formulas.
func (z *IFMAElementX4) Reduced() ElementX4 {
	var out ElementX4
	for lane := 0; lane < X4Lanes; lane++ {
		var accum [5]uint128
		for limb := range accum {
			accum[limb].lo = z.limbs[limb][lane]
		}
		reduced := reduceAccumulators(&accum)
		for limb := range reduced {
			out.limbs[limb][lane] = reduced[limb]
		}
	}
	return out
}

// Reduced canonically reduces all eight lanes. This is a boundary operation,
// not part of the composable point formulas.
func (z *IFMAElementX8) Reduced() ElementX8 {
	var out ElementX8
	for lane := 0; lane < X8Lanes; lane++ {
		var accum [5]uint128
		for limb := range accum {
			accum[limb].lo = z.limbs[limb][lane]
		}
		reduced := reduceAccumulators(&accum)
		for limb := range reduced {
			out.limbs[limb][lane] = reduced[limb]
		}
	}
	return out
}

// Add sets z=x+y modulo p and returns a composable representative. Inputs
// and output may alias. The pre-normalization limbs are below 2^53.
func (z *IFMAElementX4) Add(x, y *IFMAElementX4) *IFMAElementX4 {
	var raw IFMAProductX4
	for limb := range raw {
		for lane := range raw[limb] {
			raw[limb][lane] = x.limbs[limb][lane] + y.limbs[limb][lane]
		}
	}
	z.limbs = mustNormalizeIFMAProductX4(&raw)
	return z
}

// Add is the eight-lane analogue of IFMAElementX4.Add.
func (z *IFMAElementX8) Add(x, y *IFMAElementX8) *IFMAElementX8 {
	var raw IFMAProductX8
	for limb := range raw {
		for lane := range raw[limb] {
			raw[limb][lane] = x.limbs[limb][lane] + y.limbs[limb][lane]
		}
	}
	z.limbs = mustNormalizeIFMAProductX8(&raw)
	return z
}

// Subtract sets z=x-y modulo p. Four copies of p provide a non-negative
// limb-wise bias: every pre-normalization limb is below 6*2^51 < 2^54.
func (z *IFMAElementX4) Subtract(x, y *IFMAElementX4) *IFMAElementX4 {
	var raw IFMAProductX4
	for limb := range raw {
		bias := ifmaSubtractionBias(limb)
		for lane := range raw[limb] {
			raw[limb][lane] = x.limbs[limb][lane] + bias - y.limbs[limb][lane]
		}
	}
	z.limbs = mustNormalizeIFMAProductX4(&raw)
	return z
}

// Subtract is the eight-lane analogue of IFMAElementX4.Subtract.
func (z *IFMAElementX8) Subtract(x, y *IFMAElementX8) *IFMAElementX8 {
	var raw IFMAProductX8
	for limb := range raw {
		bias := ifmaSubtractionBias(limb)
		for lane := range raw[limb] {
			raw[limb][lane] = x.limbs[limb][lane] + bias - y.limbs[limb][lane]
		}
	}
	z.limbs = mustNormalizeIFMAProductX8(&raw)
	return z
}

// Negate sets z=-x modulo p. Inputs and output may alias.
func (z *IFMAElementX4) Negate(x *IFMAElementX4) *IFMAElementX4 {
	var raw IFMAProductX4
	for limb := range raw {
		bias := ifmaSubtractionBias(limb)
		for lane := range raw[limb] {
			raw[limb][lane] = bias - x.limbs[limb][lane]
		}
	}
	z.limbs = mustNormalizeIFMAProductX4(&raw)
	return z
}

// Negate is the eight-lane analogue of IFMAElementX4.Negate.
func (z *IFMAElementX8) Negate(x *IFMAElementX8) *IFMAElementX8 {
	var raw IFMAProductX8
	for limb := range raw {
		bias := ifmaSubtractionBias(limb)
		for lane := range raw[limb] {
			raw[limb][lane] = bias - x.limbs[limb][lane]
		}
	}
	z.limbs = mustNormalizeIFMAProductX8(&raw)
	return z
}

// ExperimentalIFMAMultiplyComposableX4 multiplies four pairs of composable
// representatives. It performs the one carry/fold pass required before the
// product can be fed back to VPMADD52, but does not canonically reduce it.
// Inputs and output may alias; out is unchanged on error.
func ExperimentalIFMAMultiplyComposableX4(out, x, y *IFMAElementX4) error {
	if !ExperimentalIFMAAvailable() {
		return ErrIFMAUnavailable
	}
	if !isIFMAElementX4(x) || !isIFMAElementX4(y) {
		return errIFMAComposableInputRange
	}
	return ifmaMultiplyComposableUncheckedX4(out, x, y)
}

// ifmaMultiplyComposableUncheckedX4 omits CPU and u52 input scans. It is for
// statically bound point schedules that gate once at their API boundary and
// preserve the composable type's range invariant internally. The raw product
// is still normalized and checked before it can re-enter another multiply.
func ifmaMultiplyComposableUncheckedX4(out, x, y *IFMAElementX4) error {
	var product IFMAProductX4
	ifmaMulRawX4(&product, &x.limbs, &y.limbs)
	normalized, ok := normalizeIFMAProductX4(&product)
	if !ok {
		return errIFMAOutputRange
	}
	out.limbs = normalized
	return nil
}

// ExperimentalIFMAMultiplyComposableX8 is the eight-lane analogue of the
// four-lane composable multiply.
func ExperimentalIFMAMultiplyComposableX8(out, x, y *IFMAElementX8) error {
	if !ExperimentalIFMAAvailable() {
		return ErrIFMAUnavailable
	}
	if !isIFMAElementX8(x) || !isIFMAElementX8(y) {
		return errIFMAComposableInputRange
	}
	return ifmaMultiplyComposableUncheckedX8(out, x, y)
}

// ifmaMultiplyComposableUncheckedX8 is the eight-lane counterpart of
// ifmaMultiplyComposableUncheckedX4.
func ifmaMultiplyComposableUncheckedX8(out, x, y *IFMAElementX8) error {
	var product IFMAProductX8
	ifmaMulRawX8(&product, &x.limbs, &y.limbs)
	normalized, ok := normalizeIFMAProductX8(&product)
	if !ok {
		return errIFMAOutputRange
	}
	out.limbs = normalized
	return nil
}

func isIFMAElementX4(x *IFMAElementX4) bool {
	for limb := range x.limbs {
		for lane := range x.limbs[limb] {
			if x.limbs[limb][lane] >= ifmaComposableLimbLimit {
				return false
			}
		}
	}
	return true
}

func isIFMAElementX8(x *IFMAElementX8) bool {
	for limb := range x.limbs {
		for lane := range x.limbs[limb] {
			if x.limbs[limb][lane] >= ifmaComposableLimbLimit {
				return false
			}
		}
	}
	return true
}

func ifmaSubtractionBias(limb int) uint64 {
	if limb == 0 {
		return 4*(uint64(1)<<LimbBits) - 76 // 4*(2^51-19)
	}
	return 4*(uint64(1)<<LimbBits) - 4 // 4*(2^51-1)
}

func mustNormalizeIFMAProductX4(x *IFMAProductX4) LimbsX4 {
	out, ok := normalizeIFMAProductX4(x)
	if !ok {
		panic("r51x5: internal x4 composable range invariant violated")
	}
	return out
}

func mustNormalizeIFMAProductX8(x *IFMAProductX8) LimbsX8 {
	out, ok := normalizeIFMAProductX8(x)
	if !ok {
		panic("r51x5: internal x8 composable range invariant violated")
	}
	return out
}

func normalizeIFMAProductX4(x *IFMAProductX4) (LimbsX4, bool) {
	if !isIFMAProductX4(*x) {
		return LimbsX4{}, false
	}
	var out LimbsX4
	for lane := 0; lane < X4Lanes; lane++ {
		var scalar Limbs
		for limb := range scalar {
			scalar[limb] = x[limb][lane]
		}
		normalized, ok := normalizeIFMAProductLane(scalar)
		if !ok {
			return LimbsX4{}, false
		}
		for limb := range normalized {
			out[limb][lane] = normalized[limb]
		}
	}
	return out, true
}

func normalizeIFMAProductX8(x *IFMAProductX8) (LimbsX8, bool) {
	if !isIFMAProductX8(*x) {
		return LimbsX8{}, false
	}
	var out LimbsX8
	for lane := 0; lane < X8Lanes; lane++ {
		var scalar Limbs
		for limb := range scalar {
			scalar[limb] = x[limb][lane]
		}
		normalized, ok := normalizeIFMAProductLane(scalar)
		if !ok {
			return LimbsX8{}, false
		}
		for limb := range normalized {
			out[limb][lane] = normalized[limb]
		}
	}
	return out, true
}

// normalizeIFMAProductLane carries one u61 folded product back into the u52
// multiplicand domain. Carries into limbs one through four are at most 1024.
// The final top carry is at most 1024, so folding it contributes at most
// 19*1024 to an already masked limb zero. Consequently limb zero is below
// 2^51+19*1024 < 2^52 and all other limbs are below 2^51.
func normalizeIFMAProductLane(x Limbs) (Limbs, bool) {
	for _, limb := range x {
		if limb >= ifmaProductLimbLimit {
			return Limbs{}, false
		}
	}
	for limb := 0; limb < 4; limb++ {
		carry := x[limb] >> LimbBits
		x[limb] &= limbMask
		x[limb+1] += carry // < 2^61 + 2^10, so no uint64 overflow.
	}
	carry := x[4] >> LimbBits
	if carry > ifmaFoldCarryMax {
		return Limbs{}, false
	}
	x[4] &= limbMask
	x[0] += 19 * carry
	if x[0] >= ifmaPostCarryLimb0Limit || !IsIFMAMultiplicand(x) {
		return Limbs{}, false
	}
	return x, true
}
