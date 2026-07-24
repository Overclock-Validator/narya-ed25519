package r51x5

import "math/bits"

// Add sets z = x + y mod p and returns z. Inputs and output may alias.
func (z *Element) Add(x, y *Element) *Element {
	var accum [5]uint128
	for i := range accum {
		accum[i].lo = x.limbs[i] + y.limbs[i]
	}
	z.limbs = reduceAccumulators(&accum)
	return z
}

// Subtract sets z = x - y mod p and returns z. Inputs and output may alias.
func (z *Element) Subtract(x, y *Element) *Element {
	xl, yl := x.limbs, y.limbs
	if compareLimbs(xl, yl) >= 0 {
		z.limbs = subtractLimbs(xl, yl)
		return z
	}
	delta := subtractLimbs(yl, xl)
	z.limbs = subtractLimbs(modulusLimbs, delta)
	return z
}

// Negate sets z = -x mod p and returns z. Input and output may alias.
func (z *Element) Negate(x *Element) *Element {
	if x.limbs == (Limbs{}) {
		z.limbs = Limbs{}
	} else {
		z.limbs = subtractLimbs(modulusLimbs, x.limbs)
	}
	return z
}

// Multiply sets z = x*y mod p and returns z. Inputs and output may alias.
//
// This scalar oracle accumulates all 25 limb products exactly. Terms above
// limb four are folded with 2^255 = 19 (mod p), then carry-propagated and
// canonically reduced. Reduced 51-bit inputs bound every accumulator below
// 2^110, comfortably inside uint128.
func (z *Element) Multiply(x, y *Element) *Element {
	xl, yl := x.limbs, y.limbs
	var accum [5]uint128
	for i := 0; i < 5; i++ {
		for j := 0; j < 5; j++ {
			k := i + j
			scale := uint64(1)
			if k >= 5 {
				k -= 5
				scale = 19
			}
			accum[k].addProduct(xl[i], yl[j], scale)
		}
	}
	z.limbs = reduceAccumulators(&accum)
	return z
}

// Square sets z = x^2 mod p and returns z. Input and output may alias.
func (z *Element) Square(x *Element) *Element { return z.Multiply(x, x) }

// Invert sets z = x^(p-2) mod p and returns z. Invert(0) is zero, matching
// the fixed-exponent field implementations used elsewhere in Narya.
func (z *Element) Invert(x *Element) *Element {
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
	return z.repeatedSquareMultiply(&x250, &x11, 5)
}

// Equal returns 1 when z and x represent the same field element and 0
// otherwise. Elements are reduced, so limb equality is field equality.
func (z *Element) Equal(x *Element) int {
	var diff uint64
	for i := range z.limbs {
		diff |= z.limbs[i] ^ x.limbs[i]
	}
	return zeroBit(diff)
}

// IsZero returns 1 when z is zero and 0 otherwise.
func (z *Element) IsZero() int {
	var aggregate uint64
	for _, x := range z.limbs {
		aggregate |= x
	}
	return zeroBit(aggregate)
}

// IsNegative returns the least significant bit of z's canonical encoding.
func (z *Element) IsNegative() int { return int(z.limbs[0] & 1) }

func zeroBit(x uint64) int { return int(1 ^ ((x | -x) >> 63)) }

func (z *Element) repeatedSquareMultiply(x, y *Element, count int) *Element {
	z.Set(x)
	for i := 0; i < count; i++ {
		z.Square(z)
	}
	return z.Multiply(z, y)
}

type uint128 struct {
	lo uint64
	hi uint64
}

func (z *uint128) addProduct(x, y, scale uint64) {
	hi, lo := bits.Mul64(x, y)
	if scale != 1 {
		scaleHi, scaleLo := bits.Mul64(lo, scale)
		lo = scaleLo
		hi = scaleHi + hi*scale
	}
	var carry uint64
	z.lo, carry = bits.Add64(z.lo, lo, 0)
	z.hi, _ = bits.Add64(z.hi, hi, carry)
}

func (z *uint128) add64(x uint64) {
	var carry uint64
	z.lo, carry = bits.Add64(z.lo, x, 0)
	z.hi, _ = bits.Add64(z.hi, 0, carry)
}

// shiftRight returns z >> n. The arithmetic bounds above guarantee that the
// result fits in 64 bits.
func (z uint128) shiftRight(n uint) uint64 {
	return z.lo>>n | z.hi<<(64-n)
}

func reduceAccumulators(accum *[5]uint128) Limbs {
	for {
		for i := 0; i < 4; i++ {
			carry := accum[i].shiftRight(LimbBits)
			accum[i] = uint128{lo: accum[i].lo & limbMask}
			accum[i+1].add64(carry)
		}

		carry := accum[4].shiftRight(LimbBits)
		accum[4] = uint128{lo: accum[4].lo & limbMask}
		if carry == 0 {
			break
		}
		// The maximum first-pass top carry is below 2^54, so 19*carry
		// fits in uint64. Later passes are smaller.
		accum[0].add64(19 * carry)
	}

	result := Limbs{
		accum[0].lo,
		accum[1].lo,
		accum[2].lo,
		accum[3].lo,
		accum[4].lo,
	}
	if compareLimbs(result, modulusLimbs) >= 0 {
		result = subtractLimbs(result, modulusLimbs)
	}
	return result
}
