package r43x6

import "math/bits"

// Add sets z = x + y mod p and returns z. Inputs and output may alias.
func (z *Element) Add(x, y *Element) *Element {
	var accum [6]uint128
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
	if delta == (Limbs{}) {
		z.limbs = Limbs{}
	} else {
		z.limbs = subtractLimbs(modulusLimbs, delta)
	}
	return z
}

// Negate sets z = -x mod p and returns z. Input and output may alias.
func (z *Element) Negate(x *Element) *Element {
	xl := x.limbs
	if xl == (Limbs{}) {
		z.limbs = Limbs{}
	} else {
		z.limbs = subtractLimbs(modulusLimbs, xl)
	}
	return z
}

// Multiply sets z = x*y mod p and returns z. Inputs and output may alias.
//
// Before explicit IFMA activation this is scalar reference arithmetic. After
// activation it dispatches to the guarded assembly correctness kernel. Both
// paths use the same radix identity: 2^(43*6) = 2^258 = 152 (mod p). Products
// above limb five are folded back by that factor before carry propagation.
func (z *Element) Multiply(x, y *Element) *Element {
	if ExperimentalIFMAEnabled() {
		if err := ifmaMultiply(z, x, y); err != nil {
			panic(err)
		}
		return z
	}
	return z.multiplyReference(x, y)
}

// multiplyReference is the scalar correctness oracle for the IFMA kernel.
// Keep it independent of the dispatching Multiply method so hardware tests
// still have a trustworthy expected result after the one-way IFMA switch.
func (z *Element) multiplyReference(x, y *Element) *Element {
	xl, yl := x.limbs, y.limbs
	var accum [6]uint128
	for i := 0; i < 6; i++ {
		for j := 0; j < 6; j++ {
			k := i + j
			scale := uint64(1)
			if k >= 6 {
				k -= 6
				scale = 152
			}
			accum[k].addProduct(xl[i], yl[j], scale)
		}
	}
	z.limbs = reduceAccumulators(&accum)
	return z
}

// Square sets z = x^2 mod p and returns z. Input and output may alias.
func (z *Element) Square(x *Element) *Element { return z.Multiply(x, x) }

// Invert sets z = x^(p-2) mod p and returns z. Invert(0) is defined as zero,
// matching the fixed exponentiation used by the field backends.
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

// Pow22523 sets z = x^(2^252-3) mod p and returns z. This is the exponent
// needed by the Edwards25519 square-root ratio calculation.
func (z *Element) Pow22523(x *Element) *Element {
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
	return z.repeatedSquareMultiply(&x250, &base, 2)
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

// IsNegative returns the least significant bit of z's canonical encoding,
// which is the Edwards25519 definition of a negative field element.
func (z *Element) IsNegative() int { return int(z.limbs[0] & 1) }

// SqrtRatio sets z to the nonnegative square root of u/v and returns z,1 when
// the ratio is square. For nonsquare ratios it returns the deterministic
// Ristretto-style representative and 0. This is the same root-selection rule
// used by the vendored Go Edwards25519 decoder.
func (z *Element) SqrtRatio(u, v *Element) (*Element, int) {
	// r = u*(u*v)^((p-5)/8). Then v*r^2/u is the quartic
	// character of u*v: +1 or -1 for square ratios, and +i or -i for
	// nonsquare ratios. This is equivalent to the conventional uv^3/uv^7
	// construction while avoiding its v^2, v^3, and v^7 precomputation.
	var uv, pow, r Element
	uv.Multiply(u, v)
	pow.Pow22523(&uv)
	r.Multiply(u, &pow)

	var r2, check, negU, negUSqrtM1 Element
	r2.Square(&r)
	check.Multiply(v, &r2)
	negU.Negate(u)
	negUSqrtM1.Multiply(&negU, &sqrtM1)

	correct := check.Equal(u)
	flipped := check.Equal(&negU)
	flippedI := check.Equal(&negUSqrtM1)
	if flipped|flippedI != 0 {
		r.Multiply(&r, &sqrtM1)
	}
	if r.IsNegative() != 0 {
		r.Negate(&r)
	}
	z.Set(&r)
	return z, correct | flipped
}

func zeroBit(x uint64) int {
	return int(1 ^ ((x | -x) >> 63))
}

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

// shiftRight returns z >> n. All accumulator bounds in this package guarantee
// that the result fits in 64 bits.
func (z uint128) shiftRight(n uint) uint64 {
	return z.lo>>n | z.hi<<(64-n)
}

func reduceAccumulators(accum *[6]uint128) Limbs {
	for {
		for i := 0; i < 5; i++ {
			carry := accum[i].shiftRight(LimbBits)
			accum[i] = uint128{lo: accum[i].lo & limbMask}
			accum[i+1].add64(carry)
		}

		carry := accum[5].shiftRight(TopLimbBits)
		accum[5] = uint128{lo: accum[5].lo & topMask}
		if carry == 0 {
			break
		}
		accum[0].add64(19 * carry)
	}

	result := Limbs{
		accum[0].lo, accum[1].lo, accum[2].lo,
		accum[3].lo, accum[4].lo, accum[5].lo,
	}
	if compareLimbs(result, modulusLimbs) >= 0 {
		result = subtractLimbs(result, modulusLimbs)
	}
	return result
}

// subtractLimbs returns x-y. It requires x >= y and both operands to use the
// canonical 43/40-bit limb widths (x itself may equal p).
func subtractLimbs(x, y Limbs) Limbs {
	var z Limbs
	borrow := uint64(0)
	for i := 0; i < 6; i++ {
		base := uint64(1 << LimbBits)
		if i == 5 {
			base = 1 << TopLimbBits
		}
		subtrahend := y[i] + borrow
		if x[i] >= subtrahend {
			z[i] = x[i] - subtrahend
			borrow = 0
		} else {
			z[i] = x[i] + base - subtrahend
			borrow = 1
		}
	}
	return z
}
