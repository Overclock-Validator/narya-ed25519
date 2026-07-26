package heea8l

import (
	"encoding/binary"
	"math/bits"
)

// SignedCoefficient is the fixed-width representation handed to a future
// signed-integer scalar-multiplication backend. Limbs are a little-endian
// unsigned magnitude. Negative is false for zero.
//
// This type describes an integer, not a scalar modulo L. Reducing it modulo L
// before multiplying a point with a torsion component would change the strict
// verification predicate.
type SignedCoefficient struct {
	Limbs    [4]uint64
	Negative bool
}

// Sign reports -1, 0, or +1.
func (x SignedCoefficient) Sign() int {
	if uint256(x.Limbs).isZero() {
		return 0
	}
	if x.Negative {
		return -1
	}
	return 1
}

// BitLen reports the length of the unsigned magnitude in bits.
func (x SignedCoefficient) BitLen() int { return uint256(x.Limbs).bitLen() }

// BytesLE returns the unsigned magnitude in little-endian form. The sign is
// deliberately separate and must be consumed by signed-integer point code.
func (x SignedCoefficient) BytesLE() (out [32]byte) {
	for i, limb := range x.Limbs {
		binary.LittleEndian.PutUint64(out[8*i:], limb)
	}
	return out
}

// FixedCandidate is the allocation-free representation of Candidate.
type FixedCandidate struct {
	Rho     SignedCoefficient
	Tau     SignedCoefficient
	Epsilon int8
}

// BitLen reports max(bitlen(abs(Rho)), bitlen(abs(Tau))).
func (c *FixedCandidate) BitLen() int {
	if rhoBits := c.Rho.BitLen(); rhoBits > c.Tau.BitLen() {
		return rhoBits
	}
	return c.Tau.BitLen()
}

// UnitMultiplier reports whether Tau is invertible modulo the full Edwards
// group exponent 8L. This is the injectivity condition required for the
// transformed equation to be equivalent to the strict equation. In
// particular, oddness alone is not sufficient: Tau=L is odd but is not a
// unit and annihilates every prime-order error point.
func (c *FixedCandidate) UnitMultiplier() bool {
	return coprimeToModulus(uint256(c.Tau.Limbs), fixedModulus)
}

// FixedSelection is the allocation-free counterpart of Selection. Candidate
// remains populated on a width fallback for diagnostics.
type FixedSelection struct {
	Candidate    FixedCandidate
	UseCandidate bool
	Fallback     FallbackReason
}

// SelectFixed performs the same modulo-8L candidate search as Select using
// fixed-size integer arithmetic. k is a canonical scalar challenge encoded in
// little-endian form and must be in [0,L).
//
// This remains research code. It is variable-time, has not been integrated
// with point multiplication, and makes no side-channel claim.
func SelectFixed(kBytes [32]byte, limit WidthLimit) FixedSelection {
	if limit != Width128 && limit != Width132 && limit != Width136 {
		return FixedSelection{Fallback: FallbackInvalidWidth}
	}
	k := uint256FromBytesLE(kBytes)
	if k.cmp(fixedOrder) >= 0 {
		return FixedSelection{Fallback: FallbackInvalidChallenge}
	}
	return selectFixed(k, limit, divMod256)
}

type divide256 func(uint256, uint256) (uint256, uint256)

func selectFixed(k uint256, limit WidthLimit, divide divide256) FixedSelection {
	return selectFixedMode(k, limit, divide, false)
}

func selectFixedBatched(k uint256, limit WidthLimit, divide divide256) FixedSelection {
	return selectFixedMode(k, limit, divide, true)
}

func selectFixedMode(k uint256, limit WidthLimit, divide divide256, batched bool) FixedSelection {
	best, ok := bestFixedForModulus(fixedModulus, k, divide, batched)
	if !ok {
		return FixedSelection{Fallback: FallbackWidthExceeded}
	}
	result := FixedSelection{Candidate: best.external()}
	if best.bitLen() > int(limit) {
		result.Fallback = FallbackWidthExceeded
		return result
	}
	result.UseCandidate = true
	result.Fallback = NoFallback
	return result
}

type uint256 [4]uint64

var (
	fixedOrder = uint256{
		0x5812631a5cf5d3ed,
		0x14def9dea2f79cd6,
		0x0000000000000000,
		0x1000000000000000,
	}
	fixedModulus = uint256{
		0xc09318d2e7ae9f68,
		0xa6f7cef517bce6b2,
		0x0000000000000000,
		0x8000000000000000,
	}
	fixedOddOrderMultiples = [...]uint256{
		fixedOrder,
		{0x0837294f16e17bc7, 0x3e9ced9be8e6d683, 0, 0x3000000000000000},
		{0xb85bef83d0cd23a1, 0x685ae1592ed6102f, 0, 0x5000000000000000},
		{0x6880b5b88ab8cb7b, 0x9218d51674c549dc, 0, 0x7000000000000000},
	}
)

func uint256FromBytesLE(in [32]byte) (out uint256) {
	for i := range out {
		out[i] = binary.LittleEndian.Uint64(in[8*i:])
	}
	return out
}

func (x uint256) cmp(y uint256) int {
	for i := len(x) - 1; i >= 0; i-- {
		if x[i] < y[i] {
			return -1
		}
		if x[i] > y[i] {
			return 1
		}
	}
	return 0
}

func (x uint256) isZero() bool { return x[0]|x[1]|x[2]|x[3] == 0 }

func (x uint256) bitLen() int {
	for i := len(x) - 1; i >= 0; i-- {
		if x[i] != 0 {
			return i*64 + bits.Len64(x[i])
		}
	}
	return 0
}

func (x uint256) bit(i uint) uint64 { return (x[i/64] >> (i % 64)) & 1 }

func (x *uint256) setBit(i uint) { x[i/64] |= uint64(1) << (i % 64) }

func add256(x, y uint256) (sum uint256, carry uint64) {
	for i := range sum {
		sum[i], carry = bits.Add64(x[i], y[i], carry)
	}
	return sum, carry
}

func sub256(x, y uint256) (difference uint256, borrow uint64) {
	for i := range difference {
		difference[i], borrow = bits.Sub64(x[i], y[i], borrow)
	}
	return difference, borrow
}

// divMod256 aligns the divisor's leading bit with the numerator and consumes
// one quotient bit per subtract-and-shift step. Unlike restoring bitwise
// division, its work is proportional to the quotient width rather than always
// scanning all 256 input bits. The shifted divisor cannot overflow: its
// leading bit is aligned at or below the numerator's leading bit.
func divMod256(numerator, denominator uint256) (quotient, remainder uint256) {
	if denominator.isZero() {
		panic("heea8l: fixed division by zero")
	}
	if numerator.cmp(denominator) < 0 {
		return uint256{}, numerator
	}
	if denominator[1]|denominator[2]|denominator[3] == 0 {
		var carry uint64
		for i := len(numerator) - 1; i >= 0; i-- {
			quotient[i], carry = bits.Div64(carry, numerator[i], denominator[0])
		}
		remainder[0] = carry
		return quotient, remainder
	}

	shift := numerator.bitLen() - denominator.bitLen()
	shifted := shl256(denominator, uint(shift))
	remainder = numerator
	for {
		if remainder.cmp(shifted) >= 0 {
			remainder, _ = sub256(remainder, shifted)
			quotient.setBit(uint(shift))
		}
		if shift == 0 {
			break
		}
		shifted = shr1_256(shifted)
		shift--
	}
	return quotient, remainder
}

func shl256(x uint256, shift uint) (out uint256) {
	if shift >= 256 {
		return out
	}
	wordShift := int(shift / 64)
	bitShift := shift % 64
	for destination := len(out) - 1; destination >= wordShift; destination-- {
		source := destination - wordShift
		out[destination] = x[source] << bitShift
		if bitShift != 0 && source > 0 {
			out[destination] |= x[source-1] >> (64 - bitShift)
		}
	}
	return out
}

func shr1_256(x uint256) uint256 {
	return uint256{
		x[0]>>1 | x[1]<<63,
		x[1]>>1 | x[2]<<63,
		x[2]>>1 | x[3]<<63,
		x[3] >> 1,
	}
}

// divMod256BitwiseOracle is the original restoring division routine. It is
// intentionally retained as an independent fixed-width test oracle. Its
// 257-bit remainder supports every nonzero 256-bit divisor.
func divMod256BitwiseOracle(numerator, denominator uint256) (quotient, remainder uint256) {
	if denominator.isZero() {
		panic("heea8l: fixed division by zero")
	}
	var wide [5]uint64
	var denominatorWide [5]uint64
	copy(denominatorWide[:4], denominator[:])
	for i := 255; i >= 0; i-- {
		carry := numerator.bit(uint(i))
		for j := range wide {
			next := wide[j] >> 63
			wide[j] = wide[j]<<1 | carry
			carry = next
		}
		if cmpWide(wide, denominatorWide) >= 0 {
			wide = subWide(wide, denominatorWide)
			quotient.setBit(uint(i))
		}
	}
	copy(remainder[:], wide[:4])
	return quotient, remainder
}

func cmpWide(x, y [5]uint64) int {
	for i := len(x) - 1; i >= 0; i-- {
		if x[i] < y[i] {
			return -1
		}
		if x[i] > y[i] {
			return 1
		}
	}
	return 0
}

func subWide(x, y [5]uint64) (difference [5]uint64) {
	var borrow uint64
	for i := range difference {
		difference[i], borrow = bits.Sub64(x[i], y[i], borrow)
	}
	return difference
}

// mul256 returns the low half of the exact 512-bit product and reports whether
// the high half is nonzero.
func mul256(x, y uint256) (product uint256, overflow bool) {
	var wide [8]uint64
	xLimbs := significantLimbs(x)
	yLimbs := significantLimbs(y)
	for i := 0; i < xLimbs; i++ {
		for j := 0; j < yLimbs; j++ {
			hi, lo := bits.Mul64(x[i], y[j])
			index := i + j
			var carry uint64
			wide[index], carry = bits.Add64(wide[index], lo, 0)
			wide[index+1], carry = bits.Add64(wide[index+1], hi, carry)
			for index += 2; carry != 0 && index < len(wide); index++ {
				wide[index], carry = bits.Add64(wide[index], 0, carry)
			}
			if carry != 0 {
				panic("heea8l: impossible 512-bit product overflow")
			}
		}
	}
	copy(product[:], wide[:4])
	overflow = wide[4]|wide[5]|wide[6]|wide[7] != 0
	return product, overflow
}

func significantLimbs(x uint256) int {
	for i := len(x); i > 0; i-- {
		if x[i-1] != 0 {
			return i
		}
	}
	return 0
}

type signed256 struct {
	mag uint256
	neg bool
}

func newSigned256(mag uint256, neg bool) signed256 {
	return signed256{mag: mag, neg: neg && !mag.isZero()}
}

func (x signed256) negate() signed256 {
	if !x.mag.isZero() {
		x.neg = !x.neg
	}
	return x
}

func addSigned256(x, y signed256) signed256 {
	if x.neg == y.neg {
		mag, carry := add256(x.mag, y.mag)
		if carry != 0 {
			panic("heea8l: signed coefficient overflow")
		}
		return newSigned256(mag, x.neg)
	}
	switch x.mag.cmp(y.mag) {
	case -1:
		mag, _ := sub256(y.mag, x.mag)
		return newSigned256(mag, y.neg)
	case 0:
		return signed256{}
	default:
		mag, _ := sub256(x.mag, y.mag)
		return newSigned256(mag, x.neg)
	}
}

func mulSigned256(x signed256, y uint256) signed256 {
	mag, overflow := mul256(x.mag, y)
	if overflow {
		panic("heea8l: signed coefficient product overflow")
	}
	return newSigned256(mag, x.neg)
}

type fixedCandidate struct {
	rho     signed256
	tau     signed256
	epsilon int8
}

func (c fixedCandidate) external() FixedCandidate {
	return FixedCandidate{
		Rho:     SignedCoefficient{Limbs: c.rho.mag, Negative: c.rho.neg},
		Tau:     SignedCoefficient{Limbs: c.tau.mag, Negative: c.tau.neg},
		Epsilon: c.epsilon,
	}
}

func (c fixedCandidate) bitLen() int {
	if rhoBits := c.rho.mag.bitLen(); rhoBits > c.tau.mag.bitLen() {
		return rhoBits
	}
	return c.tau.mag.bitLen()
}

func bestFixedForModulus(n, k uint256, divide divide256, batched bool) (fixedCandidate, bool) {
	if k.isZero() {
		return fixedCandidate{
			tau:     newSigned256(uint256{1}, false),
			epsilon: 1,
		}, true
	}

	r0, r1 := n, k
	t0 := signed256{}
	t1 := newSigned256(uint256{1}, false)
	var best fixedCandidate
	found := false
	var lookahead quotientLookahead
	for !r1.isZero() {
		considerFixed(n, &best, &found, newSigned256(r1, false), t1)

		var a, r2 uint256
		if batched {
			a, r2 = lookahead.next(r0, r1, divide)
		} else {
			a, r2 = divide(r0, r1)
		}
		aProduct, borrow := sub256(r0, r2)
		if borrow != 0 {
			panic("heea8l: invalid division remainder")
		}
		multipliers := nearbyMultipliersFixed(r0, r1, t0, t1, a, divide)
		for i := 0; i < multipliers.count; i++ {
			q := multipliers.values[i]
			qr1 := aProduct
			overflow := false
			if q != a {
				qr1, overflow = mul256(q, r1)
			}
			if overflow || qr1.cmp(r0) > 0 {
				panic("heea8l: invalid fixed intermediate row")
			}
			rho, _ := sub256(r0, qr1)
			tau := addSigned256(t0, mulSigned256(t1, q).negate())
			considerFixed(n, &best, &found, newSigned256(rho, false), tau)
		}

		t2 := addSigned256(t0, mulSigned256(t1, a).negate())
		r0, r1 = r1, r2
		t0, t1 = t1, t2
	}
	return best, found
}

// quotientLookahead is a Lehmer-style proposal queue derived from equally
// shifted leading words of consecutive EEA remainders. Every proposed
// quotient is verified against the complete 256-bit operands before use. A
// mismatch discards the queue and immediately uses the exact divider.
type quotientLookahead struct {
	values [8]uint64
	nextAt int
	count  int
}

func (l *quotientLookahead) next(r0, r1 uint256, fallback divide256) (uint256, uint256) {
	if l.nextAt == l.count {
		l.fill(r0, r1)
	}
	if l.nextAt < l.count {
		q := l.values[l.nextAt]
		product, overflow := mul256(r1, uint256{q})
		if !overflow && product.cmp(r0) <= 0 {
			remainder, _ := sub256(r0, product)
			if remainder.cmp(r1) < 0 {
				l.nextAt++
				return uint256{q}, remainder
			}
		}
		l.nextAt, l.count = 0, 0
	}
	return fallback(r0, r1)
}

func (l *quotientLookahead) fill(r0, r1 uint256) {
	l.nextAt, l.count = 0, 0
	shift := r0.bitLen() - 64
	if shift < 0 {
		shift = 0
	}
	x := shiftedLow64(r0, uint(shift))
	y := shiftedLow64(r1, uint(shift))
	if y == 0 || x < y {
		return
	}
	for l.count < len(l.values) && y != 0 {
		q := x / y
		if q == 0 {
			break
		}
		l.values[l.count] = q
		l.count++
		x, y = y, x-q*y
	}
}

func shiftedLow64(x uint256, shift uint) uint64 {
	if shift >= 256 {
		return 0
	}
	word := int(shift / 64)
	offset := shift % 64
	result := x[word] >> offset
	if offset != 0 && word+1 < len(x) {
		result |= x[word+1] << (64 - offset)
	}
	return result
}

type fixedMultipliers struct {
	values [13]uint256
	count  int
}

func nearbyMultipliersFixed(r0, r1 uint256, t0, t1 signed256, a uint256, divide divide256) fixedMultipliers {
	var result fixedMultipliers

	for d := uint64(0); d <= 2; d++ {
		du := uint256{d}
		result.add(du, a, t0, t1)
		if a.cmp(du) >= 0 {
			q, _ := sub256(a, du)
			result.add(q, a, t0, t1)
		}
	}

	center := uint256{}
	if r0.cmp(t0.mag) > 0 {
		numerator, _ := sub256(r0, t0.mag)
		denominator, carry := add256(r1, t1.mag)
		if carry == 0 {
			center, _ = divide(numerator, denominator)
			if center.cmp(a) > 0 {
				center = a
			}
		}
	}
	for d := int64(-3); d <= 3; d++ {
		if d < 0 {
			du := uint256{uint64(-d)}
			if center.cmp(du) >= 0 {
				q, _ := sub256(center, du)
				result.add(q, a, t0, t1)
			}
			continue
		}
		q, carry := add256(center, uint256{uint64(d)})
		if carry == 0 {
			result.add(q, a, t0, t1)
		}
	}
	return result
}

func (m *fixedMultipliers) add(q, a uint256, t0, t1 signed256) {
	if q.cmp(a) > 0 {
		return
	}
	// EEA coefficient rows start at (0,1) and thereafter have opposite
	// signs. Thus t0-q*t1 can be zero only in the initial q=0 case. Its
	// parity needs only the low bits because subtraction and addition agree
	// modulo two. Computing the complete coefficient here was redundant: it
	// is constructed exactly once later for each retained multiplier.
	if (t0.mag.isZero() && q.isZero()) || (t0.mag[0]^(q[0]&t1.mag[0]))&1 == 0 {
		return
	}
	for i := 0; i < m.count; i++ {
		if m.values[i] == q {
			return
		}
	}
	m.values[m.count] = q
	m.count++
}

func considerFixed(n uint256, best *fixedCandidate, found *bool, rho, tau signed256) {
	if tau.mag.isZero() || tau.mag[0]&1 == 0 || !coprimeToModulus(tau.mag, n) {
		return
	}
	candidate := fixedCandidate{rho: rho, tau: tau, epsilon: 1}
	if !*found || betterFixed(candidate, *best) {
		*best = candidate
		*found = true
	}
}

func coprimeToModulus(x, n uint256) bool {
	if x[0]&1 == 0 {
		return false
	}
	if n != fixedModulus {
		for !n.isZero() {
			_, remainder := divMod256(x, n)
			x, n = n, remainder
		}
		return x == (uint256{1})
	}
	// Every coefficient generated by the EEA is at most 8L. Since L is
	// prime, an odd coefficient is non-coprime to 8L exactly at an odd
	// multiple of L below 8L.
	for _, multiple := range fixedOddOrderMultiples {
		if x == multiple {
			return false
		}
	}
	return true
}

func betterFixed(x, y fixedCandidate) bool {
	if xWidth, yWidth := x.bitLen(), y.bitLen(); xWidth != yWidth {
		return xWidth < yWidth
	}
	xMax := max256(x.rho.mag, x.tau.mag)
	yMax := max256(y.rho.mag, y.tau.mag)
	if cmp := xMax.cmp(yMax); cmp != 0 {
		return cmp < 0
	}
	xSum, xCarry := add256(x.rho.mag, x.tau.mag)
	ySum, yCarry := add256(y.rho.mag, y.tau.mag)
	if xCarry != yCarry {
		return xCarry < yCarry
	}
	if cmp := xSum.cmp(ySum); cmp != 0 {
		return cmp < 0
	}
	if cmp := x.tau.mag.cmp(y.tau.mag); cmp != 0 {
		return cmp < 0
	}
	return compareSigned256(x.tau, y.tau) > 0
}

func max256(x, y uint256) uint256 {
	if x.cmp(y) >= 0 {
		return x
	}
	return y
}

func compareSigned256(x, y signed256) int {
	if x.neg != y.neg {
		if x.neg {
			return -1
		}
		return 1
	}
	cmp := x.mag.cmp(y.mag)
	if x.neg {
		return -cmp
	}
	return cmp
}
