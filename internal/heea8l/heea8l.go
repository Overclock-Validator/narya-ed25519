// Package heea8l contains an exact-arithmetic research implementation of
// HEEA candidate selection modulo 8 times the Ed25519 scalar order.
//
// It is deliberately isolated from signature verification. The code uses
// math/big, allocates freely, and returns an explicit fallback whenever its
// candidate does not fit the requested experimental width. It is an oracle
// and measurement vehicle, not a production scalar-decomposition backend.
package heea8l

import "math/big"

// WidthLimit is an experimental admission limit for both signed
// coefficients. These are the only limits accepted by Select.
type WidthLimit uint16

const (
	Width128 WidthLimit = 128
	Width132 WidthLimit = 132
	Width136 WidthLimit = 136
)

// FallbackReason explains why a selection must use the original verifier.
type FallbackReason uint8

const (
	NoFallback FallbackReason = iota
	FallbackInvalidWidth
	FallbackInvalidChallenge
	FallbackWidthExceeded
)

func (r FallbackReason) String() string {
	switch r {
	case NoFallback:
		return "none"
	case FallbackInvalidWidth:
		return "invalid-width"
	case FallbackInvalidChallenge:
		return "invalid-challenge"
	case FallbackWidthExceeded:
		return "width-exceeded"
	default:
		return "unknown"
	}
}

// Candidate is an exact signed relation
//
//	Rho = Epsilon * Tau * k (mod 8L), Epsilon in {-1,+1}.
//
// Rho and Tau must be consumed as signed integers by any future research
// backend. In particular, they must not be reduced modulo L before they are
// used as multipliers of points which may contain torsion.
type Candidate struct {
	Rho     big.Int
	Tau     big.Int
	Epsilon int8
}

// BitLen reports max(bitlen(abs(Rho)), bitlen(abs(Tau))).
func (c *Candidate) BitLen() int {
	rhoBits := c.Rho.BitLen()
	tauBits := c.Tau.BitLen()
	if rhoBits > tauBits {
		return rhoBits
	}
	return tauBits
}

// Selection makes fallback an explicit part of the research API. Candidate
// is retained on a width fallback for diagnostics, but UseCandidate is the
// only admission signal.
type Selection struct {
	Candidate    Candidate
	UseCandidate bool
	Fallback     FallbackReason
}

var (
	ed25519Order = func() *big.Int {
		// L = 2^252 + 27742317777372353535851937790883648493.
		l := new(big.Int).Lsh(big.NewInt(1), 252)
		c, ok := new(big.Int).SetString("27742317777372353535851937790883648493", 10)
		if !ok {
			panic("heea8l: invalid scalar-order constant")
		}
		return l.Add(l, c)
	}()
	ed25519Exponent = new(big.Int).Lsh(new(big.Int).Set(ed25519Order), 3)
)

// Order returns a fresh copy of the Ed25519 prime-subgroup order L.
func Order() *big.Int { return new(big.Int).Set(ed25519Order) }

// Modulus returns a fresh copy of N = 8L, an exponent of the full Edwards25519
// group used by the exact candidate relation.
func Modulus() *big.Int { return new(big.Int).Set(ed25519Exponent) }

// Select searches principal and parity-aware nearby intermediate EEA rows for
// a short candidate modulo N=8L. k must be a canonical challenge scalar in
// [0,L). Only a Tau coprime to 8L (equivalently nonzero and odd under these
// width limits) is admitted; every other result explicitly falls back to the
// original verifier.
func Select(k *big.Int, limit WidthLimit) Selection {
	if limit != Width128 && limit != Width132 && limit != Width136 {
		return Selection{Fallback: FallbackInvalidWidth}
	}
	if k == nil || k.Sign() < 0 || k.Cmp(ed25519Order) >= 0 {
		return Selection{Fallback: FallbackInvalidChallenge}
	}
	return selectForModulus(ed25519Exponent, k, int(limit))
}

func selectForModulus(n, k *big.Int, limit int) Selection {
	if n == nil || n.Sign() <= 0 || k == nil || k.Sign() < 0 || k.Cmp(n) >= 0 || limit <= 0 {
		return Selection{Fallback: FallbackInvalidChallenge}
	}

	best, ok := bestForModulus(n, k)
	if !ok {
		// Tau=1, Rho=k is always a candidate for valid inputs, so this is
		// defensive rather than an expected outcome.
		return Selection{Fallback: FallbackWidthExceeded}
	}
	result := Selection{Candidate: best}
	if best.BitLen() > limit {
		result.Fallback = FallbackWidthExceeded
		return result
	}
	result.UseCandidate = true
	result.Fallback = NoFallback
	return result
}

// bestForModulus walks exact EEA rows r=u*n+t*k. At every step it considers
// principal endpoints and the parity-valid intermediate rows nearest the
// L-infinity norm crossing. The work per Euclidean quotient is constant even
// when the quotient itself is large.
func bestForModulus(n, k *big.Int) (Candidate, bool) {
	if k.Sign() == 0 {
		var c Candidate
		c.Tau.SetInt64(1)
		c.Epsilon = 1
		return c, true
	}

	r0 := new(big.Int).Set(n)
	r1 := new(big.Int).Set(k)
	t0 := new(big.Int)
	t1 := big.NewInt(1)

	var best Candidate
	found := false
	for r1.Sign() != 0 {
		// r1 is a principal row. It would normally reappear as q=0 in
		// the next iteration, except when the next remainder is zero.
		consider(n, &best, &found, r1, t1)

		a := new(big.Int)
		r2 := new(big.Int)
		a.QuoRem(r0, r1, r2)

		for _, q := range nearbyMultipliers(r0, r1, t0, t1, a) {
			rho := new(big.Int).Mul(q, r1)
			rho.Sub(r0, rho)
			tau := new(big.Int).Mul(q, t1)
			tau.Sub(t0, tau)
			consider(n, &best, &found, rho, tau)
		}

		t2 := new(big.Int).Mul(a, t1)
		t2.Sub(t0, t2)
		r0, r1 = r1, r2
		t0, t1 = t1, t2
	}
	return best, found
}

// nearbyMultipliers returns a constant-size set containing the parity-valid
// endpoints and the parity-valid integers nearest
//
//	q* = (r0-|t0|)/(r1+|t1|)
//
// in the closed intermediate-row interval [0,a].
func nearbyMultipliers(r0, r1, t0, t1, a *big.Int) []*big.Int {
	seen := make(map[string]struct{}, 16)
	qs := make([]*big.Int, 0, 12)
	add := func(q *big.Int) {
		if q.Sign() < 0 || q.Cmp(a) > 0 {
			return
		}
		tau := new(big.Int).Mul(q, t1)
		tau.Sub(t0, tau)
		if tau.Sign() == 0 || tau.Bit(0) == 0 {
			return
		}
		key := q.String()
		if _, duplicate := seen[key]; duplicate {
			return
		}
		seen[key] = struct{}{}
		qs = append(qs, new(big.Int).Set(q))
	}

	// Include the nearest parity class at both interval boundaries.
	for d := int64(0); d <= 2; d++ {
		add(big.NewInt(d))
		add(new(big.Int).Sub(a, big.NewInt(d)))
	}

	absT0 := new(big.Int).Abs(new(big.Int).Set(t0))
	numerator := new(big.Int).Sub(r0, absT0)
	center := new(big.Int)
	if numerator.Sign() > 0 {
		denominator := new(big.Int).Abs(new(big.Int).Set(t1))
		denominator.Add(denominator, r1)
		center.Quo(numerator, denominator)
		if center.Cmp(a) > 0 {
			center.Set(a)
		}
	}
	// Parity-valid q values occur either at every integer or every other
	// integer. This window contains both neighbors in the allowed class.
	for d := int64(-3); d <= 3; d++ {
		add(new(big.Int).Add(center, big.NewInt(d)))
	}
	return qs
}

func consider(n *big.Int, best *Candidate, found *bool, rho, tau *big.Int) {
	if tau.Sign() == 0 || tau.Bit(0) == 0 {
		return
	}
	if new(big.Int).GCD(nil, nil, abs(tau), n).BitLen() != 1 {
		return
	}
	c := Candidate{Epsilon: 1}
	c.Rho.Set(rho)
	c.Tau.Set(tau)
	if !*found || better(&c, best) {
		*best = c
		*found = true
	}
}

func better(a, b *Candidate) bool {
	if aw, bw := a.BitLen(), b.BitLen(); aw != bw {
		return aw < bw
	}
	aMax := maxAbs(&a.Rho, &a.Tau)
	bMax := maxAbs(&b.Rho, &b.Tau)
	if cmp := aMax.Cmp(bMax); cmp != 0 {
		return cmp < 0
	}
	aSum := new(big.Int).Add(abs(&a.Rho), abs(&a.Tau))
	bSum := new(big.Int).Add(abs(&b.Rho), abs(&b.Tau))
	if cmp := aSum.Cmp(bSum); cmp != 0 {
		return cmp < 0
	}
	if cmp := abs(&a.Tau).Cmp(abs(&b.Tau)); cmp != 0 {
		return cmp < 0
	}
	return a.Tau.Cmp(&b.Tau) > 0
}

func maxAbs(a, b *big.Int) *big.Int {
	aa := abs(a)
	ab := abs(b)
	if aa.Cmp(ab) >= 0 {
		return aa
	}
	return ab
}

func abs(x *big.Int) *big.Int { return new(big.Int).Abs(new(big.Int).Set(x)) }
