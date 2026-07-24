package heea8l

import (
	"crypto/sha512"
	"encoding/binary"
	"math/big"
	"testing"
)

func TestCandidateCongruenceAndAdmission(t *testing.T) {
	n := Modulus()
	l := Order()
	for i := uint64(0); i < 1024; i++ {
		k := sampledChallenge(i, l)
		for _, limit := range []WidthLimit{Width128, Width132, Width136} {
			s := Select(k, limit)
			if s.Fallback == FallbackInvalidChallenge || s.Fallback == FallbackInvalidWidth {
				t.Fatalf("sample %d limit %d: unexpected fallback %v", i, limit, s.Fallback)
			}
			checkCandidate(t, n, k, &s.Candidate)
			if s.UseCandidate {
				if s.Fallback != NoFallback {
					t.Fatalf("sample %d: admitted with fallback %v", i, s.Fallback)
				}
				if got := s.Candidate.BitLen(); got > int(limit) {
					t.Fatalf("sample %d: admitted width %d over limit %d", i, got, limit)
				}
			} else if s.Fallback != FallbackWidthExceeded {
				t.Fatalf("sample %d: non-admission fallback = %v", i, s.Fallback)
			}
		}
	}
}

func TestZeroChallengeAndExplicitFallbacks(t *testing.T) {
	zero := new(big.Int)
	s := Select(zero, Width128)
	if !s.UseCandidate || s.Candidate.Rho.Sign() != 0 || s.Candidate.Tau.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("k=0 selection = %+v", s)
	}
	checkCandidate(t, Modulus(), zero, &s.Candidate)

	if got := Select(big.NewInt(1), WidthLimit(129)); got.UseCandidate || got.Fallback != FallbackInvalidWidth {
		t.Fatalf("invalid width selection = %+v", got)
	}
	for _, k := range []*big.Int{nil, big.NewInt(-1), Order()} {
		if got := Select(k, Width128); got.UseCandidate || got.Fallback != FallbackInvalidChallenge {
			t.Fatalf("invalid challenge %v selection = %+v", k, got)
		}
	}
}

func TestPathologicalChallengeLowerBound(t *testing.T) {
	n := Modulus()
	k := new(big.Int).Sub(n, big.NewInt(2))
	k.Quo(k, big.NewInt(10))
	if k.Cmp(Order()) >= 0 {
		t.Fatal("pathological challenge is not reduced modulo L")
	}
	for _, limit := range []WidthLimit{Width128, Width132, Width136} {
		s := Select(k, limit)
		if s.UseCandidate || s.Fallback != FallbackWidthExceeded {
			t.Fatalf("pathological k admitted at width %d: %+v", limit, s)
		}
		checkCandidate(t, n, k, &s.Candidate)
		if s.Candidate.BitLen() < 252 {
			t.Fatalf("pathological candidate only %d bits", s.Candidate.BitLen())
		}
		max := maxAbs(&s.Candidate.Rho, &s.Candidate.Tau)
		if new(big.Int).Mul(max, big.NewInt(12)).Cmp(n) < 0 {
			t.Fatalf("candidate violates proven N/12 lower bound: rho=%s tau=%s", &s.Candidate.Rho, &s.Candidate.Tau)
		}
	}
}

func TestDeterministicWidthDistribution(t *testing.T) {
	const samples = 8192
	got := distribution(samples)
	// This fixed-seed snapshot makes candidate-selection and tie-breaking
	// changes visible. It is not a claim about cryptographic probabilities.
	want := map[WidthLimit]int{
		Width128: 899,
		Width132: 4,
		Width136: 0,
	}
	for _, width := range []WidthLimit{Width128, Width132, Width136} {
		if got[width] != want[width] {
			t.Fatalf("width %d fallbacks=%d want %d (all=%v)", width, got[width], want[width], got)
		}
	}
	if got[Width128] < got[Width132] || got[Width132] < got[Width136] {
		t.Fatalf("fallback counts are not monotone: %v", got)
	}
}

// TestSmallModuliAgainstExactOracle checks the constant-work nearby-row
// selector against exhaustive odd-Tau search on reduced analogues N=8*l.
func TestSmallModuliAgainstExactOracle(t *testing.T) {
	for _, smallL := range []int64{3, 5, 7, 11, 13, 17, 19, 23, 29, 31} {
		n := big.NewInt(8 * smallL)
		for kval := int64(0); kval < smallL; kval++ {
			k := big.NewInt(kval)
			for width := 1; width <= n.BitLen(); width++ {
				fast := selectForModulus(n, k, width).UseCandidate
				exact := exactCandidateExists(n, k, width)
				if fast != exact {
					t.Fatalf("N=%d k=%d width=%d: nearby selector=%v exact=%v", n, kval, width, fast, exact)
				}
			}
		}
	}
}

func TestParityAwareIntermediateCandidate(t *testing.T) {
	// The best principal row is (rho,tau)=(16,1), which needs five
	// bits. The parity-valid intermediate row (8,9) needs four.
	n := big.NewInt(136)
	k := big.NewInt(16)
	s := selectForModulus(n, k, 4)
	if !s.UseCandidate {
		t.Fatalf("missed four-bit intermediate candidate: %+v", s)
	}
	checkCandidate(t, n, k, &s.Candidate)
	if s.Candidate.BitLen() != 4 || abs(&s.Candidate.Rho).Cmp(big.NewInt(8)) != 0 || abs(&s.Candidate.Tau).Cmp(big.NewInt(9)) != 0 {
		t.Fatalf("candidate=(%s,%s), want signs of (8,9)", &s.Candidate.Rho, &s.Candidate.Tau)
	}
}

func TestTerminalPrincipalRows(t *testing.T) {
	n := big.NewInt(136)
	for _, kval := range []int64{1, 2, 4, 8} {
		k := big.NewInt(kval)
		s := selectForModulus(n, k, k.BitLen())
		if !s.UseCandidate {
			t.Fatalf("N=136 k=%d: missed terminal principal row: %+v", kval, s)
		}
		checkCandidate(t, n, k, &s.Candidate)
	}
}

// TestFullModulusSemiconvergentCoverage independently derives every
// width-feasible parity-valid interval on each EEA segment. It guards against
// a nearby-q selector miss without enumerating enormous Euclidean quotients.
func TestFullModulusSemiconvergentCoverage(t *testing.T) {
	n := Modulus()
	l := Order()
	for i := uint64(0); i < 1024; i++ {
		k := sampledChallenge(10_000+i, l)
		candidate, ok := bestForModulus(n, k)
		if !ok {
			t.Fatalf("sample %d: no candidate", i)
		}
		for _, width := range []int{128, 132, 136} {
			fast := candidate.BitLen() <= width
			exactRows := semiconvergentExistsWithin(n, k, width)
			if fast != exactRows {
				t.Fatalf("sample %d width %d: selector=%v exact-row-interval=%v candidate=(%s,%s)",
					i, width, fast, exactRows, &candidate.Rho, &candidate.Tau)
			}
		}
	}
}

func checkCandidate(t *testing.T, n, k *big.Int, c *Candidate) {
	t.Helper()
	if c.Epsilon != 1 && c.Epsilon != -1 {
		t.Fatalf("epsilon=%d, want +/-1", c.Epsilon)
	}
	if c.Tau.Sign() == 0 || c.Tau.Bit(0) == 0 {
		t.Fatalf("tau=%s, want nonzero odd", &c.Tau)
	}
	if gcd := new(big.Int).GCD(nil, nil, abs(&c.Tau), n); gcd.BitLen() != 1 {
		t.Fatalf("gcd(tau,N)=%s, want 1 (tau=%s)", gcd, &c.Tau)
	}
	rhs := new(big.Int).Mul(&c.Tau, k)
	if c.Epsilon < 0 {
		rhs.Neg(rhs)
	}
	delta := new(big.Int).Sub(&c.Rho, rhs)
	delta.Mod(delta, n)
	if delta.Sign() != 0 {
		t.Fatalf("rho=%s is not epsilon*tau*k mod N (tau=%s epsilon=%d k=%s)", &c.Rho, &c.Tau, c.Epsilon, k)
	}
}

func sampledChallenge(counter uint64, l *big.Int) *big.Int {
	var input [16]byte
	copy(input[:8], "heea8l-v")
	binary.LittleEndian.PutUint64(input[8:], counter)
	digest := sha512.Sum512(input[:])
	k := new(big.Int).SetBytes(digest[:])
	return k.Mod(k, l)
}

func distribution(samples int) map[WidthLimit]int {
	limits := []WidthLimit{Width128, Width132, Width136}
	counts := map[WidthLimit]int{Width128: 0, Width132: 0, Width136: 0}
	l := Order()
	for i := 0; i < samples; i++ {
		k := sampledChallenge(uint64(i), l)
		candidate, ok := bestForModulus(ed25519Exponent, k)
		if !ok {
			for _, limit := range limits {
				counts[limit]++
			}
			continue
		}
		for _, limit := range limits {
			if candidate.BitLen() > int(limit) {
				counts[limit]++
			}
		}
	}
	return counts
}

// exactCandidateExists enumerates the entire width-bounded affine lattice
// slice. It is intentionally exponential in width and only suitable for the
// reduced test moduli above.
func exactCandidateExists(n, k *big.Int, width int) bool {
	bound := new(big.Int).Lsh(big.NewInt(1), uint(width))
	bound.Sub(bound, big.NewInt(1))
	b := bound.Int64()
	for tau := -b; tau <= b; tau++ {
		if tau == 0 || tau&1 == 0 {
			continue
		}
		if new(big.Int).GCD(nil, nil, big.NewInt(tau), n).BitLen() != 1 {
			continue
		}
		rho := new(big.Int).Mul(big.NewInt(tau), k)
		rho.Mod(rho, n)
		if rho.Cmp(bound) <= 0 {
			return true
		}
		rho.Sub(rho, n)
		if abs(rho).Cmp(bound) <= 0 {
			return true
		}
	}
	return false
}

func semiconvergentExistsWithin(n, k *big.Int, width int) bool {
	bound := new(big.Int).Lsh(big.NewInt(1), uint(width))
	bound.Sub(bound, big.NewInt(1))
	if k.Sign() == 0 {
		return true
	}
	r0 := new(big.Int).Set(n)
	r1 := new(big.Int).Set(k)
	t0 := new(big.Int)
	t1 := big.NewInt(1)
	for r1.Sign() != 0 {
		if withinBound(r1, t1, bound, n) {
			return true
		}
		a := new(big.Int)
		r2 := new(big.Int)
		a.QuoRem(r0, r1, r2)

		// rho(q)=r0-q*r1 <= bound gives the lower q bound.
		lo := new(big.Int)
		if delta := new(big.Int).Sub(r0, bound); delta.Sign() > 0 {
			lo.Add(delta, new(big.Int).Sub(r1, big.NewInt(1)))
			lo.Quo(lo, r1)
		}
		if lo.Sign() < 0 {
			lo.SetInt64(0)
		}

		// |tau(q)|=|t0|+q|t1| <= bound gives the upper q bound.
		hi := new(big.Int).Set(a)
		remaining := new(big.Int).Sub(bound, abs(t0))
		if remaining.Sign() >= 0 {
			tauHi := remaining.Quo(remaining, abs(t1))
			if tauHi.Cmp(hi) < 0 {
				hi.Set(tauHi)
			}
		} else {
			hi.SetInt64(-1)
		}
		if lo.Cmp(hi) <= 0 {
			q := new(big.Int).Set(lo)
			tau := new(big.Int).Mul(q, t1)
			tau.Sub(t0, tau)
			if tau.Bit(0) == 0 && t1.Bit(0) == 1 {
				q.Add(q, big.NewInt(1))
				tau.Sub(tau, t1)
			}
			if q.Cmp(hi) <= 0 && withinBound(new(big.Int).Sub(r0, new(big.Int).Mul(q, r1)), tau, bound, n) {
				return true
			}
		}

		t2 := new(big.Int).Mul(a, t1)
		t2.Sub(t0, t2)
		r0, r1 = r1, r2
		t0, t1 = t1, t2
	}
	return false
}

func withinBound(rho, tau, bound, n *big.Int) bool {
	if tau.Sign() == 0 || tau.Bit(0) == 0 || abs(rho).Cmp(bound) > 0 || abs(tau).Cmp(bound) > 0 {
		return false
	}
	return new(big.Int).GCD(nil, nil, abs(tau), n).BitLen() == 1
}
