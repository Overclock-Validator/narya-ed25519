package r43x6

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/Overclock-Validator/narya/internal/heea8l"
)

// exactSignedIntegerMult is deliberately independent of Scalar. Reducing n
// modulo the prime-subgroup order would be wrong for mixed-order points and
// would make this useless as the oracle for a future HEEA QSM.
func exactSignedIntegerMult(point *Point, n *big.Int) Point {
	if n == nil || n.Sign() == 0 {
		return *NewIdentityPoint()
	}
	absN := new(big.Int).Abs(new(big.Int).Set(n))
	acc := NewIdentityPoint()
	base := *point
	for bit := 0; bit < absN.BitLen(); bit++ {
		if absN.Bit(bit) != 0 {
			acc.Add(acc, &base)
		}
		base.Double(&base)
	}
	if n.Sign() < 0 {
		acc.Negate(acc)
	}
	return *acc
}

func exactVerificationEquation(s, k *big.Int, a, r *Point) Point {
	bTerm := exactSignedIntegerMult(NewGeneratorPoint(), s)
	aTerm := exactSignedIntegerMult(a, k)
	bTerm.Subtract(&bTerm, r)
	bTerm.Subtract(&bTerm, &aTerm)
	return bTerm
}

func exactHEEAEquation(s *big.Int, a, r *Point, candidate *heea8l.Candidate) Point {
	tauS := new(big.Int).Mul(&candidate.Tau, s)
	epsilonRho := new(big.Int).Set(&candidate.Rho)
	if candidate.Epsilon < 0 {
		epsilonRho.Neg(epsilonRho)
	}
	bTerm := exactSignedIntegerMult(NewGeneratorPoint(), tauS)
	rTerm := exactSignedIntegerMult(r, &candidate.Tau)
	aTerm := exactSignedIntegerMult(a, epsilonRho)
	bTerm.Subtract(&bTerm, &rTerm)
	bTerm.Subtract(&bTerm, &aTerm)
	return bTerm
}

func TestCorrectedHEEAIdentityOnMixedOrderPoints(t *testing.T) {
	// Each A is P+T with a nonzero prime-order component and a different
	// torsion component. Such points are allowed by DalekStrict and expose an
	// accidental scalar reduction modulo L.
	torsionIndexes := [...]int{0, 2, 10, 11, 12, 13}
	prime := exactSignedIntegerMult(NewGeneratorPoint(), big.NewInt(17))
	s := big.NewInt(0x1234567)
	l := heea8l.Order()

	for sample, torsionIndex := range torsionIndexes {
		encoded, err := hex.DecodeString(pointEdgeEncodings[torsionIndex])
		if err != nil {
			t.Fatal(err)
		}
		torsion, err := new(Point).SetBytes(encoded)
		if err != nil {
			t.Fatalf("torsion index %d did not decode: %v", torsionIndex, err)
		}
		var a Point
		a.Add(&prime, torsion)
		if new(Point).MultByCofactor(&a).IsIdentity() != 0 {
			t.Fatalf("torsion index %d produced a small-order A", torsionIndex)
		}

		// Deterministic, canonical challenge values with unrelated Euclidean
		// quotient chains. Skip only an explicit width fallback; the theorem is
		// tested on every admitted candidate.
		k := new(big.Int).Exp(big.NewInt(int64(0x101+sample)), big.NewInt(17), l)
		selection := heea8l.Select(k, heea8l.Width136)
		if !selection.UseCandidate {
			t.Logf("sample %d used the required baseline fallback: %v", sample, selection.Fallback)
			continue
		}

		// Construct R so the original full-group equation is exactly zero.
		r := exactSignedIntegerMult(NewGeneratorPoint(), s)
		ka := exactSignedIntegerMult(&a, k)
		r.Subtract(&r, &ka)
		if new(Point).MultByCofactor(&r).IsIdentity() != 0 {
			t.Fatalf("sample %d unexpectedly produced a small-order R", sample)
		}

		original := exactVerificationEquation(s, k, &a, &r)
		transformed := exactHEEAEquation(s, &a, &r, &selection.Candidate)
		scaledOriginal := exactSignedIntegerMult(&original, &selection.Candidate.Tau)
		if original.IsIdentity() != 1 || transformed.IsIdentity() != 1 {
			t.Fatalf("sample %d: corrected HEEA rejected an exact mixed-order equation", sample)
		}
		if transformed.Equal(&scaledOriginal) != 1 {
			t.Fatalf("sample %d: transformed equation != [tau] original", sample)
		}

		// A prime-order perturbation must remain a rejection. Because tau is
		// invertible modulo 8L, scaling cannot turn it into the identity.
		var badR Point
		badR.Add(&r, NewGeneratorPoint())
		badOriginal := exactVerificationEquation(s, k, &a, &badR)
		badTransformed := exactHEEAEquation(s, &a, &badR, &selection.Candidate)
		badScaled := exactSignedIntegerMult(&badOriginal, &selection.Candidate.Tau)
		if badOriginal.IsIdentity() != 0 || badTransformed.IsIdentity() != 0 {
			t.Fatalf("sample %d: corrected HEEA accepted a perturbed equation", sample)
		}
		if badTransformed.Equal(&badScaled) != 1 {
			t.Fatalf("sample %d bad equation: transformed != [tau] original", sample)
		}
	}
}

func TestModuloLHEEAIsUnsoundForAllowedMixedOrderPoints(t *testing.T) {
	// k=L-1, tau=1, rho=-1 satisfies rho=tau*k (mod L), the ordinary
	// prime-subgroup relation. Let A=R=P+T where T has order eight. The
	// transformed equation is zero, but the original is -[L]A=-[L]T != 0.
	// A and R themselves are mixed-order, not small-order, so strict point
	// prechecks do not remove this counterexample class.
	encoded, err := hex.DecodeString(pointEdgeEncodings[10])
	if err != nil {
		t.Fatal(err)
	}
	torsion, err := new(Point).SetBytes(encoded)
	if err != nil {
		t.Fatal(err)
	}
	prime := exactSignedIntegerMult(NewGeneratorPoint(), big.NewInt(17))
	var a Point
	a.Add(&prime, torsion)
	r := a
	if new(Point).MultByCofactor(&a).IsIdentity() != 0 {
		t.Fatal("counterexample A is small-order")
	}

	k := new(big.Int).Sub(heea8l.Order(), big.NewInt(1))
	original := exactVerificationEquation(new(big.Int), k, &a, &r)
	ordinaryModLCandidate := heea8l.Candidate{
		Rho:     *big.NewInt(-1),
		Tau:     *big.NewInt(1),
		Epsilon: 1,
	}
	transformed := exactHEEAEquation(new(big.Int), &a, &r, &ordinaryModLCandidate)
	if original.IsIdentity() != 0 {
		t.Fatal("ordinary-mod-L counterexample original equation is identity")
	}
	if transformed.IsIdentity() != 1 {
		t.Fatal("ordinary-mod-L counterexample transformed equation did not become identity")
	}

	// The same candidate is intentionally invalid modulo 8L.
	delta := new(big.Int).Sub(&ordinaryModLCandidate.Rho, k)
	delta.Mod(delta, heea8l.Modulus())
	if delta.Sign() == 0 {
		t.Fatal("ordinary-mod-L counterexample unexpectedly satisfies modulo-8L relation")
	}
}
