package r43x6

import (
	"math/big"
	"math/rand"
	"testing"
)

func assertBigAndReduced(t *testing.T, label string, got *Element, want *big.Int) {
	t.Helper()
	want = new(big.Int).Mod(new(big.Int).Set(want), testModulus)
	if value := elementBig(got); value.Cmp(want) != 0 {
		t.Fatalf("%s: got %x want %x\nlimbs=%#v", label, value, want, got.Limbs())
	}
	if !IsReduced(got.Limbs()) {
		t.Fatalf("%s: result is not reduced: %#v", label, got.Limbs())
	}
}

func TestArithmeticAgainstBig(t *testing.T) {
	rng := rand.New(rand.NewSource(0x436))
	for i := 0; i < 4096; i++ {
		x, xb := randomElement(t, rng)
		y, yb := randomElement(t, rng)

		var got Element
		got.Add(&x, &y)
		assertBigAndReduced(t, "add", &got, new(big.Int).Add(xb, yb))

		got.Subtract(&x, &y)
		assertBigAndReduced(t, "subtract", &got, new(big.Int).Sub(xb, yb))

		got.Negate(&x)
		assertBigAndReduced(t, "negate", &got, new(big.Int).Neg(xb))

		got.Multiply(&x, &y)
		assertBigAndReduced(t, "multiply", &got, new(big.Int).Mul(xb, yb))

		got.Square(&x)
		assertBigAndReduced(t, "square", &got, new(big.Int).Mul(xb, xb))

		// Every operation promises alias-safe receivers.
		alias := x
		alias.Add(&alias, &y)
		assertBigAndReduced(t, "aliased add", &alias, new(big.Int).Add(xb, yb))
		alias = x
		alias.Subtract(&alias, &y)
		assertBigAndReduced(t, "aliased subtract", &alias, new(big.Int).Sub(xb, yb))
		alias = x
		alias.Multiply(&alias, &y)
		assertBigAndReduced(t, "aliased multiply", &alias, new(big.Int).Mul(xb, yb))
		alias = x
		alias.Square(&alias)
		assertBigAndReduced(t, "aliased square", &alias, new(big.Int).Mul(xb, xb))

		if x.Equal(&x) != 1 || x.Equal(&y) != boolToInt(xb.Cmp(yb) == 0) {
			t.Fatalf("round %d: equality mismatch", i)
		}
		if x.IsZero() != boolToInt(xb.Sign() == 0) {
			t.Fatalf("round %d: zero mismatch", i)
		}
	}
}

func TestArithmeticBoundaries(t *testing.T) {
	values := []*big.Int{
		big.NewInt(0),
		big.NewInt(1),
		big.NewInt(2),
		big.NewInt(18),
		big.NewInt(19),
		new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 43), big.NewInt(1)),
		new(big.Int).Lsh(big.NewInt(1), 43),
		new(big.Int).Sub(new(big.Int).Set(testModulus), big.NewInt(2)),
		new(big.Int).Sub(new(big.Int).Set(testModulus), big.NewInt(1)),
	}
	for _, xb := range values {
		x := elementFromBig(t, xb)
		var neg Element
		neg.Negate(&x)
		assertBigAndReduced(t, "boundary negate", &neg, new(big.Int).Neg(xb))
		for _, yb := range values {
			y := elementFromBig(t, yb)
			var got Element
			got.Add(&x, &y)
			assertBigAndReduced(t, "boundary add", &got, new(big.Int).Add(xb, yb))
			got.Subtract(&x, &y)
			assertBigAndReduced(t, "boundary subtract", &got, new(big.Int).Sub(xb, yb))
			got.Multiply(&x, &y)
			assertBigAndReduced(t, "boundary multiply", &got, new(big.Int).Mul(xb, yb))
		}
	}
}

func TestFixedExponentiationAgainstBig(t *testing.T) {
	pMinusTwo := new(big.Int).Sub(new(big.Int).Set(testModulus), big.NewInt(2))
	pow22523Exponent := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 252), big.NewInt(3))

	inputs := []*big.Int{
		big.NewInt(0),
		big.NewInt(1),
		big.NewInt(2),
		big.NewInt(19),
		new(big.Int).Sub(new(big.Int).Set(testModulus), big.NewInt(1)),
	}
	rng := rand.New(rand.NewSource(0x22523))
	for i := 0; i < 128; i++ {
		_, x := randomElement(t, rng)
		inputs = append(inputs, x)
	}

	for i, xb := range inputs {
		x := elementFromBig(t, xb)
		var got Element
		got.Invert(&x)
		wantInvert := new(big.Int).Exp(xb, pMinusTwo, testModulus)
		assertBigAndReduced(t, "invert", &got, wantInvert)

		alias := x
		alias.Invert(&alias)
		if alias.Equal(&got) != 1 {
			t.Fatalf("input %d: aliased invert mismatch", i)
		}

		got.Pow22523(&x)
		wantPow := new(big.Int).Exp(xb, pow22523Exponent, testModulus)
		assertBigAndReduced(t, "pow22523", &got, wantPow)
		alias = x
		alias.Pow22523(&alias)
		if alias.Equal(&got) != 1 {
			t.Fatalf("input %d: aliased pow22523 mismatch", i)
		}
	}
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
