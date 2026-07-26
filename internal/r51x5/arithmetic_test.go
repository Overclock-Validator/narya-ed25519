package r51x5

import (
	"bytes"
	"math/big"
	"math/rand"
	"testing"

	edwardsfield "github.com/Overclock-Validator/narya-ed25519/internal/edwards25519/field"
)

func assertBigAndReduced(t *testing.T, label string, got *Element, want *big.Int) {
	t.Helper()
	want = new(big.Int).Mod(new(big.Int).Set(want), testModulus)
	if value := elementBig(got); value.Cmp(want) != 0 {
		t.Fatalf("%s: got %x want %x; limbs=%#v", label, value, want, got.Limbs())
	}
	if !IsReduced(got.Limbs()) {
		t.Fatalf("%s: result is not reduced: %#v", label, got.Limbs())
	}
}

func assertEdwardsEqual(t *testing.T, label string, got *Element, want *edwardsfield.Element) {
	t.Helper()
	encoded := got.Bytes()
	if !bytes.Equal(encoded[:], want.Bytes()) {
		t.Fatalf("%s: got %x want %x", label, encoded, want.Bytes())
	}
}

func TestArithmeticAgainstBigAndEdwardsField(t *testing.T) {
	rng := rand.New(rand.NewSource(0x51_05))
	for i := 0; i < 4096; i++ {
		x, xb := randomElement(t, rng)
		y, yb := randomElement(t, rng)
		xBytes, yBytes := x.Bytes(), y.Bytes()
		var fx, fy, fw edwardsfield.Element
		_, _ = fx.SetBytes(xBytes[:])
		_, _ = fy.SetBytes(yBytes[:])

		var got Element
		got.Add(&x, &y)
		assertBigAndReduced(t, "add", &got, new(big.Int).Add(xb, yb))
		assertEdwardsEqual(t, "add Edwards", &got, fw.Add(&fx, &fy))

		got.Subtract(&x, &y)
		assertBigAndReduced(t, "subtract", &got, new(big.Int).Sub(xb, yb))
		assertEdwardsEqual(t, "subtract Edwards", &got, fw.Subtract(&fx, &fy))

		got.Negate(&x)
		assertBigAndReduced(t, "negate", &got, new(big.Int).Neg(xb))
		assertEdwardsEqual(t, "negate Edwards", &got, fw.Negate(&fx))

		got.Multiply(&x, &y)
		assertBigAndReduced(t, "multiply", &got, new(big.Int).Mul(xb, yb))
		assertEdwardsEqual(t, "multiply Edwards", &got, fw.Multiply(&fx, &fy))

		got.Square(&x)
		assertBigAndReduced(t, "square", &got, new(big.Int).Mul(xb, xb))
		assertEdwardsEqual(t, "square Edwards", &got, fw.Square(&fx))

		alias := x
		alias.Add(&alias, &y)
		assertBigAndReduced(t, "aliased add", &alias, new(big.Int).Add(xb, yb))
		alias = x
		alias.Subtract(&alias, &y)
		assertBigAndReduced(t, "aliased subtract", &alias, new(big.Int).Sub(xb, yb))
		alias = x
		alias.Negate(&alias)
		assertBigAndReduced(t, "aliased negate", &alias, new(big.Int).Neg(xb))
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
		if x.IsNegative() != int(xBytes[0]&1) {
			t.Fatalf("round %d: sign mismatch", i)
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
		new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 51), big.NewInt(1)),
		new(big.Int).Lsh(big.NewInt(1), 51),
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

func TestInvertAgainstBigAndEdwardsField(t *testing.T) {
	pMinusTwo := new(big.Int).Sub(new(big.Int).Set(testModulus), big.NewInt(2))
	inputs := []*big.Int{
		big.NewInt(0),
		big.NewInt(1),
		big.NewInt(2),
		big.NewInt(19),
		new(big.Int).Sub(new(big.Int).Set(testModulus), big.NewInt(1)),
	}
	rng := rand.New(rand.NewSource(0x1_51_05))
	for i := 0; i < 128; i++ {
		_, x := randomElement(t, rng)
		inputs = append(inputs, x)
	}

	for i, xb := range inputs {
		x := elementFromBig(t, xb)
		var got Element
		got.Invert(&x)
		want := new(big.Int).Exp(xb, pMinusTwo, testModulus)
		assertBigAndReduced(t, "invert", &got, want)

		xBytes := x.Bytes()
		var fx, fw edwardsfield.Element
		_, _ = fx.SetBytes(xBytes[:])
		assertEdwardsEqual(t, "invert Edwards", &got, fw.Invert(&fx))

		alias := x
		alias.Invert(&alias)
		if alias.Equal(&got) != 1 {
			t.Fatalf("input %d: aliased inversion mismatch", i)
		}
	}
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
