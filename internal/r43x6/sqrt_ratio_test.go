package r43x6

import (
	"math/big"
	"math/rand"
	"testing"
)

// sqrtRatioConventional is the previous uv^3/uv^7 formulation. It remains in
// tests as an independent oracle for the lower-operation-count production
// formula.
func sqrtRatioConventional(u, v *Element) (Element, int) {
	var v2, v3, v4, uv3, uv7, pow, r Element
	v2.Square(v)
	v3.Multiply(&v2, v)
	uv3.Multiply(u, &v3)
	v4.Square(&v2)
	uv7.Multiply(&uv3, &v4)
	pow.Pow22523(&uv7)
	r.Multiply(&uv3, &pow)

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
	return r, correct | flipped
}

func TestSqrtRatioSimplifiedMatchesConventional(t *testing.T) {
	zero := new(Element)
	one := new(Element).One()
	inputs := [][2]Element{
		{*zero, *zero},
		{*zero, *one},
		{*one, *zero},
		{*one, *one},
	}

	rng := rand.New(rand.NewSource(0x5a7))
	quarticCounts := [4]int{}
	quarticExponent := new(big.Int).Rsh(new(big.Int).Sub(new(big.Int).Set(testModulus), big.NewInt(1)), 2)
	oneBig := big.NewInt(1)
	minusOneBig := new(big.Int).Sub(new(big.Int).Set(testModulus), big.NewInt(1))
	sqrtM1Big := elementBig(&sqrtM1)
	minusSqrtM1Big := new(big.Int).Sub(new(big.Int).Set(testModulus), sqrtM1Big)

	for len(inputs) < 260 {
		u, ub := randomElement(t, rng)
		v, vb := randomElement(t, rng)
		uv := new(big.Int).Mul(ub, vb)
		uv.Mod(uv, testModulus)
		if uv.Sign() != 0 {
			character := new(big.Int).Exp(uv, quarticExponent, testModulus)
			switch {
			case character.Cmp(oneBig) == 0:
				quarticCounts[0]++
			case character.Cmp(minusOneBig) == 0:
				quarticCounts[1]++
			case character.Cmp(sqrtM1Big) == 0:
				quarticCounts[2]++
			case character.Cmp(minusSqrtM1Big) == 0:
				quarticCounts[3]++
			default:
				t.Fatalf("unexpected quartic character %x", character)
			}
		}
		inputs = append(inputs, [2]Element{u, v})
	}

	for i, pair := range inputs {
		u, v := pair[0], pair[1]
		wantRoot, wantSquare := sqrtRatioConventional(&u, &v)
		var gotRoot Element
		_, gotSquare := gotRoot.SqrtRatio(&u, &v)
		if gotSquare != wantSquare || gotRoot.Equal(&wantRoot) != 1 {
			t.Fatalf("input %d: simplified sqrt ratio differs: square=%d/%d root=%x/%x", i, gotSquare, wantSquare, gotRoot.Bytes(), wantRoot.Bytes())
		}

		var root2, check Element
		root2.Square(&gotRoot)
		check.Multiply(&v, &root2)
		if gotSquare == 1 && check.Equal(&u) != 1 {
			t.Fatalf("input %d: claimed square root does not satisfy v*r^2=u", i)
		}
	}

	for class, count := range quarticCounts {
		if count < 32 {
			t.Fatalf("quartic class %d covered only %d times", class, count)
		}
	}
}
