// Copyright 2026 Overclock Validator
// Licensed under the Apache License, Version 2.0; see the LICENSE file at
// the root of this repository.
//
// This file is part of narya and is NOT vendored upstream code. The
// BSD-3-Clause LICENSE in this directory governs the vendored Go /
// filippo.io edwards25519 files only, and does not apply here.

package field

import (
	"math/rand"
	"testing"
)

// sqrtRatioLegacy is the pre-simplification formula retained only as an
// independent differential oracle. quartic identifies check/u as
// 1, -1, i, or -i for nonzero u.
func sqrtRatioLegacy(u, v *Element) (out Element, wasSquare, quartic int) {
	var t0, v2, uv3, uv7, rr Element
	v2.Square(v)
	uv3.Multiply(u, t0.Multiply(&v2, v))
	uv7.Multiply(&uv3, t0.Square(&v2))
	rr.Multiply(&uv3, t0.Pow22523(&uv7))

	var check, uNeg, uI, uNegI Element
	check.Multiply(v, t0.Square(&rr))
	uNeg.Negate(u)
	uI.Multiply(u, sqrtM1)
	uNegI.Negate(&uI)

	correct := check.Equal(u)
	flipped := check.Equal(&uNeg)
	flippedI := check.Equal(&uNegI)
	switch {
	case correct == 1:
		quartic = 0
	case flipped == 1:
		quartic = 1
	case check.Equal(&uI) == 1:
		quartic = 2
	case flippedI == 1:
		quartic = 3
	default:
		quartic = -1
	}

	var rPrime Element
	rPrime.Multiply(&rr, sqrtM1)
	rr.Select(&rPrime, &rr, flipped|flippedI)
	out.Absolute(&rr)
	return out, correct | flipped, quartic
}

func TestSqrtRatioSimplifiedMatchesLegacy(t *testing.T) {
	rng := rand.New(rand.NewSource(0x22523))
	seenQuartic := [4]bool{}

	test := func(name string, u, v *Element) {
		t.Helper()
		want, wantSquare, quartic := sqrtRatioLegacy(u, v)
		var got Element
		_, gotSquare := got.SqrtRatio(u, v)
		if gotSquare != wantSquare || got.Equal(&want) != 1 {
			t.Fatalf("%s: simplified=(%x,%d) legacy=(%x,%d)", name, got.Bytes(), gotSquare, want.Bytes(), wantSquare)
		}
		if quartic >= 0 && quartic < len(seenQuartic) && u.Equal(feZero) == 0 {
			seenQuartic[quartic] = true
		}

		// The implementation contract permits the output to alias either input.
		uAlias := *u
		_, uSquare := uAlias.SqrtRatio(&uAlias, v)
		if uSquare != wantSquare || uAlias.Equal(&want) != 1 {
			t.Fatalf("%s: u-alias differs from legacy", name)
		}
		vAlias := *v
		_, vSquare := vAlias.SqrtRatio(u, &vAlias)
		if vSquare != wantSquare || vAlias.Equal(&want) != 1 {
			t.Fatalf("%s: v-alias differs from legacy", name)
		}
	}

	var zero, one Element
	one.One()
	test("u=0/v=1", &zero, &one)
	test("u=1/v=0", &one, &zero)
	test("u=0/v=0", &zero, &zero)

	for i := 0; i < 4096; i++ {
		var ub, vb [32]byte
		if _, err := rng.Read(ub[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := rng.Read(vb[:]); err != nil {
			t.Fatal(err)
		}
		var u, v Element
		if _, err := u.SetBytes(ub[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := v.SetBytes(vb[:]); err != nil {
			t.Fatal(err)
		}
		test("random", &u, &v)
	}

	for class, seen := range seenQuartic {
		if !seen {
			t.Fatalf("quartic class %d was not exercised", class)
		}
	}
}

func BenchmarkSqrtRatioFormula(b *testing.B) {
	var ub, vb [32]byte
	for i := range ub {
		ub[i] = byte(3*i + 1)
		vb[i] = byte(5*i + 7)
	}
	var u, v Element
	if _, err := u.SetBytes(ub[:]); err != nil {
		b.Fatal(err)
	}
	if _, err := v.SetBytes(vb[:]); err != nil {
		b.Fatal(err)
	}

	b.Run("legacy", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			sqrtRatioLegacy(&u, &v)
		}
	})
	b.Run("simplified", func(b *testing.B) {
		var out Element
		for i := 0; i < b.N; i++ {
			out.SqrtRatio(&u, &v)
		}
	})
}
