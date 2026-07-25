// Copyright 2026 Overclock Validator
// Licensed under the Apache License, Version 2.0; see the LICENSE file at
// the root of this repository.
//
// This file is part of narya and is NOT vendored upstream code. The
// BSD-3-Clause LICENSE in this directory governs the vendored Go /
// filippo.io edwards25519 files only, and does not apply here.

package edwards25519

import (
	"math/rand"
	"testing"

	"github.com/Overclock-Validator/narya/internal/edwards25519/field"
)

func TestEqualAffineWithNonUnitZ(t *testing.T) {
	rng := rand.New(rand.NewSource(0xaff1))
	var zero, one field.Element
	one.One()

	for round := 0; round < 128; round++ {
		var wide [64]byte
		_, _ = rng.Read(wide[:])
		scalar, err := NewScalar().SetUniformBytes(wide[:])
		if err != nil {
			t.Fatal(err)
		}

		point := (&Point{}).ScalarBaseMult(scalar)
		affine, err := (&Point{}).SetBytes(point.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		// Avoid the torsion-coordinate special cases so the two negative
		// assertions below independently exercise the X and Y comparisons.
		if affine.x.Equal(&zero) == 1 || affine.y.Equal(&zero) == 1 {
			round--
			continue
		}

		var lambda field.Element
		for {
			var encoded [32]byte
			_, _ = rng.Read(encoded[:])
			encoded[31] &= 0x7f
			if _, err := lambda.SetBytes(encoded[:]); err != nil {
				t.Fatal(err)
			}
			if lambda.Equal(&zero) == 0 && lambda.Equal(&one) == 0 {
				break
			}
		}

		// Scale every extended coordinate by the same nonzero lambda. This
		// preserves x=X/Z, y=Y/Z, and T/Z=xy while ensuring Z is non-unit.
		var projective Point
		projective.x.Multiply(&affine.x, &lambda)
		projective.y.Multiply(&affine.y, &lambda)
		projective.z.Set(&lambda)
		projective.t.Multiply(&affine.t, &lambda)

		if projective.z.Equal(&one) == 1 {
			t.Fatal("test constructed unit Z")
		}
		if got := projective.EqualAffine(affine); got != 1 {
			t.Fatalf("round %d: EqualAffine rejected an equivalent non-unit-Z point", round)
		}
		if got := projective.Equal(affine); got != 1 {
			t.Fatalf("round %d: general Equal rejected test setup", round)
		}

		// (-x,y) shares y and catches an implementation missing the X
		// cross-product.
		negX := *affine
		negX.x.Negate(&affine.x)
		negX.t.Negate(&affine.t)
		if got := projective.EqualAffine(&negX); got != 0 {
			t.Fatalf("round %d: EqualAffine ignored the X cross-product", round)
		}

		// (x,-y) shares x and catches an implementation missing the Y
		// cross-product.
		negY := *affine
		negY.y.Negate(&affine.y)
		negY.t.Negate(&affine.t)
		if got := projective.EqualAffine(&negY); got != 0 {
			t.Fatalf("round %d: EqualAffine ignored the Y cross-product", round)
		}
	}
}
