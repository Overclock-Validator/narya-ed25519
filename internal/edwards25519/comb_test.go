// Copyright 2026 Overclock Validator
// Licensed under the Apache License, Version 2.0; see the LICENSE file at
// the root of this repository.

package edwards25519

import (
	"math/rand"
	"testing"
)

func TestPubkeyTableMatchesColdDoubleScalarMult(t *testing.T) {
	rng := rand.New(rand.NewSource(0x434f4d42))
	for round := 0; round < 128; round++ {
		pointScalar := randomScalarForCombTest(t, rng)
		a := randomScalarForCombTest(t, rng)
		b := randomScalarForCombTest(t, rng)

		point := (&Point{}).ScalarBaseMult(pointScalar)
		table := NewPubkeyTable(point)
		want := (&Point{}).VarTimeDoubleScalarBaseMult(a, point, b)
		got := (&Point{}).VarTimeDoubleCombMult(a, table, b)
		if got.Equal(want) != 1 {
			t.Fatalf("round %d: comb-table DSM differs from cold DSM", round)
		}
	}
}

func randomScalarForCombTest(t *testing.T, rng *rand.Rand) *Scalar {
	t.Helper()
	var wide [64]byte
	_, _ = rng.Read(wide[:])
	s, err := NewScalar().SetUniformBytes(wide[:])
	if err != nil {
		t.Fatal(err)
	}
	return s
}
