// Test fixtures derived from Firedancer's Ed25519 regression corpus.
// Copyright 2022 Firedancer Contributors. Licensed under Apache-2.0.
// Narya adds the Go harness and independent checks; see the repository NOTICE.

package r43x6

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Firedancer retained these fixed cases after they exposed faults in its
// AVX-512 point/precompute code. Narya does not copy the affected cached-point
// macro, but the vectors are valuable permanent checks for any future r43
// point schedule or table port.
//
// Sources:
//
//   - https://github.com/firedancer-io/firedancer/commit/e49d8f36aeb0c803be345a23a3e25b763c11fcf4
//   - https://github.com/firedancer-io/firedancer/commit/d823719a97fa730f7abad362486fd5b4d3ba296d
//   - https://github.com/firedancer-io/firedancer/commit/d2d03d7b890f8babb9d7e7fa68938dfa46e6bc62
//   - https://github.com/firedancer-io/firedancer/blob/3ed37488372b7e50bb03ca30477be48508ee7022/src/ballet/ed25519/test_ed25519.c
func TestFiredancerPointArithmeticRegressions(t *testing.T) {
	tests := []struct {
		name       string
		operation  string
		a, b, want string
	}{
		{
			name:      "add-precomputed",
			operation: "add",
			a:         "0100000000000000000000000000000000b90000000000000000000000000080",
			b:         "0000000000000000000000000000000000fb0000000000000000000000000080",
			want:      "1e7eb8ea9e26b4e89d6ae958797cee2d0a64ecf2f3a50eb4d4fff0492abf0658",
		},
		{
			name:      "subtract-1",
			operation: "subtract",
			a:         "01d5a4fc9af1e0cceec08818a6eba5b6068ac2a7b7862af0b3ba085fe942bb28",
			b:         "287e68afe7a4b3d01165472d2dc4a2ae8bccfeab6835852017916d0c2718c51e",
			want:      "a0beff37e6888bb25cfa14255247ea71d8276b8cd830d989e860aef22619fde2",
		},
		{
			name:      "subtract-2",
			operation: "subtract",
			a:         "09090909090909090909090909090909090906090909099c0909090909090909",
			b:         "0909090909097e09090909090909090909090909090909090909090909090909",
			want:      "fa390a04c279c64396b818038dada0ba3d42aabcc5afe095440a8eff270e82f9",
		},
		{
			name:      "subtract-noncanonical-b",
			operation: "subtract",
			a:         "0100000000000000000000000000000000b90000000000000000000000000080",
			b:         "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			want:      "39b4ef21660663d8955e024b1a7d921cf76b6300dbd94827d47ec62829a7dddc",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			aBytes := mustDecodeFiredancerHex(t, test.a, 32)
			bBytes := mustDecodeFiredancerHex(t, test.b, 32)
			want := mustDecodeFiredancerHex(t, test.want, 32)
			a := mustPoint(t, aBytes)
			b := mustPoint(t, bBytes)
			if test.name == "subtract-noncanonical-b" {
				canonicalB := b.Bytes()
				if bytes.Equal(canonicalB[:], bBytes) {
					t.Fatal("fixture B unexpectedly had a canonical encoding")
				}
			}

			apply := func(out, left, right *Point) {
				switch test.operation {
				case "add":
					out.Add(left, right)
				case "subtract":
					out.Subtract(left, right)
				default:
					t.Fatalf("unknown operation %q", test.operation)
				}
			}
			assertEncoding := func(label string, got *Point) {
				t.Helper()
				encoded := got.Bytes()
				if !bytes.Equal(encoded[:], want) {
					t.Fatalf("%s=%x want=%x", label, encoded, want)
				}
			}

			var got Point
			apply(&got, a, b)
			assertEncoding("ordinary", &got)
			aliasA := *a
			apply(&aliasA, &aliasA, b)
			assertEncoding("A-alias", &aliasA)
			aliasB := *b
			apply(&aliasB, a, &aliasB)
			assertEncoding("B-alias", &aliasB)
		})
	}
}

func TestFiredancerVariableBasePrecomputeRegression(t *testing.T) {
	pointBytes := mustDecodeFiredancerHex(t, "0000000000000000003b0000e8e8e8000000000000000000000000000000ffff", 32)
	scalarBytes := mustDecodeFiredancerHex(t, "005d0000000000000000000000000000000000000000000015b6b6b6b6000000", 32)
	want := mustDecodeFiredancerHex(t, "7b1e1037cbe6e84f922a9b0651ed50570530d6157853debba755d5904021740e", 32)

	point := mustPoint(t, pointBytes)
	scalar, err := new(Scalar).SetCanonicalBytes(scalarBytes)
	if err != nil {
		t.Fatalf("invalid scalar fixture: %v", err)
	}
	var zero Scalar
	got := new(Point).VarTimeDoubleScalarBaseMult(scalar, point, &zero)
	encoded := got.Bytes()
	if !bytes.Equal(encoded[:], want) {
		t.Fatalf("scalar multiplication=%x want=%x", encoded, want)
	}
}

func mustDecodeFiredancerHex(t *testing.T, value string, size int) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != size {
		t.Fatalf("malformed Firedancer fixture %q", value)
	}
	return decoded
}
