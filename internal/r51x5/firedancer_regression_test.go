package r51x5

import (
	"bytes"
	"encoding/hex"
	"runtime"
	"testing"
)

type firedancerPointRegression struct {
	name       string
	operation  string
	a, b, want string
}

var firedancerPointRegressions = []firedancerPointRegression{
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

// These fixed cases caught signed-fold, negation, and cached-add bugs in
// Firedancer's AVX-512 implementation. Repeat each case in every x4/x8 lane so
// any future lane-native Narya schedule retains the historical coverage.
//
// Sources:
//
//   - https://github.com/firedancer-io/firedancer/commit/e49d8f36aeb0c803be345a23a3e25b763c11fcf4
//   - https://github.com/firedancer-io/firedancer/commit/d823719a97fa730f7abad362486fd5b4d3ba296d
//   - https://github.com/firedancer-io/firedancer/commit/d2d03d7b890f8babb9d7e7fa68938dfa46e6bc62
func TestFiredancerPointArithmeticRegressionsX4X8(t *testing.T) {
	for _, test := range firedancerPointRegressions {
		test := test
		t.Run(test.name, func(t *testing.T) {
			aBytes := mustDecodeFiredancerR51Hex(t, test.a)
			bBytes := mustDecodeFiredancerR51Hex(t, test.b)
			want := mustDecodeFiredancerR51Hex(t, test.want)
			var encodedA8, encodedB8 [X8Lanes][32]byte
			for lane := 0; lane < X8Lanes; lane++ {
				encodedA8[lane], encodedB8[lane] = aBytes, bBytes
			}
			var a8, b8, got8 PointX8
			if a8.SetBytes(&encodedA8) != 0xff || b8.SetBytes(&encodedB8) != 0xff {
				t.Fatal("x8 fixture decode failed")
			}
			applyFiredancerPointOperationX8(t, test.operation, &got8, &a8, &b8)
			assertFiredancerPointX8Encoding(t, &got8, &want)

			var encodedA4, encodedB4 [X4Lanes][32]byte
			for lane := 0; lane < X4Lanes; lane++ {
				encodedA4[lane], encodedB4[lane] = aBytes, bBytes
			}
			var a4, b4, got4 PointX4
			if a4.SetBytes(&encodedA4) != 0x0f || b4.SetBytes(&encodedB4) != 0x0f {
				t.Fatal("x4 fixture decode failed")
			}
			applyFiredancerPointOperationX4(t, test.operation, &got4, &a4, &b4)
			assertFiredancerPointX4Encoding(t, &got4, &want)

			if test.name == "subtract-noncanonical-b" {
				canonical := b8.Bytes()
				if bytes.Equal(canonical[0][:], bBytes[:]) {
					t.Fatal("fixture B unexpectedly had a canonical encoding")
				}
			}
		})
	}
}

func TestFiredancerPointArithmeticRegressionsIFMA(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	for _, test := range firedancerPointRegressions {
		test := test
		t.Run(test.name, func(t *testing.T) {
			aBytes := mustDecodeFiredancerR51Hex(t, test.a)
			bBytes := mustDecodeFiredancerR51Hex(t, test.b)
			want := mustDecodeFiredancerR51Hex(t, test.want)
			var encodedA8, encodedB8 [X8Lanes][32]byte
			for lane := 0; lane < X8Lanes; lane++ {
				encodedA8[lane], encodedB8[lane] = aBytes, bBytes
			}
			var a8, b8 PointX8
			if a8.SetBytes(&encodedA8) != 0xff || b8.SetBytes(&encodedB8) != 0xff {
				t.Fatal("fixture decode failed")
			}
			var aIFMA, bIFMA, gotIFMA IFMAPointX8
			aIFMA.SetReduced(&a8)
			bIFMA.SetReduced(&b8)
			if test.operation == "subtract" {
				bIFMA.X.Negate(&bIFMA.X)
				bIFMA.T.Negate(&bIFMA.T)
			}
			if err := ExperimentalIFMAPointAddComposableX8(&gotIFMA, &aIFMA, &bIFMA); err != nil {
				t.Fatal(err)
			}
			got := gotIFMA.Reduced()
			assertFiredancerPointX8Encoding(t, &got, &want)
		})
	}
}

func TestFiredancerVariableBasePrecomputeRegressionX4X8(t *testing.T) {
	pointBytes := mustDecodeFiredancerR51Hex(t, "0000000000000000003b0000e8e8e8000000000000000000000000000000ffff")
	scalarBytes := mustDecodeFiredancerR51Hex(t, "005d0000000000000000000000000000000000000000000015b6b6b6b6000000")
	want := mustDecodeFiredancerR51Hex(t, "7b1e1037cbe6e84f922a9b0651ed50570530d6157853debba755d5904021740e")

	var pointEncodings8 [X8Lanes][32]byte
	var scalars8 [X8Lanes][32]byte
	for lane := 0; lane < X8Lanes; lane++ {
		pointEncodings8[lane], scalars8[lane] = pointBytes, scalarBytes
	}
	var base8 PointX8
	if base8.SetBytes(&pointEncodings8) != 0xff {
		t.Fatal("x8 base decode failed")
	}

	var pointEncodings4 [X4Lanes][32]byte
	var scalars4 [X4Lanes][32]byte
	for lane := 0; lane < X4Lanes; lane++ {
		pointEncodings4[lane], scalars4[lane] = pointBytes, scalarBytes
	}
	var base4 PointX4
	if base4.SetBytes(&pointEncodings4) != 0x0f {
		t.Fatal("x4 base decode failed")
	}

	for _, radixBits := range []uint{4, 5, 6} {
		var ordinary8 ExperimentalVariableBaseWorkspaceX8
		ordinary8.Prepare(&base8, radixBits)
		var got8 PointX8
		if mask := ordinary8.Evaluate(&got8, &scalars8, 0, 0xff); mask != 0xff {
			t.Fatalf("radix %d x8 mask=%02x", 1<<radixBits, mask)
		}
		assertFiredancerPointX8Encoding(t, &got8, &want)

		var ordinary4 ExperimentalVariableBaseWorkspaceX4
		ordinary4.Prepare(&base4, radixBits)
		var got4 PointX4
		if mask := ordinary4.Evaluate(&got4, &scalars4, 0, 0x0f); mask != 0x0f {
			t.Fatalf("radix %d x4 mask=%02x", 1<<radixBits, mask)
		}
		assertFiredancerPointX4Encoding(t, &got4, &want)

		if !ExperimentalIFMAAvailable() {
			continue
		}
		hardware8 := testIFMAVariableX8(radixBits)
		if err := hardware8.Prepare(&base8, radixBits); err != nil {
			t.Fatal(err)
		}
		var gotIFMA8 IFMAPointX8
		if mask, err := hardware8.Evaluate(&gotIFMA8, &scalars8, 0, 0xff); err != nil || mask != 0xff {
			t.Fatalf("radix %d IFMA x8=(%02x,%v)", 1<<radixBits, mask, err)
		}
		got8 = gotIFMA8.Reduced()
		assertFiredancerPointX8Encoding(t, &got8, &want)

		hardware4 := testIFMAVariableX4(radixBits)
		if err := hardware4.Prepare(&base4, radixBits); err != nil {
			t.Fatal(err)
		}
		var gotIFMA4 IFMAPointX4
		if mask, err := hardware4.Evaluate(&gotIFMA4, &scalars4, 0, 0x0f); err != nil || mask != 0x0f {
			t.Fatalf("radix %d IFMA x4=(%02x,%v)", 1<<radixBits, mask, err)
		}
		got4 = gotIFMA4.Reduced()
		assertFiredancerPointX4Encoding(t, &got4, &want)
	}
}

func applyFiredancerPointOperationX8(t *testing.T, operation string, out, a, b *PointX8) {
	t.Helper()
	if operation == "add" {
		out.Add(a, b)
		return
	}
	if operation == "subtract" {
		out.Subtract(a, b)
		return
	}
	t.Fatalf("unknown operation %q", operation)
}

func applyFiredancerPointOperationX4(t *testing.T, operation string, out, a, b *PointX4) {
	t.Helper()
	if operation == "add" {
		out.Add(a, b)
		return
	}
	if operation == "subtract" {
		out.Subtract(a, b)
		return
	}
	t.Fatalf("unknown operation %q", operation)
}

func assertFiredancerPointX8Encoding(t *testing.T, point *PointX8, want *[32]byte) {
	t.Helper()
	encoded := point.Bytes()
	for lane := 0; lane < X8Lanes; lane++ {
		if encoded[lane] != *want {
			t.Fatalf("x8 lane %d=%x want=%x", lane, encoded[lane], want)
		}
	}
}

func assertFiredancerPointX4Encoding(t *testing.T, point *PointX4, want *[32]byte) {
	t.Helper()
	encoded := point.Bytes()
	for lane := 0; lane < X4Lanes; lane++ {
		if encoded[lane] != *want {
			t.Fatalf("x4 lane %d=%x want=%x", lane, encoded[lane], want)
		}
	}
}

func mustDecodeFiredancerR51Hex(t *testing.T, value string) [32]byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		t.Fatalf("malformed Firedancer fixture %q", value)
	}
	var out [32]byte
	copy(out[:], decoded)
	return out
}
