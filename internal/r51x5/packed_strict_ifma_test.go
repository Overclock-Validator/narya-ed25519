package r51x5

import (
	"bytes"
	"testing"
)

func TestPackedCanonicalREncodingX4IsIndependentOfSmallOrderCheck(t *testing.T) {
	identity := [32]byte{1}
	orderTwo := [32]byte{0xec}
	modulus := [32]byte{0xed}
	for index := 1; index < 31; index++ {
		orderTwo[index] = 0xff
		modulus[index] = 0xff
	}
	orderTwo[31] = 0x7f
	modulus[31] = 0x7f

	for _, test := range []struct {
		name    string
		encoded []byte
		want    bool
	}{
		{name: "wrong-length", encoded: make([]byte, 31), want: false},
		{name: "identity", encoded: identity[:], want: true},
		{name: "order-two", encoded: orderTwo[:], want: true},
		{name: "modulus-alias", encoded: modulus[:], want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := packedCanonicalREncodingX4(test.encoded); got != test.want {
				t.Fatalf("canonical=%v want=%v", got, test.want)
			}
		})
	}

	for name, canonical := range map[string][32]byte{
		"identity":  identity,
		"order-two": orderTwo,
	} {
		negativeZero := canonical
		negativeZero[31] |= 0x80
		if packedCanonicalREncodingX4(negativeZero[:]) {
			t.Fatalf("%s negative-zero alias accepted", name)
		}
		var decoded Point
		if _, err := decoded.SetBytes(negativeZero[:]); err != nil {
			t.Fatalf("%s permissive decode failed: %v", name, err)
		}
		reencoded := decoded.Bytes()
		if bytes.Equal(reencoded[:], negativeZero[:]) {
			t.Fatalf("%s reference re-encoding unexpectedly preserved alias", name)
		}
	}
}
