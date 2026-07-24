package r43x6

import (
	"bytes"
	"math/big"
	"math/rand"
	"testing"
)

var testModulus = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))

func littleEndianBig(in []byte) *big.Int {
	reversed := append([]byte(nil), in...)
	for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
		reversed[i], reversed[j] = reversed[j], reversed[i]
	}
	return new(big.Int).SetBytes(reversed)
}

func canonicalBytes(x *big.Int) [32]byte {
	var out [32]byte
	encoded := x.Bytes()
	for i := range encoded {
		out[i] = encoded[len(encoded)-1-i]
	}
	return out
}

func elementFromBig(t *testing.T, x *big.Int) Element {
	t.Helper()
	encoded := canonicalBytes(x)
	z, err := FromCanonicalBytes(encoded[:])
	if err != nil {
		t.Fatalf("FromCanonicalBytes(%x): %v", encoded, err)
	}
	return z
}

func elementBig(z *Element) *big.Int {
	encoded := z.Bytes()
	return littleEndianBig(encoded[:])
}

func randomElement(t *testing.T, rng *rand.Rand) (Element, *big.Int) {
	t.Helper()
	var encoded [32]byte
	_, _ = rng.Read(encoded[:])
	encoded[31] &= 0x7f
	x := littleEndianBig(encoded[:])
	x.Mod(x, testModulus)
	return elementFromBig(t, x), x
}

func TestCanonicalPackUnpack(t *testing.T) {
	boundary := []*big.Int{
		big.NewInt(0),
		big.NewInt(1),
		big.NewInt(18),
		big.NewInt(19),
		new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 40), big.NewInt(1)),
		new(big.Int).Lsh(big.NewInt(1), 40),
		new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 43), big.NewInt(1)),
		new(big.Int).Lsh(big.NewInt(1), 43),
		new(big.Int).Lsh(big.NewInt(1), 86),
		new(big.Int).Lsh(big.NewInt(1), 129),
		new(big.Int).Lsh(big.NewInt(1), 172),
		new(big.Int).Lsh(big.NewInt(1), 215),
		new(big.Int).Lsh(big.NewInt(1), 254),
		new(big.Int).Sub(new(big.Int).Set(testModulus), big.NewInt(2)),
		new(big.Int).Sub(new(big.Int).Set(testModulus), big.NewInt(1)),
	}

	check := func(label string, x *big.Int) {
		t.Helper()
		want := canonicalBytes(x)
		z, err := FromCanonicalBytes(want[:])
		if err != nil {
			t.Fatalf("%s: decode failed: %v", label, err)
		}
		if !IsReduced(z.Limbs()) {
			t.Fatalf("%s: decode produced non-reduced limbs %#v", label, z.Limbs())
		}
		got := z.Bytes()
		if got != want {
			t.Fatalf("%s: round trip got %x want %x", label, got, want)
		}
		if value := elementBig(&z); value.Cmp(x) != 0 {
			t.Fatalf("%s: represented integer got %x want %x", label, value, x)
		}
	}

	for _, x := range boundary {
		check("boundary", x)
	}

	rng := rand.New(rand.NewSource(43))
	for i := 0; i < 4096; i++ {
		_, x := randomElement(t, rng)
		check("random", x)
	}

	var unchanged Element
	unchanged.One()
	wantUnchanged := unchanged.Bytes()
	invalid := [][32]byte{
		canonicalBytes(new(big.Int).Set(testModulus)),
		canonicalBytes(new(big.Int).Add(new(big.Int).Set(testModulus), big.NewInt(1))),
		canonicalBytes(new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(1))),
	}
	var highBit [32]byte
	highBit[31] = 0x80
	invalid = append(invalid, highBit)
	for _, encoded := range invalid {
		if _, err := unchanged.SetCanonicalBytes(encoded[:]); err == nil {
			t.Fatalf("accepted non-canonical encoding %x", encoded)
		}
		if got := unchanged.Bytes(); got != wantUnchanged {
			t.Fatalf("failed decode changed receiver: got %x want %x", got, wantUnchanged)
		}
	}
	for _, wrongLength := range [][]byte{nil, make([]byte, 31), make([]byte, 33)} {
		if _, err := unchanged.SetCanonicalBytes(wrongLength); err == nil {
			t.Fatalf("accepted encoding with length %d", len(wrongLength))
		}
	}

	zero := New()
	if zero.IsZero() != 1 {
		t.Fatal("zero value is not zero")
	}
	if got := zero.Bytes(); !bytes.Equal(got[:], make([]byte, 32)) {
		t.Fatalf("zero encoding = %x", got)
	}
}

func TestRangeContracts(t *testing.T) {
	maxUnsigned := Limbs{1<<UnsignedBits - 1, 1<<UnsignedBits - 1, 1<<UnsignedBits - 1, 1<<UnsignedBits - 1, 1<<UnsignedBits - 1, 1<<UnsignedBits - 1}
	if !IsUnsigned(maxUnsigned) {
		t.Fatal("maximum u62 limbs rejected")
	}
	notUnsigned := maxUnsigned
	notUnsigned[3]++
	if IsUnsigned(notUnsigned) {
		t.Fatal("2^62 limb accepted as unsigned")
	}

	maxUnreduced := Limbs{1<<UnreducedBits - 1, 1<<UnreducedBits - 1, 1<<UnreducedBits - 1, 1<<UnreducedBits - 1, 1<<UnreducedBits - 1, 1<<UnreducedBits - 1}
	if !IsUnreduced(maxUnreduced) {
		t.Fatal("maximum u47 limbs rejected")
	}
	notUnreduced := maxUnreduced
	notUnreduced[5]++
	if IsUnreduced(notUnreduced) {
		t.Fatal("2^47 limb accepted as unreduced")
	}

	maxUnpacked := Limbs{limbMask, limbMask, limbMask, limbMask, limbMask, 1<<UnpackedTopBits - 1}
	if !IsUnpacked(maxUnpacked) {
		t.Fatal("maximum unpacked limbs rejected")
	}
	notUnpacked := maxUnpacked
	notUnpacked[5]++
	if IsUnpacked(notUnpacked) {
		t.Fatal("2^41 top limb accepted as unpacked")
	}

	twoPMinusOne := subtractLimbs(twiceModulusLimbs, Limbs{1})
	if !IsNearlyReduced(twoPMinusOne) {
		t.Fatal("2p-1 rejected as nearly reduced")
	}
	if IsNearlyReduced(twiceModulusLimbs) {
		t.Fatal("2p accepted as nearly reduced")
	}
	if !IsNearlyReduced(modulusLimbs) {
		t.Fatal("p rejected as nearly reduced")
	}
	if IsReduced(modulusLimbs) {
		t.Fatal("p accepted as reduced")
	}
	pMinusOne := subtractLimbs(modulusLimbs, Limbs{1})
	if !IsReduced(pMinusOne) {
		t.Fatal("p-1 rejected as reduced")
	}
}
