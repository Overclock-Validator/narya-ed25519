package r51x5

import (
	"bytes"
	"math/big"
	"math/rand"
	"testing"

	edwardsfield "github.com/Overclock-Validator/narya-ed25519/internal/edwards25519/field"
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

func TestCanonicalEncodingAgainstBigAndEdwardsField(t *testing.T) {
	boundary := []*big.Int{
		big.NewInt(0),
		big.NewInt(1),
		big.NewInt(18),
		big.NewInt(19),
		new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 51), big.NewInt(1)),
		new(big.Int).Lsh(big.NewInt(1), 51),
		new(big.Int).Lsh(big.NewInt(1), 102),
		new(big.Int).Lsh(big.NewInt(1), 153),
		new(big.Int).Lsh(big.NewInt(1), 204),
		new(big.Int).Lsh(big.NewInt(1), 254),
		new(big.Int).Sub(new(big.Int).Set(testModulus), big.NewInt(2)),
		new(big.Int).Sub(new(big.Int).Set(testModulus), big.NewInt(1)),
	}

	check := func(label string, x *big.Int) {
		t.Helper()
		want := canonicalBytes(x)
		z, err := FromCanonicalBytes(want[:])
		if err != nil {
			t.Fatalf("%s: decode: %v", label, err)
		}
		if !IsReduced(z.Limbs()) {
			t.Fatalf("%s: non-reduced limbs %#v", label, z.Limbs())
		}
		if got := z.Bytes(); got != want {
			t.Fatalf("%s: round trip got %x want %x", label, got, want)
		}
		if got := elementBig(&z); got.Cmp(x) != 0 {
			t.Fatalf("%s: integer got %x want %x", label, got, x)
		}
		var other edwardsfield.Element
		if _, err := other.SetBytes(want[:]); err != nil {
			t.Fatalf("%s: Edwards field decode: %v", label, err)
		}
		if got := other.Bytes(); !bytes.Equal(got, want[:]) {
			t.Fatalf("%s: Edwards field got %x want %x", label, got, want)
		}
	}

	for _, x := range boundary {
		check("boundary", x)
	}
	rng := rand.New(rand.NewSource(0x5151))
	for i := 0; i < 4096; i++ {
		_, x := randomElement(t, rng)
		check("random", x)
	}
}

func TestPermissiveEncodingAgainstBigAndEdwardsField(t *testing.T) {
	inputs := make([][32]byte, 0, 4+19+4096)
	inputs = append(inputs, [32]byte{})
	// Five normalized radix-51 limbs span [0, 2^255), while the field ends
	// at p=2^255-19. Exhaust the complete non-canonical integer interval:
	// p+j must decode permissively to j for every 0 <= j <= 18.
	for j := int64(0); j <= 18; j++ {
		inputs = append(inputs, canonicalBytes(new(big.Int).Add(new(big.Int).Set(testModulus), big.NewInt(j))))
	}
	inputs = append(inputs, canonicalBytes(new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(1))))
	highBitZero := [32]byte{}
	highBitZero[31] = 0x80
	inputs = append(inputs, highBitZero)

	rng := rand.New(rand.NewSource(0x25519))
	for i := 0; i < 4096; i++ {
		var in [32]byte
		_, _ = rng.Read(in[:])
		inputs = append(inputs, in)
	}

	for i, in := range inputs {
		masked := in
		masked[31] &= 0x7f
		wantBig := littleEndianBig(masked[:])
		wantBig.Mod(wantBig, testModulus)
		want := canonicalBytes(wantBig)

		var got Element
		if _, err := got.SetBytes(in[:]); err != nil {
			t.Fatalf("input %d: SetBytes: %v", i, err)
		}
		if encoded := got.Bytes(); encoded != want {
			t.Fatalf("input %d: got %x want %x", i, encoded, want)
		}

		var other edwardsfield.Element
		if _, err := other.SetBytes(in[:]); err != nil {
			t.Fatalf("input %d: Edwards SetBytes: %v", i, err)
		}
		if encoded := got.Bytes(); !bytes.Equal(encoded[:], other.Bytes()) {
			t.Fatalf("input %d: Edwards mismatch got %x want %x", i, encoded, other.Bytes())
		}
	}
}

func TestCanonicalRejectsAndPreservesReceiver(t *testing.T) {
	var unchanged Element
	unchanged.One()
	want := unchanged.Bytes()
	invalid := make([][32]byte, 0, 21)
	for j := int64(0); j <= 18; j++ {
		invalid = append(invalid, canonicalBytes(new(big.Int).Add(new(big.Int).Set(testModulus), big.NewInt(j))))
	}
	var highBit [32]byte
	highBit[31] = 0x80
	invalid = append(invalid, highBit)
	for _, encoded := range invalid {
		if _, err := unchanged.SetCanonicalBytes(encoded[:]); err == nil {
			t.Fatalf("accepted non-canonical encoding %x", encoded)
		}
		if got := unchanged.Bytes(); got != want {
			t.Fatalf("failed decode changed receiver: got %x want %x", got, want)
		}
	}
	for _, wrongLength := range [][]byte{nil, make([]byte, 31), make([]byte, 33)} {
		if _, err := unchanged.SetCanonicalBytes(wrongLength); err == nil {
			t.Fatalf("canonical decode accepted length %d", len(wrongLength))
		}
		if _, err := unchanged.SetBytes(wrongLength); err == nil {
			t.Fatalf("permissive decode accepted length %d", len(wrongLength))
		}
		if got := unchanged.Bytes(); got != want {
			t.Fatalf("failed length check changed receiver: got %x want %x", got, want)
		}
	}
}

func TestRangeContracts(t *testing.T) {
	pMinusOne := subtractLimbs(modulusLimbs, Limbs{1})
	if !IsReduced(pMinusOne) {
		t.Fatal("p-1 rejected as reduced")
	}
	if IsReduced(modulusLimbs) {
		t.Fatal("p accepted as reduced")
	}
	overwide := pMinusOne
	overwide[2] = 1 << LimbBits
	if IsReduced(overwide) {
		t.Fatal("2^51 limb accepted as reduced")
	}

	maxIFMA := Limbs{1<<IFMAMultiplicandBits - 1, 1<<IFMAMultiplicandBits - 1, 1<<IFMAMultiplicandBits - 1, 1<<IFMAMultiplicandBits - 1, 1<<IFMAMultiplicandBits - 1}
	if !IsIFMAMultiplicand(maxIFMA) {
		t.Fatal("maximum 52-bit IFMA limbs rejected")
	}
	tooWide := maxIFMA
	tooWide[3]++
	if IsIFMAMultiplicand(tooWide) {
		t.Fatal("2^52 limb accepted as an IFMA multiplicand")
	}
	if IsReduced(maxIFMA) {
		t.Fatal("loose IFMA limbs accepted as reduced")
	}

	if New().IsZero() != 1 {
		t.Fatal("zero value is not zero")
	}
}
