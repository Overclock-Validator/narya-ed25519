package sigprep

import (
	"bytes"
	stded25519 "crypto/ed25519"
	"crypto/sha512"
	"math/big"
	"math/rand"
	"testing"

	"github.com/Overclock-Validator/narya-ed25519/internal/edwards25519"
)

// The identity that justifies building this stage before SIMD-0376 is decided:
// the cofactored predicate needs no new front-half code, because its byte-level
// rules are exactly the permissive ones. If this ever stops holding, the
// package comment's table is wrong and a ZIP215 equation cannot simply reuse
// this stage.
func TestZIP215SharesStdlibByteRules(t *testing.T) {
	if ZIP215 != StdlibCompat {
		t.Fatalf("ZIP215 byte rules %+v differ from StdlibCompat %+v", ZIP215, StdlibCompat)
	}
	if DalekStrict == StdlibCompat {
		t.Fatal("DalekStrict must differ from the permissive rules")
	}
}

// smallOrderEncodingOracle is the deliberately slow definition: decode the
// encoding with the permissive decoder and ask the resulting point whether it
// is small order. The fast path in this package is a byte classification that
// must agree with it on every input.
func smallOrderEncodingOracle(b []byte) bool {
	if len(b) != 32 {
		return false
	}
	p, err := (&edwards25519.Point{}).SetBytes(b)
	if err != nil {
		return false
	}
	return p.IsSmallOrder()
}

func TestSmallOrderEncodingMatchesDecodingOracle(t *testing.T) {
	// Every encoding the classification claims is small order.
	var claimed [][32]byte
	for _, first := range []byte{0x00, 0x01, 0x26, 0xc7, 0xec, 0xed, 0xee} {
		for _, template := range smallOrderTemplates(first) {
			for _, sign := range []byte{0x00, 0x80} {
				candidate := template
				candidate[31] = candidate[31]&0x7f | sign
				claimed = append(claimed, candidate)
			}
		}
	}
	for _, candidate := range claimed {
		if !SmallOrderEncoding(candidate[:]) {
			t.Fatalf("%x: classification rejects its own template", candidate)
		}
		if !smallOrderEncodingOracle(candidate[:]) {
			t.Fatalf("%x: classified small order but the decoder disagrees", candidate)
		}
	}
	if len(claimed) != 14 {
		t.Fatalf("expected 14 small-order encodings, built %d", len(claimed))
	}

	// And a large random sweep in the other direction: nothing else may be
	// classified small order, and nothing else may decode to a small-order
	// point.
	rng := rand.New(rand.NewSource(20260726))
	for i := 0; i < 200000; i++ {
		var candidate [32]byte
		for j := range candidate {
			candidate[j] = byte(rng.Intn(256))
		}
		// Bias toward the interesting first bytes so the comparison branches
		// are actually reached rather than exiting at the switch.
		if i%2 == 0 {
			candidate[0] = []byte{0x00, 0x01, 0x26, 0xc7, 0xec, 0xed, 0xee}[i%7]
		}
		if got, want := SmallOrderEncoding(candidate[:]), smallOrderEncodingOracle(candidate[:]); got != want {
			t.Fatalf("%x: classification=%v decoder=%v", candidate, got, want)
		}
	}
}

func smallOrderTemplates(first byte) [][32]byte {
	var out [][32]byte
	build := func(fill, last byte) [32]byte {
		var v [32]byte
		v[0] = first
		for i := 1; i < 31; i++ {
			v[i] = fill
		}
		v[31] = last
		return v
	}
	switch first {
	case 0x00, 0x01:
		out = append(out, build(0x00, 0x00))
	case 0x26:
		out = append(out, smallOrderNegAlpha)
	case 0xc7:
		out = append(out, smallOrderAlpha)
	case 0xec, 0xed, 0xee:
		out = append(out, build(0xff, 0x7f))
	}
	return out
}

// The scalar gate must be exactly "strictly less than l", with l itself
// rejected. An off-by-one here silently changes the accepted signature set.
func TestCanonicalScalarEncodingBoundary(t *testing.T) {
	order := new(big.Int)
	order.SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)

	encode := func(v *big.Int) [32]byte {
		var out [32]byte
		bytesBE := v.Bytes()
		for i, b := range bytesBE {
			out[len(bytesBE)-1-i] = b
		}
		return out
	}

	cases := []struct {
		delta int64
		want  bool
	}{
		{-2, true}, {-1, true}, {0, false}, {1, false}, {2, false},
	}
	for _, c := range cases {
		v := new(big.Int).Add(order, big.NewInt(c.delta))
		encoded := encode(v)
		if got := CanonicalScalarEncoding(encoded[:]); got != c.want {
			t.Fatalf("l%+d: canonical=%v want %v", c.delta, got, c.want)
		}
	}

	var zero [32]byte
	if !CanonicalScalarEncoding(zero[:]) {
		t.Fatal("zero must be canonical")
	}
	if CanonicalScalarEncoding(zero[:31]) {
		t.Fatal("a short scalar must be rejected")
	}

	// Every value with any of the top three bits set exceeds l, which is what
	// makes the sig[63]&224 fast reject that this replaces exactly equivalent.
	for bit := 5; bit < 8; bit++ {
		var candidate [32]byte
		candidate[31] = 1 << uint(bit)
		if CanonicalScalarEncoding(candidate[:]) {
			t.Fatalf("scalar with bit %d of the top byte set must be rejected", 248+bit)
		}
	}
}

// The challenge is H(R ‖ A ‖ M) over the original byte strings. A caller that
// substituted a re-encoded A would change k for every non-canonical public key,
// which silently changes the accepted set.
func TestChallengeHashesOriginalBytesInOrder(t *testing.T) {
	pub := &[32]byte{}
	for i := range pub {
		pub[i] = byte(i + 1)
	}
	msg := []byte("challenge ordering is load bearing")
	sig := make([]byte, 64)
	for i := range sig {
		sig[i] = byte(0xa0 + i)
	}

	want := sha512.Sum512(append(append(append([]byte{}, sig[:32]...), pub[:]...), msg...))
	if got := Challenge(pub, msg, sig); got != want {
		t.Fatalf("challenge digest mismatch\n got %x\nwant %x", got, want)
	}

	segments := ChallengeSegments(pub, msg, sig)
	if !bytes.Equal(segments[0], sig[:32]) {
		t.Error("segment 0 must be the signature's R half")
	}
	if !bytes.Equal(segments[1], pub[:]) {
		t.Error("segment 1 must be the public key")
	}
	if !bytes.Equal(segments[2], msg) {
		t.Error("segment 2 must be the message")
	}
}

// Prepare must agree with the naive spelling it replaces: hash, then reduce
// with the vendored wide reduction.
func TestPrepareMatchesNaiveSequence(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 2000; i++ {
		pub, msg, sig := randomSignature(t, rng)
		prepared, ok := Prepare(DalekStrict, pub, msg, sig)
		if !ok {
			t.Fatalf("honest signature %d rejected by the gates", i)
		}

		digest := sha512.Sum512(append(append(append([]byte{}, sig[:32]...), pub[:]...), msg...))
		naive, err := edwards25519.NewScalar().SetUniformBytes(digest[:])
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(prepared.K[:], naive.Bytes()) {
			t.Fatalf("case %d: reduced challenge mismatch\n got %x\nwant %x", i, prepared.K, naive.Bytes())
		}
		if !bytes.Equal(prepared.R[:], sig[:32]) {
			t.Fatalf("case %d: R half mismatch", i)
		}
		if !bytes.Equal(prepared.S[:], sig[32:]) {
			t.Fatalf("case %d: S half mismatch", i)
		}
	}
}

// The gates must reject the forgery that motivates strict verification, and
// must not reject it under the permissive rules, since that difference is the
// entire delta between the two predicates.
func TestStrictRejectsIdentityKeyForgeryPermissiveDoesNot(t *testing.T) {
	// A = the identity point encoding. With [k]A vanishing for every k, any
	// (R, s) with R = [s]B satisfies the equation for any message.
	pub := &[32]byte{1}
	msg := []byte("no private key was involved")

	s, err := edwards25519.NewScalar().SetUniformBytes(bytes.Repeat([]byte{3}, 64))
	if err != nil {
		t.Fatal(err)
	}
	r := (&edwards25519.Point{}).ScalarBaseMult(s)
	sig := make([]byte, 64)
	copy(sig[:32], r.Bytes())
	copy(sig[32:], s.Bytes())

	if Admit(DalekStrict, pub, sig) {
		t.Fatal("strict rules must reject a small-order public key")
	}
	if _, ok := Prepare(DalekStrict, pub, msg, sig); ok {
		t.Fatal("strict Prepare must reject it too, not merely Admit")
	}
	if !Admit(StdlibCompat, pub, sig) {
		t.Fatal("permissive rules must admit it; the equation is what accepts it")
	}
	if _, ok := Prepare(StdlibCompat, pub, msg, sig); !ok {
		t.Fatal("permissive Prepare must admit it")
	}
	if !Admit(ZIP215, pub, sig) {
		t.Fatal("cofactored rules share the permissive byte gates")
	}
}

func TestAdmitFailsClosed(t *testing.T) {
	_, _, sig := randomSignature(t, rand.New(rand.NewSource(11)))

	if Admit(DalekStrict, nil, sig) {
		t.Error("a nil public key must be rejected")
	}
	var pub [32]byte
	for _, length := range []int{0, 32, 63, 65, 128} {
		if Admit(DalekStrict, &pub, make([]byte, length)) {
			t.Errorf("a %d-byte signature must be rejected", length)
		}
	}
	if _, ok := Parse(DalekStrict, nil, sig); ok {
		t.Error("Parse must agree with Admit on a nil public key")
	}
}

// Parse and Admit must never disagree: Parse is defined as Admit plus a split,
// and a batch former that gates with Admit then parses would otherwise process
// an item it believed rejected.
func TestParseAgreesWithAdmit(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	rules := []Rules{DalekStrict, StdlibCompat}
	for i := 0; i < 20000; i++ {
		pub, _, sig := randomSignature(t, rng)
		corrupt(rng, pub, sig)
		for _, r := range rules {
			_, parsed := Parse(r, pub, sig)
			if admitted := Admit(r, pub, sig); parsed != admitted {
				t.Fatalf("case %d rules=%+v: Parse=%v Admit=%v", i, r, parsed, admitted)
			}
		}
	}
}

func randomSignature(tb testing.TB, rng *rand.Rand) (*[32]byte, []byte, []byte) {
	tb.Helper()
	seed := make([]byte, stded25519.SeedSize)
	for i := range seed {
		seed[i] = byte(rng.Intn(256))
	}
	priv := stded25519.NewKeyFromSeed(seed)
	msg := make([]byte, rng.Intn(200))
	for i := range msg {
		msg[i] = byte(rng.Intn(256))
	}
	sig := stded25519.Sign(priv, msg)
	var pub [32]byte
	copy(pub[:], priv.Public().(stded25519.PublicKey))
	return &pub, msg, sig
}

// corrupt applies one of several mutations that target the specific gates,
// so the comparison sweeps exercise rejection paths rather than only honest
// signatures.
func corrupt(rng *rand.Rand, pub *[32]byte, sig []byte) {
	switch rng.Intn(6) {
	case 0: // leave honest
	case 1: // small-order public key
		*pub = [32]byte{1}
	case 2: // small-order R
		copy(sig[:32], smallOrderAlpha[:])
	case 3: // non-canonical R above p
		for i := range sig[:32] {
			sig[i] = 0xff
		}
		sig[31] = 0x7f
	case 4: // non-canonical S at or above l
		copy(sig[32:], ScalarOrderEncoding[:])
	case 5: // top bits of S set
		sig[63] |= 0xe0
	}
}

func BenchmarkPrepare(b *testing.B) {
	pub, msg, sig := randomSignature(b, rand.New(rand.NewSource(1)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := Prepare(DalekStrict, pub, msg, sig); !ok {
			b.Fatal("honest signature rejected")
		}
	}
}

func BenchmarkAdmit(b *testing.B) {
	pub, _, sig := randomSignature(b, rand.New(rand.NewSource(1)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !Admit(DalekStrict, pub, sig) {
			b.Fatal("honest signature rejected")
		}
	}
}
