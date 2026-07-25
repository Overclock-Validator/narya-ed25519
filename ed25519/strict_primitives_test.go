package ed25519

import (
	"bytes"
	stded25519 "crypto/ed25519"
	"encoding/hex"
	"fmt"
	"math/rand"
	"testing"

	"github.com/Overclock-Validator/narya/internal/edwards25519"
)

var sevenSmallOrderLow255 = [...]string{
	"0000000000000000000000000000000000000000000000000000000000000000",
	"0100000000000000000000000000000000000000000000000000000000000000",
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
}

// smallOrderEncodingReference is the literal, deliberately slow definition
// used only as a differential oracle: decode permissively and test [8]P = O.
func smallOrderEncodingReference(b []byte) bool {
	p, err := (&edwards25519.Point{}).SetBytes(b)
	if err != nil {
		return false
	}
	return p.IsSmallOrder()
}

// rejectedByStrictLegacyDecodeCofactor is the complete historical strict
// pre-pass kept only for before/after tests and benchmarks. Each original
// compressed input is decoded with the same permissive point decoder as the
// generic verifier, then classified by the literal [8]P == identity test.
// Decode failures remain for the equation verifier to reject, matching the
// production pre-pass contract.
func rejectedByStrictLegacyDecodeCofactor(pub *[32]byte, sig []byte) bool {
	if smallOrderEncodingReference(pub[:]) {
		return true
	}
	if len(sig) == stded25519.SignatureSize && smallOrderEncodingReference(sig[:32]) {
		return true
	}
	return false
}

type completeStrictPrecheckMode struct {
	name   string
	reject func(*[32]byte, []byte) bool
}

var completeStrictPrecheckModes = [...]completeStrictPrecheckMode{
	{name: "legacy-decode-cofactor", reject: rejectedByStrictLegacyDecodeCofactor},
	{name: "seven-value", reject: rejectedByStrict},
}

// verifyGenericWithStrictPrecheck is deliberately the single wrapper used by
// both benchmark modes. Only the strict rejection predicate varies; profile
// dispatch and the complete generic equation are structurally identical. In
// particular, compat runs through the same wrapper while skipping both strict
// predicates, making its paired rows an unaffected-path overhead control.
func verifyGenericWithStrictPrecheck(profile Profile, mode completeStrictPrecheckMode, pub *[32]byte, message, sig []byte) bool {
	switch profile {
	case DalekStrict:
		if mode.reject(pub, sig) {
			return false
		}
	case StdlibCompat:
		// Compat intentionally has no small-order rejection.
	default:
		panic("ed25519: unknown test-only strict-precheck profile")
	}
	return (genericBackend{}).verify(profile, pub, message, sig, nil)
}

func checkCompleteStrictPrecheckModes(t *testing.T, label string, pub *[32]byte, message, sig []byte) {
	t.Helper()
	legacyRejected := rejectedByStrictLegacyDecodeCofactor(pub, sig)
	fastRejected := rejectedByStrict(pub, sig)
	if legacyRejected != fastRejected {
		t.Fatalf("%s prepass legacy=%v seven-value=%v\npub=%x\nsig=%x", label, legacyRejected, fastRejected, pub[:], sig)
	}
	for _, profile := range []Profile{DalekStrict, StdlibCompat} {
		legacy := verifyGenericWithStrictPrecheck(profile, completeStrictPrecheckModes[0], pub, message, sig)
		fast := verifyGenericWithStrictPrecheck(profile, completeStrictPrecheckModes[1], pub, message, sig)
		production := verifyOne(genericBackend{}, profile, pub, message, sig, nil)
		oracle := referenceVerifyProfile(profile, pub, message, sig)
		if legacy != fast || fast != production || production != oracle {
			t.Fatalf("%s profile=%d legacy=%v seven-value=%v production=%v oracle=%v\npub=%x\nmsg=%x\nsig=%x", label, profile, legacy, fast, production, oracle, pub[:], message, sig)
		}
	}
}

func canonicalRReference(r []byte) bool {
	p, err := (&edwards25519.Point{}).SetBytes(r)
	if err != nil {
		return false
	}
	return bytes.Equal(p.Bytes(), r)
}

func TestSmallOrderEncodingClassifier(t *testing.T) {
	for _, encoded := range sevenSmallOrderLow255 {
		base, err := hex.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		for sign := byte(0); sign <= 1; sign++ {
			b := append([]byte(nil), base...)
			b[31] = b[31]&0x7f | sign<<7
			if !smallOrderEncoding(b) {
				t.Fatalf("classifier missed low255=%s sign=%d", encoded, sign)
			}
			if !smallOrderEncodingReference(b) {
				t.Fatalf("oracle says low255=%s sign=%d is not small-order", encoded, sign)
			}

			// Check every one-bit neighbor against the mathematical oracle.
			// Some neighbors coincide with another member of the seven-value
			// set, so their expected result must come from the oracle.
			for bit := 0; bit < 255; bit++ {
				mutated := append([]byte(nil), b...)
				mutated[bit/8] ^= 1 << uint(bit%8)
				got := smallOrderEncoding(mutated)
				want := smallOrderEncodingReference(mutated)
				if got != want {
					t.Fatalf("one-bit neighbor mismatch: low255=%s sign=%d bit=%d got=%v want=%v\nencoding=%x", encoded, sign, bit, got, want, mutated)
				}
			}
		}
	}

	if smallOrderEncoding(nil) || smallOrderEncoding(make([]byte, 31)) || smallOrderEncoding(make([]byte, 33)) {
		t.Fatal("classifier accepted a wrong-length encoding")
	}

	rng := rand.New(rand.NewSource(0x5eed))
	for i := 0; i < 4096; i++ {
		b := make([]byte, 32)
		_, _ = rng.Read(b)
		if got, want := smallOrderEncoding(b), smallOrderEncodingReference(b); got != want {
			t.Fatalf("random classifier mismatch at %d: got=%v want=%v\nencoding=%x", i, got, want, b)
		}
	}
}

func TestCanonicalREncoding(t *testing.T) {
	if canonicalREncoding(nil) || canonicalREncoding(make([]byte, 31)) || canonicalREncoding(make([]byte, 33)) {
		t.Fatal("canonical-R predicate accepted a wrong-length encoding")
	}

	// Both x=0 points have noncanonical sign-bit-one aliases. Canonicality must
	// reject them without relying on the separate small-order classifier.
	for _, negativeZero := range [][]byte{
		append([]byte{1}, make([]byte, 30)...),
		append([]byte{0xec}, bytes.Repeat([]byte{0xff}, 30)...),
	} {
		negativeZero = append(negativeZero, 0x80)
		if negativeZero[0] == 0xec {
			negativeZero[31] = 0xff
		}
		if !smallOrderEncoding(negativeZero) {
			t.Fatal("negative-zero case was not classified small-order")
		}
		if canonicalREncoding(negativeZero) || canonicalRReference(negativeZero) {
			t.Fatalf("negative-zero encoding passed canonicality: %x", negativeZero)
		}
	}

	check := func(label string, r []byte) bool {
		t.Helper()
		if _, err := (&edwards25519.Point{}).SetBytes(r); err != nil {
			return false
		}
		got := canonicalREncoding(r)
		want := canonicalRReference(r)
		if got != want {
			t.Fatalf("%s: canonical-R mismatch got=%v want=%v\nencoding=%x", label, got, want, r)
		}
		return !want
	}

	// SetBytes reduces p+n to n. Exercise every possible unreduced alias;
	// only the aliases that actually decode and are not small-order enter the
	// equivalence domain.
	var sawUnreducedNonSmall bool
	for n := byte(2); n <= 18; n++ {
		for sign := byte(0); sign <= 1; sign++ {
			r := make([]byte, 32)
			r[0] = 0xed + n
			for i := 1; i < 31; i++ {
				r[i] = 0xff
			}
			r[31] = 0x7f | sign<<7
			if check("unreduced alias", r) {
				sawUnreducedNonSmall = true
			}
		}
	}
	if !sawUnreducedNonSmall {
		t.Fatal("test did not exercise a decodable non-small-order y >= p encoding")
	}

	generator := edwards25519.NewGeneratorPoint().Bytes()
	check("generator", generator)

	rng := rand.New(rand.NewSource(0xc4a0))
	var checked int
	for i := 0; i < 8192; i++ {
		r := make([]byte, 32)
		_, _ = rng.Read(r)
		if _, err := (&edwards25519.Point{}).SetBytes(r); err != nil {
			continue
		}
		check("random decodable point", r)
		checked++
	}
	if checked < 1000 {
		t.Fatalf("canonical-R differential test covered only %d decodable points", checked)
	}
}

func TestStrictPrecheckCompletePipelineDifferential(t *testing.T) {
	t.Run("CCTV", func(t *testing.T) {
		for _, vector := range cctvVectors {
			pubBytes, err := hex.DecodeString(vector.pub)
			if err != nil || len(pubBytes) != stded25519.PublicKeySize {
				t.Fatalf("tc=%d invalid public key fixture", vector.tcID)
			}
			message, err := hex.DecodeString(vector.msg)
			if err != nil {
				t.Fatalf("tc=%d invalid message fixture: %v", vector.tcID, err)
			}
			signature, err := hex.DecodeString(vector.sig)
			if err != nil || len(signature) != stded25519.SignatureSize {
				t.Fatalf("tc=%d invalid signature fixture", vector.tcID)
			}
			var pub [stded25519.PublicKeySize]byte
			copy(pub[:], pubBytes)
			checkCompleteStrictPrecheckModes(t, fmt.Sprintf("CCTV/tc=%d", vector.tcID), &pub, message, signature)
		}
	})

	t.Run("Wycheproof", func(t *testing.T) {
		for _, vector := range wycheproofVectors {
			pubBytes, err := hex.DecodeString(vector.pub)
			if err != nil || len(pubBytes) != stded25519.PublicKeySize {
				t.Fatalf("tc=%d invalid public key fixture", vector.tcID)
			}
			message, err := hex.DecodeString(vector.msg)
			if err != nil {
				t.Fatalf("tc=%d invalid message fixture: %v", vector.tcID, err)
			}
			signature, err := hex.DecodeString(vector.sig)
			if err != nil || len(signature) != stded25519.SignatureSize {
				t.Fatalf("tc=%d invalid signature fixture", vector.tcID)
			}
			var pub [stded25519.PublicKeySize]byte
			copy(pub[:], pubBytes)
			checkCompleteStrictPrecheckModes(t, fmt.Sprintf("Wycheproof/tc=%d", vector.tcID), &pub, message, signature)
		}
	})

	var seed [stded25519.SeedSize]byte
	for index := range seed {
		seed[index] = byte(3*index + 1)
	}
	privateKey := stded25519.NewKeyFromSeed(seed[:])
	var honestPub [stded25519.PublicKeySize]byte
	copy(honestPub[:], privateKey.Public().(stded25519.PublicKey))
	message := []byte("complete strict precheck edge differential")
	honestSignature := stded25519.Sign(privateKey, message)

	t.Run("edge-points", func(t *testing.T) {
		rng := rand.New(rand.NewSource(0x51ed))
		checkEdge := func(label string, encoded []byte) {
			t.Helper()
			if len(encoded) != 32 {
				t.Fatalf("%s has %d bytes", label, len(encoded))
			}
			var edgePub [stded25519.PublicKeySize]byte
			copy(edgePub[:], encoded)
			checkCompleteStrictPrecheckModes(t, label+"/A", &edgePub, message, honestSignature)

			edgeR := make([]byte, stded25519.SignatureSize)
			copy(edgeR[:32], encoded)
			_, _ = rng.Read(edgeR[32:])
			edgeR[63] &= 0x1f
			checkCompleteStrictPrecheckModes(t, label+"/R", &honestPub, message, edgeR)
		}

		for index, encodedHex := range edgePoints {
			encoded, err := hex.DecodeString(encodedHex)
			if err != nil {
				t.Fatal(err)
			}
			checkEdge(fmt.Sprintf("edgePoints/%d", index), encoded)
		}
		for index, encodedHex := range sevenSmallOrderLow255 {
			encoded, err := hex.DecodeString(encodedHex)
			if err != nil {
				t.Fatal(err)
			}
			for sign := byte(0); sign <= 1; sign++ {
				candidate := append([]byte(nil), encoded...)
				candidate[31] = candidate[31]&0x7f | sign<<7
				checkEdge(fmt.Sprintf("small-order/%d/sign=%d", index, sign), candidate)
			}
		}

		checkCompleteStrictPrecheckModes(t, "wrong-signature-length/63", &honestPub, message, honestSignature[:63])
		checkCompleteStrictPrecheckModes(t, "wrong-signature-length/65", &honestPub, message, append(append([]byte(nil), honestSignature...), 0))
	})

	t.Run("random", func(t *testing.T) {
		rng := rand.New(rand.NewSource(0xc01dbeef))
		for round := 0; round < 512; round++ {
			var roundSeed [stded25519.SeedSize]byte
			_, _ = rng.Read(roundSeed[:])
			roundKey := stded25519.NewKeyFromSeed(roundSeed[:])
			var pub [stded25519.PublicKeySize]byte
			copy(pub[:], roundKey.Public().(stded25519.PublicKey))
			roundMessage := make([]byte, rng.Intn(1400))
			_, _ = rng.Read(roundMessage)
			signature := stded25519.Sign(roundKey, roundMessage)
			checkCompleteStrictPrecheckModes(t, fmt.Sprintf("random/%d/valid", round), &pub, roundMessage, signature)

			mutated := append([]byte(nil), signature...)
			mutated[rng.Intn(len(mutated))] ^= 1 << uint(rng.Intn(8))
			checkCompleteStrictPrecheckModes(t, fmt.Sprintf("random/%d/mutated-signature", round), &pub, roundMessage, mutated)

			var randomPub [stded25519.PublicKeySize]byte
			_, _ = rng.Read(randomPub[:])
			randomSignature := make([]byte, stded25519.SignatureSize)
			_, _ = rng.Read(randomSignature)
			checkCompleteStrictPrecheckModes(t, fmt.Sprintf("random/%d/garbage", round), &randomPub, roundMessage, randomSignature)
		}
	})
}

var benchmarkStrictPredicateResult bool

// BenchmarkStrictPointPrechecks keeps the production byte predicates beside
// their deliberately slow mathematical specifications. Complete-verifier
// benchmarks remain the release gate; these rows identify how much of a
// change comes from replacing decode-plus-[8]P and re-encoding R.
func BenchmarkStrictPointPrechecks(b *testing.B) {
	ordinary := edwards25519.NewGeneratorPoint().Bytes()
	small, err := hex.DecodeString(sevenSmallOrderLow255[5])
	if err != nil {
		b.Fatal(err)
	}
	cases := []struct {
		name string
		in   []byte
		fn   func([]byte) bool
	}{
		{"small-order/fast/common", ordinary, smallOrderEncoding},
		{"small-order/oracle/common", ordinary, smallOrderEncodingReference},
		{"small-order/fast/match", small, smallOrderEncoding},
		{"small-order/oracle/match", small, smallOrderEncodingReference},
		{"canonical-R/fast", ordinary, canonicalREncoding},
		{"canonical-R/oracle", ordinary, canonicalRReference},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			var result bool
			for i := 0; i < b.N; i++ {
				result = tc.fn(tc.in)
			}
			benchmarkStrictPredicateResult = result
		})
	}
}

// BenchmarkStrictPrecheckCompletePipeline measures the historical and current
// strict pre-passes around the exact same uncached generic verifier. Release
// message sizes are explicit so these rows can be selected without pulling in
// the larger diagnostic message sweep. Compat is a structural control: both
// modes traverse the same wrapper and skip strict rejection.
func BenchmarkStrictPrecheckCompletePipeline(b *testing.B) {
	profiles := [...]struct {
		name    string
		profile Profile
	}{
		{name: "strict", profile: DalekStrict},
		{name: "compat", profile: StdlibCompat},
	}
	for _, messageSize := range []int{64, 200, 1232} {
		fixture := makeFixture(b, messageSize)
		for _, profile := range profiles {
			for _, mode := range completeStrictPrecheckModes {
				name := fmt.Sprintf("profile=%s/mode=%s/msg=%d", profile.name, mode.name, messageSize)
				b.Run(name, func(b *testing.B) {
					b.ReportAllocs()
					var result bool
					for iteration := 0; iteration < b.N; iteration++ {
						result = verifyGenericWithStrictPrecheck(profile.profile, mode, &fixture.pub, fixture.msg, fixture.sig)
					}
					benchmarkStrictPredicateResult = result
				})
			}
		}
	}
}
