package ed25519

import (
	stded25519 "crypto/ed25519"
	"encoding/hex"
	"testing"
)

// FuzzVerifyDifferential keeps every public verification path tied to two
// independent predicates: crypto/ed25519 for StdlibCompat, and that predicate
// plus referenceSmallOrderEncoding's decoded [8]P oracle for DalekStrict.
// The strict oracle intentionally never calls the production classifier.
func FuzzVerifyDifferential(f *testing.F) {
	seed := [stded25519.SeedSize]byte{
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
	}
	priv := stded25519.NewKeyFromSeed(seed[:])
	pub := append([]byte(nil), priv.Public().(stded25519.PublicKey)...)
	msg := []byte("narya differential fuzz seed")
	sig := stded25519.Sign(priv, msg)

	f.Add(pub, msg, sig)
	badSig := append([]byte(nil), sig...)
	badSig[0] ^= 1
	f.Add(pub, msg, badSig)
	f.Add(pub, msg, sig[:63])
	f.Add(pub[:31], msg, sig)

	for _, encoded := range edgePoints {
		point, err := hex.DecodeString(encoded)
		if err != nil {
			f.Fatalf("invalid edge-point seed %q: %v", encoded, err)
		}
		f.Add(point, msg, sig)
		edgeR := append([]byte(nil), sig...)
		copy(edgeR[:32], point)
		f.Add(pub, msg, edgeR)
	}

	f.Fuzz(func(t *testing.T, pubBytes, message, signature []byte) {
		// Keep individual fuzz cases bounded. Length mutations still cover every
		// public-key/signature length around the protocol sizes.
		if len(message) > 4096 || len(signature) > 128 {
			return
		}

		if len(pubBytes) != stded25519.PublicKeySize {
			if VerifyStrict(pubBytes, message, signature) {
				t.Fatalf("VerifyStrict accepted a %d-byte public key", len(pubBytes))
			}
			return
		}

		var pub [32]byte
		copy(pub[:], pubBytes)
		want := map[Profile]bool{
			StdlibCompat: referenceVerifyProfile(StdlibCompat, &pub, message, signature),
			DalekStrict:  referenceVerifyProfile(DalekStrict, &pub, message, signature),
		}

		if got := VerifyStrict(pubBytes, message, signature); got != want[DalekStrict] {
			t.Fatalf("VerifyStrict=%v want %v\npub %x\nmsg %x\nsig %x", got, want[DalekStrict], pubBytes, message, signature)
		}

		// Preload a Cache when the key decodes, so fuzzing exercises the actual
		// cached-table path without spending eight redundant admissions per case.
		cache := &Cache{MaxTableBytes: 1}
		cache.bytes.Store(1)
		pre, preErr := Precompute(&pub)
		if preErr == nil {
			cache.tables.Store(pub, pre)
		}

		for _, profile := range []Profile{StdlibCompat, DalekStrict} {
			profile := profile
			withProfile(profile, func() {
				assertFuzzVerdict(t, "Verify", Verify(&pub, message, signature), want[profile], &pub, message, signature)
				assertFuzzVerdict(t, "Cache.Verify", cache.Verify(&pub, message, signature), want[profile], &pub, message, signature)

				if preErr == nil {
					assertFuzzVerdict(t, "PrecomputedKey.Verify", pre.Verify(message, signature), want[profile], &pub, message, signature)
				} else if want[profile] {
					t.Fatalf("Precompute rejected a key whose signature oracle accepts\npub %x", pub)
				}

				pubs := []*[32]byte{&pub}
				msgs := [][]byte{message}
				sigs := [][]byte{signature}
				ok := make([]bool, 1)
				all := VerifyBatch(pubs, msgs, sigs, ok)
				assertFuzzVerdict(t, "VerifyBatch[0]", ok[0], want[profile], &pub, message, signature)
				assertFuzzVerdict(t, "VerifyBatch(all)", all, want[profile], &pub, message, signature)

				ok[0] = false
				all = cache.VerifyBatch(pubs, msgs, sigs, ok)
				assertFuzzVerdict(t, "Cache.VerifyBatch[0]", ok[0], want[profile], &pub, message, signature)
				assertFuzzVerdict(t, "Cache.VerifyBatch(all)", all, want[profile], &pub, message, signature)
			})
		}
	})
}

func assertFuzzVerdict(t *testing.T, path string, got, want bool, pub *[32]byte, msg, sig []byte) {
	t.Helper()
	if got != want {
		t.Fatalf("%s=%v want %v\npub %x\nmsg %x\nsig %x", path, got, want, pub, msg, sig)
	}
}
