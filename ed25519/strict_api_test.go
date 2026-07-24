package ed25519

import (
	stded25519 "crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func strictDivergenceVector(t *testing.T) (*[32]byte, []byte, []byte) {
	t.Helper()
	for _, v := range cctvVectors {
		pubBytes, err := hex.DecodeString(v.pub)
		if err != nil || len(pubBytes) != stded25519.PublicKeySize {
			continue
		}
		msg, err := hex.DecodeString(v.msg)
		if err != nil {
			continue
		}
		sig, err := hex.DecodeString(v.sig)
		if err != nil || len(sig) != stded25519.SignatureSize {
			continue
		}
		if !stded25519.Verify(pubBytes, msg, sig) {
			continue
		}
		if !smallOrderEncoding(pubBytes) && !smallOrderEncoding(sig[:32]) {
			continue
		}
		var pub [32]byte
		copy(pub[:], pubBytes)
		return &pub, msg, sig
	}
	t.Fatal("CCTV corpus contains no stdlib/strict divergence vector")
	return nil, nil, nil
}

// TestExplicitStrictBatchAndCacheAPIs pins that consensus callers can
// select DalekStrict without relying on mutable package-wide state.
func TestExplicitStrictBatchAndCacheAPIs(t *testing.T) {
	strictPub, strictMsg, strictSig := strictDivergenceVector(t)
	pubBytes, privateKey, err := stded25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var validPub [32]byte
	copy(validPub[:], pubBytes)
	validMsg := []byte("explicit strict API")
	validSig := stded25519.Sign(privateKey, validMsg)

	withProfile(StdlibCompat, func() {
		pubs := []*[32]byte{&validPub, strictPub}
		msgs := [][]byte{validMsg, strictMsg}
		sigs := [][]byte{validSig, strictSig}

		compatOK := make([]bool, len(pubs))
		if !VerifyBatch(pubs, msgs, sigs, compatOK) {
			t.Fatalf("compat batch rejected inputs: %v", compatOK)
		}

		strictOK := make([]bool, len(pubs))
		if VerifyBatchStrict(pubs, msgs, sigs, strictOK) {
			t.Fatal("strict batch reported all-valid for a strict-only rejection")
		}
		if !strictOK[0] || strictOK[1] {
			t.Fatalf("strict batch verdicts = %v, want [true false]", strictOK)
		}

		cache := &Cache{}
		if !cache.Verify(&validPub, validMsg, validSig) ||
			!cache.Verify(strictPub, strictMsg, strictSig) {
			t.Fatal("compat cache rejected a stdlib-valid input")
		}
		if !cache.VerifyStrict(&validPub, validMsg, validSig) {
			t.Fatal("strict cache rejected a valid signature")
		}
		if cache.VerifyStrict(strictPub, strictMsg, strictSig) {
			t.Fatal("strict cache accepted a small-order signature")
		}

		cachedOK := make([]bool, len(pubs))
		if cache.VerifyBatchStrict(pubs, msgs, sigs, cachedOK) {
			t.Fatal("strict cached batch reported all-valid")
		}
		if !cachedOK[0] || cachedOK[1] {
			t.Fatalf("strict cached batch verdicts = %v, want [true false]", cachedOK)
		}
	})
}

// TestCacheStrictRejectionDoesNotAffectAdmission preserves the cache's
// precheck-before-lookup ordering for both explicit strict entry points.
func TestCacheStrictRejectionDoesNotAffectAdmission(t *testing.T) {
	pub, msg, sig := strictDivergenceVector(t)
	c := &Cache{}
	if c.VerifyStrict(pub, msg, sig) {
		t.Fatal("strict cache accepted a small-order signature")
	}
	ok := []bool{true}
	if c.VerifyBatchStrict([]*[32]byte{pub}, [][]byte{msg}, [][]byte{sig}, ok) {
		t.Fatal("strict cached batch accepted a small-order signature")
	}
	if ok[0] {
		t.Fatal("strict cached batch left a rejected verdict true")
	}
	if got := c.Stats(); got.Hits != 0 || got.Misses != 0 {
		t.Fatalf("strict precheck touched cache admission: %+v", got)
	}
}
