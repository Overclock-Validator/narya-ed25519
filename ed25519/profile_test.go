package ed25519

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	mrand "math/rand"
	"testing"
)

// withProfile runs fn with the default profile set to p, restoring it
// afterward. Tests run sequentially, so this is safe.
func withProfile(p Profile, fn func()) {
	prev := DefaultProfile()
	SetDefaultProfile(p)
	defer SetDefaultProfile(prev)
	fn()
}

func TestUnknownProfileCannotWeakenDefault(t *testing.T) {
	previous := DefaultProfile()
	defer SetDefaultProfile(previous)

	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("SetDefaultProfile accepted an unknown profile")
			}
		}()
		SetDefaultProfile(Profile(0xff))
	}()
	if got := DefaultProfile(); got != previous {
		t.Fatalf("unknown profile changed default from %d to %d", previous, got)
	}

	defer func() {
		if recover() == nil {
			t.Fatal("internal profile dispatch accepted an unknown profile")
		}
	}()
	_ = rejectedByProfile(Profile(0xff), new([32]byte), make([]byte, 64))
}

// TestStdlibCompatProfile confirms that under StdlibCompat, narya is
// exactly crypto/ed25519.Verify on the full differential mix — the
// baseline the strict profile then tightens.
func TestStdlibCompatProfile(t *testing.T) {
	withProfile(StdlibCompat, func() {
		rng := mrand.New(mrand.NewSource(7))
		c := &Cache{}
		for round := 0; round < 200; round++ {
			pubk, priv, _ := ed25519.GenerateKey(rand.Reader)
			var pub [32]byte
			copy(pub[:], pubk)
			msg := make([]byte, rng.Intn(200))
			rng.Read(msg)
			sig := ed25519.Sign(priv, msg)
			// referenceVerify == stdlib under this profile.
			if referenceVerify(&pub, msg, sig) != ed25519.Verify(pub[:], msg, sig) {
				t.Fatal("oracle drifted from stdlib under StdlibCompat")
			}
			check(t, c, &pub, msg, sig)
		}
	})
}

// TestVerifyStrictIgnoresDefault confirms VerifyStrict enforces
// DalekStrict even when the package default is flipped to StdlibCompat
// — consensus P2P sites must not be weakened by mutable global state.
func TestVerifyStrictIgnoresDefault(t *testing.T) {
	// A small-order public key: strict rejects, stdlib accepts a
	// matching signature. Use an all-honest signature so only the
	// small-order rule decides.
	msg := []byte("no dependence on global profile")
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	honestSig := ed25519.Sign(priv, msg)

	var smallOrderPub [32]byte
	raw, _ := hex.DecodeString("0100000000000000000000000000000000000000000000000000000000000000")
	copy(smallOrderPub[:], raw)
	if !smallOrderEncoding(smallOrderPub[:]) {
		t.Fatal("test vector is not small-order")
	}

	withProfile(StdlibCompat, func() {
		// VerifyStrict must reject the small-order key regardless of the
		// StdlibCompat default.
		if VerifyStrict(smallOrderPub[:], msg, honestSig) {
			t.Fatal("VerifyStrict accepted a small-order key under StdlibCompat default")
		}
		// Wrong-length pub yields false, never a panic.
		if VerifyStrict(smallOrderPub[:31], msg, honestSig) {
			t.Fatal("VerifyStrict accepted a 31-byte pub")
		}
	})
}

// TestStrictRejectsSmallOrder is the consensus fix: mainnet
// (verify_strict) rejects small-order A and small-order R, which the
// standard library accepts. For every small-order encoding used as the
// public key or as R, DalekStrict must reject where StdlibCompat may
// accept, and the two profiles must agree on all non-small-order
// inputs.
func TestStrictRejectsSmallOrder(t *testing.T) {
	msg := []byte("strict vs compat")
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	honestPub := priv.Public().(ed25519.PublicKey)
	honestSig := ed25519.Sign(priv, msg)

	// Confirm the edgePoints corpus actually contains small-order
	// encodings (guards the test itself).
	var sawSmallOrder bool
	for _, hexEnc := range edgePoints {
		raw, _ := hex.DecodeString(hexEnc)
		if smallOrderEncoding(raw) {
			sawSmallOrder = true
		}
	}
	if !sawSmallOrder {
		t.Fatal("edgePoints has no small-order encoding; test is vacuous")
	}

	rng := mrand.New(mrand.NewSource(11))
	for _, hexEnc := range edgePoints {
		raw, _ := hex.DecodeString(hexEnc)
		var edge [32]byte
		copy(edge[:], raw)
		small := smallOrderEncoding(raw)

		// Try the edge encoding as the public key, and as R with an
		// honest key, over a spread of signatures.
		for i := 0; i < 12; i++ {
			asKeySig := make([]byte, 64)
			rng.Read(asKeySig)
			asKeySig[63] &= 0x1f

			var honest [32]byte
			copy(honest[:], honestPub)
			asR := make([]byte, 64)
			copy(asR[:32], edge[:])
			rng.Read(asR[32:])
			asR[63] &= 0x1f

			cases := []struct {
				pub *[32]byte
				sig []byte
			}{
				{&edge, asKeySig},
				{&edge, honestSig},
				{&honest, asR},
			}
			for _, cse := range cases {
				var compat, strict bool
				withProfile(StdlibCompat, func() { compat = Verify(cse.pub, msg, cse.sig) })
				withProfile(DalekStrict, func() { strict = Verify(cse.pub, msg, cse.sig) })

				// Strict never accepts more than compat.
				if strict && !compat {
					t.Fatalf("strict accepted what compat rejected\npub %x sig %x", cse.pub, cse.sig)
				}
				// Where they differ, the cause must be a small-order A
				// or a small-order canonical R that compat accepted.
				if compat != strict {
					aSmall := smallOrderEncoding(cse.pub[:])
					rSmall := len(cse.sig) == 64 && smallOrderEncoding(cse.sig[:32])
					if !aSmall && !rSmall {
						t.Fatalf("profiles differ with no small-order cause\npub %x sig %x", cse.pub, cse.sig)
					}
				}
			}
		}

		// A small-order key can never verify under strict, for any sig.
		if small {
			withProfile(DalekStrict, func() {
				if Verify(&edge, msg, honestSig) {
					t.Fatalf("strict accepted a small-order public key %x", edge)
				}
			})
		}
	}
}

// TestStrictMatchesFiredancerOnSmallOrder cross-checks the strict
// profile against Firedancer's independent verdict: every CCTV vector
// that the standard library accepts but Firedancer rejects should,
// under DalekStrict, be rejected by narya too when the cause is a
// small-order point — tying our fix to a second implementation's
// behavior rather than only to our own oracle.
func TestStrictMatchesFiredancerOnSmallOrder(t *testing.T) {
	withProfile(DalekStrict, func() {
		var checked int
		for _, v := range cctvVectors {
			pubRaw, _ := hex.DecodeString(v.pub)
			msg, _ := hex.DecodeString(v.msg)
			sig, _ := hex.DecodeString(v.sig)
			if len(pubRaw) != 32 || len(sig) != 64 {
				continue
			}
			var pub [32]byte
			copy(pub[:], pubRaw)

			stdlibOK := ed25519.Verify(pubRaw, msg, sig)
			aSmall := smallOrderEncoding(pubRaw)
			rSmall := smallOrderEncoding(sig[:32])

			// stdlib accepts, Firedancer rejects, cause is small order:
			// narya-strict must reject.
			if stdlibOK && !v.fdOK && (aSmall || rSmall) {
				if Verify(&pub, msg, sig) {
					t.Fatalf("tc %d: strict accepted a small-order case Firedancer rejects", v.tcID)
				}
				checked++
			}
		}
		if checked == 0 {
			t.Fatal("no small-order stdlib/Firedancer divergence exercised; corpus or logic changed")
		}
		t.Logf("cross-checked %d small-order strict rejections against Firedancer", checked)
	})
}
