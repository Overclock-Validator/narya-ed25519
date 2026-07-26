package ed25519

import (
	"fmt"
	"testing"

	"github.com/Overclock-Validator/narya-ed25519/internal/edwards25519"
)

// The shared profile pre-pass is not universal. A backend implementing
// rawBatchBackend or rawStrictSingleBackend is called with the caller's slices
// directly, skipping applyProfile and verifyOne respectively, so it must apply
// the byte-level rules itself.
//
// That obligation previously held only by convention: exactly one backend
// implemented those interfaces and it happened to re-apply the rules. Nothing
// checked it, and a second implementation that forgot would silently accept
// small-order public keys under DalekStrict, which is the precise divergence
// this library exists to prevent.
//
// This test converts the convention into an assertion, over every registered
// backend rather than the one that exists today.
func TestRawBackendPathsApplyTheProfilePrePass(t *testing.T) {
	// A signature that is valid under the plain equation but must be rejected
	// by the strict pre-pass: A is the identity, so [k]A vanishes and any
	// (R, s) with R = [s]B satisfies the equation for any message.
	pub := &[32]byte{1}
	message := []byte("only the pre-pass rejects this")

	scalar, err := edwards25519.NewScalar().SetUniformBytes(make([]byte, 64))
	if err != nil {
		t.Fatal(err)
	}
	scalar, err = scalar.SetCanonicalBytes(append(append([]byte{7}, make([]byte, 30)...), 0))
	if err != nil {
		t.Fatal(err)
	}
	commitment := (&edwards25519.Point{}).ScalarBaseMult(scalar)
	sig := make([]byte, 64)
	copy(sig[:32], commitment.Bytes())
	copy(sig[32:], scalar.Bytes())

	// Sanity: this must be exactly the interesting case. Accepted permissively,
	// rejected strictly. If it stops being so the test proves nothing.
	if !genericBackend.verify(genericBackend{}, StdlibCompat, pub, message, sig, nil) {
		t.Fatal("fixture is not accepted under StdlibCompat; it cannot distinguish the pre-pass")
	}
	if !rejectedByProfile(DalekStrict, pub, sig) {
		t.Fatal("fixture is not rejected by the strict pre-pass; it cannot distinguish the pre-pass")
	}

	for name, b := range registry {
		name, b := name, b
		t.Run(name, func(t *testing.T) {
			if !backendUsable(t, name, b) {
				t.Skipf("backend %q is not available on this host", name)
			}

			if raw, ok := b.(rawStrictSingleBackend); ok {
				if raw.verifyStrictRaw(pub, message, sig) {
					t.Error("verifyStrictRaw accepted a small-order public key; it bypasses verifyOne and must apply the strict rules itself")
				}
			}

			if raw, ok := b.(rawBatchBackend); ok {
				// Sweep the width so a backend that gates only its scalar tail,
				// or only its vector groups, is still caught.
				for _, n := range []int{1, 2, 4, 8, 9} {
					pubs := make([]*[32]byte, n)
					msgs := make([][]byte, n)
					sigs := make([][]byte, n)
					verdicts := make([]bool, n)
					for i := range pubs {
						pubs[i], msgs[i], sigs[i] = pub, message, sig
					}
					if raw.verifyBatchRaw(DalekStrict, pubs, msgs, sigs, verdicts) {
						t.Errorf("n=%d: verifyBatchRaw reported all-valid for small-order keys", n)
					}
					for i, got := range verdicts {
						if got {
							t.Errorf("n=%d lane %d: verifyBatchRaw accepted a small-order public key; it bypasses applyProfile and must apply the strict rules itself", n, i)
						}
					}
				}
			}
		})
	}
}

// backendUsable reports whether a registered backend can run here. Activation
// is the same gate SetBackend applies, so a backend that would fail to select
// is skipped rather than reported as a pre-pass failure.
func backendUsable(t *testing.T, name string, b backend) bool {
	t.Helper()
	if activator, ok := b.(activatingBackend); ok {
		if err := activator.activate(); err != nil {
			return false
		}
	}
	if _, ok := b.(rawBatchBackend); !ok {
		if _, ok := b.(rawStrictSingleBackend); !ok {
			// Nothing to check: this backend has no bypass path.
			t.Skipf("backend %q implements no raw entry point", name)
		}
	}
	return true
}

// A raw batch path must also keep per-item verdicts aligned when only some
// items are rejected by the pre-pass. A backend that bailed out of the whole
// group on the first bad item would pass the test above while rejecting valid
// signatures.
func TestRawBatchPathRejectsOnlyThePrePassFailures(t *testing.T) {
	fixture := makeBatchFixture(t, 8, 200)
	badPub := &[32]byte{1}

	for name, b := range registry {
		raw, ok := b.(rawBatchBackend)
		if !ok {
			continue
		}
		name, raw, b := name, raw, b
		t.Run(name, func(t *testing.T) {
			if activator, ok := b.(activatingBackend); ok {
				if err := activator.activate(); err != nil {
					t.Skipf("backend %q is not available on this host", name)
				}
			}
			for bad := 0; bad < len(fixture.pubs); bad++ {
				pubs := append([]*[32]byte(nil), fixture.pubs...)
				pubs[bad] = badPub
				verdicts := make([]bool, len(pubs))
				if raw.verifyBatchRaw(DalekStrict, pubs, fixture.msgs, fixture.sigs, verdicts) {
					t.Fatalf("bad=%d: reported all-valid", bad)
				}
				for i, got := range verdicts {
					if want := i != bad; got != want {
						t.Fatalf("bad=%d lane %d: verdict=%v want %v", bad, i, got, want)
					}
				}
			}
		})
	}
}

var _ = fmt.Sprintf
