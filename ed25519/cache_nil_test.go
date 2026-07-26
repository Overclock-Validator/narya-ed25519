package ed25519

import (
	stded25519 "crypto/ed25519"
	"crypto/rand"
	"fmt"
	"testing"
)

// A nil *Cache must behave the same way for every input.
//
// Before this it did not: the strict pre-pass returns before touching the
// receiver, so a signature rejected on bytes alone came back false, while a
// signature that reached a table lookup dereferenced nil and panicked. A caller
// who wired a nil cache and happened to exercise it with an invalid signature
// would see it working, and meet the panic in production on the first valid one.
//
// The chosen behaviour is to fail closed, matching PrecomputedKey.Verify. What
// matters more than the choice is that it no longer depends on the data.
func TestNilCacheFailsClosedForEveryInput(t *testing.T) {
	var cache *Cache

	pub, msg, sig := freshSignature(t)

	// A valid signature: this is the case that used to panic.
	if cache.Verify(pub, msg, sig) {
		t.Error("nil cache accepted a valid signature")
	}
	if cache.VerifyStrict(pub, msg, sig) {
		t.Error("nil cache accepted a valid signature under VerifyStrict")
	}

	// A signature the strict pre-pass rejects: this case already returned
	// false, and must keep doing so.
	smallOrderPub := &[32]byte{1}
	if cache.VerifyStrict(smallOrderPub, msg, sig) {
		t.Error("nil cache accepted a small-order public key")
	}

	// A malformed signature, rejected before any lookup.
	if cache.VerifyStrict(pub, msg, sig[:63]) {
		t.Error("nil cache accepted a short signature")
	}

	// Batch, including widths that straddle the vector group boundaries and an
	// empty batch, whose vacuous-true result must match the uncached API.
	for _, n := range []int{0, 1, 3, 4, 8, 9} {
		t.Run(fmt.Sprintf("batch/n=%d", n), func(t *testing.T) {
			pubs := make([]*[32]byte, n)
			msgs := make([][]byte, n)
			sigs := make([][]byte, n)
			verdicts := make([]bool, n)
			for i := 0; i < n; i++ {
				pubs[i], msgs[i], sigs[i] = pub, msg, sig
			}

			all := cache.VerifyBatchStrict(pubs, msgs, sigs, verdicts)
			if want := n == 0; all != want {
				t.Errorf("all=%v want %v", all, want)
			}
			for i, got := range verdicts {
				if got {
					t.Errorf("lane %d accepted under a nil cache", i)
				}
			}
		})
	}

	// A caller bug in slice lengths must still be loud, and must be loud in the
	// same way it is for a live cache rather than silently returning false.
	t.Run("mismatchedLengthsStillPanic", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Error("mismatched slice lengths must panic for a nil cache too")
			}
		}()
		cache.VerifyBatchStrict(make([]*[32]byte, 2), make([][]byte, 1), make([][]byte, 2), make([]bool, 2))
	})
}

func freshSignature(t *testing.T) (*[32]byte, []byte, []byte) {
	t.Helper()
	public, private, err := stded25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("nil cache behaviour must not depend on the input")
	var pub [32]byte
	copy(pub[:], public)
	return &pub, msg, stded25519.Sign(private, msg)
}
