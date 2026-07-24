package ed25519

import (
	stded25519 "crypto/ed25519"

	"github.com/Overclock-Validator/narya/internal/edwards25519"
)

func init() { register("stdlib", stdlibBackend{}) }

// stdlibBackend routes every verification to crypto/ed25519 with no
// acceleration. It exists as the rollback proof point: behavior under
// this backend is the standard library by definition, so a divergence
// suspicion can be settled by flipping one knob.
type stdlibBackend struct{}

func (stdlibBackend) name() string { return "stdlib" }

func (stdlibBackend) supportsPrecomp() bool { return false }

func (stdlibBackend) verify(_ Profile, pub *[32]byte, message, sig []byte, _ *PrecomputedKey) bool {
	return stded25519.Verify(pub[:], message, sig)
}

func (stdlibBackend) verifyBatch(_ Profile, items []batchItem) {
	for i := range items {
		if items[i].skip {
			continue
		}
		items[i].ok = stded25519.Verify(items[i].pub[:], items[i].msg, items[i].sig)
	}
}

func (stdlibBackend) buildPrecomp(pub *[32]byte) (*PrecomputedKey, error) {
	// Decode via the vendored internals purely to honor the error
	// contract; verification stays on the plain stdlib path.
	if _, err := (&edwards25519.Point{}).SetBytes(pub[:]); err != nil {
		return nil, err
	}
	return &PrecomputedKey{raw: *pub, size: 32}, nil
}
