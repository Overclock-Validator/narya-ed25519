package ed25519

import (
	"bytes"
	"crypto/sha512"

	"github.com/Overclock-Validator/narya-ed25519/internal/edwards25519"
	"github.com/Overclock-Validator/narya-ed25519/internal/r43x6"
)

func init() { register("ifma", ifmaBackend{}) }

// ifmaBackend is the first complete, correctness-oriented verifier over the
// r43x6 field. It is deliberately forced-only: pick("") never selects it, and
// selecting it explicitly performs the one-way, CPU-gated activation below.
// Its current scalar multiplication is the straightforward width-5/width-8
// reference schedule; cache tables and lane-parallel DSM are later stages.
type ifmaBackend struct{}

func (ifmaBackend) name() string { return "ifma" }

func (ifmaBackend) supportsPrecomp() bool { return false }

func (ifmaBackend) activate() error {
	return r43x6.EnableExperimentalIFMA()
}

func (ifmaBackend) buildPrecomp(pub *[32]byte) (*PrecomputedKey, error) {
	if !r43x6.ExperimentalIFMAEnabled() {
		panic("ed25519: ifma backend used without activation")
	}
	if _, err := new(r43x6.Point).SetBytes(pub[:]); err != nil {
		return nil, err
	}
	// This reference stage deliberately has no backend-native key table.
	return &PrecomputedKey{raw: *pub, size: 32}, nil
}

func (ifmaBackend) verify(profile Profile, pub *[32]byte, message, sig []byte, _ *PrecomputedKey) bool {
	if !r43x6.ExperimentalIFMAEnabled() {
		panic("ed25519: ifma backend used without activation")
	}
	return verifyR43Pipeline(profile, pub, message, sig)
}

// verifyR43Pipeline contains the backend's complete profile-aware verifier.
// Keeping the activation guard outside it lets non-IFMA CI execute this exact
// control flow over r43x6's scalar arithmetic, while the forced backend runs
// the same code after field dispatch has switched to assembly.
func verifyR43Pipeline(profile Profile, pub *[32]byte, message, sig []byte) bool {
	if len(sig) != 64 {
		return false
	}

	var a r43x6.Point
	if _, err := a.SetBytes(pub[:]); err != nil {
		return false
	}
	var s r43x6.Scalar
	if _, err := s.SetCanonicalBytes(sig[32:]); err != nil {
		return false
	}

	// The standalone byte predicate checks canonical compressed R independently
	// of the shared small-order pre-pass. Retaining decoded R lets the final
	// comparison avoid Q.Bytes and its field inversion.
	var strictR r43x6.Point
	if profile == DalekStrict {
		if !canonicalREncoding(sig[:32]) {
			return false
		}
		if _, err := strictR.SetBytes(sig[:32]); err != nil {
			return false
		}
	}

	h := sha512.New()
	_, _ = h.Write(sig[:32])
	_, _ = h.Write(pub[:])
	_, _ = h.Write(message)
	var digest [sha512.Size]byte
	h.Sum(digest[:0])

	// Reuse the independently tested canonical reduction from the vendored
	// Edwards implementation. The group equation itself is entirely r43x6.
	reducedK, err := edwards25519.NewScalar().SetUniformBytes(digest[:])
	if err != nil {
		return false
	}
	var k r43x6.Scalar
	if _, err := k.SetCanonicalBytes(reducedK.Bytes()); err != nil {
		return false
	}

	q := new(r43x6.Point).VarTimeVerifyMult(&s, &k, &a)
	if profile == DalekStrict {
		return q.EqualAffine(&strictR) == 1
	}
	encodedQ := q.Bytes()
	return bytes.Equal(encodedQ[:], sig[:32])
}

func (b ifmaBackend) verifyBatch(profile Profile, items []batchItem) {
	for i := range items {
		it := &items[i]
		if it.skip {
			continue
		}
		it.ok = b.verify(profile, it.pub, it.msg, it.sig, it.pre)
	}
}
