package ed25519

import (
	"bytes"

	"github.com/Overclock-Validator/narya-ed25519/internal/r43x6"
	"github.com/Overclock-Validator/narya-ed25519/internal/sigprep"
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
	// The shared byte-level gates and challenge. This backend compares points
	// rather than re-encoding, so the canonical-R gate is load-bearing here:
	// without it a non-canonical R would decode to the same point the equation
	// produces and be accepted.
	rules := profile.rules()
	prepared, ok := sigprep.Prepare(rules, pub, message, sig)
	if !ok {
		return false
	}

	var a r43x6.Point
	if _, err := a.SetBytes(pub[:]); err != nil {
		return false
	}
	var s r43x6.Scalar
	if _, err := s.SetCanonicalBytes(prepared.S[:]); err != nil {
		return false
	}

	// Retaining decoded R lets the final comparison avoid Q.Bytes and its
	// field inversion. Only the strict profile has a decoded R to compare
	// against; the permissive one settles R by re-encoding.
	var strictR r43x6.Point
	if rules.RequireCanonicalR {
		if _, err := strictR.SetBytes(prepared.R[:]); err != nil {
			return false
		}
	}

	var k r43x6.Scalar
	if _, err := k.SetCanonicalBytes(prepared.K[:]); err != nil {
		return false
	}

	q := new(r43x6.Point).VarTimeVerifyMult(&s, &k, &a)
	if rules.RequireCanonicalR {
		return q.EqualAffine(&strictR) == 1
	}
	encodedQ := q.Bytes()
	return bytes.Equal(encodedQ[:], prepared.R[:])
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
