package ed25519

import (
	"bytes"

	"github.com/Overclock-Validator/narya-ed25519/internal/edwards25519"
	"github.com/Overclock-Validator/narya-ed25519/internal/sigprep"
	"github.com/Overclock-Validator/narya-ed25519/sha512mb"
)

func init() { register("generic", genericBackend{}) }

// genericBackend is pure Go over vendored edwards25519 internals: the
// non-field baseline is filippo.io/edwards25519 v1.0.0 and the field package
// is synchronized to v1.2.0, with the local modifications recorded in NOTICE.
// Its profile semantics are established by edge-case and differential tests,
// not assumed from shared implementation ancestry. Hot keys get a fixed-base
// comb table that removes the doubling chain.
type genericBackend struct{}

func (genericBackend) name() string { return "generic" }

func (genericBackend) supportsPrecomp() bool { return true }

const (
	// A PubkeyTable is 32 windows of 8 affine points, 3 field elements
	// (5 limbs) each.
	genericTableBytes = 32 * 8 * 3 * 5 * 8

	// A PubkeyNAFTable is 8 projective cached points, 4 field elements
	// (5 limbs) each. It is an experimental compact warm-key tier: it saves
	// public-key decoding and width-5 table construction, while the larger
	// PubkeyTable remains the hot tier that also removes the doubling chain.
	genericCompactTableBytes = 8 * 4 * 5 * 8
)

func (genericBackend) buildPrecomp(pub *[32]byte) (*PrecomputedKey, error) {
	A, err := (&edwards25519.Point{}).SetBytes(pub[:])
	if err != nil {
		return nil, err
	}
	return &PrecomputedKey{
		raw:   *pub,
		table: edwards25519.NewPubkeyTable((&edwards25519.Point{}).Negate(A)),
		size:  genericTableBytes,
	}, nil
}

// buildCompactPrecomp constructs the native compact warm-key representation.
// Cache policy intentionally does not use it yet; benchmarks must establish
// its recurrence and working-set crossover before it becomes an admission
// tier.
func (genericBackend) buildCompactPrecomp(pub *[32]byte) (*PrecomputedKey, error) {
	A, err := (&edwards25519.Point{}).SetBytes(pub[:])
	if err != nil {
		return nil, err
	}
	return &PrecomputedKey{
		raw:   *pub,
		table: edwards25519.NewPubkeyNAFTable((&edwards25519.Point{}).Negate(A)),
		size:  genericCompactTableBytes,
	}, nil
}

func (genericBackend) verify(profile Profile, pub *[32]byte, message, sig []byte, pre *PrecomputedKey) bool {
	var table *edwards25519.PubkeyTable
	var compact *edwards25519.PubkeyNAFTable
	if pre != nil {
		switch native := pre.table.(type) {
		case *edwards25519.PubkeyTable:
			table = native
		case *edwards25519.PubkeyNAFTable:
			compact = native
		}
	}

	// The shared byte-level gates. This backend settles R by re-encoding its
	// computed point and byte-comparing, which already rejects every
	// non-canonical R: decoding reduces the encoding, so the re-encoded form
	// cannot equal a non-reduced input. Applying the gate explicitly changes no
	// verdict, and lets the backend be called directly without depending on the
	// shared pre-pass having run.
	prepared, ok := sigprep.Parse(profile.rules(), pub, sig)
	if !ok {
		return false
	}

	var minusA *edwards25519.Point
	if table == nil && compact == nil {
		A, err := (&edwards25519.Point{}).SetBytes(pub[:])
		if err != nil {
			return false
		}
		minusA = (&edwards25519.Point{}).Negate(A)
	}

	// Reduce natively rather than through sigprep.Reduce: this backend wants an
	// edwards25519.Scalar, and routing through canonical bytes would add a
	// round-trip on the reference path for no gain.
	digest := sigprep.Challenge(pub, message, sig)
	k, err := edwards25519.NewScalar().SetUniformBytes(digest[:])
	if err != nil {
		return false
	}

	s, err := edwards25519.NewScalar().SetCanonicalBytes(prepared.S[:])
	if err != nil {
		return false
	}

	// R = [s]B - [k]A must re-encode to the signature's R bytes. The
	// cached table holds -A, so the comb path is all additions.
	var r *edwards25519.Point
	if table != nil {
		r = (&edwards25519.Point{}).VarTimeDoubleCombMult(k, table, s)
	} else if compact != nil {
		r = (&edwards25519.Point{}).VarTimeDoubleScalarBaseMultTable(k, compact, s)
	} else {
		r = (&edwards25519.Point{}).VarTimeDoubleScalarBaseMult(k, minusA, s)
	}
	return bytes.Equal(prepared.R[:], r.Bytes())
}

// verifyBatch runs the batch pipeline: a scalar precheck-and-decode
// pass that drops items whose verdict is already known false, one
// multi-buffer hash round for the survivors' k = H(R ‖ A ‖ M), then
// per-item point math. Verdicts are per-signature and bit-identical
// to verify — batching only ever amortizes hashing and decoding, it
// never mixes signatures into one equation.
func (g genericBackend) verifyBatch(profile Profile, items []batchItem) {
	type work struct {
		idx     int
		table   *edwards25519.PubkeyTable
		compact *edwards25519.PubkeyNAFTable
		minusA  *edwards25519.Point
		s       *edwards25519.Scalar
	}
	live := make([]work, 0, len(items))
	hashIn := make([][][]byte, 0, len(items))

	rules := profile.rules()
	for i := range items {
		it := &items[i]
		if it.skip {
			continue
		}
		prepared, admitted := sigprep.Parse(rules, it.pub, it.sig)
		if !admitted {
			continue
		}
		w := work{idx: i}
		if it.pre != nil {
			switch native := it.pre.table.(type) {
			case *edwards25519.PubkeyTable:
				w.table = native
			case *edwards25519.PubkeyNAFTable:
				w.compact = native
			}
		}
		if w.table == nil && w.compact == nil {
			A, err := (&edwards25519.Point{}).SetBytes(it.pub[:])
			if err != nil {
				continue
			}
			w.minusA = (&edwards25519.Point{}).Negate(A)
		}
		s, err := edwards25519.NewScalar().SetCanonicalBytes(prepared.S[:])
		if err != nil {
			continue
		}
		w.s = s
		live = append(live, w)
		segments := sigprep.ChallengeSegments(it.pub, it.msg, it.sig)
		hashIn = append(hashIn, segments[:])
	}

	digests := make([][64]byte, len(live))
	sha512mb.Sum512Batch(digests, hashIn)

	for j := range live {
		w := &live[j]
		it := &items[w.idx]
		k, err := edwards25519.NewScalar().SetUniformBytes(digests[j][:])
		if err != nil {
			continue
		}
		var r *edwards25519.Point
		if w.table != nil {
			r = (&edwards25519.Point{}).VarTimeDoubleCombMult(k, w.table, w.s)
		} else if w.compact != nil {
			r = (&edwards25519.Point{}).VarTimeDoubleScalarBaseMultTable(k, w.compact, w.s)
		} else {
			r = (&edwards25519.Point{}).VarTimeDoubleScalarBaseMult(k, w.minusA, w.s)
		}
		it.ok = bytes.Equal(it.sig[:32], r.Bytes())
	}
}
