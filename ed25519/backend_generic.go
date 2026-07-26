package ed25519

import (
	"bytes"
	"crypto/sha512"

	"github.com/Overclock-Validator/narya-ed25519/internal/edwards25519"
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

func (genericBackend) verify(_ Profile, pub *[32]byte, message, sig []byte, pre *PrecomputedKey) bool {
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

	if len(sig) != 64 || sig[63]&224 != 0 {
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

	kh := sha512.New()
	kh.Write(sig[:32])
	kh.Write(pub[:])
	kh.Write(message)
	var hramDigest [sha512.Size]byte
	kh.Sum(hramDigest[:0])
	k, err := edwards25519.NewScalar().SetUniformBytes(hramDigest[:])
	if err != nil {
		return false
	}

	s, err := edwards25519.NewScalar().SetCanonicalBytes(sig[32:])
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
	return bytes.Equal(sig[:32], r.Bytes())
}

// verifyBatch runs the batch pipeline: a scalar precheck-and-decode
// pass that drops items whose verdict is already known false, one
// multi-buffer hash round for the survivors' k = H(R ‖ A ‖ M), then
// per-item point math. Verdicts are per-signature and bit-identical
// to verify — batching only ever amortizes hashing and decoding, it
// never mixes signatures into one equation.
func (g genericBackend) verifyBatch(_ Profile, items []batchItem) {
	type work struct {
		idx     int
		table   *edwards25519.PubkeyTable
		compact *edwards25519.PubkeyNAFTable
		minusA  *edwards25519.Point
		s       *edwards25519.Scalar
	}
	live := make([]work, 0, len(items))
	hashIn := make([][][]byte, 0, len(items))

	for i := range items {
		it := &items[i]
		if it.skip || len(it.sig) != 64 || it.sig[63]&224 != 0 {
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
		s, err := edwards25519.NewScalar().SetCanonicalBytes(it.sig[32:])
		if err != nil {
			continue
		}
		w.s = s
		live = append(live, w)
		hashIn = append(hashIn, [][]byte{it.sig[:32], it.pub[:], it.msg})
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
