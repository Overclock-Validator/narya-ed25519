package ed25519

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/Overclock-Validator/narya/internal/r51x5"
)

// r51Backend is the forced-only Zen 4 throughput backend. It deliberately
// remains outside automatic selection until the hardware, corpus, race, and
// complete-path review gates are closed. Each pooled worker owns all mutable
// decoder, DSM, and batch-finalizer scratch; workers share no mutable curve
// state.
//
// The current dispatch keeps full x4 groups together, sends two- and
// three-signature tails through one partial x4 group, and leaves a singleton
// to the lower-latency single-signature implementation. In particular, a
// five-signature batch is one full r51 group plus one singleton rather than
// two underfilled r51 groups.
type r51Backend struct {
	activateOnce sync.Once
	activateErr  error
	batchPool    sync.Pool
	singlePool   sync.Pool
	faults       atomic.Uint64
}

type r51BatchWorker struct {
	pipeline *r51IFMABatchQPipeline
	err      error
}

type r51SingleWorker struct {
	verifier *r51x5.ExperimentalPackedStrictVerifierX4
	err      error
}

var registeredR51Backend = new(r51Backend)

func init() { register("r51", registeredR51Backend) }

func (*r51Backend) name() string { return "r51" }

func (b *r51Backend) backendStats() BackendStats {
	return BackendStats{InternalFaultFallbacks: b.faults.Load()}
}

// Per-key partial-comb tables remain behind a complete-verifier/cache-policy
// gate, so this first promoted cold backend does not claim native precompute
// support. Cache calls still use the native batch path; they simply cannot
// install backend-specific entries yet.
func (*r51Backend) supportsPrecomp() bool { return false }

func (b *r51Backend) activate() error {
	b.activateOnce.Do(func() {
		firstBatch := b.newBatchWorker()
		if firstBatch.err != nil {
			b.activateErr = firstBatch.err
			return
		}
		firstSingle := b.newSingleWorker()
		if firstSingle.err != nil {
			b.activateErr = firstSingle.err
			return
		}
		b.batchPool.New = func() any { return b.newBatchWorker() }
		b.singlePool.New = func() any { return b.newSingleWorker() }
		b.batchPool.Put(firstBatch)
		b.singlePool.Put(firstSingle)
	})
	return b.activateErr
}

func (*r51Backend) newBatchWorker() *r51BatchWorker {
	pipeline, err := newR51IFMABatchQPipeline()
	return &r51BatchWorker{pipeline: pipeline, err: err}
}

func (*r51Backend) newSingleWorker() *r51SingleWorker {
	verifier, err := r51x5.NewExperimentalPackedStrictVerifierX4()
	return &r51SingleWorker{verifier: verifier, err: err}
}

func (b *r51Backend) buildPrecomp(pub *[32]byte) (*PrecomputedKey, error) {
	var point r51x5.Point
	if _, err := point.SetBytes(pub[:]); err != nil {
		return nil, err
	}
	return &PrecomputedKey{raw: *pub, size: 32}, nil
}

func (b *r51Backend) verify(profile Profile, pub *[32]byte, message, sig []byte, _ *PrecomputedKey) bool {
	ok, err := b.verifyOne(profile, pub, message, sig)
	if err == nil {
		return ok
	}
	b.faults.Add(1)
	return verifyOne(genericBackend{}, profile, pub, message, sig, nil)
}

func (b *r51Backend) verifyOne(profile Profile, pub *[32]byte, message, sig []byte) (bool, error) {
	if err := b.activate(); err != nil {
		return false, err
	}
	switch profile {
	case StdlibCompat:
		// The packed projective finalizer intentionally implements only the
		// strict predicate. Compat retains its literal encoded-Q comparison.
		return (genericBackend{}).verify(profile, pub, message, sig, nil), nil
	case DalekStrict:
	default:
		panic("ed25519: unsupported r51 singleton profile")
	}

	worker := b.singlePool.Get().(*r51SingleWorker)
	if worker.err != nil {
		return false, fmt.Errorf("ed25519: construct packed r51 worker: %w", worker.err)
	}
	if worker.verifier == nil {
		return false, fmt.Errorf("ed25519: construct packed r51 worker: nil verifier")
	}
	ok, err := worker.verifier.Verify(pub, message, sig)
	if err == nil {
		b.singlePool.Put(worker)
	}
	return ok, err
}

func (b *r51Backend) verifyBatchRaw(profile Profile, pubs []*[32]byte, msgs, sigs [][]byte, ok []bool) bool {
	if len(pubs) != len(msgs) || len(msgs) != len(sigs) || len(sigs) != len(ok) {
		panic("ed25519: r51 raw batch slice lengths differ")
	}
	all, err := b.verifyBatchRawErr(profile, pubs, msgs, sigs, ok)
	if err != nil {
		b.faults.Add(1)
		return fallbackGenericBatch(profile, pubs, msgs, sigs, ok)
	}
	return all
}

func (b *r51Backend) verifyBatchRawErr(profile Profile, pubs []*[32]byte, msgs, sigs [][]byte, ok []bool) (bool, error) {
	if err := b.activate(); err != nil {
		return false, err
	}
	for i := range ok {
		ok[i] = false
	}
	if len(ok) == 0 {
		return true, nil
	}

	full := len(ok) &^ (r51x5.X4Lanes - 1)
	needsBatchWorker := full != 0 || len(ok)-full > 1
	var worker *r51BatchWorker
	if needsBatchWorker {
		worker = b.batchPool.Get().(*r51BatchWorker)
		if worker.err != nil {
			return false, fmt.Errorf("ed25519: construct r51 worker: %w", worker.err)
		}
		if worker.pipeline == nil {
			return false, fmt.Errorf("ed25519: construct r51 worker: nil pipeline")
		}
	}
	returnWorker := func() {
		if worker != nil {
			b.batchPool.Put(worker)
		}
	}

	if full != 0 {
		if _, err := worker.pipeline.VerifyBatch(profile, pubs[:full], msgs[:full], sigs[:full], ok[:full]); err != nil {
			return false, err
		}
	}

	tail := len(ok) - full
	switch tail {
	case 0:
	case 1:
		verdict, err := b.verifyOne(profile, pubs[full], msgs[full], sigs[full])
		if err != nil {
			return false, err
		}
		ok[full] = verdict
	case 2, 3:
		if _, err := worker.pipeline.VerifyBatch(profile, pubs[full:], msgs[full:], sigs[full:], ok[full:]); err != nil {
			return false, err
		}
	default:
		panic("ed25519: unreachable r51 tail width")
	}
	returnWorker()
	worker = nil

	all := true
	for _, verdict := range ok {
		all = all && verdict
	}
	return all, nil
}

func (b *r51Backend) verifyBatch(profile Profile, items []batchItem) {
	const maxChunk = r51BatchQMaxChunk
	for offset := 0; offset < len(items); offset += maxChunk {
		count := minR51(len(items)-offset, maxChunk)
		var pubs [maxChunk]*[32]byte
		var msgs, sigs [maxChunk][]byte
		var verdicts [maxChunk]bool
		for i := 0; i < count; i++ {
			item := &items[offset+i]
			pubs[i], msgs[i], sigs[i] = item.pub, item.msg, item.sig
		}
		b.verifyBatchRaw(profile, pubs[:count], msgs[:count], sigs[:count], verdicts[:count])
		for i := 0; i < count; i++ {
			items[offset+i].ok = verdicts[i]
		}
	}
}

func fallbackGenericBatch(profile Profile, pubs []*[32]byte, msgs, sigs [][]byte, ok []bool) bool {
	all := true
	generic := genericBackend{}
	for i := range ok {
		ok[i] = verifyOne(generic, profile, pubs[i], msgs[i], sigs[i], nil)
		all = all && ok[i]
	}
	return all
}
