package ed25519

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/Overclock-Validator/narya/internal/cpufeat"
	"github.com/Overclock-Validator/narya/internal/r51x5"
)

// r51Backend is the forced-only Zen 4/Zen 5 throughput backend. It deliberately
// remains outside automatic selection until the hardware, corpus, race, and
// complete-path review gates are closed. Each pooled worker owns all mutable
// decoder, DSM, and batch-finalizer scratch; workers share no mutable curve
// state.
//
// Zen 4 keeps full x4 groups together. Zen 5 uses native x8 groups when at
// least eight signatures are available and retains x4 for the tail. Strict
// one- and two-item tails use the lower-latency packed singleton implementation,
// while a strict three-item tail uses one partial x4 group. StdlibCompat retains
// the native partial-group path for two and three items because the packed
// verifier intentionally implements only DalekStrict.
type r51Backend struct {
	activateOnce sync.Once
	activateErr  error
	batchPool    sync.Pool
	singlePool   sync.Pool
	faults       atomic.Uint64
}

type r51BatchWorker struct {
	pipeline       *r51IFMABatchQPipeline
	decodedStorage [r51BatchQMaxChunk]r51DecodedAEntry
	decoded        [r51BatchQMaxChunk]*r51DecodedAEntry
	err            error
}

type r51SingleWorker struct {
	verifier *r51x5.ExperimentalPackedStrictVerifierX4
	err      error
}

var registeredR51Backend = new(r51Backend)

// r51DecodedATable is the broad, batch-oriented warm tier. It retains only a
// permissively decoded point; PrecomputedKey.raw separately binds it to the
// exact original encoding that must remain in H(R || A || M).
type r51DecodedATable struct {
	point r51x5.Point
}

const r51DecodedATableBytes = 4 * 5 * 8

func init() { register("r51", registeredR51Backend) }

func (*r51Backend) name() string { return "r51" }

func (b *r51Backend) backendStats() BackendStats {
	return BackendStats{InternalFaultFallbacks: b.faults.Load()}
}

// The registered warm tier retains only decoded A. It bypasses decompression
// in useful-width batches while leaving scalar multiplication, original-byte
// hashing, strict prechecks, and final equality unchanged. Per-key partial
// comb tables remain behind their separate complete-verifier/cache-policy gate.
func (*r51Backend) supportsPrecomp() bool { return true }

func (*r51Backend) batchOnlyPrecomp() {}

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
	var pipeline *r51IFMABatchQPipeline
	var err error
	if cpufeat.PreferWideIFMA() {
		pipeline, err = newR51IFMABatchQX8CombPipelineWithFinalizer(r51IFMABatchQFinalizerLiteral)
	} else {
		pipeline, err = newR51IFMABatchQPipeline()
	}
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
	return &PrecomputedKey{
		raw:   *pub,
		table: &r51DecodedATable{point: point},
		size:  r51DecodedATableBytes,
	}, nil
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
	return b.verifyBatchRawPrecomputedErr(profile, pubs, msgs, sigs, ok, nil)
}

func (b *r51Backend) verifyBatchRawPrecomputedErr(profile Profile, pubs []*[32]byte, msgs, sigs [][]byte, ok []bool, pre []*PrecomputedKey) (bool, error) {
	if pre != nil && len(pre) != len(pubs) {
		panic("ed25519: r51 precomputed batch slice length differs")
	}
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
	tail := len(ok) - full
	strictPackedPair := profile == DalekStrict && tail == 2
	needsBatchWorker := full != 0 || (tail > 1 && !strictPackedPair)
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
		for offset := 0; offset < full; offset += r51BatchQMaxChunk {
			count := minR51(full-offset, r51BatchQMaxChunk)
			if pre == nil {
				if _, err := worker.pipeline.VerifyBatch(
					profile,
					pubs[offset:offset+count],
					msgs[offset:offset+count],
					sigs[offset:offset+count],
					ok[offset:offset+count],
				); err != nil {
					return false, err
				}
				continue
			}
			decoded := worker.resolveDecodedA(pubs[offset:offset+count], pre[offset:offset+count])
			if _, err := worker.pipeline.verifyBatchWithDecodedA(
				profile,
				pubs[offset:offset+count],
				msgs[offset:offset+count],
				sigs[offset:offset+count],
				ok[offset:offset+count],
				decoded,
			); err != nil {
				return false, err
			}
		}
	}

	switch tail {
	case 0:
	case 1:
		verdict, err := b.verifyOne(profile, pubs[full], msgs[full], sigs[full])
		if err != nil {
			return false, err
		}
		ok[full] = verdict
	case 2:
		if strictPackedPair {
			for index := full; index < full+tail; index++ {
				verdict, err := b.verifyOne(profile, pubs[index], msgs[index], sigs[index])
				if err != nil {
					return false, err
				}
				ok[index] = verdict
			}
			break
		}
		if _, err := worker.pipeline.VerifyBatch(profile, pubs[full:], msgs[full:], sigs[full:], ok[full:]); err != nil {
			return false, err
		}
	case 3:
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

func (worker *r51BatchWorker) resolveDecodedA(pubs []*[32]byte, pre []*PrecomputedKey) []*r51DecodedAEntry {
	if len(pubs) != len(pre) || len(pubs) > len(worker.decoded) {
		panic("ed25519: invalid r51 decoded-A resolution width")
	}
	for index := range pubs {
		worker.decoded[index] = nil
		prepared := pre[index]
		if prepared == nil || pubs[index] == nil || prepared.raw != *pubs[index] {
			continue
		}
		table, ok := prepared.table.(*r51DecodedATable)
		if !ok || table == nil {
			continue
		}
		worker.decodedStorage[index] = r51DecodedAEntry{raw: prepared.raw, point: table.point}
		worker.decoded[index] = &worker.decodedStorage[index]
	}
	return worker.decoded[:len(pubs)]
}

// r51UseDecodedAPrecomputed reports whether the measured decode saving is
// large enough to pay for resolving, packing, and scattering a mixed hit
// layout. Full-hit groups win at every native batch width. On both Zen 4 and
// Zen 5, partial hits below a complete 64-item encoder chunk were neutral or
// slower; a full chunk crossed over at roughly 25% hits. Keep the conservative
// common rule here rather than making an unmeasured intermediate width part of
// the supported dispatch contract.
func r51UseDecodedAPrecomputed(count, hits int) bool {
	return hits == count || (count == r51BatchQMaxChunk && hits*4 >= count)
}

func (b *r51Backend) verifyBatchRawCached(profile Profile, pubs []*[32]byte, msgs, sigs [][]byte, ok []bool, lookup precomputedKeyLookup) bool {
	if len(pubs) != len(msgs) || len(msgs) != len(sigs) || len(sigs) != len(ok) {
		panic("ed25519: r51 cached raw batch slice lengths differ")
	}
	if lookup == nil {
		panic("ed25519: nil r51 precomputed-key lookup")
	}
	// The packed strict singleton/two-item path cannot consume a decoded point,
	// and the three-item x4 tail cannot amortize a mixed hit. Cache admission is
	// still performed by Cache after these verdicts, so bypassing lookup here
	// does not prevent recurring narrow traffic from warming a later batch.
	if len(pubs) < r51x5.X4Lanes {
		return b.verifyBatchRaw(profile, pubs, msgs, sigs, ok)
	}

	all := true
	for offset := 0; offset < len(pubs); offset += r51BatchQMaxChunk {
		count := minR51(len(pubs)-offset, r51BatchQMaxChunk)
		var pre [r51BatchQMaxChunk]*PrecomputedKey
		hits := 0
		for index := 0; index < count; index++ {
			absolute := offset + index
			if !rejectedByProfile(profile, pubs[absolute], sigs[absolute]) {
				pre[index] = lookup.lookup(pubs[absolute])
				if pre[index] != nil {
					hits++
				}
			}
		}
		var prepared []*PrecomputedKey
		if r51UseDecodedAPrecomputed(count, hits) {
			prepared = pre[:count]
		}
		chunkAll, err := b.verifyBatchRawPrecomputedErr(
			profile,
			pubs[offset:offset+count],
			msgs[offset:offset+count],
			sigs[offset:offset+count],
			ok[offset:offset+count],
			prepared,
		)
		if err != nil {
			b.faults.Add(1)
			return fallbackGenericBatch(profile, pubs, msgs, sigs, ok)
		}
		all = all && chunkAll
	}
	return all
}

func (b *r51Backend) verifyBatch(profile Profile, items []batchItem) {
	const maxChunk = r51BatchQMaxChunk
	for offset := 0; offset < len(items); offset += maxChunk {
		count := minR51(len(items)-offset, maxChunk)
		var pubs [maxChunk]*[32]byte
		var msgs, sigs [maxChunk][]byte
		var pre [maxChunk]*PrecomputedKey
		var verdicts [maxChunk]bool
		for i := 0; i < count; i++ {
			item := &items[offset+i]
			pubs[i], msgs[i], sigs[i] = item.pub, item.msg, item.sig
			pre[i] = item.pre
		}
		all, err := b.verifyBatchRawPrecomputedErr(profile, pubs[:count], msgs[:count], sigs[:count], verdicts[:count], pre[:count])
		if err != nil {
			b.faults.Add(1)
			all = fallbackGenericBatch(profile, pubs[:count], msgs[:count], sigs[:count], verdicts[:count])
		}
		_ = all
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
