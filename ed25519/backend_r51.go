package ed25519

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/Overclock-Validator/narya-ed25519/internal/cpufeat"
	"github.com/Overclock-Validator/narya-ed25519/internal/r51x5"
)

// r51Backend is the forced-only Zen 4/Zen 5 throughput backend. It deliberately
// remains outside automatic selection until the hardware, corpus, race, and
// complete-path review gates are closed. Each pooled worker owns all mutable
// decoder, DSM, and batch-finalizer scratch; workers share no mutable curve
// state.
//
// Zen 4 and Zen 5 use x8 groups when at least eight signatures are available
// and retain x4 for the tail. Strict
// one- and two-item tails use the lower-latency packed singleton implementation,
// while a strict three-item tail uses one partial x4 group. StdlibCompat retains
// the native partial-group path for two and three items because the packed
// verifier intentionally implements only DalekStrict.
type r51Backend struct {
	activateOnce  sync.Once
	activateErr   error
	batchPool     sync.Pool
	singlePool    sync.Pool
	warmPool      sync.Pool
	warmBuildPool sync.Pool
	faults        atomic.Uint64
}

type r51BatchWorker struct {
	pipeline *r51IFMABatchQPipeline
	decoded  [r51BatchQMaxChunk]*r51DecodedAEntry
	err      error
}

type r51SingleWorker struct {
	verifier *r51x5.ExperimentalPackedStrictVerifierX4
	err      error
}

type r51WarmWorker struct {
	verifier *r51x5.WarmCombStrictVerifierX4
	err      error
	keys     [r51BatchQMaxChunk]*r51x5.WarmCombKeyA6R9
	pubs     [r51BatchQMaxChunk][32]byte
	msgs     [r51BatchQMaxChunk][]byte
	sigs     [r51BatchQMaxChunk][]byte
	verdicts [r51BatchQMaxChunk]bool
}

type r51WarmBuildWorker struct {
	workspace r51x5.WarmCombBuildWorkspaceX4
}

var registeredR51Backend = new(r51Backend)

// r51DecodedATable is the broad, batch-oriented warm tier. Its immutable entry
// is stored in the exact form consumed by the batch pipeline so a lookup does
// not copy a 160-byte point into worker scratch. PrecomputedKey.raw separately
// retains the public cache-key binding.
type r51DecodedATable struct {
	entry r51DecodedAEntry
}

const r51DecodedATableBytes = 32 + 4*5*8

// r51WarmTable is the promoted immutable entry. It retains the broad decoded-A
// representation so a group that cannot use the homogeneous comb can still
// take the decoded tier without rebuilding or mutating cache state.
type r51WarmTable struct {
	decoded r51DecodedAEntry
	warm    r51x5.WarmCombKeyA6R9
}

const r51WarmTableBytes = r51DecodedATableBytes + r51x5.WarmCombKeyA6R9Bytes

func init() { register("r51", registeredR51Backend) }

func (*r51Backend) name() string { return "r51" }

func (b *r51Backend) backendStats() BackendStats {
	return BackendStats{InternalFaultFallbacks: b.faults.Load()}
}

// The first tier retains decoded A; the x8 cold path on Zen 4 and Zen 5
// consumes it directly. Four independently hot strict keys can be promoted to
// immutable A6/r9 tables and evaluated as one homogeneous x4 group.
func (*r51Backend) supportsPrecomp() bool { return true }

func (*r51Backend) promotionThreshold() int32 { return 8 }

func (*r51Backend) soloPromotionThreshold() int32 { return 32 }

func (*r51Backend) promotable(pre *PrecomputedKey) bool {
	if pre == nil {
		return false
	}
	table, ok := pre.table.(*r51DecodedATable)
	return ok && table != nil && table.entry.raw == pre.raw
}

func (b *r51Backend) buildPromotedPrecompGroup(
	pubs *[precomputedPromotionWidth]*[32]byte,
	current *[precomputedPromotionWidth]*PrecomputedKey,
) ([precomputedPromotionWidth]*PrecomputedKey, error) {
	promoted, err := b.buildWarmPrecompGroup(pubs, current)
	if err != nil {
		b.faults.Add(1)
	}
	return promoted, err
}

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
		b.warmPool.New = func() any {
			verifier, err := r51x5.NewWarmCombStrictVerifierX4()
			return &r51WarmWorker{verifier: verifier, err: err}
		}
		b.warmBuildPool.New = func() any { return new(r51WarmBuildWorker) }
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
		if err == nil {
			pipeline.experimentalRawSquareX8 = cpufeat.PreferRawSquareIFMA()
		}
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
		table: &r51DecodedATable{entry: r51DecodedAEntry{raw: *pub, point: point}},
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

// verifyStrictRaw is the direct public VerifyStrict seam. Unlike verify, its
// caller has not applied the shared profile pre-pass, so the packed verifier's
// complete and independently tested strict byte checks remain load-bearing.
// Internal faults still recompute through the generic strict predicate and
// increment the same operational counter as every other r51 entry point.
func (b *r51Backend) verifyStrictRaw(pub *[32]byte, message, sig []byte) bool {
	ok, err := b.verifyOne(DalekStrict, pub, message, sig)
	if err == nil {
		return ok
	}
	b.faults.Add(1)
	return verifyOne(genericBackend{}, DalekStrict, pub, message, sig, nil)
}

func (b *r51Backend) verifyOne(profile Profile, pub *[32]byte, message, sig []byte) (bool, error) {
	// rawBatchBackend bypasses the shared applyProfile wrapper. Keep the nil
	// guard local so the StdlibCompat singleton/tail fallback cannot pass a nil
	// public key directly into genericBackend.verify.
	if pub == nil {
		return false, nil
	}
	if err := b.activate(); err != nil {
		return false, err
	}
	switch profile {
	case StdlibCompat:
		// The packed projective finalizer intentionally implements only the
		// strict predicate. Compat retains its literal encoded-Q comparison.
		//
		// genericBackend.verify documents that the shared entry point has
		// already applied the profile pre-pass, but a raw-batch backend skips
		// applyProfile, so this branch has to supply the nil guard itself. The
		// strict branch below gets it from packedStrictBytePrechecksX4.
		return verifyOne(genericBackend{}, profile, pub, message, sig, nil), nil
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
	// Deliberately not deferred. Every error below is an internal fault, and the
	// caller answers it by recomputing the whole batch on the generic backend; a
	// pipeline that just failed keeps its partially written scratch, so it is
	// dropped for the garbage collector rather than recycled. Only a clean run
	// puts the worker back, matching the singleton pool's `if err == nil` above.
	returnWorker := func() {
		if worker != nil {
			b.batchPool.Put(worker)
		}
	}

	for offset := 0; offset < full; {
		warmWidth := 0
		if pre != nil && profile == DalekStrict {
			warmWidth = r51WarmDispatchWidth(pubs, pre, offset, full)
		}
		if warmWidth != 0 {
			warmEnd := offset + warmWidth
			for warmEnd < full && warmEnd-offset < r51BatchQMaxChunk {
				next := r51WarmDispatchWidth(pubs, pre, warmEnd, full)
				if next == 0 || warmEnd+next-offset > r51BatchQMaxChunk {
					break
				}
				warmEnd += next
			}
			if _, err := b.verifyWarmGroups(
				pubs[offset:warmEnd], msgs[offset:warmEnd], sigs[offset:warmEnd],
				ok[offset:warmEnd], pre[offset:warmEnd],
			); err != nil {
				return false, err
			}
			offset = warmEnd
			continue
		}

		coldStart := offset
		coldEnd := minR51(full, coldStart+r51BatchQMaxChunk)
		for candidate := coldStart + r51x5.X4Lanes; candidate < coldEnd; candidate += r51x5.X4Lanes {
			if pre != nil && profile == DalekStrict && r51WarmDispatchWidth(pubs, pre, candidate, full) != 0 {
				coldEnd = candidate
				break
			}
		}
		if pre == nil {
			if _, err := worker.pipeline.VerifyBatch(profile, pubs[coldStart:coldEnd], msgs[coldStart:coldEnd], sigs[coldStart:coldEnd], ok[coldStart:coldEnd]); err != nil {
				return false, err
			}
		} else {
			decoded := worker.resolveDecodedA(pubs[coldStart:coldEnd], pre[coldStart:coldEnd])
			if _, err := worker.pipeline.verifyBatchWithDecodedA(
				profile,
				pubs[coldStart:coldEnd],
				msgs[coldStart:coldEnd],
				sigs[coldStart:coldEnd],
				ok[coldStart:coldEnd],
				decoded,
			); err != nil {
				return false, err
			}
		}
		offset = coldEnd
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
		switch table := prepared.table.(type) {
		case *r51DecodedATable:
			if table != nil && table.entry.raw == prepared.raw {
				worker.decoded[index] = &table.entry
			}
		case *r51WarmTable:
			if table != nil && table.decoded.raw == prepared.raw {
				worker.decoded[index] = &table.decoded
			}
		}
	}
	return worker.decoded[:len(pubs)]
}

func r51WarmGroupAvailable(pubs []*[32]byte, pre []*PrecomputedKey) bool {
	if len(pubs) != r51x5.X4Lanes || len(pre) != r51x5.X4Lanes {
		return false
	}
	for lane := 0; lane < r51x5.X4Lanes; lane++ {
		prepared := pre[lane]
		if prepared == nil || pubs[lane] == nil || prepared.raw != *pubs[lane] {
			return false
		}
		table, ok := prepared.table.(*r51WarmTable)
		if !ok || table == nil || table.decoded.raw != prepared.raw {
			return false
		}
	}
	return true
}

func (b *r51Backend) verifyWarmGroup(
	pubs []*[32]byte,
	msgs, sigs [][]byte,
	ok []bool,
	pre []*PrecomputedKey,
) (bool, error) {
	return b.verifyWarmGroups(pubs, msgs, sigs, ok, pre)
}

func (b *r51Backend) verifyWarmGroups(
	pubs []*[32]byte,
	msgs, sigs [][]byte,
	ok []bool,
	pre []*PrecomputedKey,
) (bool, error) {
	count := len(pubs)
	if count == 0 || count%r51x5.X4Lanes != 0 || count > r51BatchQMaxChunk ||
		len(msgs) != count || len(sigs) != count || len(ok) != count || len(pre) != count {
		return false, fmt.Errorf("ed25519: invalid r51 warm width %d", count)
	}
	for offset := 0; offset < count; offset += r51x5.X4Lanes {
		if !r51WarmGroupAvailable(pubs[offset:offset+r51x5.X4Lanes], pre[offset:offset+r51x5.X4Lanes]) {
			return false, fmt.Errorf("ed25519: invalid r51 warm group at %d", offset)
		}
	}
	worker := b.warmPool.Get().(*r51WarmWorker)
	if worker.err != nil {
		return false, fmt.Errorf("ed25519: construct r51 warm worker: %w", worker.err)
	}
	if worker.verifier == nil {
		return false, fmt.Errorf("ed25519: construct r51 warm worker: nil verifier")
	}
	for index := 0; index < count; index++ {
		table := pre[index].table.(*r51WarmTable)
		worker.keys[index] = &table.warm
		worker.pubs[index] = *pubs[index]
		worker.msgs[index] = msgs[index]
		worker.sigs[index] = sigs[index]
	}
	all, err := worker.verifier.VerifyBatch(
		worker.keys[:count], worker.pubs[:count], worker.msgs[:count],
		worker.sigs[:count], worker.verdicts[:count],
	)
	if err != nil {
		return false, err
	}
	copy(ok, worker.verdicts[:count])
	clear(worker.keys[:count])
	clear(worker.msgs[:count])
	clear(worker.sigs[:count])
	b.warmPool.Put(worker)
	return all, nil
}

func (b *r51Backend) buildWarmPrecompGroup(
	pubs *[r51x5.X4Lanes]*[32]byte,
	current *[r51x5.X4Lanes]*PrecomputedKey,
) ([r51x5.X4Lanes]*PrecomputedKey, error) {
	var out [r51x5.X4Lanes]*PrecomputedKey
	if err := b.activate(); err != nil {
		return out, err
	}
	var encoded [r51x5.X4Lanes][32]byte
	var tables [r51x5.X4Lanes]*r51WarmTable
	var warm [r51x5.X4Lanes]*r51x5.WarmCombKeyA6R9
	for lane := 0; lane < r51x5.X4Lanes; lane++ {
		if pubs[lane] == nil || current[lane] == nil || current[lane].raw != *pubs[lane] {
			return out, fmt.Errorf("ed25519: invalid r51 warm-build lane %d", lane)
		}
		decoded, ok := current[lane].table.(*r51DecodedATable)
		if !ok || decoded == nil || decoded.entry.raw != current[lane].raw {
			return out, fmt.Errorf("ed25519: r51 warm-build lane %d is not a decoded entry", lane)
		}
		encoded[lane] = *pubs[lane]
		tables[lane] = &r51WarmTable{decoded: decoded.entry}
		warm[lane] = &tables[lane].warm
	}
	worker := b.warmBuildPool.Get().(*r51WarmBuildWorker)
	if err := worker.workspace.BuildWarmCombKeysA6R9X4(&warm, &encoded); err != nil {
		return out, err
	}
	b.warmBuildPool.Put(worker)
	for lane := 0; lane < r51x5.X4Lanes; lane++ {
		out[lane] = &PrecomputedKey{raw: encoded[lane], table: tables[lane], size: r51WarmTableBytes}
	}
	return out, nil
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

func r51DecodedACacheEnabled() bool { return cpufeat.PreferDecodedAIFMA() }

// r51WarmDispatchWidth preserves x8 occupancy on both Zen 4 and Zen 5. A warm
// x4 group is consumed as an aligned pair, except for one final four-item tail
// that has no x8 partner.
func r51WarmDispatchWidth(pubs []*[32]byte, pre []*PrecomputedKey, offset, full int) int {
	if offset < 0 || offset+r51x5.X4Lanes > full || full > minR51(len(pubs), len(pre)) ||
		!r51WarmGroupAvailable(pubs[offset:offset+r51x5.X4Lanes], pre[offset:offset+r51x5.X4Lanes]) {
		return 0
	}
	if !cpufeat.PreferWarmX8IFMA() {
		return r51x5.X4Lanes
	}
	if offset%r51x5.X8Lanes != 0 {
		return 0
	}
	if offset+r51x5.X4Lanes == full {
		return r51x5.X4Lanes
	}
	if offset+r51x5.X8Lanes <= full &&
		r51WarmGroupAvailable(pubs[offset+r51x5.X4Lanes:offset+r51x5.X8Lanes], pre[offset+r51x5.X4Lanes:offset+r51x5.X8Lanes]) {
		return r51x5.X8Lanes
	}
	return 0
}

func r51HasWarmDispatch(pubs []*[32]byte, pre []*PrecomputedKey) bool {
	full := minR51(len(pubs), len(pre)) &^ (r51x5.X4Lanes - 1)
	for offset := 0; offset < full; offset += r51x5.X4Lanes {
		if r51WarmDispatchWidth(pubs, pre, offset, full) != 0 {
			return true
		}
	}
	return false
}

func (b *r51Backend) verifyBatchRawCached(profile Profile, pubs []*[32]byte, msgs, sigs [][]byte, ok []bool, cache precomputedKeyCache) bool {
	if len(pubs) != len(msgs) || len(msgs) != len(sigs) || len(sigs) != len(ok) {
		panic("ed25519: r51 cached raw batch slice lengths differ")
	}
	if cache == nil {
		panic("ed25519: nil r51 precomputed-key lookup")
	}
	// The packed strict singleton/two-item path cannot consume a decoded point,
	// and the three-item x4 tail cannot amortize a mixed hit. Cache admission is
	// still requested after each valid verdict, so bypassing lookup here does
	// not prevent recurring narrow traffic from warming a later batch.
	if len(pubs) < r51x5.X4Lanes {
		all := b.verifyBatchRaw(profile, pubs, msgs, sigs, ok)
		for index := range ok {
			if ok[index] {
				cache.admit(b, pubs[index])
			}
		}
		return all
	}

	all := true
	for offset := 0; offset < len(pubs); offset += r51BatchQMaxChunk {
		count := minR51(len(pubs)-offset, r51BatchQMaxChunk)
		var pre [r51BatchQMaxChunk]*PrecomputedKey
		hits := 0
		for index := 0; index < count; index++ {
			absolute := offset + index
			if !rejectedByProfile(profile, pubs[absolute], sigs[absolute]) {
				pre[index] = cache.lookup(pubs[absolute])
				if pre[index] != nil {
					hits++
				}
			}
		}
		var prepared []*PrecomputedKey
		if r51HasWarmDispatch(pubs[offset:offset+count], pre[:count]) ||
			(r51DecodedACacheEnabled() && r51UseDecodedAPrecomputed(count, hits)) {
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
			all = fallbackGenericBatch(profile, pubs, msgs, sigs, ok)
			for index := range ok {
				if ok[index] {
					// Faults are exceptional, so conservatively rechecking the
					// table here is preferable to retaining per-chunk hit state.
					cache.admit(b, pubs[index])
				}
			}
			return all
		}
		for index := 0; index < count; index++ {
			absolute := offset + index
			if ok[absolute] {
				if pre[index] == nil {
					cache.admit(b, pubs[absolute])
				} else if profile == DalekStrict {
					cache.promote(b, pre[index])
				}
			}
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
