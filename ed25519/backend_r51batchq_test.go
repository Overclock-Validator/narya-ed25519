package ed25519

import (
	stded25519 "crypto/ed25519"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"unsafe"

	"github.com/Overclock-Validator/narya/internal/r51x5"
)

func requireR51IFMABatchQPipeline(t testing.TB) *r51IFMABatchQPipeline {
	return requireR51IFMABatchQPipelineFinalizer(t, r51IFMABatchQFinalizerLiteral)
}

func requireR51IFMABatchQPipelineFinalizer(t testing.TB, finalizer r51IFMABatchQFinalizer) *r51IFMABatchQPipeline {
	t.Helper()
	if !r51IFMAPipelineAvailable(r51IFMATwoX4) {
		t.Skipf("forced two-x4 r51 IFMA batch-Q pipeline unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	pipeline, err := newR51IFMABatchQPipelineWithFinalizer(finalizer)
	if err != nil {
		t.Fatalf("new forced two-x4 radix-64 batch-Q pipeline finalizer=%d: %v", finalizer, err)
	}
	return pipeline
}

func requireR51IFMABatchQCombPipeline(t testing.TB) *r51IFMABatchQPipeline {
	t.Helper()
	if !r51IFMAPipelineAvailable(r51IFMATwoX4) {
		t.Skipf("forced two-x4 r51 IFMA batch-Q comb pipeline unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	pipeline, err := newR51IFMABatchQCombPipelineWithFinalizer(r51IFMABatchQFinalizerLiteral)
	if err != nil {
		t.Fatalf("new forced two-x4 radix-32/comb256 batch-Q pipeline: %v", err)
	}
	return pipeline
}

func assertR51IFMABatchQVectors(t *testing.T, batchQ, comb, yFirst, paired, literal *r51IFMABatchQPipelineSet, vectors []r51ReferenceVector, profile Profile) {
	t.Helper()
	pubs := make([]*[32]byte, len(vectors))
	msgs := make([][]byte, len(vectors))
	sigs := make([][]byte, len(vectors))
	want := make([]bool, len(vectors))
	wantAll := true
	for index := range vectors {
		pubs[index], msgs[index], sigs[index] = &vectors[index].pub, vectors[index].msg, vectors[index].sig
		want[index] = referenceVerifyProfile(profile, pubs[index], msgs[index], sigs[index])
		wantAll = wantAll && want[index]
	}

	sets := []*r51IFMABatchQPipelineSet{batchQ, comb, yFirst, paired, literal}
	for _, set := range sets {
		got := make([]bool, len(vectors))
		gotAll, err := set.verify(profile, pubs, msgs, sigs, got)
		if err != nil {
			t.Fatalf("%s: %v", set.name, err)
		}
		if gotAll != wantAll {
			t.Fatalf("%s aggregate=%v want=%v profile=%d count=%d", set.name, gotAll, wantAll, profile, len(vectors))
		}
		for index := range got {
			if got[index] != want[index] {
				t.Fatalf("%s lane=%d got=%v want=%v profile=%d\npub=%x\nmsg=%x\nsig=%x", set.name, index, got[index], want[index], profile, vectors[index].pub, vectors[index].msg, vectors[index].sig)
			}
		}
	}
}

// r51IFMABatchQPipelineSet gives one concrete call shape to the four complete
// verifier variants in differential tests without adding an interface to the
// timed implementation.
type r51IFMABatchQPipelineSet struct {
	name     string
	batchQ   *r51IFMABatchQPipeline
	ordinary *r51IFMAPipeline
}

func (set *r51IFMABatchQPipelineSet) verify(profile Profile, pubs []*[32]byte, msgs, sigs [][]byte, ok []bool) (bool, error) {
	if set.batchQ != nil {
		return set.batchQ.VerifyBatch(profile, pubs, msgs, sigs, ok)
	}
	return set.ordinary.VerifyBatch(profile, pubs, msgs, sigs, ok)
}

func newR51IFMABatchQPipelineSets(t testing.TB) (batchQ, comb, yFirst, paired, literal *r51IFMABatchQPipelineSet) {
	t.Helper()
	return &r51IFMABatchQPipelineSet{
			name:   "single-A/cross-group-batch-Q",
			batchQ: requireR51IFMABatchQPipeline(t),
		}, &r51IFMABatchQPipelineSet{
			name:   "single-A/radix32-comb256/cross-group-batch-Q",
			batchQ: requireR51IFMABatchQCombPipeline(t),
		}, &r51IFMABatchQPipelineSet{
			name:   "single-A/y-first",
			batchQ: requireR51IFMABatchQPipelineFinalizer(t, r51IFMABatchQFinalizerYFirst),
		}, &r51IFMABatchQPipelineSet{
			name:     "paired-AR/projective",
			ordinary: requireR51IFMAPipeline(t, r51IFMATwoX4, 6),
		}, &r51IFMABatchQPipelineSet{
			name:     "single-A/per-x4-literal-Q",
			ordinary: requireR51IFMAEncodedQReferencePipeline(t, r51IFMATwoX4, 6),
		}
}

func TestR51IFMABatchQPipelineDifferential(t *testing.T) {
	batchQ, comb, yFirst, paired, literal := newR51IFMABatchQPipelineSets(t)

	mixture := makeR51HonestVectors(t, 67)
	for index := range mixture {
		switch index % 7 {
		case 1:
			mixture[index].msg[0] ^= 0x80
		case 2:
			mixture[index].sig[7] ^= 0x20
		case 3:
			mixture[index].sig[63] |= 0xe0
		case 4:
			mixture[index].pub[11] ^= 0x08
		}
	}
	mixture[63] = makeR51MixedOrderValidVector(t)

	for _, profile := range []Profile{DalekStrict, StdlibCompat} {
		t.Run(fmt.Sprintf("profile=%d/cctv", profile), func(t *testing.T) {
			assertR51IFMABatchQVectors(t, batchQ, comb, yFirst, paired, literal, r51CCTVVectors(t), profile)
		})
		t.Run(fmt.Sprintf("profile=%d/wycheproof", profile), func(t *testing.T) {
			assertR51IFMABatchQVectors(t, batchQ, comb, yFirst, paired, literal, r51WycheproofVectors(t), profile)
		})
		for _, count := range []int{1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 32, 63, 64, 65, 67} {
			count := count
			t.Run(fmt.Sprintf("profile=%d/mixture/n=%d", profile, count), func(t *testing.T) {
				assertR51IFMABatchQVectors(t, batchQ, comb, yFirst, paired, literal, mixture[:count], profile)
			})
		}
	}
}

func makeR51DecodedAEntries(tb testing.TB, pubs []*[32]byte, hit func(int) bool) ([]r51DecodedAEntry, []*r51DecodedAEntry) {
	tb.Helper()
	storage := make([]r51DecodedAEntry, len(pubs))
	entries := make([]*r51DecodedAEntry, len(pubs))
	for index, pub := range pubs {
		if pub == nil || !hit(index) {
			continue
		}
		var point r51x5.Point
		if _, err := point.SetBytes(pub[:]); err != nil {
			continue
		}
		storage[index] = r51DecodedAEntry{raw: *pub, point: point}
		entries[index] = &storage[index]
	}
	return storage, entries
}

func assertR51IFMABatchQDecodedA(t *testing.T, vectors []r51ReferenceVector, profile Profile, hit func(int) bool, mutateEntries func([]r51DecodedAEntry, []*r51DecodedAEntry)) {
	t.Helper()
	pubs := make([]*[32]byte, len(vectors))
	msgs := make([][]byte, len(vectors))
	sigs := make([][]byte, len(vectors))
	want := make([]bool, len(vectors))
	wantAll := true
	for index := range vectors {
		pubs[index], msgs[index], sigs[index] = &vectors[index].pub, vectors[index].msg, vectors[index].sig
		want[index] = referenceVerifyProfile(profile, pubs[index], msgs[index], sigs[index])
		wantAll = wantAll && want[index]
	}
	storage, entries := makeR51DecodedAEntries(t, pubs, hit)
	if mutateEntries != nil {
		mutateEntries(storage, entries)
	}

	for _, compactMisses := range []bool{false, true} {
		name := "original-miss-groups"
		if compactMisses {
			name = "compacted-misses"
		}
		got := make([]bool, len(vectors))
		pipeline := requireR51IFMABatchQPipeline(t)
		var gotAll bool
		var err error
		if compactMisses {
			gotAll, err = pipeline.verifyBatchWithDecodedA(profile, pubs, msgs, sigs, got, entries)
		} else {
			gotAll, err = pipeline.verifyBatchWithDecodedAUncompacted(profile, pubs, msgs, sigs, got, entries)
		}
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if gotAll != wantAll {
			t.Fatalf("%s aggregate=%v want=%v profile=%d count=%d", name, gotAll, wantAll, profile, len(vectors))
		}
		for index := range got {
			if got[index] != want[index] {
				t.Fatalf("%s lane=%d got=%v want=%v profile=%d\npub=%x\nmsg=%x\nsig=%x", name, index, got[index], want[index], profile, vectors[index].pub, vectors[index].msg, vectors[index].sig)
			}
		}
	}
}

func TestR51IFMABatchQDecodedADifferential(t *testing.T) {
	mixture := makeR51HonestVectors(t, 67)
	for index := range mixture {
		switch index % 7 {
		case 1:
			mixture[index].msg[0] ^= 0x80
		case 2:
			mixture[index].sig[7] ^= 0x20
		case 3:
			mixture[index].sig[63] |= 0xe0
		case 4:
			mixture[index].pub[11] ^= 0x08
		}
	}
	mixture[63] = makeR51MixedOrderValidVector(t)

	patterns := []struct {
		name string
		hit  func(int) bool
	}{
		{name: "all-cold", hit: func(int) bool { return false }},
		{name: "alternating", hit: func(index int) bool { return index%2 == 0 }},
		{name: "clustered", hit: func(index int) bool { return index >= 17 && index < 49 }},
		{name: "all-decoded", hit: func(int) bool { return true }},
	}
	for _, profile := range []Profile{DalekStrict, StdlibCompat} {
		for _, pattern := range patterns {
			for _, count := range []int{1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 32, 63, 64, 65, 67} {
				t.Run(fmt.Sprintf("profile=%d/pattern=%s/n=%d", profile, pattern.name, count), func(t *testing.T) {
					assertR51IFMABatchQDecodedA(t, mixture[:count], profile, pattern.hit, nil)
				})
			}
		}
	}

	// An entry for a different raw encoding is a cold miss, never a point hit.
	// This protects the original A bytes in H(R || A || M) even when multiple
	// byte strings decode to one mathematical point.
	for _, profile := range []Profile{DalekStrict, StdlibCompat} {
		t.Run(fmt.Sprintf("profile=%d/raw-mismatch-falls-back", profile), func(t *testing.T) {
			assertR51IFMABatchQDecodedA(t, mixture[:17], profile, func(int) bool { return true }, func(storage []r51DecodedAEntry, entries []*r51DecodedAEntry) {
				for index, entry := range entries {
					if entry == nil {
						continue
					}
					storage[index].raw[0] ^= 0x80
				}
			})
		})
	}
}

func TestR51IFMABatchQDecodedACorpora(t *testing.T) {
	for _, profile := range []Profile{DalekStrict, StdlibCompat} {
		t.Run(fmt.Sprintf("profile=%d/cctv", profile), func(t *testing.T) {
			assertR51IFMABatchQDecodedA(t, r51CCTVVectors(t), profile, func(int) bool { return true }, nil)
		})
		t.Run(fmt.Sprintf("profile=%d/wycheproof", profile), func(t *testing.T) {
			assertR51IFMABatchQDecodedA(t, r51WycheproofVectors(t), profile, func(int) bool { return true }, nil)
		})
	}
}

func TestR51IFMABatchQDecodedAEveryX8HitMask(t *testing.T) {
	fixture := makeBatchFixture(t, r51x5.X8Lanes, 200)
	storage, allEntries := makeR51DecodedAEntries(t, fixture.pubs, func(int) bool { return true })
	_ = storage
	direct := requireR51IFMABatchQPipeline(t)
	compacted := requireR51IFMABatchQPipeline(t)
	entries := make([]*r51DecodedAEntry, r51x5.X8Lanes)
	directOK := make([]bool, r51x5.X8Lanes)
	compactedOK := make([]bool, r51x5.X8Lanes)

	for _, profile := range []Profile{DalekStrict, StdlibCompat} {
		for hitMask := 0; hitMask < 1<<r51x5.X8Lanes; hitMask++ {
			for lane := range entries {
				entries[lane] = nil
				if hitMask&(1<<lane) != 0 {
					entries[lane] = allEntries[lane]
				}
			}
			directAll, err := direct.verifyBatchWithDecodedAUncompacted(profile, fixture.pubs, fixture.msgs, fixture.sigs, directOK, entries)
			if err != nil {
				t.Fatalf("profile=%d mask=%02x direct: %v", profile, hitMask, err)
			}
			compactedAll, err := compacted.verifyBatchWithDecodedA(profile, fixture.pubs, fixture.msgs, fixture.sigs, compactedOK, entries)
			if err != nil {
				t.Fatalf("profile=%d mask=%02x compacted: %v", profile, hitMask, err)
			}
			if !directAll || !compactedAll {
				t.Fatalf("profile=%d mask=%02x aggregate=(%v,%v), want true", profile, hitMask, directAll, compactedAll)
			}
			for lane := range directOK {
				if !directOK[lane] || compactedOK[lane] != directOK[lane] {
					t.Fatalf("profile=%d mask=%02x lane=%d verdicts=(%v,%v)", profile, hitMask, lane, directOK[lane], compactedOK[lane])
				}
			}
		}
	}
}

func TestR51IFMABatchQDecodedAInvalidMissScatter(t *testing.T) {
	vectors := makeR51HonestVectors(t, 17)
	invalid := findR51InvalidEncoding(t)
	for _, lane := range []int{0, 3, 4, 7, 8, 15, 16} {
		mutated := cloneR51Vectors(vectors)
		mutated[lane].pub = invalid
		for _, profile := range []Profile{DalekStrict, StdlibCompat} {
			t.Run(fmt.Sprintf("profile=%d/lane=%d", profile, lane), func(t *testing.T) {
				assertR51IFMABatchQDecodedA(t, mutated, profile, func(int) bool { return true }, nil)
			})
		}
	}
}

func TestR51IFMABatchQPipelineFiredancerFuzzRegressions(t *testing.T) {
	batchQ, comb, yFirst, paired, literal := newR51IFMABatchQPipelineSets(t)
	vectors := repeatFiredancerFuzzRegressionVectors(t, 17)
	for _, profile := range []Profile{DalekStrict, StdlibCompat} {
		assertR51IFMABatchQVectors(t, batchQ, comb, yFirst, paired, literal, vectors, profile)
	}
}

func TestR51IFMABatchQPipelineEveryLaneAndTailMapping(t *testing.T) {
	batchQ, comb, yFirst, paired, literal := newR51IFMABatchQPipelineSets(t)
	honest := makeR51HonestVectors(t, 64)
	for _, count := range []int{1, 4, 8, 9, 16, 17, 32, 64} {
		for lane := 0; lane < count; lane++ {
			invalid := cloneR51Vectors(honest[:count])
			invalid[lane].msg[0] ^= 0x80
			t.Run(fmt.Sprintf("n=%d/lane=%d", count, lane), func(t *testing.T) {
				assertR51IFMABatchQVectors(t, batchQ, comb, yFirst, paired, literal, invalid, DalekStrict)
			})
		}
	}
}

func TestR51IFMABatchQPipelineKernelErrorClearsPriorChunkVerdicts(t *testing.T) {
	pipeline := requireR51IFMABatchQPipeline(t)
	failure := errors.New("injected second-chunk batch-encoding failure")
	encodeCalls := 0
	pipeline.beforeBatchEncode = func() error {
		encodeCalls++
		if encodeCalls == 2 {
			return failure
		}
		return nil
	}

	fixture := makeBatchFixture(t, 65, 200)
	for index := range fixture.ok {
		fixture.ok[index] = true
	}
	all, err := pipeline.VerifyBatch(DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok)
	if all || !errors.Is(err, failure) {
		t.Fatalf("verification=(%v,%v), want (false,injected failure)", all, err)
	}
	if encodeCalls != 2 {
		t.Fatalf("batch encodes=%d, want 2", encodeCalls)
	}
	for lane, accepted := range fixture.ok {
		if accepted {
			t.Fatalf("lane %d retained a verdict after later-chunk failure", lane)
		}
	}
}

func TestR51IFMABatchQPipelineZeroAllocations(t *testing.T) {
	pipeline := requireR51IFMABatchQPipeline(t)
	for _, count := range []int{1, 4, 8, 16, 32, 64, 65} {
		fixture := makeBatchFixture(t, count, 200)
		if allocs := testing.AllocsPerRun(10, func() {
			all, err := pipeline.VerifyBatch(DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok)
			if err != nil || !all {
				panic(fmt.Sprintf("verify=(%v,%v)", all, err))
			}
		}); allocs != 0 {
			t.Fatalf("count=%d allocations=%v", count, allocs)
		}
	}

	invalid := makeBatchFixture(t, 64, 200)
	for _, lane := range []int{0, 3, 4, 7, 8, 15, 16, 31, 32, 63} {
		invalid.sigs[lane] = append([]byte(nil), invalid.sigs[lane]...)
		invalid.sigs[lane][63] |= 0xe0
	}
	if allocs := testing.AllocsPerRun(10, func() {
		if _, err := pipeline.VerifyBatch(DalekStrict, invalid.pubs, invalid.msgs, invalid.sigs, invalid.ok); err != nil {
			panic(err)
		}
	}); allocs != 0 {
		t.Fatalf("sparse-invalid allocations=%v", allocs)
	}
}

func TestR51IFMABatchQCombPipelineZeroAllocations(t *testing.T) {
	pipeline := requireR51IFMABatchQCombPipeline(t)
	for _, count := range []int{1, 4, 8, 16, 32, 64, 65} {
		fixture := makeBatchFixture(t, count, 200)
		if allocs := testing.AllocsPerRun(10, func() {
			all, err := pipeline.VerifyBatch(DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok)
			if err != nil || !all {
				panic(fmt.Sprintf("verify=(%v,%v)", all, err))
			}
		}); allocs != 0 {
			t.Fatalf("count=%d allocations=%v", count, allocs)
		}
	}
}

func TestR51IFMAYFirstPipelineZeroAllocations(t *testing.T) {
	for _, profile := range []Profile{DalekStrict, StdlibCompat} {
		for _, count := range []int{4, 8, 64} {
			fixture := makeBatchFixture(t, count, 200)
			pipeline := requireR51IFMABatchQPipelineFinalizer(t, r51IFMABatchQFinalizerYFirst)
			if allocs := testing.AllocsPerRun(10, func() {
				all, err := pipeline.VerifyBatch(profile, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok)
				if err != nil || !all {
					panic(fmt.Sprintf("verify=(%v,%v)", all, err))
				}
			}); allocs != 0 {
				t.Fatalf("profile=%d count=%d allocations=%v", profile, count, allocs)
			}
		}
	}
}

func r51DecodedAHitIndex(count, hits int, layout string, index int) bool {
	if hits <= 0 {
		return false
	}
	if hits >= count {
		return true
	}
	switch layout {
	case "clustered":
		// Cold lanes first, followed by a contiguous decoded-point region. This
		// makes the original per-x4 schedule's best naturally grouped case.
		return index >= count-hits
	case "striped":
		// Spread exactly hits entries across the batch. This approximates the
		// original-order case in which almost every x4 group contains a miss.
		return ((index+1)*hits)/count != (index*hits)/count
	default:
		panic("unknown decoded-A benchmark layout")
	}
}

func r51DecodedAMissGroups(entries []*r51DecodedAEntry) int {
	groups := 0
	for start := 0; start < len(entries); start += r51x5.X4Lanes {
		end := minR51(start+r51x5.X4Lanes, len(entries))
		for index := start; index < end; index++ {
			if entries[index] == nil {
				groups++
				break
			}
		}
	}
	return groups
}

// r51DecodedABenchmarkCache measures the existing Cache implementation's
// likely steady-state lookup shape without pretending admission or eviction is
// already wired to the dormant r51 backend. Stats are aggregated once per
// batch so concurrent hot paths do not contend on two atomics per signature.
type r51DecodedABenchmarkCache struct {
	entries sync.Map // [32]byte -> *r51DecodedAEntry
	hits    atomic.Int64
	misses  atomic.Int64
}

func (cache *r51DecodedABenchmarkCache) resolve(pubs []*[32]byte, out []*r51DecodedAEntry) int {
	hits := 0
	for index, pub := range pubs {
		out[index] = nil
		if value, ok := cache.entries.Load(*pub); ok {
			out[index] = value.(*r51DecodedAEntry)
			hits++
		}
	}
	cache.hits.Add(int64(hits))
	cache.misses.Add(int64(len(pubs) - hits))
	return hits
}

func makeR51DecodedABenchmarkCache(tb testing.TB, pubs []*[32]byte, hit func(int) bool) (*r51DecodedABenchmarkCache, []r51DecodedAEntry) {
	tb.Helper()
	storage, allEntries := makeR51DecodedAEntries(tb, pubs, func(int) bool { return true })
	cache := new(r51DecodedABenchmarkCache)
	for index, entry := range allEntries {
		if entry != nil && hit(index) {
			cache.entries.Store(storage[index].raw, entry)
		}
	}
	return cache, storage
}

func TestR51IFMABatchQDecodedAZeroAllocations(t *testing.T) {
	for _, count := range []int{1, 4, 8, 17, 64, 65, 129} {
		fixture := makeBatchFixture(t, count, 200)
		for _, profile := range []Profile{DalekStrict, StdlibCompat} {
			for _, percent := range []int{0, 25, 50, 75, 100} {
				hits := count * percent / 100
				layouts := []string{"clustered", "striped"}
				if hits == 0 || hits == count {
					layouts = layouts[:1]
				}
				for _, layout := range layouts {
					_, entries := makeR51DecodedAEntries(t, fixture.pubs, func(index int) bool {
						return r51DecodedAHitIndex(count, hits, layout, index)
					})
					pipeline := requireR51IFMABatchQPipeline(t)
					if allocs := testing.AllocsPerRun(10, func() {
						all, err := pipeline.verifyBatchWithDecodedA(profile, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok, entries)
						if err != nil || !all {
							panic(fmt.Sprintf("verify=(%v,%v)", all, err))
						}
					}); allocs != 0 {
						t.Fatalf("profile=%d count=%d hits=%d layout=%s allocations=%v", profile, count, percent, layout, allocs)
					}
				}
			}
		}
	}
}

func TestR51IFMABatchQDecodedACacheLookupZeroAllocations(t *testing.T) {
	fixture := makeBatchFixture(t, 64, 200)
	cache, storage := makeR51DecodedABenchmarkCache(t, fixture.pubs, func(index int) bool { return index%2 == 0 })
	_ = storage
	entries := make([]*r51DecodedAEntry, len(fixture.pubs))
	pipeline := requireR51IFMABatchQPipeline(t)
	cache.resolve(fixture.pubs, entries)
	if allocs := testing.AllocsPerRun(10, func() {
		if hits := cache.resolve(fixture.pubs, entries); hits != 32 {
			panic(fmt.Sprintf("hits=%d", hits))
		}
		all, err := pipeline.verifyBatchWithDecodedA(DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok, entries)
		if err != nil || !all {
			panic(fmt.Sprintf("verify=(%v,%v)", all, err))
		}
	}); allocs != 0 {
		t.Fatalf("lookup+verify allocations=%v", allocs)
	}
}

// BenchmarkR51IFMABatchQGate measures the complete-path tradeoff at the
// actual candidate radix. The batch-Q row crosses all x4 groups in a chunk;
// the literal row encodes each x4 group independently and remains the byte-
// predicate oracle; the paired row is the current strict baseline.
func BenchmarkR51IFMABatchQGate(b *testing.B) {
	for _, messageSize := range []int{64, 200, 1232} {
		for _, count := range []int{1, 2, 3, 4, 8, 16, 32, 64} {
			fixture := makeBatchFixture(b, count, messageSize)
			b.Run(fmt.Sprintf("decode=paired-AR/final=projective/path=two-x4/radixA=64/n=%d/msg=%d", count, messageSize), func(b *testing.B) {
				benchmarkR51IFMABatchQOrdinary(b, requireR51IFMAPipeline(b, r51IFMATwoX4, 6), &fixture, count)
			})
			b.Run(fmt.Sprintf("decode=single-A/final=literal-per-x4/path=two-x4/radixA=64/n=%d/msg=%d", count, messageSize), func(b *testing.B) {
				benchmarkR51IFMABatchQOrdinary(b, requireR51IFMAEncodedQReferencePipeline(b, r51IFMATwoX4, 6), &fixture, count)
			})
			b.Run(fmt.Sprintf("decode=single-A/final=batch-Q/path=two-x4/radixA=64/n=%d/msg=%d", count, messageSize), func(b *testing.B) {
				pipeline := requireR51IFMABatchQPipeline(b)
				b.ReportAllocs()
				b.ResetTimer()
				var result bool
				for iteration := 0; iteration < b.N; iteration++ {
					var err error
					result, err = pipeline.VerifyBatch(DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok)
					if err != nil {
						b.Fatal(err)
					}
				}
				benchmarkR51IFMAPipelineResult = result
				b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*count)/1000, "µs/sig")
			})
			b.Run(fmt.Sprintf("decode=single-A/final=batch-Q/path=two-x4/radixA=32/fixedB=comb256/n=%d/msg=%d", count, messageSize), func(b *testing.B) {
				pipeline := requireR51IFMABatchQCombPipeline(b)
				b.ReportAllocs()
				b.ResetTimer()
				var result bool
				for iteration := 0; iteration < b.N; iteration++ {
					var err error
					result, err = pipeline.VerifyBatch(DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok)
					if err != nil {
						b.Fatal(err)
					}
				}
				benchmarkR51IFMAPipelineResult = result
				b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*count)/1000, "µs/sig")
			})
		}
	}
}

// BenchmarkR51IFMAYFirstFinalizerGate compares the two cross-group finalizers
// on identical complete-verifier work. Invalid lanes retain canonical,
// non-small-order R byte strings but deterministically change their raw y, so
// they pass strict byte preparation and exercise the final equation rather
// than an early policy rejection.
func BenchmarkR51IFMAYFirstFinalizerGate(b *testing.B) {
	finalizers := []struct {
		name string
		mode r51IFMABatchQFinalizer
	}{
		{name: "literal-batch-Q", mode: r51IFMABatchQFinalizerLiteral},
		{name: "y-first", mode: r51IFMABatchQFinalizerYFirst},
	}
	for _, count := range []int{4, 8, 64} {
		for _, validPercent := range []int{0, 25, 50, 75, 100} {
			fixture, expected := makeR51YFirstMixtureFixture(b, count, validPercent)
			for _, finalizer := range finalizers {
				name := fmt.Sprintf("final=%s/valid=%d/y-mismatch=%d/n=%d/msg=200", finalizer.name, validPercent, 100-validPercent, count)
				b.Run(name, func(b *testing.B) {
					pipeline := requireR51IFMABatchQPipelineFinalizer(b, finalizer.mode)
					all, err := pipeline.VerifyBatch(DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok)
					if err != nil {
						b.Fatal(err)
					}
					if all != (validPercent == 100) {
						b.Fatalf("preflight aggregate=%v", all)
					}
					for lane := range expected {
						if fixture.ok[lane] != expected[lane] {
							b.Fatalf("preflight lane=%d got=%v want=%v", lane, fixture.ok[lane], expected[lane])
						}
					}

					b.ReportAllocs()
					b.ResetTimer()
					var result bool
					for iteration := 0; iteration < b.N; iteration++ {
						result, err = pipeline.VerifyBatch(DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok)
						if err != nil {
							b.Fatal(err)
						}
					}
					benchmarkR51IFMAPipelineResult = result
					validCount := count * validPercent / 100
					b.ReportMetric(float64(validCount), "valid-sigs/op")
					b.ReportMetric(float64(count-validCount), "y-mismatch-sigs/op")
					b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*count)/1000, "µs/sig")
				})
			}
		}
	}
}

func makeR51YFirstMixtureFixture(tb testing.TB, count, validPercent int) (batchFixture, []bool) {
	tb.Helper()
	if validPercent < 0 || validPercent > 100 || validPercent%25 != 0 {
		tb.Fatalf("invalid y-first valid percentage %d", validPercent)
	}
	fixture := makeBatchFixture(tb, count, 200)
	validCount := count * validPercent / 100
	expected := make([]bool, count)
	for lane := 0; lane < count; lane++ {
		expected[lane] = r51DecodedAHitIndex(count, validCount, "striped", lane)
		if expected[lane] {
			continue
		}
		mutateR51CanonicalRForYMismatch(tb, fixture.pubs[lane], fixture.msgs[lane], fixture.sigs[lane])
	}
	for lane := range expected {
		got := referenceVerifyProfile(DalekStrict, fixture.pubs[lane], fixture.msgs[lane], fixture.sigs[lane])
		if got != expected[lane] {
			tb.Fatalf("y-first fixture lane=%d valid=%v want=%v", lane, got, expected[lane])
		}
	}
	return fixture, expected
}

func mutateR51CanonicalRForYMismatch(tb testing.TB, pub *[32]byte, message, sig []byte) {
	tb.Helper()
	if pub == nil || len(sig) != stded25519.SignatureSize {
		tb.Fatal("invalid y-first mutation fixture")
	}
	sign := sig[31] & 0x80
	var yBytes [32]byte
	copy(yBytes[:], sig[:32])
	yBytes[31] &= 0x7f
	var y, one r51x5.Element
	if _, err := y.SetCanonicalBytes(yBytes[:]); err != nil {
		tb.Fatal(err)
	}
	one.One()
	for attempt := 0; attempt < 32; attempt++ {
		y.Add(&y, &one)
		candidate := y.Bytes()
		candidate[31] |= sign
		if smallOrderEncoding(candidate[:]) {
			continue
		}
		copy(sig[:32], candidate[:])
		if !referenceVerifyProfile(DalekStrict, pub, message, sig) {
			return
		}
	}
	tb.Fatal("failed to construct canonical-R y-mismatch fixture")
}

// BenchmarkR51DecodedAPointGate measures the arithmetic upper bound of an
// exact-key decoded-point tier. Entry construction and lookup are deliberately
// outside the timed region; a later cache benchmark must add those costs after
// this gate establishes whether bypassing A decode is large enough to matter.
// The two schedules consume the same original input and hit layout: original
// decodes misses in their existing x4 groups, while miss-compact pays the real
// pack/scatter work to fill x4 decode groups across each <=64-item chunk.
func BenchmarkR51DecodedAPointGate(b *testing.B) {
	for _, messageSize := range []int{64, 200, 1232} {
		for _, count := range []int{4, 8, 17, 64} {
			fixture := makeBatchFixture(b, count, messageSize)
			b.Run(fmt.Sprintf("lookup=none/schedule=cold/hit-layout=original/hits=0/n=%d/msg=%d", count, messageSize), func(b *testing.B) {
				pipeline := requireR51IFMABatchQPipeline(b)
				b.ReportAllocs()
				b.ResetTimer()
				var result bool
				for iteration := 0; iteration < b.N; iteration++ {
					var err error
					result, err = pipeline.VerifyBatch(DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok)
					if err != nil {
						b.Fatal(err)
					}
				}
				benchmarkR51IFMAPipelineResult = result
				b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*count)/1000, "µs/sig")
			})

			for _, percent := range []int{0, 25, 50, 75, 100} {
				hits := count * percent / 100
				layouts := []string{"clustered", "striped"}
				if hits == 0 || hits == count {
					layouts = layouts[:1]
				}
				for _, layout := range layouts {
					_, entries := makeR51DecodedAEntries(b, fixture.pubs, func(index int) bool {
						return r51DecodedAHitIndex(count, hits, layout, index)
					})
					for _, schedule := range []string{"original", "miss-compact"} {
						name := fmt.Sprintf("lookup=pre-resolved/schedule=%s/hit-layout=%s/hits=%d/n=%d/msg=%d", schedule, layout, percent, count, messageSize)
						b.Run(name, func(b *testing.B) {
							pipeline := requireR51IFMABatchQPipeline(b)
							b.ReportAllocs()
							b.ResetTimer()
							var result bool
							for iteration := 0; iteration < b.N; iteration++ {
								var err error
								if schedule == "original" {
									result, err = pipeline.verifyBatchWithDecodedAUncompacted(DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok, entries)
								} else {
									result, err = pipeline.verifyBatchWithDecodedA(DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok, entries)
								}
								if err != nil {
									b.Fatal(err)
								}
							}
							benchmarkR51IFMAPipelineResult = result
							decodeGroups := r51DecodedAMissGroups(entries)
							if schedule == "miss-compact" {
								decodeGroups = (count - hits + r51x5.X4Lanes - 1) / r51x5.X4Lanes
							}
							b.ReportMetric(float64(decodeGroups), "decode-groups/op")
							b.ReportMetric(float64(hits), "decoded-hits/op")
							b.ReportMetric(float64(count-hits), "misses/op")
							b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*count)/1000, "µs/sig")
						})
					}
				}
			}
		}
	}
}

// BenchmarkR51DecodedACacheLookupGate adds steady-state sync.Map lookup and
// batch-aggregated hit/miss atomics to the paid miss-compaction path. Table
// construction, admission, and eviction remain outside this gate.
func BenchmarkR51DecodedACacheLookupGate(b *testing.B) {
	for _, count := range []int{4, 8, 64} {
		fixture := makeBatchFixture(b, count, 200)
		b.Run(fmt.Sprintf("lookup=none/stats=none/schedule=miss-compact/hit-layout=none/hits=0/n=%d/msg=200", count), func(b *testing.B) {
			pipeline := requireR51IFMABatchQPipeline(b)
			b.ReportAllocs()
			b.ResetTimer()
			var result bool
			for iteration := 0; iteration < b.N; iteration++ {
				var err error
				result, err = pipeline.VerifyBatch(DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok)
				if err != nil {
					b.Fatal(err)
				}
			}
			benchmarkR51IFMAPipelineResult = result
			b.ReportMetric(float64((count+r51x5.X4Lanes-1)/r51x5.X4Lanes), "decode-groups/op")
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*count)/1000, "µs/sig")
		})
		for _, percent := range []int{0, 25, 50, 75, 100} {
			hitCount := count * percent / 100
			for _, layout := range []string{"clustered", "striped"} {
				if (hitCount == 0 || hitCount == count) && layout == "striped" {
					continue
				}
				cache, storage := makeR51DecodedABenchmarkCache(b, fixture.pubs, func(index int) bool {
					return r51DecodedAHitIndex(count, hitCount, layout, index)
				})
				_ = storage
				entries := make([]*r51DecodedAEntry, count)
				// Promote sync.Map's read-mostly snapshot before timing.
				cache.resolve(fixture.pubs, entries)
				cache.resolve(fixture.pubs, entries)

				name := fmt.Sprintf("lookup=sync-map/stats=batch/schedule=miss-compact/hit-layout=%s/hits=%d/n=%d/msg=200", layout, percent, count)
				b.Run(name, func(b *testing.B) {
					pipeline := requireR51IFMABatchQPipeline(b)
					b.ReportAllocs()
					b.ResetTimer()
					var result bool
					for iteration := 0; iteration < b.N; iteration++ {
						hits := cache.resolve(fixture.pubs, entries)
						if hits != hitCount {
							b.Fatalf("hits=%d want=%d", hits, hitCount)
						}
						var err error
						result, err = pipeline.verifyBatchWithDecodedA(DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok, entries)
						if err != nil {
							b.Fatal(err)
						}
					}
					benchmarkR51IFMAPipelineResult = result
					b.ReportMetric(float64((count-hitCount+r51x5.X4Lanes-1)/r51x5.X4Lanes), "decode-groups/op")
					b.ReportMetric(float64(hitCount), "decoded-hits/op")
					b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*count)/1000, "µs/sig")
				})
			}
		}
	}
}

func benchmarkR51IFMABatchQOrdinary(b *testing.B, pipeline *r51IFMAPipeline, fixture *batchFixture, count int) {
	b.Helper()
	b.ReportAllocs()
	b.ResetTimer()
	var result bool
	for iteration := 0; iteration < b.N; iteration++ {
		var err error
		result, err = pipeline.VerifyBatch(DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok)
		if err != nil {
			b.Fatal(err)
		}
	}
	benchmarkR51IFMAPipelineResult = result
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*count)/1000, "µs/sig")
}

// BenchmarkR51IFMABatchQParallel compares independent per-worker workspaces at
// the caller's GOMAXPROCS. Run it separately at 1/2/4/8/16 so each row sees
// the intended core and cache pressure. The read-only fixture is shared.
func BenchmarkR51IFMABatchQParallel(b *testing.B) {
	type workerState struct {
		batchQ *r51IFMABatchQPipeline
		paired *r51IFMAPipeline
		ok     []bool
		result bool
		err    error
		used   bool
	}

	const count = 64
	fixture := makeBatchFixture(b, count, 200)
	workers := runtime.GOMAXPROCS(0)
	for _, useBatchQ := range []bool{false, true} {
		final := "paired-AR-projective"
		if useBatchQ {
			final = "single-A-batch-Q"
		}
		b.Run(fmt.Sprintf("workers=%d/final=%s/n=64/msg=200", workers, final), func(b *testing.B) {
			states := make([]workerState, workers)
			available := make(chan *workerState, workers)
			for index := range states {
				if useBatchQ {
					states[index].batchQ = requireR51IFMABatchQPipeline(b)
				} else {
					states[index].paired = requireR51IFMAPipeline(b, r51IFMATwoX4, 6)
				}
				states[index].ok = make([]bool, count)
				available <- &states[index]
			}

			b.ReportAllocs()
			b.SetParallelism(1)
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				state := <-available
				for pb.Next() {
					state.used = true
					if useBatchQ {
						state.result, state.err = state.batchQ.VerifyBatch(DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, state.ok)
					} else {
						state.result, state.err = state.paired.VerifyBatch(DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, state.ok)
					}
					if state.err != nil {
						break
					}
				}
				available <- state
			})
			b.StopTimer()

			result := true
			for range states {
				state := <-available
				if state.err != nil {
					b.Fatal(state.err)
				}
				if state.used && !state.result {
					b.Fatal("parallel r51 batch-Q gate rejected a valid fixture")
				}
				result = result && (!state.used || state.result)
			}
			benchmarkR51IFMAPipelineResult = result
			elapsed := b.Elapsed()
			b.ReportMetric(float64(b.N*count)/elapsed.Seconds(), "sig/s")
			b.ReportMetric(float64(elapsed.Nanoseconds())/float64(b.N*count)/1000, "µs/sig")
			if useBatchQ {
				var pipeline r51IFMABatchQPipeline
				scratchBytes := unsafe.Sizeof(pipeline.encoder) + unsafe.Sizeof(pipeline.points) +
					unsafe.Sizeof(pipeline.active) + unsafe.Sizeof(pipeline.encoded) +
					unsafe.Sizeof(pipeline.final) + unsafe.Sizeof(pipeline.decodedAPoints) +
					unsafe.Sizeof(pipeline.decodedAScalars) + unsafe.Sizeof(pipeline.decodedAMissBytes) +
					unsafe.Sizeof(pipeline.decodedAMissLanes)
				b.ReportMetric(float64(scratchBytes), "batch-scratch-B/worker")
			}
		})
	}
}
