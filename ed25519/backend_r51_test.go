package ed25519

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"unsafe"

	"github.com/Overclock-Validator/narya/internal/cpufeat"
	"github.com/Overclock-Validator/narya/internal/r51x5"
)

func requireR51Backend(t testing.TB) *r51Backend {
	t.Helper()
	if !r51IFMAPipelineAvailable(r51IFMATwoX4) {
		t.Skipf("r51 x4 IFMA pipeline unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	b := new(r51Backend)
	if err := b.activate(); err != nil {
		t.Fatalf("activate r51 backend: %v", err)
	}
	return b
}

func requireR51DecodedACache(t testing.TB) *r51Backend {
	t.Helper()
	backend := requireR51Backend(t)
	if !r51DecodedACacheEnabled() {
		t.Skip("r51 decoded-A Cache tier is enabled only on native-wide IFMA CPUs")
	}
	return backend
}

func TestR51BackendUnsupportedGate(t *testing.T) {
	if r51IFMAPipelineAvailable(r51IFMATwoX4) {
		t.Skip("r51 x4 IFMA pipeline is available; hardware tests cover activation")
	}
	if err := new(r51Backend).activate(); err == nil {
		t.Fatal("r51 backend activated without the required IFMA and SHA kernels")
	}
}

func TestR51BackendBatchWidthSelection(t *testing.T) {
	if !r51IFMAPipelineAvailable(r51IFMATwoX4) {
		t.Skipf("r51 x4 IFMA pipeline unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	worker := new(r51Backend).newBatchWorker()
	if worker.err != nil {
		t.Fatal(worker.err)
	}
	if worker.pipeline == nil {
		t.Fatal("nil r51 batch pipeline")
	}
	gotWide := worker.pipeline.wideCore != nil
	if gotWide != cpufeat.PreferWideIFMA() {
		t.Fatalf("wide=%v want=%v pipeline=%s", gotWide, cpufeat.PreferWideIFMA(), worker.pipeline)
	}
	t.Logf("prefer-wide=%v pipeline=%s", gotWide, worker.pipeline)
}

func TestR51BackendDecodedACacheHardwareGate(t *testing.T) {
	backend := requireR51Backend(t)
	if !backend.supportsPrecomp() {
		t.Fatal("r51 warm-cache staging is disabled")
	}
	if got, want := r51DecodedACacheEnabled(), cpufeat.PreferWideIFMA(); got != want {
		t.Fatalf("decoded-A arithmetic enabled=%v want=%v", got, want)
	}
}

func admitR51DecodedATestEntry(t testing.TB, cache *Cache, backend *r51Backend, pub *[32]byte) {
	t.Helper()
	for sighting := 0; sighting < buildThreshold; sighting++ {
		cache.admit(backend, pub)
	}
	value, ok := cache.tables.Load(*pub)
	if !ok {
		t.Fatal("decoded-A entry was not admitted")
	}
	pre := value.(*PrecomputedKey)
	if pre.raw != *pub {
		t.Fatal("decoded-A entry lost its exact raw-key binding")
	}
	if _, ok := pre.table.(*r51DecodedATable); !ok {
		t.Fatalf("decoded-A native table type %T", pre.table)
	}
}

func TestR51BackendDecodedAPrecomputeShape(t *testing.T) {
	backend := requireR51Backend(t)
	fixture := makeFixture(t, 200)
	pre, err := backend.buildPrecomp(&fixture.pub)
	if err != nil {
		t.Fatal(err)
	}
	if pre.raw != fixture.pub || pre.size != r51DecodedATableBytes {
		t.Fatalf("precomputed metadata raw=%x size=%d", pre.raw, pre.size)
	}
	if got := int64(unsafe.Sizeof(r51DecodedATable{})); got != r51DecodedATableBytes {
		t.Fatalf("decoded-A payload size=%d accounting=%d", got, r51DecodedATableBytes)
	}
	table, ok := pre.table.(*r51DecodedATable)
	if !ok || table == nil {
		t.Fatalf("decoded-A table type %T", pre.table)
	}
	if table.entry.raw != fixture.pub {
		t.Fatalf("decoded-A entry raw=%x, want %x", table.entry.raw, fixture.pub)
	}
	if got := table.entry.point.Bytes(); got != fixture.pub {
		t.Fatalf("decoded-A point re-encoded as %x, want %x", got, fixture.pub)
	}
	if !pre.VerifyStrict(fixture.msg, fixture.sig) {
		t.Fatal("decoded-A PrecomputedKey rejected a valid strict signature")
	}
}

func TestR51BackendDecodedACacheDifferential(t *testing.T) {
	backend := requireR51DecodedACache(t)
	for _, profile := range []Profile{DalekStrict, StdlibCompat} {
		for _, count := range []int{1, 3, 4, 8, 9, 17, 64, 65} {
			fixture := makeBatchFixture(t, count, 1232)
			cache := &Cache{MaxTableBytes: int64(count+1) * r51DecodedATableBytes}
			for lane, pub := range fixture.pubs {
				if lane%2 == 0 {
					admitR51DecodedATestEntry(t, cache, backend, pub)
				}
			}
			verdicts := make([]bool, count)
			gotAll := cache.verifyBatchWithBackend(backend, profile, fixture.pubs, fixture.msgs, fixture.sigs, verdicts)
			wantAll := true
			for lane := range verdicts {
				want := referenceVerifyProfile(profile, fixture.pubs[lane], fixture.msgs[lane], fixture.sigs[lane])
				wantAll = wantAll && want
				if verdicts[lane] != want {
					t.Fatalf("profile=%d n=%d lane=%d got=%v want=%v", profile, count, lane, verdicts[lane], want)
				}
			}
			if gotAll != wantAll {
				t.Fatalf("profile=%d n=%d aggregate=%v want=%v", profile, count, gotAll, wantAll)
			}
		}
	}
}

func TestR51BackendDecodedACacheInvalidEquationsDoNotAdmit(t *testing.T) {
	backend := requireR51DecodedACache(t)
	fixture := makeBatchFixture(t, 8, 200)
	for lane := range fixture.msgs {
		fixture.msgs[lane] = append([]byte(nil), fixture.msgs[lane]...)
		fixture.msgs[lane][0] ^= 0x80
	}
	cache := &Cache{MaxTableBytes: int64(len(fixture.pubs)) * r51DecodedATableBytes}
	for attempt := 0; attempt < 2*buildThreshold; attempt++ {
		if cache.verifyBatchWithBackend(backend, DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok) {
			t.Fatalf("invalid-equation batch accepted at attempt %d", attempt)
		}
	}
	if got := cache.Stats(); got.Tables != 0 || got.TableBytes != 0 {
		t.Fatalf("invalid equations affected decoded-A admission: %+v", got)
	}
	if got := cache.seenCount.Load(); got != 0 {
		t.Fatalf("invalid equations created %d admission records", got)
	}
}

func TestR51BackendDecodedACacheNarrowTrafficAdmitsWithoutLookup(t *testing.T) {
	backend := requireR51DecodedACache(t)
	fixture := makeBatchFixture(t, 3, 200)
	cache := &Cache{MaxTableBytes: 3 * r51DecodedATableBytes}

	for sighting := 0; sighting < buildThreshold; sighting++ {
		if !cache.verifyWithBackend(backend, DalekStrict, fixture.pubs[0], fixture.msgs[0], fixture.sigs[0]) {
			t.Fatalf("singleton sighting %d rejected", sighting)
		}
	}
	if got := cache.Stats(); got.Tables != 1 || got.Hits != 0 || got.Misses != 0 {
		t.Fatalf("singleton batch-only admission stats: %+v", got)
	}

	for count := 1; count < r51x5.X4Lanes; count++ {
		if !cache.verifyBatchWithBackend(
			backend,
			DalekStrict,
			fixture.pubs[:count],
			fixture.msgs[:count],
			fixture.sigs[:count],
			fixture.ok[:count],
		) {
			t.Fatalf("n=%d narrow cached batch rejected", count)
		}
	}
	if got := cache.Stats(); got.Hits != 0 || got.Misses != 0 {
		t.Fatalf("narrow batch performed unusable lookups: %+v", got)
	}
}

func TestR51DecodedAPrecomputedDispatch(t *testing.T) {
	for _, test := range []struct {
		count int
		hits  int
		want  bool
	}{
		{count: 4, hits: 2, want: false},
		{count: 4, hits: 4, want: true},
		{count: 8, hits: 4, want: false},
		{count: 8, hits: 8, want: true},
		{count: 17, hits: 8, want: false},
		{count: 17, hits: 17, want: true},
		{count: 64, hits: 15, want: false},
		{count: 64, hits: 16, want: true},
		{count: 64, hits: 64, want: true},
	} {
		if got := r51UseDecodedAPrecomputed(test.count, test.hits); got != test.want {
			t.Fatalf("count=%d hits=%d got=%v want=%v", test.count, test.hits, got, test.want)
		}
	}
}

func TestR51BackendDecodedACacheHitZeroAllocations(t *testing.T) {
	backend := requireR51DecodedACache(t)
	for _, count := range []int{4, 8, 64} {
		fixture := makeBatchFixture(t, count, 1232)
		cache := &Cache{MaxTableBytes: int64(count) * r51DecodedATableBytes}
		for _, pub := range fixture.pubs {
			admitR51DecodedATestEntry(t, cache, backend, pub)
			// This gate measures the steady decoded-A tier. Promotion has its
			// own build/accounting and warm-verifier allocation gates; allowing
			// it to cross its threshold inside AllocsPerRun would deliberately
			// measure one-time table construction rather than verification.
			cache.promotionState(*pub).status.Store(promotionDisabled)
		}
		if !cache.verifyBatchWithBackend(backend, DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok) {
			t.Fatalf("count=%d warmup rejected valid batch", count)
		}
		allocs := testing.AllocsPerRun(100, func() {
			if !cache.verifyBatchWithBackend(backend, DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok) {
				panic("r51 decoded-A cache rejected valid batch")
			}
		})
		if allocs != 0 {
			t.Fatalf("count=%d decoded-A cache-hit allocations=%v want=0", count, allocs)
		}
	}
}

func TestR51BackendInternalFaultFallsBackToGeneric(t *testing.T) {
	fault := errors.New("injected native fault")
	b := new(r51Backend)
	// Mark activation complete without touching hardware, then inject workers
	// that fail before any native instruction. This makes the operational
	// fault policy testable on every architecture.
	b.activateOnce.Do(func() {})
	b.singlePool.New = func() any { return &r51SingleWorker{err: fault} }
	b.batchPool.New = func() any { return &r51BatchWorker{err: fault} }

	single := makeFixture(t, 200)
	if !b.verify(DalekStrict, &single.pub, single.msg, single.sig, nil) {
		t.Fatal("singleton native fault did not fall back to generic verification")
	}
	batch := makeBatchFixture(t, 4, 200)
	verdicts := make([]bool, len(batch.pubs))
	if !b.verifyBatchRaw(DalekStrict, batch.pubs, batch.msgs, batch.sigs, verdicts) {
		t.Fatalf("batch native fault did not fall back: %v", verdicts)
	}
	if got := b.backendStats().InternalFaultFallbacks; got != 2 {
		t.Fatalf("fault fallback count=%d, want 2", got)
	}
}

func TestR51BackendDispatchDifferential(t *testing.T) {
	b := requireR51Backend(t)
	for _, profile := range []Profile{DalekStrict, StdlibCompat} {
		for _, n := range []int{0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 32, 64, 65} {
			n, profile := n, profile
			t.Run(fmt.Sprintf("profile=%d/n=%d", profile, n), func(t *testing.T) {
				bf := makeBatchFixture(t, n, 200)
				for badLane := -1; badLane < n; badLane++ {
					msgs := append([][]byte(nil), bf.msgs...)
					if badLane >= 0 {
						bad := append([]byte(nil), msgs[badLane]...)
						bad[0] ^= 1
						msgs[badLane] = bad
					}
					verdicts := make([]bool, n)
					gotAll := b.verifyBatchRaw(profile, bf.pubs, msgs, bf.sigs, verdicts)
					wantAll := true
					for lane := range verdicts {
						want := referenceVerifyProfile(profile, bf.pubs[lane], msgs[lane], bf.sigs[lane])
						wantAll = wantAll && want
						if verdicts[lane] != want {
							t.Fatalf("bad-lane=%d lane=%d got=%v want=%v", badLane, lane, verdicts[lane], want)
						}
					}
					if gotAll != wantAll {
						t.Fatalf("bad-lane=%d aggregate=%v want=%v", badLane, gotAll, wantAll)
					}
				}
			})
		}
	}
}

func TestR51BackendBatchItemPathMatchesRaw(t *testing.T) {
	b := requireR51Backend(t)
	for _, n := range []int{1, 2, 4, 5, 8, 17, 64, 65, 129} {
		bf := makeBatchFixture(t, n, 1232)
		items := makeItems(bf.pubs, bf.msgs, bf.sigs, make([]bool, n))
		applyProfile(DalekStrict, items)
		b.verifyBatch(DalekStrict, items)
		for lane := range items {
			want := referenceVerifyProfile(DalekStrict, bf.pubs[lane], bf.msgs[lane], bf.sigs[lane])
			if items[lane].ok != want {
				t.Fatalf("n=%d lane=%d got=%v want=%v", n, lane, items[lane].ok, want)
			}
		}
	}
}

func TestR51BackendConcurrentWorkers(t *testing.T) {
	b := requireR51Backend(t)
	const workers = 8
	fixtures := make([]batchFixture, workers)
	for worker := range fixtures {
		fixtures[worker] = makeBatchFixture(t, 17+worker, 64+worker*17)
	}

	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for worker := range fixtures {
		worker := worker
		wg.Add(1)
		go func() {
			defer wg.Done()
			bf := &fixtures[worker]
			verdicts := make([]bool, len(bf.pubs))
			for round := 0; round < 32; round++ {
				if !b.verifyBatchRaw(DalekStrict, bf.pubs, bf.msgs, bf.sigs, verdicts) {
					errs <- fmt.Errorf("worker=%d round=%d rejected valid batch", worker, round)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestR51BackendSteadyStateZeroAllocations(t *testing.T) {
	b := requireR51Backend(t)
	for _, count := range []int{2, 64} {
		bf := makeBatchFixture(t, count, 200)
		verdicts := make([]bool, len(bf.pubs))
		if !b.verifyBatchRaw(DalekStrict, bf.pubs, bf.msgs, bf.sigs, verdicts) {
			t.Fatalf("count=%d warmup rejected valid batch", count)
		}
		allocs := testing.AllocsPerRun(100, func() {
			if !b.verifyBatchRaw(DalekStrict, bf.pubs, bf.msgs, bf.sigs, verdicts) {
				panic("r51 backend rejected valid batch")
			}
		})
		if allocs != 0 {
			t.Fatalf("count=%d steady-state allocations=%v want=0", count, allocs)
		}
	}
}

func BenchmarkR51BackendDispatch(b *testing.B) {
	backend := requireR51Backend(b)
	for _, size := range benchMsgSizes {
		for _, n := range []int{1, 2, 3, 4, 5, 8, 9, 16, 17, 32, 64} {
			size, n := size, n
			bf := makeBatchFixture(b, n, size)
			b.Run(fmt.Sprintf("n=%d/msg=%d", n, size), func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if !backend.verifyBatchRaw(DalekStrict, bf.pubs, bf.msgs, bf.sigs, bf.ok) {
						b.Fatal("verify failed")
					}
				}
				b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*n)/1000, "us/sig")
			})
		}
	}
}

// BenchmarkR51DecodedACacheTier measures the registered backend through the
// actual Cache lookup, admission-bypass, raw-batch, worker-pool, native-width,
// and final-verdict path. The fixture uses distinct keys and a striped hit
// layout. The cache budget is filled before timing so misses remain misses;
// this isolates a stable hit-rate workload instead of letting a benchmark
// silently warm from 0% to 100% during b.N.
func BenchmarkR51DecodedACacheTier(b *testing.B) {
	backend := requireR51DecodedACache(b)
	for _, messageSize := range []int{64, 200, 1232} {
		for _, count := range []int{1, 4, 8, 17, 64} {
			fixture := makeBatchFixture(b, count, messageSize)
			b.Run(fmt.Sprintf("path=cold/hits=0/n=%d/msg=%d", count, messageSize), func(b *testing.B) {
				if !backend.verifyBatchRaw(DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok) {
					b.Fatal("cold warmup rejected valid batch")
				}
				faultsBefore := backend.faults.Load()
				b.ReportAllocs()
				b.ResetTimer()
				for range b.N {
					if !backend.verifyBatchRaw(DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok) {
						b.Fatal("cold verification rejected valid batch")
					}
				}
				b.ReportMetric(float64(backend.faults.Load()-faultsBefore), "native-faults")
				b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*count)/1000, "us/signature")
			})

			for _, percent := range []int{0, 25, 50, 75, 100} {
				hitCount := count * percent / 100
				b.Run(fmt.Sprintf("path=cache/hits=%d/n=%d/msg=%d", percent, count, messageSize), func(b *testing.B) {
					budget := int64(hitCount) * r51DecodedATableBytes
					if budget == 0 {
						budget = 1 // smaller than one entry: stable all-miss cache
					}
					cache := &Cache{MaxTableBytes: budget}
					for lane, pub := range fixture.pubs {
						if r51DecodedAHitIndex(count, hitCount, "striped", lane) {
							admitR51DecodedATestEntry(b, cache, backend, pub)
						}
					}
					if hitCount == 0 {
						// Mark each key permanently ineligible before timing; otherwise
						// the eighth benchmark iteration would pay construction and
						// change the workload it claims to measure.
						for _, pub := range fixture.pubs {
							for sighting := 0; sighting < buildThreshold; sighting++ {
								cache.admit(backend, pub)
							}
						}
					}
					if !cache.verifyBatchWithBackend(backend, DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok) {
						b.Fatal("cache warmup rejected valid batch")
					}
					faultsBefore := backend.faults.Load()
					b.ReportAllocs()
					b.ResetTimer()
					for range b.N {
						if !cache.verifyBatchWithBackend(backend, DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok) {
							b.Fatal("cache verification rejected valid batch")
						}
					}
					b.ReportMetric(float64(hitCount), "decoded-hits/op")
					b.ReportMetric(float64(backend.faults.Load()-faultsBefore), "native-faults")
					b.ReportMetric(float64(cache.Stats().TableBytes), "table-bytes")
					b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*count)/1000, "us/signature")
				})
			}
		}
	}
}

// BenchmarkR51DecodedACacheHardwareBypass pins the non-degrading Zen 4 route.
// When decoded-A precomputation is not profitable, Cache must reach the same
// raw native batch entry point without lookup/admission bookkeeping.
func BenchmarkR51DecodedACacheHardwareBypass(b *testing.B) {
	backend := requireR51Backend(b)
	if r51DecodedACacheEnabled() {
		b.Skip("r51 decoded-A Cache tier is enabled on this CPU")
	}
	for _, messageSize := range []int{64, 200, 1232} {
		for _, count := range []int{8, 64} {
			fixture := makeBatchFixture(b, count, messageSize)
			cache := new(Cache)
			for _, path := range []struct {
				name   string
				verify func() bool
			}{
				{name: "cold", verify: func() bool {
					return verifyBatch(backend, DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok, nil)
				}},
				{name: "cache-bypass", verify: func() bool {
					return cache.verifyBatchWithBackend(backend, DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok)
				}},
			} {
				b.Run(fmt.Sprintf("path=%s/n=%d/msg=%d", path.name, count, messageSize), func(b *testing.B) {
					if !path.verify() {
						b.Fatal("warmup rejected valid batch")
					}
					faultsBefore := backend.faults.Load()
					b.ReportAllocs()
					b.ResetTimer()
					for range b.N {
						if !path.verify() {
							b.Fatal("verification rejected valid batch")
						}
					}
					b.ReportMetric(float64(backend.faults.Load()-faultsBefore), "native-faults")
					b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*count)/1000, "us/signature")
				})
			}
		}
	}
}

// BenchmarkR51PublicWrapperGate measures the exported strict-batch wrapper and
// the registered backend's raw entry point in the same binary, on the same
// fixtures. Comparing this gate is stronger than comparing unrelated test
// binaries, whose code layout and CPU-frequency clusters can obscure a
// sub-percent wrapper cost. Run with -count so each process repeats private
// then public under the same machine state.
func BenchmarkR51PublicWrapperGate(b *testing.B) {
	if err := SetBackend("r51"); err != nil {
		b.Skipf("forced r51 backend unavailable: %v", err)
	}
	backend, ok := active().(*r51Backend)
	if !ok {
		b.Fatalf("active backend type %T, want *r51Backend", active())
	}

	for _, size := range benchMsgSizes {
		for _, n := range []int{1, 4, 8, 64} {
			size, n := size, n
			bf := makeBatchFixture(b, n, size)
			for _, path := range []struct {
				name   string
				verify func() bool
			}{
				{
					name: "private-core",
					verify: func() bool {
						return backend.verifyBatchRaw(DalekStrict, bf.pubs, bf.msgs, bf.sigs, bf.ok)
					},
				},
				{
					name: "public-wrapper",
					verify: func() bool {
						return VerifyBatchStrict(bf.pubs, bf.msgs, bf.sigs, bf.ok)
					},
				},
			} {
				path := path
				b.Run(fmt.Sprintf("msg=%d/n=%d/path=%s", size, n, path.name), func(b *testing.B) {
					if !path.verify() {
						b.Fatal("warmup rejected valid fixture")
					}
					b.ReportAllocs()
					b.ResetTimer()
					for range b.N {
						if !path.verify() {
							b.Fatal("verify failed")
						}
					}
					b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*n)/1000, "us/signature")
				})
			}
		}
	}
}

// BenchmarkR51SingletonDispatchOverhead keeps the packed core and backend
// adapter in one test binary. Cross-package benchmark binaries can differ
// enough in code layout to obscure sub-microsecond dispatch costs.
func BenchmarkR51SingletonDispatchOverhead(b *testing.B) {
	backend := requireR51Backend(b)
	direct, err := r51x5.NewExperimentalPackedStrictVerifierX4()
	if err != nil {
		b.Fatal(err)
	}
	f := makeFixture(b, 200)

	b.Run("direct-packed", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			ok, err := direct.Verify(&f.pub, f.msg, f.sig)
			if err != nil || !ok {
				b.Fatalf("direct packed verify=(%v,%v)", ok, err)
			}
		}
	})
	b.Run("pool-get-put-only", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			worker := backend.singlePool.Get().(*r51SingleWorker)
			backend.singlePool.Put(worker)
		}
	})
	b.Run("pooled-backend", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			ok, err := backend.verifyOne(DalekStrict, &f.pub, f.msg, f.sig)
			if err != nil || !ok {
				b.Fatalf("pooled backend verify=(%v,%v)", ok, err)
			}
		}
	})
}
