package ed25519

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"testing"

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
