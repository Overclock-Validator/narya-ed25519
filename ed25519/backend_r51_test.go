package ed25519

import (
	"fmt"
	"runtime"
	"sync"
	"testing"
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
	bf := makeBatchFixture(t, 64, 200)
	verdicts := make([]bool, len(bf.pubs))
	if !b.verifyBatchRaw(DalekStrict, bf.pubs, bf.msgs, bf.sigs, verdicts) {
		t.Fatal("warmup rejected valid batch")
	}
	allocs := testing.AllocsPerRun(100, func() {
		if !b.verifyBatchRaw(DalekStrict, bf.pubs, bf.msgs, bf.sigs, verdicts) {
			panic("r51 backend rejected valid batch")
		}
	})
	if allocs != 0 {
		t.Fatalf("steady-state allocations=%v want=0", allocs)
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
