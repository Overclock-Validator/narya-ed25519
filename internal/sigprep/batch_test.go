package sigprep

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"
)

// batchWidths straddle every boundary the multi-buffer hash cares about: the
// x4 and x8 group widths, one either side of each, and depths well past them.
// A batch former that silently drops a partial tail group passes at 8 and 64
// and fails here.
var batchWidths = []int{1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 512}

func buildInputs(tb testing.TB, rng *rand.Rand, n int) (pubs []*[32]byte, msgs, sigs [][]byte) {
	tb.Helper()
	for i := 0; i < n; i++ {
		pub, msg, sig := randomSignature(tb, rng)
		pubs = append(pubs, pub)
		msgs = append(msgs, msg)
		sigs = append(sigs, sig)
	}
	return pubs, msgs, sigs
}

// The batch result must equal what preparing each item alone would produce,
// including which items are live. Anything else means a lane's value or verdict
// landed on its neighbour, which batching must never do.
func TestBatchMatchesSinglePrepare(t *testing.T) {
	for _, rules := range []Rules{DalekStrict, StdlibCompat} {
		for _, n := range batchWidths {
			t.Run(fmt.Sprintf("strict=%v/n=%d", rules.RejectSmallOrderA, n), func(t *testing.T) {
				rng := rand.New(rand.NewSource(int64(n) * 31))
				pubs, msgs, sigs := buildInputs(t, rng, n)
				// Corrupt a scattered subset so live and dead items interleave.
				for i := range sigs {
					if i%3 == 1 {
						corrupt(rng, pubs[i], sigs[i])
					}
				}

				var batch Batch
				batch.Prepare(rules, pubs, msgs, sigs)

				if batch.Len() != n {
					t.Fatalf("Len=%d want %d", batch.Len(), n)
				}
				for i := 0; i < n; i++ {
					want, wantOK := Prepare(rules, pubs[i], msgs[i], sigs[i])
					if got := batch.Live(i); got != wantOK {
						t.Fatalf("item %d: batch live=%v single ok=%v", i, got, wantOK)
					}
					if !wantOK {
						continue
					}
					if *batch.At(i) != want {
						t.Fatalf("item %d: batch %+v != single %+v", i, *batch.At(i), want)
					}
				}
			})
		}
	}
}

// A single invalid item must not disturb its neighbours regardless of where it
// sits, including the first and last lane of a group. Sweeping every position
// catches an off-by-one in the compaction that a random subset would miss.
func TestBatchInvalidItemAtEveryPosition(t *testing.T) {
	const n = 17
	for bad := 0; bad < n; bad++ {
		t.Run(fmt.Sprintf("bad=%d", bad), func(t *testing.T) {
			rng := rand.New(rand.NewSource(int64(bad) + 1000))
			pubs, msgs, sigs := buildInputs(t, rng, n)
			// A small-order public key: rejected by the strict gates alone.
			*pubs[bad] = [32]byte{1}

			var batch Batch
			live := batch.Prepare(DalekStrict, pubs, msgs, sigs)
			if live != n-1 {
				t.Fatalf("live=%d want %d", live, n-1)
			}
			for i := 0; i < n; i++ {
				if batch.Live(i) != (i != bad) {
					t.Fatalf("item %d: live=%v", i, batch.Live(i))
				}
				if i == bad {
					if *batch.At(i) != (Prepared{}) {
						t.Fatalf("rejected item %d must stay zeroed", i)
					}
					continue
				}
				want, ok := Prepare(DalekStrict, pubs[i], msgs[i], sigs[i])
				if !ok || *batch.At(i) != want {
					t.Fatalf("item %d disturbed by a rejection at %d", i, bad)
				}
			}
		})
	}
}

// Rejected items must not occupy hash lanes. Lanes are the resource the
// multi-buffer kernel parallelizes over, so hashing a signature whose verdict
// is already settled wastes one outright.
func TestBatchDoesNotHashRejectedItems(t *testing.T) {
	const n = 32
	rng := rand.New(rand.NewSource(4242))
	pubs, msgs, sigs := buildInputs(t, rng, n)
	for i := range pubs {
		if i%2 == 0 {
			*pubs[i] = [32]byte{1}
		}
	}

	var batch Batch
	live := batch.Prepare(DalekStrict, pubs, msgs, sigs)
	if live != n/2 {
		t.Fatalf("live=%d want %d", live, n/2)
	}
	if len(batch.lanes) != n/2 {
		t.Fatalf("hashed %d items, want %d", len(batch.lanes), n/2)
	}
	if len(batch.segments) != n/2 {
		t.Fatalf("built %d hash inputs, want %d", len(batch.segments), n/2)
	}
	// Compaction must preserve the mapping back to the original index.
	for compact, index := range batch.lanes {
		if index != compact*2+1 {
			t.Fatalf("lane %d maps to index %d, want %d", compact, index, compact*2+1)
		}
	}
}

// A batch where nothing survives the gates must not reach the hash at all.
func TestBatchAllRejected(t *testing.T) {
	const n = 8
	rng := rand.New(rand.NewSource(5))
	pubs, msgs, sigs := buildInputs(t, rng, n)
	for i := range pubs {
		*pubs[i] = [32]byte{1}
	}

	var batch Batch
	if live := batch.Prepare(DalekStrict, pubs, msgs, sigs); live != 0 {
		t.Fatalf("live=%d want 0", live)
	}
	for i := 0; i < n; i++ {
		if batch.Live(i) {
			t.Fatalf("item %d must be dead", i)
		}
	}
}

// Reuse must be complete: a shorter second group must not leave a longer first
// group's verdicts or values visible.
func TestBatchResetClearsPriorGroup(t *testing.T) {
	rng := rand.New(rand.NewSource(9))
	pubs, msgs, sigs := buildInputs(t, rng, 16)

	var batch Batch
	batch.Prepare(DalekStrict, pubs, msgs, sigs)
	first := *batch.At(3)

	// Now a shorter group whose item 3 is rejected. The stale value from the
	// first group must not survive.
	short := 4
	*pubs[3] = [32]byte{1}
	batch.Prepare(DalekStrict, pubs[:short], msgs[:short], sigs[:short])

	if batch.Len() != short {
		t.Fatalf("Len=%d want %d", batch.Len(), short)
	}
	if batch.Live(3) {
		t.Fatal("item 3 must be dead in the second group")
	}
	if *batch.At(3) == first {
		t.Fatal("stale prepared value from the previous group survived Reset")
	}
	if *batch.At(3) != (Prepared{}) {
		t.Fatal("rejected item must be zeroed")
	}
}

// Worker-local scratch is the whole point of the type: after the first group of
// a given size, a hot loop must not allocate. If this regresses, deep chunking
// trades one allocation per signature for the batching it was meant to buy.
func TestBatchAllocatesNothingAfterWarmup(t *testing.T) {
	const n = 64
	rng := rand.New(rand.NewSource(13))
	pubs, msgs, sigs := buildInputs(t, rng, n)

	var batch Batch
	batch.Prepare(DalekStrict, pubs, msgs, sigs)

	if allocations := testing.AllocsPerRun(20, func() {
		batch.Prepare(DalekStrict, pubs, msgs, sigs)
	}); allocations != 0 {
		t.Fatalf("allocations = %v, want 0", allocations)
	}
}

// The reduced challenge must be the same value whether it came from the batch
// or from the one-shot Reduce, since a batch former and a singleton path can
// both feed the same equation.
func TestBatchReduceMatchesOneShot(t *testing.T) {
	const n = 12
	rng := rand.New(rand.NewSource(21))
	pubs, msgs, sigs := buildInputs(t, rng, n)

	var batch Batch
	batch.Prepare(StdlibCompat, pubs, msgs, sigs)
	for i := 0; i < n; i++ {
		digest := Challenge(pubs[i], msgs[i], sigs[i])
		want := Reduce(&digest)
		if !bytes.Equal(batch.At(i).K[:], want[:]) {
			t.Fatalf("item %d: batch K %x != one-shot %x", i, batch.At(i).K, want)
		}
	}
}

func BenchmarkBatchPrepare(b *testing.B) {
	for _, n := range []int{1, 8, 64, 512} {
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			rng := rand.New(rand.NewSource(int64(n)))
			pubs, msgs, sigs := buildInputs(b, rng, n)
			var batch Batch
			batch.Prepare(DalekStrict, pubs, msgs, sigs)

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				batch.Prepare(DalekStrict, pubs, msgs, sigs)
			}
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*n), "ns/sig")
		})
	}
}
