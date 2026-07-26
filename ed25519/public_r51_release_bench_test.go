//go:build r51_release_bench

package ed25519_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	narya "github.com/Overclock-Validator/narya-ed25519/ed25519"
)

var publicR51ReleaseSink bool

type publicR51Fixture struct {
	pubs []*[ed25519.PublicKeySize]byte
	msgs [][]byte
	sigs [][]byte
}

func newPublicR51Fixture(tb testing.TB, count, messageSize int) publicR51Fixture {
	tb.Helper()

	fixture := publicR51Fixture{
		pubs: make([]*[ed25519.PublicKeySize]byte, count),
		msgs: make([][]byte, count),
		sigs: make([][]byte, count),
	}
	for i := range count {
		pub, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			tb.Fatalf("GenerateKey(%d): %v", i, err)
		}
		publicKey := new([ed25519.PublicKeySize]byte)
		copy(publicKey[:], pub)
		message := make([]byte, messageSize)
		if _, err := rand.Read(message); err != nil {
			tb.Fatalf("rand.Read message %d: %v", i, err)
		}
		// Keep otherwise-identical fixture construction from accidentally
		// producing the same message in multiple lanes.
		message[0] ^= byte(i)

		fixture.pubs[i] = publicKey
		fixture.msgs[i] = message
		fixture.sigs[i] = ed25519.Sign(privateKey, message)
	}
	return fixture
}

func forcePublicR51(tb testing.TB) {
	tb.Helper()
	if err := narya.SetBackend("r51"); err != nil {
		tb.Skipf("forced r51 backend unavailable: %v", err)
	}
	if got := narya.ActiveBackend(); got != "r51" {
		tb.Fatalf("ActiveBackend() = %q, want r51", got)
	}
}

func assertPublicR51Verdicts(tb testing.TB, ok []bool, invalid int) {
	tb.Helper()
	for i, got := range ok {
		want := i != invalid
		if got != want {
			tb.Fatalf("verdict[%d] = %v, want %v", i, got, want)
		}
	}
}

func assertNoPublicR51FaultFallbacks(tb testing.TB) {
	tb.Helper()
	if faults := narya.ActiveBackendStats().InternalFaultFallbacks; faults != 0 {
		tb.Fatalf("r51 internal fault fallbacks = %d, want zero", faults)
	}
}

// BenchmarkPublicR51VerifyBatchStrict is the PR 1 release benchmark. Unlike
// the diagnostic benchmarks in package ed25519, this external-package
// benchmark can reach the implementation only through the exported API.
// Run it in a fresh process because backend selection is process-global:
//
//	GOMAXPROCS=1 go test -tags r51_release_bench -run '^$' \
//	  -bench '^BenchmarkPublicR51VerifyBatchStrict$' -benchmem \
//	  -benchtime=3s -count=10 ./ed25519
func BenchmarkPublicR51VerifyBatchStrict(b *testing.B) {
	forcePublicR51(b)

	for _, messageSize := range []int{200, 1232, 4096} {
		fixture := newPublicR51Fixture(b, 64, messageSize)
		for _, count := range []int{1, 2, 4, 8, 64} {
			b.Run(fmt.Sprintf("msg=%d/n=%d", messageSize, count), func(b *testing.B) {
				pubs := fixture.pubs[:count]
				msgs := fixture.msgs[:count]
				sigs := fixture.sigs[:count]
				ok := make([]bool, count)

				if all := narya.VerifyBatchStrict(pubs, msgs, sigs, ok); !all {
					b.Fatal("valid fixture rejected before timing")
				}
				assertPublicR51Verdicts(b, ok, -1)
				assertNoPublicR51FaultFallbacks(b)

				b.ReportAllocs()
				b.SetBytes(int64(messageSize * count))
				b.ResetTimer()
				for range b.N {
					publicR51ReleaseSink = narya.VerifyBatchStrict(pubs, msgs, sigs, ok)
				}
				b.StopTimer()

				if !publicR51ReleaseSink {
					b.Fatal("valid fixture rejected during timing")
				}
				assertPublicR51Verdicts(b, ok, -1)
				assertNoPublicR51FaultFallbacks(b)
				b.ReportMetric(0, "internal-fault-fallbacks")
				b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*count)/1e3, "us/signature")
				b.ReportMetric(float64(b.N*count)/b.Elapsed().Seconds(), "signatures/s")
			})
		}
	}
}

// BenchmarkPublicR51SingletonEntryPoints compares the two exported ways to
// verify exactly one strict signature. It builds one fixture before either
// timer starts, avoiding BenchmarkPublicR51VerifyBatchStrict's intentionally
// wider fixture matrix when diagnosing singleton wrapper overhead.
func BenchmarkPublicR51SingletonEntryPoints(b *testing.B) {
	forcePublicR51(b)
	for _, messageSize := range []int{200, 1232, 4096} {
		fixture := newPublicR51Fixture(b, 1, messageSize)
		pub := fixture.pubs[0]
		msg := fixture.msgs[0]
		sig := fixture.sigs[0]
		ok := make([]bool, 1)

		b.Run(fmt.Sprintf("msg=%d/VerifyStrict", messageSize), func(b *testing.B) {
			if !narya.VerifyStrict(pub[:], msg, sig) {
				b.Fatal("valid fixture rejected before timing")
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				publicR51ReleaseSink = narya.VerifyStrict(pub[:], msg, sig)
			}
			b.StopTimer()
			if !publicR51ReleaseSink {
				b.Fatal("valid fixture rejected during timing")
			}
			assertNoPublicR51FaultFallbacks(b)
		})

		b.Run(fmt.Sprintf("msg=%d/VerifyBatchStrict-n=1", messageSize), func(b *testing.B) {
			if !narya.VerifyBatchStrict(fixture.pubs, fixture.msgs, fixture.sigs, ok) {
				b.Fatal("valid fixture rejected before timing")
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				publicR51ReleaseSink = narya.VerifyBatchStrict(fixture.pubs, fixture.msgs, fixture.sigs, ok)
			}
			b.StopTimer()
			if !publicR51ReleaseSink || !ok[0] {
				b.Fatal("valid fixture rejected during timing")
			}
			assertNoPublicR51FaultFallbacks(b)
		})
	}
}

func preparePublicR51WarmCache(tb testing.TB, fixture *publicR51Fixture) *narya.Cache {
	tb.Helper()

	// The release fixture contains 64 distinct keys. Four MiB is comfortably
	// above their complete promoted-table payload while remaining small enough
	// to catch an accidental table-size explosion.
	cache := &narya.Cache{MaxTableBytes: 4 << 20}
	ok := make([]bool, len(fixture.pubs))
	for attempt := 0; attempt < 64; attempt++ {
		if all := cache.VerifyBatchStrict(fixture.pubs, fixture.msgs, fixture.sigs, ok); !all {
			tb.Fatalf("warm-cache setup rejected a valid fixture at attempt %d", attempt)
		}
		assertPublicR51Verdicts(tb, ok, -1)
		if stats := cache.Stats(); stats.PromotedTables == int64(len(fixture.pubs)) {
			return cache
		}
	}
	stats := cache.Stats()
	tb.Fatalf(
		"warm-cache setup promoted %d/%d tables after 64 attempts (tables=%d bytes=%d)",
		stats.PromotedTables,
		len(fixture.pubs),
		stats.Tables,
		stats.TableBytes,
	)
	return nil
}

// BenchmarkPublicR51CacheVerifyBatchStrict is the public warm-key companion
// to BenchmarkPublicR51VerifyBatchStrict. Setup promotes all 64 distinct keys
// before any sub-benchmark timer starts; each width then measures an honestly
// populated Cache call rather than a private prepared-table seam.
func BenchmarkPublicR51CacheVerifyBatchStrict(b *testing.B) {
	forcePublicR51(b)

	for _, messageSize := range []int{200, 1232, 4096} {
		fixture := newPublicR51Fixture(b, 64, messageSize)
		cache := preparePublicR51WarmCache(b, &fixture)
		for _, count := range []int{1, 2, 4, 8, 64} {
			b.Run(fmt.Sprintf("msg=%d/n=%d", messageSize, count), func(b *testing.B) {
				pubs := fixture.pubs[:count]
				msgs := fixture.msgs[:count]
				sigs := fixture.sigs[:count]
				ok := make([]bool, count)

				if all := cache.VerifyBatchStrict(pubs, msgs, sigs, ok); !all {
					b.Fatal("valid warm fixture rejected before timing")
				}
				assertPublicR51Verdicts(b, ok, -1)
				assertNoPublicR51FaultFallbacks(b)

				b.ReportAllocs()
				b.SetBytes(int64(messageSize * count))
				b.ResetTimer()
				for range b.N {
					publicR51ReleaseSink = cache.VerifyBatchStrict(pubs, msgs, sigs, ok)
				}
				b.StopTimer()

				if !publicR51ReleaseSink {
					b.Fatal("valid warm fixture rejected during timing")
				}
				assertPublicR51Verdicts(b, ok, -1)
				assertNoPublicR51FaultFallbacks(b)
				stats := cache.Stats()
				b.ReportMetric(0, "internal-fault-fallbacks")
				b.ReportMetric(float64(stats.PromotedTables), "warm-tables")
				b.ReportMetric(float64(stats.TableBytes), "table-bytes")
				b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*count)/1e3, "us/signature")
				b.ReportMetric(float64(b.N*count)/b.Elapsed().Seconds(), "signatures/s")
			})
		}
	}
}

func primePublicR51Parallel(tb testing.TB, fixture *publicR51Fixture, count int) {
	tb.Helper()

	workers := runtime.GOMAXPROCS(0)
	start := make(chan struct{})
	var wait sync.WaitGroup
	var failed atomic.Bool
	wait.Add(workers)
	for range workers {
		go func() {
			defer wait.Done()
			var ok [8]bool
			<-start
			if !narya.VerifyBatchStrict(
				fixture.pubs[:count],
				fixture.msgs[:count],
				fixture.sigs[:count],
				ok[:count],
			) {
				failed.Store(true)
			}
		}()
	}
	close(start)
	wait.Wait()
	if failed.Load() {
		tb.Fatal("parallel pool priming rejected a valid fixture")
	}
	assertNoPublicR51FaultFallbacks(tb)
}

// BenchmarkPublicR51VerifyBatchStrictParallel measures concurrent callers of
// the exported cold API. Each benchmark operation verifies one independent
// batch; RunParallel distributes those operations across GOMAXPROCS workers.
// The backend pools are primed concurrently before timing so this measures
// steady-state scaling rather than worker construction.
func BenchmarkPublicR51VerifyBatchStrictParallel(b *testing.B) {
	forcePublicR51(b)

	const messageSize = 1232
	fixture := newPublicR51Fixture(b, 8, messageSize)
	for _, count := range []int{4, 8} {
		b.Run(fmt.Sprintf("msg=%d/n=%d", messageSize, count), func(b *testing.B) {
			primePublicR51Parallel(b, &fixture, count)
			pubs := fixture.pubs[:count]
			msgs := fixture.msgs[:count]
			sigs := fixture.sigs[:count]

			var failed atomic.Bool
			b.ReportAllocs()
			b.SetBytes(int64(messageSize * count))
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				var ok [8]bool
				for pb.Next() {
					if !narya.VerifyBatchStrict(pubs, msgs, sigs, ok[:count]) {
						failed.Store(true)
					}
				}
			})
			b.StopTimer()

			if failed.Load() {
				b.Fatal("parallel verification rejected a valid fixture")
			}
			assertNoPublicR51FaultFallbacks(b)
			b.ReportMetric(0, "internal-fault-fallbacks")
			b.ReportMetric(float64(runtime.GOMAXPROCS(0)), "GOMAXPROCS")
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*count)/1e3, "us/signature")
			b.ReportMetric(float64(b.N*count)/b.Elapsed().Seconds(), "signatures/s")
		})
	}
}

// BenchmarkPublicR51VerifyBatchStrictInvalid records the two important
// fail-closed shapes separately: a canonical-scalar precheck failure in lane
// zero, and a full late equation failure in the final lane. It still invokes
// only the exported strict batch API.
func BenchmarkPublicR51VerifyBatchStrictInvalid(b *testing.B) {
	forcePublicR51(b)

	const messageSize = 200
	for _, count := range []int{1, 8, 64} {
		fixture := newPublicR51Fixture(b, count, messageSize)

		b.Run(fmt.Sprintf("kind=noncanonical-S-first/n=%d", count), func(b *testing.B) {
			sigs := append([][]byte(nil), fixture.sigs...)
			sigs[0] = append([]byte(nil), sigs[0]...)
			copy(sigs[0][32:], []byte{
				0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
				0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
			})
			ok := make([]bool, count)
			if all := narya.VerifyBatchStrict(fixture.pubs, fixture.msgs, sigs, ok); all {
				b.Fatal("noncanonical S accepted before timing")
			}
			assertPublicR51Verdicts(b, ok, 0)

			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				publicR51ReleaseSink = narya.VerifyBatchStrict(fixture.pubs, fixture.msgs, sigs, ok)
			}
			b.StopTimer()
			if publicR51ReleaseSink {
				b.Fatal("noncanonical S accepted during timing")
			}
			assertPublicR51Verdicts(b, ok, 0)
			assertNoPublicR51FaultFallbacks(b)
			b.ReportMetric(0, "internal-fault-fallbacks")
		})

		b.Run(fmt.Sprintf("kind=bad-message-last/n=%d", count), func(b *testing.B) {
			msgs := append([][]byte(nil), fixture.msgs...)
			msgs[count-1] = append([]byte(nil), msgs[count-1]...)
			msgs[count-1][0] ^= 1
			ok := make([]bool, count)
			if all := narya.VerifyBatchStrict(fixture.pubs, msgs, fixture.sigs, ok); all {
				b.Fatal("bad message accepted before timing")
			}
			assertPublicR51Verdicts(b, ok, count-1)

			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				publicR51ReleaseSink = narya.VerifyBatchStrict(fixture.pubs, msgs, fixture.sigs, ok)
			}
			b.StopTimer()
			if publicR51ReleaseSink {
				b.Fatal("bad message accepted during timing")
			}
			assertPublicR51Verdicts(b, ok, count-1)
			assertNoPublicR51FaultFallbacks(b)
			b.ReportMetric(0, "internal-fault-fallbacks")
		})
	}
}
