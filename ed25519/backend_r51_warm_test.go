package ed25519

import (
	"fmt"
	"testing"
	"unsafe"

	"github.com/Overclock-Validator/narya/internal/cpufeat"
	"github.com/Overclock-Validator/narya/internal/r51x5"
)

func buildR51WarmGroupForTest(
	tb testing.TB,
	backend *r51Backend,
	pubs []*[32]byte,
) [r51x5.X4Lanes]*PrecomputedKey {
	tb.Helper()
	if len(pubs) != r51x5.X4Lanes {
		tb.Fatalf("warm test group width=%d", len(pubs))
	}
	var pubGroup [r51x5.X4Lanes]*[32]byte
	var decoded [r51x5.X4Lanes]*PrecomputedKey
	for lane := 0; lane < r51x5.X4Lanes; lane++ {
		pubGroup[lane] = pubs[lane]
		pre, err := backend.buildPrecomp(pubs[lane])
		if err != nil {
			tb.Fatal(err)
		}
		decoded[lane] = pre
	}
	warm, err := backend.buildWarmPrecompGroup(&pubGroup, &decoded)
	if err != nil {
		tb.Fatal(err)
	}
	return warm
}

func TestR51WarmPrecomputeShapeAndStrictDifferential(t *testing.T) {
	backend := requireR51Backend(t)
	if got, want := int64(unsafe.Sizeof(r51WarmTable{})), int64(r51WarmTableBytes); got != want {
		t.Fatalf("r51 warm table bytes=%d accounting=%d", got, want)
	}
	fixture := makeBatchFixture(t, 8, 1232)
	first := buildR51WarmGroupForTest(t, backend, fixture.pubs[:4])
	var pre [8]*PrecomputedKey
	copy(pre[:4], first[:])
	for lane := 4; lane < len(pre); lane++ {
		decoded, err := backend.buildPrecomp(fixture.pubs[lane])
		if err != nil {
			t.Fatal(err)
		}
		pre[lane] = decoded
	}

	verdicts := make([]bool, len(fixture.pubs))
	all, err := backend.verifyBatchRawPrecomputedErr(
		DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, verdicts, pre[:],
	)
	if err != nil {
		t.Fatal(err)
	}
	if !all {
		t.Fatalf("mixed warm/decoded verdicts=%v", verdicts)
	}
	for lane := range pre[:4] {
		if pre[lane].size != r51WarmTableBytes || pre[lane].raw != *fixture.pubs[lane] {
			t.Fatalf("lane=%d warm metadata size=%d raw=%x", lane, pre[lane].size, pre[lane].raw)
		}
		if _, ok := pre[lane].table.(*r51WarmTable); !ok {
			t.Fatalf("lane=%d warm table type %T", lane, pre[lane].table)
		}
	}

	mutated := append([][]byte(nil), fixture.sigs...)
	mutated[2] = append([]byte(nil), mutated[2]...)
	mutated[2][11] ^= 0x40
	all, err = backend.verifyBatchRawPrecomputedErr(
		DalekStrict, fixture.pubs, fixture.msgs, mutated, verdicts, pre[:],
	)
	if err != nil {
		t.Fatal(err)
	}
	if all {
		t.Fatal("warm group accepted an invalid equation")
	}
	for lane := range verdicts {
		want := referenceVerifyProfile(DalekStrict, fixture.pubs[lane], fixture.msgs[lane], mutated[lane])
		if verdicts[lane] != want {
			t.Fatalf("lane=%d got=%v want=%v", lane, verdicts[lane], want)
		}
	}
}

func TestR51WarmPrecomputedGroupZeroAllocations(t *testing.T) {
	backend := requireR51Backend(t)
	fixture := makeBatchFixture(t, r51x5.X4Lanes, 1232)
	pre := buildR51WarmGroupForTest(t, backend, fixture.pubs)
	verdicts := make([]bool, r51x5.X4Lanes)
	if all, err := backend.verifyBatchRawPrecomputedErr(
		DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, verdicts, pre[:],
	); err != nil || !all {
		t.Fatalf("warmup all=%v err=%v verdicts=%v", all, err, verdicts)
	}
	allocations := testing.AllocsPerRun(100, func() {
		all, err := backend.verifyBatchRawPrecomputedErr(
			DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, verdicts, pre[:],
		)
		if err != nil || !all {
			panic("r51 warm group verification failed")
		}
	})
	if allocations != 0 {
		t.Fatalf("r51 warm group allocations=%v want=0", allocations)
	}
}

func TestR51WarmDispatchPreservesNativeWidth(t *testing.T) {
	backend := requireR51Backend(t)
	fixture := makeBatchFixture(t, 8, 200)
	first := buildR51WarmGroupForTest(t, backend, fixture.pubs[:4])
	second := buildR51WarmGroupForTest(t, backend, fixture.pubs[4:])
	var pre [8]*PrecomputedKey
	copy(pre[:4], first[:])
	if got := r51WarmDispatchWidth(fixture.pubs, pre[:], 0, 8); cpufeat.PreferWideIFMA() && got != 0 {
		t.Fatalf("native-wide half-warm dispatch width=%d want=0", got)
	} else if !cpufeat.PreferWideIFMA() && got != r51x5.X4Lanes {
		t.Fatalf("x4 half-warm dispatch width=%d want=%d", got, r51x5.X4Lanes)
	}
	copy(pre[4:], second[:])
	if got := r51WarmDispatchWidth(fixture.pubs, pre[:], 0, 8); cpufeat.PreferWideIFMA() && got != r51x5.X8Lanes {
		t.Fatalf("native-wide full-warm dispatch width=%d want=%d", got, r51x5.X8Lanes)
	} else if !cpufeat.PreferWideIFMA() && got != r51x5.X4Lanes {
		t.Fatalf("x4 full-warm dispatch width=%d want=%d", got, r51x5.X4Lanes)
	}
	if got := r51WarmDispatchWidth(fixture.pubs[:4], pre[:4], 0, 4); got != r51x5.X4Lanes {
		t.Fatalf("final warm tail dispatch width=%d want=%d", got, r51x5.X4Lanes)
	}
}

func TestR51CachePromotesOnlyValidStrictHits(t *testing.T) {
	backend := requireR51Backend(t)
	fixture := makeBatchFixture(t, r51x5.X4Lanes, 1232)
	cache := &Cache{MaxTableBytes: r51x5.X4Lanes * r51WarmTableBytes}
	for _, pub := range fixture.pubs {
		admitR51DecodedATestEntry(t, cache, backend, pub)
	}

	badMessages := append([][]byte(nil), fixture.msgs...)
	for lane := range badMessages {
		badMessages[lane] = append([]byte(nil), badMessages[lane]...)
		badMessages[lane][0] ^= 0x80
	}
	for attempt := int32(0); attempt < backend.promotionThreshold(); attempt++ {
		if cache.verifyBatchWithBackend(backend, DalekStrict, fixture.pubs, badMessages, fixture.sigs, fixture.ok) {
			t.Fatalf("invalid equations accepted at attempt %d", attempt)
		}
	}
	if got := cache.Stats().PromotedTables; got != 0 {
		t.Fatalf("invalid equations promoted %d tables", got)
	}

	for hit := int32(0); hit < backend.promotionThreshold(); hit++ {
		if !cache.verifyBatchWithBackend(backend, DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok) {
			t.Fatalf("valid promotion hit %d rejected", hit)
		}
	}
	stats := cache.Stats()
	if stats.Tables != r51x5.X4Lanes || stats.PromotedTables != r51x5.X4Lanes || stats.TableBytes != r51x5.X4Lanes*r51WarmTableBytes {
		t.Fatalf("warm promotion stats=%+v", stats)
	}
	if faults := backend.backendStats().InternalFaultFallbacks; faults != 0 {
		t.Fatalf("warm promotion native faults=%d", faults)
	}

	if !cache.verifyBatchWithBackend(backend, DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok) {
		t.Fatal("promoted warm group rejected valid batch")
	}
	allocations := testing.AllocsPerRun(100, func() {
		if !cache.verifyBatchWithBackend(backend, DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok) {
			panic("promoted r51 Cache group rejected valid batch")
		}
	})
	if allocations != 0 {
		t.Fatalf("promoted r51 Cache allocations=%v want=0", allocations)
	}
}

func BenchmarkR51WarmPrecomputedGroup(b *testing.B) {
	backend := requireR51Backend(b)
	for _, messageSize := range []int{64, 200, 1232} {
		fixture := makeBatchFixture(b, r51x5.X4Lanes, messageSize)
		pre := buildR51WarmGroupForTest(b, backend, fixture.pubs)
		b.Run(fmt.Sprintf("n=4/msg=%d", messageSize), func(b *testing.B) {
			if all, err := backend.verifyBatchRawPrecomputedErr(
				DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok, pre[:],
			); err != nil || !all {
				b.Fatalf("warmup all=%v err=%v", all, err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				all, err := backend.verifyBatchRawPrecomputedErr(
					DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok, pre[:],
				)
				if err != nil || !all {
					b.Fatalf("verify all=%v err=%v", all, err)
				}
			}
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*r51x5.X4Lanes)/1000, "us/sig")
		})
	}
}

func BenchmarkR51WarmCacheGroup(b *testing.B) {
	backend := requireR51Backend(b)
	for _, messageSize := range []int{64, 200, 1232} {
		fixture := makeBatchFixture(b, r51x5.X4Lanes, messageSize)
		cache := &Cache{MaxTableBytes: r51x5.X4Lanes * r51WarmTableBytes}
		for _, pub := range fixture.pubs {
			admitR51DecodedATestEntry(b, cache, backend, pub)
		}
		for hit := int32(0); hit < backend.promotionThreshold(); hit++ {
			if !cache.verifyBatchWithBackend(backend, DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok) {
				b.Fatal("promotion warmup rejected valid batch")
			}
		}
		if got := cache.Stats().PromotedTables; got != r51x5.X4Lanes {
			b.Fatalf("promoted tables=%d want=%d", got, r51x5.X4Lanes)
		}
		b.Run(fmt.Sprintf("n=4/msg=%d", messageSize), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				if !cache.verifyBatchWithBackend(backend, DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok) {
					b.Fatal("warm Cache verification rejected valid batch")
				}
			}
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*r51x5.X4Lanes)/1000, "us/sig")
		})
	}
}

func prepareR51CacheTierBenchmark(
	b *testing.B,
	backend *r51Backend,
	fixture *batchFixture,
	warmGroups int,
) *Cache {
	b.Helper()
	cache := &Cache{MaxTableBytes: int64(len(fixture.pubs)) * r51WarmTableBytes}
	for _, pub := range fixture.pubs {
		admitR51DecodedATestEntry(b, cache, backend, pub)
	}
	for group := 0; group < warmGroups; group++ {
		start := group * r51x5.X4Lanes
		end := start + r51x5.X4Lanes
		for hit := int32(0); hit < backend.promotionThreshold(); hit++ {
			if !cache.verifyBatchWithBackend(
				backend,
				DalekStrict,
				fixture.pubs[start:end],
				fixture.msgs[start:end],
				fixture.sigs[start:end],
				fixture.ok[start:end],
			) {
				b.Fatal("warm-tier promotion rejected valid group")
			}
		}
	}
	// Keep the timed hit density stable. Candidate keys that the setup did not
	// promote remain immutable decoded entries and cannot cross a threshold
	// during b.N.
	for index := warmGroups * r51x5.X4Lanes; index < len(fixture.pubs); index++ {
		value, _ := cache.promotions.LoadOrStore(*fixture.pubs[index], new(promotionState))
		value.(*promotionState).status.Store(promotionDisabled)
	}
	if got := cache.Stats().PromotedTables; got != int64(warmGroups*r51x5.X4Lanes) {
		b.Fatalf("warm-tier setup promoted=%d want=%d", got, warmGroups*r51x5.X4Lanes)
	}
	return cache
}

// BenchmarkR51CacheTierMatrix compares the stable production paths: no Cache,
// first-tier decoded/staging entries, and homogeneous warm x4 groups. Warm
// percentages count complete groups rather than scattered individual hits,
// because a partial group deliberately remains on the cold/decoded path.
func BenchmarkR51CacheTierMatrix(b *testing.B) {
	backend := requireR51Backend(b)
	for _, messageSize := range []int{64, 200, 1232} {
		for _, count := range []int{4, 8, 64} {
			fixture := makeBatchFixture(b, count, messageSize)
			b.Run(fmt.Sprintf("tier=cold/warm=0/n=%d/msg=%d", count, messageSize), func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()
				for iteration := 0; iteration < b.N; iteration++ {
					if !backend.verifyBatchRaw(DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok) {
						b.Fatal("cold verification rejected valid batch")
					}
				}
				b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*count)/1000, "us/sig")
			})

			percentages := []int{0, 100}
			if count == 8 {
				percentages = []int{0, 50, 100}
			} else if count == 64 {
				percentages = []int{0, 25, 50, 75, 100}
			}
			for _, percent := range percentages {
				warmGroups := (count / r51x5.X4Lanes) * percent / 100
				cache := prepareR51CacheTierBenchmark(b, backend, &fixture, warmGroups)
				b.Run(fmt.Sprintf("tier=cache/warm=%d/n=%d/msg=%d", percent, count, messageSize), func(b *testing.B) {
					b.ReportAllocs()
					b.ResetTimer()
					for iteration := 0; iteration < b.N; iteration++ {
						if !cache.verifyBatchWithBackend(backend, DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok) {
							b.Fatal("cache-tier verification rejected valid batch")
						}
					}
					stats := cache.Stats()
					b.ReportMetric(float64(stats.PromotedTables), "warm-tables")
					b.ReportMetric(float64(stats.TableBytes), "table-bytes")
					b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*count)/1000, "us/sig")
				})
			}
		}
	}
}
