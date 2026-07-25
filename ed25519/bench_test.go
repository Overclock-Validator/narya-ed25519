package ed25519

import (
	stded25519 "crypto/ed25519"
	"crypto/rand"
	"fmt"
	"testing"
)

// Benchmark harness. Every implementation runs the same honest inputs so
// results are directly comparable in one `go test -bench` run:
//
//	stdlib        crypto/ed25519.Verify — the baseline Mithril used
//	narya-compat  narya StdlibCompat — same predicate as stdlib, our arithmetic
//	narya-strict  narya DalekStrict (mainnet semantics) — adds the small-order
//	              pre-pass, so (strict - compat) is the cost of that pre-pass
//	narya-cached  narya through a warm Cache (per-key comb table)
//
// Message sizes span a tiny signature up to the Solana packet cap (~1232B),
// so the hashing fraction (which the experimental sha512mb kernels target) is
// visible: hashing grows with message size, point math does not. Keep the
// original 64/200/1232 release-gate sizes while also covering the 176-byte,
// 512-byte, and 1024-byte regimes used by throughput-oriented workloads.
var benchMsgSizes = []int{64, 176, 200, 512, 1024, 1232}

// The dense 1..17 sweep exposes x8 lane-fill and boundary effects around
// 8/9 and 16/17. The larger sizes keep the throughput regimes visible.
var benchBatchSizes = []int{
	1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
	32, 64,
}

type sigFixture struct {
	pubk stded25519.PublicKey
	pub  [32]byte
	msg  []byte
	sig  []byte
}

func makeFixture(tb testing.TB, msgSize int) sigFixture {
	tb.Helper()
	pubk, priv, err := stded25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	msg := make([]byte, msgSize)
	if _, err := rand.Read(msg); err != nil {
		tb.Fatal(err)
	}
	var f sigFixture
	f.pubk = pubk
	copy(f.pub[:], pubk)
	f.msg = msg
	f.sig = stded25519.Sign(priv, msg)
	return f
}

func makeFixtures(tb testing.TB, n, msgSize int) []sigFixture {
	fs := make([]sigFixture, n)
	for i := range fs {
		fs[i] = makeFixture(tb, msgSize)
	}
	return fs
}

type batchFixture struct {
	fs   []sigFixture
	pubs []*[32]byte
	msgs [][]byte
	sigs [][]byte
	ok   []bool
}

func makeBatchFixture(tb testing.TB, n, msgSize int) batchFixture {
	tb.Helper()
	bf := batchFixture{
		fs:   makeFixtures(tb, n, msgSize),
		pubs: make([]*[32]byte, n),
		msgs: make([][]byte, n),
		sigs: make([][]byte, n),
		ok:   make([]bool, n),
	}
	for i := range bf.fs {
		bf.pubs[i] = &bf.fs[i].pub
		bf.msgs[i] = bf.fs[i].msg
		bf.sigs[i] = bf.fs[i].sig
	}
	return bf
}

// makeRatioMix builds independent batches whose complete phase cycle has an
// exact numerator/denominator marked ratio, even when n is smaller than the
// denominator. Independent batches let cache-mix benchmarks preload a key in
// one phase without turning the same key into a hit in another phase.
func makeRatioMix(tb testing.TB, n, msgSize, numerator, denominator int, mark func(*batchFixture, int)) []batchFixture {
	tb.Helper()
	if denominator <= 0 || numerator < 0 || numerator > denominator {
		tb.Fatalf("invalid benchmark ratio %d/%d", numerator, denominator)
	}
	batches := make([]batchFixture, denominator)
	for phase := range batches {
		batches[phase] = makeBatchFixture(tb, n, msgSize)
		for lane := 0; lane < n; lane++ {
			if (phase*n+lane)%denominator < numerator {
				mark(&batches[phase], lane)
			}
		}
	}
	return batches
}

func makeQuarterMix(tb testing.TB, n, msgSize, quarter int, mark func(*batchFixture, int)) []batchFixture {
	tb.Helper()
	return makeRatioMix(tb, n, msgSize, quarter, 4, mark)
}

// BenchmarkVerify is the headline single-signature comparison:
// implementation x message size.
func BenchmarkVerify(b *testing.B) {
	for _, sz := range benchMsgSizes {
		f := makeFixture(b, sz)

		b.Run(fmt.Sprintf("impl=stdlib/msg=%d", sz), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if !stded25519.Verify(f.pubk, f.msg, f.sig) {
					b.Fatal("verify failed")
				}
			}
		})

		b.Run(fmt.Sprintf("impl=narya-compat/msg=%d", sz), func(b *testing.B) {
			withProfile(StdlibCompat, func() {
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if !Verify(&f.pub, f.msg, f.sig) {
						b.Fatal("verify failed")
					}
				}
			})
		})

		b.Run(fmt.Sprintf("impl=narya-strict/msg=%d", sz), func(b *testing.B) {
			withProfile(DalekStrict, func() {
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if !Verify(&f.pub, f.msg, f.sig) {
						b.Fatal("verify failed")
					}
				}
			})
		})

		b.Run(fmt.Sprintf("impl=narya-cached/msg=%d", sz), func(b *testing.B) {
			c := &Cache{}
			for j := 0; j < buildThreshold; j++ { // warm the table
				c.Verify(&f.pub, f.msg, f.sig)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if !c.Verify(&f.pub, f.msg, f.sig) {
					b.Fatal("verify failed")
				}
			}
		})
	}
}

// BenchmarkVerifyBatch compares a loop of stdlib verifies against narya's
// batch pipeline (cold keys — fresh signer per item, the miss-dominated
// arbitrary-key regime). Reported as µs per signature so batch sizes are
// directly comparable.
func BenchmarkVerifyBatch(b *testing.B) {
	for _, sz := range benchMsgSizes {
		for _, n := range benchBatchSizes {
			bf := makeBatchFixture(b, n, sz)

			b.Run(fmt.Sprintf("impl=stdlib-loop/n=%d/msg=%d", n, sz), func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					for j := range bf.fs {
						if !stded25519.Verify(bf.fs[j].pubk, bf.fs[j].msg, bf.fs[j].sig) {
							b.Fatal("verify failed")
						}
					}
				}
				b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*n)/1000, "µs/sig")
			})

			b.Run(fmt.Sprintf("impl=narya-batch/n=%d/msg=%d", n, sz), func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					if !VerifyBatch(bf.pubs, bf.msgs, bf.sigs, bf.ok) {
						b.Fatal("verify failed")
					}
				}
				b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*n)/1000, "µs/sig")
			})
		}
	}
}

// BenchmarkVerifyBatchCacheMix measures stable table-hit ratios. Four phases
// make the quarter ratios exact and ten phases make 10/90 exact, including at
// n=1. Miss keys cannot cross the admission threshold, so a long benchmark
// does not silently become a 100%-hit run.
func BenchmarkVerifyBatchCacheMix(b *testing.B) {
	for _, msgSize := range benchMsgSizes {
		for _, n := range benchBatchSizes {
			for _, hitPct := range []int{0, 10, 25, 50, 75, 90, 100} {
				c := &Cache{MaxTableBytes: 1}
				c.bytes.Store(1) // keep designated misses from earning tables
				numerator, denominator := hitPct/25, 4
				if hitPct%25 != 0 {
					numerator, denominator = hitPct/10, 10
				}
				batches := makeRatioMix(b, n, msgSize, numerator, denominator, func(bf *batchFixture, lane int) {
					pre, err := Precompute(bf.pubs[lane])
					if err != nil {
						b.Fatal(err)
					}
					c.tables.Store(*bf.pubs[lane], pre)
				})

				b.Run(fmt.Sprintf("impl=narya-cache/n=%d/msg=%d/hits=%d", n, msgSize, hitPct), func(b *testing.B) {
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						for phase := range batches {
							bf := &batches[phase]
							if !c.VerifyBatch(bf.pubs, bf.msgs, bf.sigs, bf.ok) {
								b.Fatal("verify failed")
							}
						}
					}
					b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*len(batches)*n)/1000, "µs/sig")
				})
			}
		}
	}
}

// BenchmarkVerifyBatchValidity varies the fraction of invalid signatures.
// Invalid items cycle through a non-canonical S, a wrong-length signature,
// a strict small-order-key rejection and a bad-message equation failure, so
// the benchmark covers both early exits and full arithmetic rejections.
func BenchmarkVerifyBatchValidity(b *testing.B) {
	for _, msgSize := range benchMsgSizes {
		for _, n := range benchBatchSizes {
			for _, invalidPct := range []int{0, 25, 50, 75, 100} {
				invalidOrdinal := 0
				batches := makeQuarterMix(b, n, msgSize, invalidPct/25, func(bf *batchFixture, lane int) {
					switch invalidOrdinal & 3 {
					case 0: // scalar precheck
						sig := append([]byte(nil), bf.sigs[lane]...)
						sig[63] |= 0xe0
						bf.sigs[lane] = sig
					case 1: // length precheck
						bf.sigs[lane] = append([]byte(nil), bf.sigs[lane][:63]...)
					case 2: // strict profile precheck
						bf.pubs[lane] = new([32]byte)
						bf.pubs[lane][0] = 1 // identity encoding
					case 3: // reaches the verification equation
						msg := append([]byte(nil), bf.msgs[lane]...)
						msg[0] ^= 1
						bf.msgs[lane] = msg
					}
					invalidOrdinal++
				})
				for phase := range batches {
					VerifyBatch(batches[phase].pubs, batches[phase].msgs, batches[phase].sigs, batches[phase].ok)
					for lane := range batches[phase].ok {
						want := referenceVerify(batches[phase].pubs[lane], batches[phase].msgs[lane], batches[phase].sigs[lane])
						if batches[phase].ok[lane] != want {
							b.Fatalf("invalid-mix setup mismatch: phase=%d lane=%d got=%v want=%v", phase, lane, batches[phase].ok[lane], want)
						}
					}
				}

				b.Run(fmt.Sprintf("impl=narya-batch/n=%d/msg=%d/invalid=%d", n, msgSize, invalidPct), func(b *testing.B) {
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						for phase := range batches {
							bf := &batches[phase]
							VerifyBatch(bf.pubs, bf.msgs, bf.sigs, bf.ok)
						}
					}
					b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*len(batches)*n)/1000, "µs/sig")
				})
			}
		}
	}
}

// BenchmarkVerifyBatchInvalidLane places one full-equation failure in every
// lane. Keeping each position independently benchmarked makes masked x4/x8
// verdict mapping and tail regressions visible instead of sampling only the
// group boundaries.
func BenchmarkVerifyBatchInvalidLane(b *testing.B) {
	for _, msgSize := range benchMsgSizes {
		for _, n := range []int{8, 9, 16, 17} {
			for lane := 0; lane < n; lane++ {
				bf := makeBatchFixture(b, n, msgSize)
				badMsg := append([]byte(nil), bf.msgs[lane]...)
				badMsg[0] ^= 1
				bf.msgs[lane] = badMsg
				VerifyBatch(bf.pubs, bf.msgs, bf.sigs, bf.ok)
				if bf.ok[lane] {
					b.Fatalf("invalid-lane setup unexpectedly verified: n=%d lane=%d", n, lane)
				}

				b.Run(fmt.Sprintf("impl=narya-batch/n=%d/msg=%d/invalid-lane=%d", n, msgSize, lane), func(b *testing.B) {
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						VerifyBatch(bf.pubs, bf.msgs, bf.sigs, bf.ok)
					}
					b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*n)/1000, "µs/sig")
				})
			}
		}
	}
}

// BenchmarkTableBuild measures the one-time build cost of each native
// precomputation tier.
func BenchmarkTableBuild(b *testing.B) {
	f := makeFixture(b, 200)
	generic := genericBackend{}
	b.Run("tier=compact-naf", func(b *testing.B) {
		b.ReportMetric(genericCompactTableBytes, "table-bytes")
		for i := 0; i < b.N; i++ {
			if _, err := generic.buildCompactPrecomp(&f.pub); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("tier=hot-comb", func(b *testing.B) {
		b.ReportMetric(genericTableBytes, "table-bytes")
		for i := 0; i < b.N; i++ {
			if _, err := generic.buildPrecomp(&f.pub); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkGenericPrecomputeTier measures the complete portable verifier with
// no table, the compact width-5 NAF table, and the existing full comb table.
// The compact tier is native Narya code and remains experimental until its
// build and reuse crossover is established on production-shaped hardware.
func BenchmarkGenericPrecomputeTier(b *testing.B) {
	generic := genericBackend{}
	for _, sz := range []int{64, 200, 1232} {
		f := makeFixture(b, sz)
		compact, err := generic.buildCompactPrecomp(&f.pub)
		if err != nil {
			b.Fatal(err)
		}
		hot, err := generic.buildPrecomp(&f.pub)
		if err != nil {
			b.Fatal(err)
		}
		for _, tc := range []struct {
			name string
			pre  *PrecomputedKey
		}{
			{name: "cold"},
			{name: "compact-naf", pre: compact},
			{name: "hot-comb", pre: hot},
		} {
			b.Run(fmt.Sprintf("tier=%s/msg=%d", tc.name, sz), func(b *testing.B) {
				var tableBytes int64
				if tc.pre != nil {
					tableBytes = tc.pre.size
				}
				b.ReportMetric(float64(tableBytes), "table-bytes")
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if !verifyOne(generic, DalekStrict, &f.pub, f.msg, f.sig, tc.pre) {
						b.Fatal("verify failed")
					}
				}
			})
		}
	}
}

// BenchmarkGenericPrecomputeLifecycle includes construction and every verify
// in a finite recurrence episode. Unlike the steady-state tier benchmark, it
// directly exposes when compact and hot precomputation repay their build cost.
func BenchmarkGenericPrecomputeLifecycle(b *testing.B) {
	generic := genericBackend{}
	fixtures := makeFixtures(b, 64, 200)
	for _, repeats := range []int{1, 2, 3, 4, 5, 6, 7, 8, 16, 32, 64} {
		for _, tier := range []string{"cold", "compact-naf", "hot-comb"} {
			b.Run(fmt.Sprintf("tier=%s/repeats=%d", tier, repeats), func(b *testing.B) {
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					f := &fixtures[i%len(fixtures)]
					var pre *PrecomputedKey
					var err error
					switch tier {
					case "compact-naf":
						pre, err = generic.buildCompactPrecomp(&f.pub)
					case "hot-comb":
						pre, err = generic.buildPrecomp(&f.pub)
					}
					if err != nil {
						b.Fatal(err)
					}
					for verifyIndex := 0; verifyIndex < repeats; verifyIndex++ {
						if !verifyOne(generic, DalekStrict, &f.pub, f.msg, f.sig, pre) {
							b.Fatal("verify failed")
						}
					}
				}
				b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*repeats)/1000, "µs/sig")
			})
		}
	}
}

// BenchmarkGenericCompactBatchTail measures the native compact table for the
// n=1..4 remainder regime. Every item has a distinct recurring key, which is
// the harder cache-locality case than a homogeneous signer group.
func BenchmarkGenericCompactBatchTail(b *testing.B) {
	generic := genericBackend{}
	for _, sz := range []int{64, 200, 1232} {
		for _, n := range []int{1, 2, 3, 4} {
			bf := makeBatchFixture(b, n, sz)
			compact := make(map[[32]byte]*PrecomputedKey, n)
			hot := make(map[[32]byte]*PrecomputedKey, n)
			for i := range bf.fs {
				var err error
				compact[bf.fs[i].pub], err = generic.buildCompactPrecomp(&bf.fs[i].pub)
				if err != nil {
					b.Fatal(err)
				}
				hot[bf.fs[i].pub], err = generic.buildPrecomp(&bf.fs[i].pub)
				if err != nil {
					b.Fatal(err)
				}
			}

			for _, tc := range []struct {
				name   string
				lookup func(*[32]byte) *PrecomputedKey
			}{
				{name: "cold"},
				{name: "compact-naf", lookup: func(pub *[32]byte) *PrecomputedKey { return compact[*pub] }},
				{name: "hot-comb", lookup: func(pub *[32]byte) *PrecomputedKey { return hot[*pub] }},
			} {
				b.Run(fmt.Sprintf("tier=%s/n=%d/msg=%d", tc.name, n, sz), func(b *testing.B) {
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						if !verifyBatch(generic, DalekStrict, bf.pubs, bf.msgs, bf.sigs, bf.ok, tc.lookup) {
							b.Fatal("verify failed")
						}
					}
					b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*n)/1000, "µs/sig")
				})
			}
		}
	}
}

// BenchmarkVerifyWorkingSet measures the cached path when the table
// working set exceeds the CPU caches, cycling through nKeys hot keys — the
// realistic "recurring signers" case rather than one always-hot key.
func BenchmarkVerifyWorkingSet(b *testing.B) {
	for _, nKeys := range []int{16, 512, 4096} {
		b.Run(fmt.Sprintf("keys=%d", nKeys), func(b *testing.B) {
			c := &Cache{MaxTableBytes: (int64(nKeys) + 10) * genericTableBytes}
			fs := makeFixtures(b, nKeys, 200)
			for i := range fs {
				for j := 0; j < buildThreshold; j++ {
					c.Verify(&fs[i].pub, fs[i].msg, fs[i].sig)
				}
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				k := i % nKeys
				if !c.Verify(&fs[k].pub, fs[k].msg, fs[k].sig) {
					b.Fatal("verify failed")
				}
			}
		})
	}
}

// BenchmarkGenericPrecomputeWorkingSet compares all three native tiers at the
// same deterministic reuse distance. It deliberately bypasses Cache policy so
// the arithmetic and table-footprint crossover can be measured independently
// from admission bookkeeping.
func BenchmarkGenericPrecomputeWorkingSet(b *testing.B) {
	generic := genericBackend{}
	for _, nKeys := range []int{1, 16, 512, 4096} {
		fs := makeFixtures(b, nKeys, 200)
		for _, tier := range []string{"cold", "compact-naf", "hot-comb"} {
			b.Run(fmt.Sprintf("tier=%s/keys=%d", tier, nKeys), func(b *testing.B) {
				precomputed := make([]*PrecomputedKey, nKeys)
				for i := range fs {
					var err error
					switch tier {
					case "compact-naf":
						precomputed[i], err = generic.buildCompactPrecomp(&fs[i].pub)
					case "hot-comb":
						precomputed[i], err = generic.buildPrecomp(&fs[i].pub)
					}
					if err != nil {
						b.Fatal(err)
					}
				}
				if nKeys > 0 && precomputed[0] != nil {
					b.ReportMetric(float64(precomputed[0].size), "bytes/key")
				}
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					index := i % nKeys
					f := &fs[index]
					if !verifyOne(generic, DalekStrict, &f.pub, f.msg, f.sig, precomputed[index]) {
						b.Fatal("verify failed")
					}
				}
			})
		}
	}
}
