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
// so the hashing fraction (which the future sha512mb kernel targets) is
// visible: hashing grows with message size, point math does not.
var benchMsgSizes = []int{64, 200, 1232}

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
	for _, sz := range []int{200, 1232} {
		for _, n := range []int{8, 64} {
			fs := makeFixtures(b, n, sz)
			pubs := make([]*[32]byte, n)
			msgs := make([][]byte, n)
			sigs := make([][]byte, n)
			ok := make([]bool, n)
			for i := range fs {
				pubs[i] = &fs[i].pub
				msgs[i] = fs[i].msg
				sigs[i] = fs[i].sig
			}

			b.Run(fmt.Sprintf("impl=stdlib-loop/n=%d/msg=%d", n, sz), func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					for j := range fs {
						if !stded25519.Verify(fs[j].pubk, fs[j].msg, fs[j].sig) {
							b.Fatal("verify failed")
						}
					}
				}
				b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*n)/1000, "µs/sig")
			})

			b.Run(fmt.Sprintf("impl=narya-batch/n=%d/msg=%d", n, sz), func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					if !VerifyBatch(pubs, msgs, sigs, ok) {
						b.Fatal("verify failed")
					}
				}
				b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*n)/1000, "µs/sig")
			})
		}
	}
}

// BenchmarkTableBuild measures the one-time cost of admitting a key into
// the comb cache (the amortized-over-8-sightings expense).
func BenchmarkTableBuild(b *testing.B) {
	f := makeFixture(b, 200)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Precompute(&f.pub); err != nil {
			b.Fatal(err)
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
