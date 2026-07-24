package unaffectedbench

// This file is deliberately standalone: scripts/zen4-gate.sh copies the exact
// package into a git archive of unaffectedBaselineRevision, then compiles and
// benchmarks that archive and the current tree with the same Go toolchain.
// Keep this harness limited to public APIs present in both revisions.

import (
	stded25519 "crypto/ed25519"
	"fmt"
	"testing"

	narya "github.com/Overclock-Validator/narya/ed25519"
)

const unaffectedBaselineRevision = "05bf37ca843842f54109581755d587dc552e7aa8"

type fixture struct {
	pubs []*[32]byte
	msgs [][]byte
	sigs [][]byte
	ok   []bool
}

func newFixture(tb testing.TB, count, messageSize int) fixture {
	tb.Helper()
	result := fixture{
		pubs: make([]*[32]byte, count),
		msgs: make([][]byte, count),
		sigs: make([][]byte, count),
		ok:   make([]bool, count),
	}
	for lane := 0; lane < count; lane++ {
		seed := make([]byte, stded25519.SeedSize)
		for index := range seed {
			seed[index] = byte(17*lane + 29*index + messageSize)
		}
		privateKey := stded25519.NewKeyFromSeed(seed)
		publicKey := privateKey.Public().(stded25519.PublicKey)
		pub := new([32]byte)
		copy(pub[:], publicKey)
		message := make([]byte, messageSize)
		for index := range message {
			message[index] = byte(31*lane + 7*index + messageSize)
		}
		result.pubs[lane] = pub
		result.msgs[lane] = message
		result.sigs[lane] = stded25519.Sign(privateKey, message)
	}
	return result
}

var benchmarkResult bool

// BenchmarkUnaffectedCompatCompletePipeline exercises the portable public
// StdlibCompat path that the strict/r51 work must not regress. n=1 uses Verify;
// n=8/64 use VerifyBatch and therefore include batch construction, hashing,
// point arithmetic, verdict collection, and their allocations. The gate forces
// OVERCLOCK_ED25519_BACKEND=generic for both separately compiled revisions.
func BenchmarkUnaffectedCompatCompletePipeline(b *testing.B) {
	narya.SetDefaultProfile(narya.StdlibCompat)
	for _, messageSize := range []int{64, 200, 1232} {
		for _, count := range []int{1, 8, 64} {
			input := newFixture(b, count, messageSize)
			shape := "batch"
			if count == 1 {
				shape = "single"
			}
			b.Run(fmt.Sprintf("shape=%s/n=%d/msg=%d", shape, count, messageSize), func(b *testing.B) {
				b.ReportAllocs()
				var result bool
				b.ResetTimer()
				for iteration := 0; iteration < b.N; iteration++ {
					if count == 1 {
						result = narya.Verify(input.pubs[0], input.msgs[0], input.sigs[0])
					} else {
						result = narya.VerifyBatch(input.pubs, input.msgs, input.sigs, input.ok)
					}
				}
				benchmarkResult = result
				if !result {
					b.Fatal("portable compat verifier rejected a valid fixture")
				}
				b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*count)/1000, "us/sig")
			})
		}
	}
}
