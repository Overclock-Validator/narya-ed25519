package heea8l

import (
	"encoding/binary"
	"math/big"
	"math/rand"
	"testing"
)

func signedBig(x SignedCoefficient) *big.Int {
	magnitude := x.BytesLE()
	out := new(big.Int).SetBytes(reverseBytes(magnitude))
	if x.Negative {
		out.Neg(out)
	}
	return out
}

func reverseBytes(in [32]byte) []byte {
	out := make([]byte, len(in))
	for i, b := range in {
		out[len(in)-1-i] = b
	}
	return out
}

// randomChallengeBytes returns a canonical scalar below L.
func randomChallengeBytes(rng *rand.Rand) [32]byte {
	for {
		var out [32]byte
		for i := 0; i < 4; i++ {
			binary.LittleEndian.PutUint64(out[8*i:], rng.Uint64())
		}
		// Clear the top bits so rejection terminates quickly.
		out[31] &= 0x0f
		if uint256FromBytesLE(out).cmp(fixedOrder) < 0 {
			return out
		}
	}
}

// The Lehmer selector must agree with the exact principal-Euclid selector on
// every input, not merely produce some valid candidate. Batching is only
// permitted while the wide values are clear of the stopping width, so the two
// must stop on the same row of the same sequence.
func TestLehmerMatchesExactSelector(t *testing.T) {
	rng := rand.New(rand.NewSource(20260726))
	for _, limit := range []WidthLimit{Width128, Width132, Width136} {
		for i := 0; i < 20000; i++ {
			k := randomChallengeBytes(rng)
			want := SelectEuclidPrincipal(k, limit)
			got := SelectLehmer(k, limit)

			if got.UseCandidate != want.UseCandidate || got.Fallback != want.Fallback {
				t.Fatalf("limit=%d k=%x: use=%v/%v fallback=%v/%v",
					limit, k, got.UseCandidate, want.UseCandidate, got.Fallback, want.Fallback)
			}
			if !want.UseCandidate {
				continue
			}
			if got.Candidate.Rho != want.Candidate.Rho || got.Candidate.Tau != want.Candidate.Tau {
				t.Fatalf("limit=%d k=%x: candidate mismatch\n got rho=%v tau=%v\nwant rho=%v tau=%v",
					limit, k, got.Candidate.Rho, want.Candidate.Rho, got.Candidate.Tau, want.Candidate.Tau)
			}
		}
	}
}

// The congruence rho == tau*k (mod 8L) and the unit condition on tau are what
// make the transformed equation equivalent to the strict one. Check them
// directly rather than trusting agreement with the other selector alone.
func TestLehmerCandidateSatisfiesCongruence(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 5000; i++ {
		kBytes := randomChallengeBytes(rng)
		selection := SelectLehmer(kBytes, Width128)
		if !selection.UseCandidate {
			continue
		}
		if !selection.Candidate.UnitMultiplier() {
			t.Fatalf("k=%x: tau is not a unit modulo 8L", kBytes)
		}
		if got := selection.Candidate.BitLen(); got > int(Width128) {
			t.Fatalf("k=%x: candidate width %d exceeds limit", kBytes, got)
		}
		rho := signedBig(selection.Candidate.Rho)
		tau := signedBig(selection.Candidate.Tau)
		k := new(big.Int).SetBytes(reverseBytes(kBytes))
		lhs := new(big.Int).Mod(rho, ed25519Exponent)
		rhs := new(big.Int).Mod(new(big.Int).Mul(tau, k), ed25519Exponent)
		if lhs.Cmp(rhs) != 0 {
			t.Fatalf("k=%x: rho != tau*k (mod 8L)", kBytes)
		}
	}
}

func TestLehmerEdgeChallenges(t *testing.T) {
	var zero [32]byte
	if got := SelectLehmer(zero, Width128); !got.UseCandidate {
		t.Fatal("k=0 must select the trivial candidate")
	}

	// L itself is not a canonical challenge.
	var atOrder [32]byte
	for i, limb := range fixedOrder {
		binary.LittleEndian.PutUint64(atOrder[8*i:], limb)
	}
	if got := SelectLehmer(atOrder, Width128); got.Fallback != FallbackInvalidChallenge {
		t.Fatalf("k=L must be rejected, got fallback=%v", got.Fallback)
	}

	if got := SelectLehmer(zero, WidthLimit(200)); got.Fallback != FallbackInvalidWidth {
		t.Fatalf("invalid width must be rejected, got fallback=%v", got.Fallback)
	}
}

func TestLehmerIsAllocationFree(t *testing.T) {
	rng := rand.New(rand.NewSource(11))
	k := randomChallengeBytes(rng)
	if allocations := testing.AllocsPerRun(50, func() {
		SelectLehmer(k, Width128)
	}); allocations != 0 {
		t.Fatalf("allocations = %v, want 0", allocations)
	}
}

// Confirms the acceleration is actually engaging: if no batch ever ran, the
// benchmark below would be measuring the exact selector under another name.
func TestLehmerActuallyBatches(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	var totalBatched, totalExact, samples, totalBatches int
	for i := 0; i < 2000; i++ {
		k := uint256FromBytesLE(randomChallengeBytes(rng))
		selection, stats := selectLehmer(k, Width128)
		if !selection.UseCandidate {
			continue
		}
		totalBatched += stats.BatchedSteps
		totalExact += stats.Exact
		totalBatches += stats.Batches
		samples++
	}
	if samples == 0 {
		t.Fatal("no admitted samples")
	}
	batchedShare := float64(totalBatched) / float64(totalBatched+totalExact)
	t.Logf("batched %.1f%% | batches=%d steps/batch=%.2f | exact=%d", 100*batchedShare, totalBatches, float64(totalBatched)/float64(totalBatches), totalExact)
	if batchedShare < 0.25 {
		t.Fatalf("Lehmer batching covered only %.1f%% of steps", 100*batchedShare)
	}
}

func BenchmarkSelectLehmer(b *testing.B) {
	rng := rand.New(rand.NewSource(20260726))
	keys := make([][32]byte, 512)
	for i := range keys {
		keys[i] = randomChallengeBytes(rng)
	}
	for _, limit := range []WidthLimit{Width128, Width132, Width136} {
		b.Run(benchWidthName(limit), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				SelectLehmer(keys[i%len(keys)], limit)
			}
		})
	}
}

func benchWidthName(limit WidthLimit) string {
	switch limit {
	case Width128:
		return "width=128"
	case Width132:
		return "width=132"
	default:
		return "width=136"
	}
}
