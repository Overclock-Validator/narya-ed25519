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

func TestApplyLehmerMatrixMatchesReference(t *testing.T) {
	rng := rand.New(rand.NewSource(0x8_1e4e7))
	for sample := 0; sample < 100000; sample++ {
		rows := [2]principalEuclidRow{}
		for row := range rows {
			for limb := range rows[row].rho {
				rows[row].rho[limb] = rng.Uint64()
				rows[row].tau.mag[limb] = rng.Uint64()
			}
			rows[row].tau.neg = rng.Intn(2) != 0
		}
		coefficient := func() int64 {
			value := int64(rng.Uint32() & (lehmerCoefficientCap - 1))
			if rng.Intn(2) != 0 {
				value = -value
			}
			return value
		}
		a, b, c, d := coefficient(), coefficient(), coefficient(), coefficient()
		got, gotOK := applyLehmerMatrix(rows, a, b, c, d)
		want, wantOK := applyLehmerMatrixReference(rows, a, b, c, d)
		if gotOK != wantOK || got != want {
			t.Fatalf("sample=%d matrix=[%d %d;%d %d] ok=%v/%v\n got=%+v\nwant=%+v",
				sample, a, b, c, d, gotOK, wantOK, got, want)
		}
	}
}

func TestSubMulUint64Signed320MatchesReference(t *testing.T) {
	rng := rand.New(rand.NewSource(0x5355424d554c))
	for sample := 0; sample < 100000; sample++ {
		var x, y signed320
		for limb := range x.mag {
			x.mag[limb] = rng.Uint64()
			y.mag[limb] = rng.Uint64()
		}
		x.neg = rng.Intn(2) != 0
		y.neg = rng.Intn(2) != 0
		multiplier := rng.Uint64()
		if sample%16 == 0 {
			multiplier = 0
		}
		got, gotOK := subMulUint64Signed320(x, y, multiplier)
		want, wantOK := subMulUint64Signed320Reference(x, y, multiplier)
		if gotOK != wantOK || got != want {
			t.Fatalf("sample=%d multiplier=%x ok=%v/%v\n got=%+v\nwant=%+v",
				sample, multiplier, gotOK, wantOK, got, want)
		}
	}
}

type lehmerMatrixFixture struct {
	rows       [2]principalEuclidRow
	a, b, c, d int64
}

func makeLehmerMatrixFixtures(tb testing.TB) []lehmerMatrixFixture {
	tb.Helper()
	rng := rand.New(rand.NewSource(20260726))
	fixtures := make([]lehmerMatrixFixture, 0, 512)
	for len(fixtures) < cap(fixtures) {
		k := uint256FromBytesLE(randomChallengeBytes(rng))
		rows := [2]principalEuclidRow{
			{rho: fixedModulus},
			{rho: k, tau: signed320FromUint64(1)},
		}
		for !rows[1].rho.isZero() && rows[1].rho.bitLen() > int(Width128)+lehmerGuardBits {
			a, b, c, d, steps := lehmerMatrix(rows[0].rho, rows[1].rho)
			if steps == 0 {
				quotient, remainder := divMod256(rows[0].rho, rows[1].rho)
				if quotient[1]|quotient[2]|quotient[3] != 0 {
					break
				}
				tau, ok := subMulUint64Signed320(rows[0].tau, rows[1].tau, quotient[0])
				if !ok {
					break
				}
				rows[0], rows[1] = rows[1], principalEuclidRow{rho: remainder, tau: tau}
				continue
			}
			fixtures = append(fixtures, lehmerMatrixFixture{rows: rows, a: a, b: b, c: c, d: d})
			next, ok := applyLehmerMatrixReference(rows, a, b, c, d)
			if !ok {
				tb.Fatal("reference rejected reachable Lehmer matrix")
			}
			rows = next
			if len(fixtures) == cap(fixtures) {
				break
			}
		}
	}
	return fixtures
}

func BenchmarkApplyLehmerMatrix(b *testing.B) {
	fixtures := makeLehmerMatrixFixtures(b)
	for _, candidate := range []struct {
		name string
		fn   func([2]principalEuclidRow, int64, int64, int64, int64) ([2]principalEuclidRow, bool)
	}{
		{name: "fused", fn: applyLehmerMatrix},
		{name: "four-combine-reference", fn: applyLehmerMatrixReference},
	} {
		candidate := candidate
		b.Run(candidate.name, func(b *testing.B) {
			b.ReportAllocs()
			var result [2]principalEuclidRow
			var ok bool
			for i := 0; i < b.N; i++ {
				fixture := &fixtures[i%len(fixtures)]
				result, ok = candidate.fn(fixture.rows, fixture.a, fixture.b, fixture.c, fixture.d)
			}
			if !ok {
				b.Fatal("reachable matrix rejected")
			}
			benchmarkFixedSelection = FixedSelection{Candidate: FixedCandidate{Rho: SignedCoefficient{Limbs: result[1].rho}}}
		})
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

// BenchmarkSelectLehmerComparison keeps the input distribution identical for
// all selectors. The older standalone benchmarks intentionally exercise
// different admitted and fallback challenges, so comparing their headline
// numbers would not measure the reducer alone.
func BenchmarkSelectLehmerComparison(b *testing.B) {
	rng := rand.New(rand.NewSource(20260726))
	keys := make([][32]byte, 512)
	for i := range keys {
		keys[i] = randomChallengeBytes(rng)
	}

	for _, limit := range []WidthLimit{Width128, Width132, Width136} {
		b.Run(benchWidthName(limit), func(b *testing.B) {
			for _, selector := range []struct {
				name string
				fn   func([32]byte, WidthLimit) FixedSelection
			}{
				{name: "lehmer", fn: SelectLehmer},
				{name: "lehmer-four-combine-reference", fn: selectLehmerFourCombineReference},
				{name: "principal-euclid", fn: SelectEuclidPrincipal},
				{name: "shift-subtract", fn: SelectShiftSubtract},
			} {
				selector := selector
				b.Run(selector.name, func(b *testing.B) {
					b.ReportAllocs()
					var result FixedSelection
					for i := 0; i < b.N; i++ {
						result = selector.fn(keys[i%len(keys)], limit)
					}
					benchmarkFixedSelection = result
				})
			}
		})
	}
}

// selectLehmerFourCombineReference duplicates the production selector's
// control flow while retaining the former four-combine matrix application.
// It exists only in tests so the complete before/after paths can be timed in
// the same binary without putting an indirect call in the production loop.
func selectLehmerFourCombineReference(kBytes [32]byte, limit WidthLimit) FixedSelection {
	if limit != Width128 && limit != Width132 && limit != Width136 {
		return FixedSelection{Fallback: FallbackInvalidWidth}
	}
	k := uint256FromBytesLE(kBytes)
	if k.cmp(fixedOrder) >= 0 {
		return FixedSelection{Fallback: FallbackInvalidChallenge}
	}
	if k.isZero() {
		return FixedSelection{
			Candidate: FixedCandidate{
				Tau:     SignedCoefficient{Limbs: [4]uint64{1}},
				Epsilon: 1,
			},
			UseCandidate: true,
			Fallback:     NoFallback,
		}
	}

	rows := [2]principalEuclidRow{
		{rho: fixedModulus},
		{rho: k, tau: signed320FromUint64(1)},
	}
	if candidate, ok := principalEuclidCandidate(rows[1], int(limit)); ok {
		return FixedSelection{Candidate: candidate, UseCandidate: true}
	}

	iterations := 0
	for !rows[1].rho.isZero() && iterations < principalEuclidIterationCap {
		if rows[1].rho.bitLen() > int(limit)+lehmerGuardBits {
			a, b, c, d, steps := lehmerMatrix(rows[0].rho, rows[1].rho)
			if steps > 0 {
				next, ok := applyLehmerMatrixReference(rows, a, b, c, d)
				if !ok {
					return FixedSelection{Fallback: FallbackWidthExceeded}
				}
				rows = next
				iterations += steps
				if candidate, ok := principalEuclidCandidate(rows[1], int(limit)); ok {
					return FixedSelection{Candidate: candidate, UseCandidate: true}
				}
				continue
			}
		}

		quotient, remainder := divMod256(rows[0].rho, rows[1].rho)
		iterations++
		if quotient[1]|quotient[2]|quotient[3] != 0 {
			return FixedSelection{Fallback: FallbackWidthExceeded}
		}
		tau, ok := subMulUint64Signed320(rows[0].tau, rows[1].tau, quotient[0])
		if !ok || tau.mag[4] != 0 {
			return FixedSelection{Fallback: FallbackWidthExceeded}
		}
		rows[0], rows[1] = rows[1], principalEuclidRow{rho: remainder, tau: tau}
		if candidate, ok := principalEuclidCandidate(rows[1], int(limit)); ok {
			return FixedSelection{Candidate: candidate, UseCandidate: true}
		}
	}
	return FixedSelection{Fallback: FallbackWidthExceeded}
}

func TestLehmerCompletePathMatchesFourCombineReference(t *testing.T) {
	rng := rand.New(rand.NewSource(0x4c45484d4552))
	for _, limit := range []WidthLimit{Width128, Width132, Width136} {
		for sample := 0; sample < 20000; sample++ {
			k := randomChallengeBytes(rng)
			got := SelectLehmer(k, limit)
			want := selectLehmerFourCombineReference(k, limit)
			if got != want {
				t.Fatalf("limit=%d sample=%d k=%x:\n got=%+v\nwant=%+v", limit, sample, k, got, want)
			}
		}
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
