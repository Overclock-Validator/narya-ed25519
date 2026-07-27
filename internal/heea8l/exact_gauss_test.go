package heea8l

import (
	"fmt"
	"math/big"
	"testing"
)

func TestExactGaussSmallModuliAgainstBruteForce(t *testing.T) {
	for _, smallL := range []int64{3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43} {
		n := big.NewInt(8 * smallL)
		for kval := int64(0); kval < smallL; kval++ {
			k := big.NewInt(kval)
			got, stats, ok := bestOddLInfForModulus(n, k)
			if !ok {
				t.Fatalf("L=%d k=%d: exact Gauss selector failed (stats=%+v)", smallL, kval, stats)
			}
			checkCandidate(t, n, k, &got)
			want, ok := bruteOddLInfForModulus(n, k)
			if !ok {
				t.Fatalf("L=%d k=%d: brute-force selector failed", smallL, kval)
			}
			if gotMax, wantMax := maxAbs(&got.Rho, &got.Tau), maxAbs(&want.Rho, &want.Tau); gotMax.Cmp(wantMax) != 0 {
				t.Fatalf("L=%d k=%d: Gauss=(%s,%s) max=%s brute=(%s,%s) max=%s stats=%+v",
					smallL, kval, &got.Rho, &got.Tau, gotMax,
					&want.Rho, &want.Tau, wantMax, stats)
			}
			if stats.Steps > exactGaussStepCap || stats.Candidates > 10 {
				t.Fatalf("L=%d k=%d: stats=%+v exceed proof bounds", smallL, kval, stats)
			}
		}
	}
}

func TestExactGaussMatchesExistingOracle(t *testing.T) {
	l := Order()
	n := Modulus()
	edges := []*big.Int{
		big.NewInt(0),
		big.NewInt(1),
		big.NewInt(2),
		big.NewInt(3),
		new(big.Int).Rsh(new(big.Int).Set(l), 1),
		new(big.Int).Sub(new(big.Int).Set(l), big.NewInt(2)),
		new(big.Int).Sub(new(big.Int).Set(l), big.NewInt(1)),
	}
	pathological := new(big.Int).Sub(n, big.NewInt(2))
	pathological.Quo(pathological, big.NewInt(10))
	edges = append(edges, pathological)

	check := func(label string, k *big.Int) {
		t.Helper()
		got, stats, ok := bestOddLInfForModulus(n, k)
		if !ok {
			t.Fatalf("%s: exact Gauss selector failed (stats=%+v)", label, stats)
		}
		checkCandidate(t, n, k, &got)
		want, ok := bestForModulus(n, k)
		if !ok {
			t.Fatalf("%s: existing oracle failed", label)
		}
		if gotMax, wantMax := maxAbs(&got.Rho, &got.Tau), maxAbs(&want.Rho, &want.Tau); gotMax.Cmp(wantMax) != 0 {
			t.Fatalf("%s k=%s: Gauss=(%s,%s) max=%s existing=(%s,%s) max=%s stats=%+v",
				label, k, &got.Rho, &got.Tau, gotMax,
				&want.Rho, &want.Tau, wantMax, stats)
		}
		if stats.Steps > exactGaussStepCap || stats.Candidates > 10 {
			t.Fatalf("%s: stats=%+v exceed proof bounds", label, stats)
		}
	}

	for index, k := range edges {
		check(fmt.Sprintf("edge-%d", index), k)
	}
	for sample := uint64(0); sample < 8192; sample++ {
		check(fmt.Sprintf("sample-%d", sample), sampledChallenge(2_000_000+sample, l))
	}
}

func TestExactGaussWorstCaseWidths(t *testing.T) {
	n := Modulus()
	l := Order()

	pathological := new(big.Int).Sub(n, big.NewInt(2))
	pathological.Quo(pathological, big.NewInt(10))
	wantPathological := new(big.Int).Add(n, big.NewInt(11))
	wantPathological.Quo(wantPathological, big.NewInt(12))

	lMinusOne := new(big.Int).Sub(l, big.NewInt(1))
	wantLMinusOne := new(big.Int).Add(l, big.NewInt(5))
	wantLMinusOne.Rsh(wantLMinusOne, 1)

	for _, test := range []struct {
		name string
		k    *big.Int
		want *big.Int
	}{
		{name: "(8L-2)/10", k: pathological, want: wantPathological},
		{name: "L-1", k: lMinusOne, want: wantLMinusOne},
	} {
		candidate, stats, ok := bestOddLInfForModulus(n, test.k)
		if !ok {
			t.Fatalf("%s: exact Gauss selector failed (stats=%+v)", test.name, stats)
		}
		checkCandidate(t, n, test.k, &candidate)
		if got := maxAbs(&candidate.Rho, &candidate.Tau); got.Cmp(test.want) != 0 {
			t.Fatalf("%s: M(k)=%s want %s candidate=(%s,%s)",
				test.name, got, test.want, &candidate.Rho, &candidate.Tau)
		}
		if candidate.BitLen() != 252 {
			t.Fatalf("%s: width=%d want 252", test.name, candidate.BitLen())
		}
	}
}

func TestSelectExactGaussAdmissionAndFallbacks(t *testing.T) {
	l := Order()
	for sample := uint64(0); sample < 1024; sample++ {
		k := sampledChallenge(2_200_000+sample, l)
		for _, width := range []WidthLimit{Width128, Width132, Width136} {
			got := SelectExactGauss(k, width)
			want := Select(k, width)
			if got.UseCandidate != want.UseCandidate || got.Fallback != want.Fallback {
				t.Fatalf("sample=%d width=%d admission=(%v,%v) want=(%v,%v)",
					sample, width, got.UseCandidate, got.Fallback,
					want.UseCandidate, want.Fallback)
			}
			checkCandidate(t, Modulus(), k, &got.Candidate)
		}
	}
	if got := SelectExactGauss(big.NewInt(1), WidthLimit(129)); got.UseCandidate || got.Fallback != FallbackInvalidWidth {
		t.Fatalf("invalid width selection=%+v", got)
	}
	for name, k := range map[string]*big.Int{
		"nil":      nil,
		"negative": big.NewInt(-1),
		"order":    Order(),
	} {
		if got := SelectExactGauss(k, Width128); got.UseCandidate || got.Fallback != FallbackInvalidChallenge {
			t.Fatalf("%s selection=%+v", name, got)
		}
	}
}

func TestSelectExactGaussFixedMatchesOracle(t *testing.T) {
	l := Order()
	n := Modulus()
	edges := []*big.Int{
		big.NewInt(0),
		big.NewInt(1),
		big.NewInt(2),
		big.NewInt(3),
		big.NewInt(15),
		big.NewInt(16),
		big.NewInt(17),
		new(big.Int).Rsh(new(big.Int).Set(l), 1),
		new(big.Int).Sub(new(big.Int).Set(l), big.NewInt(2)),
		new(big.Int).Sub(new(big.Int).Set(l), big.NewInt(1)),
	}
	pathological := new(big.Int).Sub(n, big.NewInt(2))
	pathological.Quo(pathological, big.NewInt(10))
	edges = append(edges, pathological)

	check := func(label string, k *big.Int) {
		t.Helper()
		encoded := bigToLittle32(t, k)
		candidate, stats, ok := bestOddLInfFixed(uint256FromBytesLE(encoded))
		if !ok {
			t.Fatalf("%s k=%s: fixed exact selector failed (stats=%+v)", label, k, stats)
		}
		got := candidate.external()
		checkFixedCandidate(t, n, k, got)
		want, _, ok := bestOddLInfForModulus(n, k)
		if !ok {
			t.Fatalf("%s: math/big exact selector failed", label)
		}
		if gotMax, wantMax := max256(candidate.rho.mag, candidate.tau.mag), bigToUint256(t, maxAbs(&want.Rho, &want.Tau)); gotMax != wantMax {
			t.Fatalf("%s k=%s: fixed=(%s,%s) max=%s oracle=(%s,%s) max=%s stats=%+v",
				label, k, fixedSignedBig(got.Rho), fixedSignedBig(got.Tau), uint256Big(gotMax),
				&want.Rho, &want.Tau, maxAbs(&want.Rho, &want.Tau), stats)
		}
		if stats.EuclidSteps > principalEuclidIterationCap || stats.GaussSteps > 16 || stats.Candidates > 10 {
			t.Fatalf("%s: stats=%+v exceed bounds", label, stats)
		}
		for _, width := range []WidthLimit{Width128, Width132, Width136} {
			fixedSelection := SelectExactGaussFixed(encoded, width)
			oracleSelection := SelectExactGauss(k, width)
			if fixedSelection.UseCandidate != oracleSelection.UseCandidate || fixedSelection.Fallback != oracleSelection.Fallback {
				t.Fatalf("%s width=%d: fixed=(%v,%v) oracle=(%v,%v)", label, width,
					fixedSelection.UseCandidate, fixedSelection.Fallback,
					oracleSelection.UseCandidate, oracleSelection.Fallback)
			}
		}
	}

	for index, k := range edges {
		check(fmt.Sprintf("edge-%d", index), k)
	}
	for sample := uint64(0); sample < 8192; sample++ {
		check(fmt.Sprintf("sample-%d", sample), sampledChallenge(2_400_000+sample, l))
	}
}

func TestSelectExactGaussFixedZeroAllocations(t *testing.T) {
	k := bigToLittle32(t, sampledChallenge(2_500_000, Order()))
	if allocations := testing.AllocsPerRun(100, func() {
		SelectExactGaussFixed(k, Width132)
	}); allocations != 0 {
		t.Fatalf("allocations=%v want 0", allocations)
	}
}

func TestExactGaussFixedWideArithmeticAgainstBig(t *testing.T) {
	for sample := uint64(0); sample < 4096; sample++ {
		left := sampledUint256(2_700_000 + 2*sample)
		right := sampledUint256(2_700_000 + 2*sample + 1)
		if left.isZero() {
			left[0] = 1
		}
		product := mulWide256(left, right)
		wantProduct := new(big.Int).Mul(uint256Big(left), uint256Big(right))
		if uint512Big(product).Cmp(wantProduct) != 0 {
			t.Fatalf("sample=%d: wide product=%s want %s", sample, uint512Big(product), wantProduct)
		}
		denominator := uint512{left[0], left[1], left[2], left[3]}
		quotient, remainder, ok := divMod512To256(product, denominator)
		if !ok || quotient != right || remainder != (uint512{}) {
			t.Fatalf("sample=%d: division=(%s,%s,%v) want (%s,0,true)",
				sample, uint256Big(quotient), uint512Big(remainder), ok, uint256Big(right))
		}
	}
}

func TestNearestAllowedIntegers(t *testing.T) {
	for _, test := range []struct {
		name        string
		numerator   int64
		denominator int64
		parity      int
		below       int64
		above       int64
	}{
		{name: "positive", numerator: 7, denominator: 3, parity: -1, below: 2, above: 3},
		{name: "negative", numerator: -7, denominator: 3, parity: -1, below: -3, above: -2},
		{name: "negative-denominator", numerator: 7, denominator: -3, parity: -1, below: -3, above: -2},
		{name: "exact-even", numerator: 6, denominator: 3, parity: 0, below: 2, above: 2},
		{name: "even-class", numerator: 7, denominator: 3, parity: 0, below: 2, above: 4},
		{name: "odd-class-negative", numerator: -7, denominator: 3, parity: 1, below: -3, above: -1},
	} {
		t.Run(test.name, func(t *testing.T) {
			below, above := nearestAllowedIntegers(
				big.NewInt(test.numerator), big.NewInt(test.denominator), test.parity,
			)
			if below.Cmp(big.NewInt(test.below)) != 0 || above.Cmp(big.NewInt(test.above)) != 0 {
				t.Fatalf("got (%s,%s), want (%d,%d)", below, above, test.below, test.above)
			}
		})
	}
}

func TestEEACrossoverNeedsBoundedGaussFinish(t *testing.T) {
	l := Order()
	n := Modulus()
	maxFinish := 0
	for sample := uint64(0); sample < 8192; sample++ {
		k := sampledChallenge(2_300_000+sample, l)
		if k.Sign() == 0 {
			continue
		}
		left, right, euclidSteps, ok := eeaNormCrossoverBasis(n, k)
		if !ok {
			t.Fatalf("sample=%d k=%s: no norm crossover", sample, k)
		}
		left, right, finishSteps, ok := gaussReduceExact(left, right, 16)
		if !ok || !validReducedBasis(n, k, &left, &right) {
			t.Fatalf("sample=%d k=%s: Gauss finish failed after %d steps", sample, k, finishSteps)
		}
		if finishSteps > maxFinish {
			maxFinish = finishSteps
		}
		if euclidSteps > 384 || finishSteps > 16 {
			t.Fatalf("sample=%d: Euclid=%d Gauss=%d exceed caps", sample, euclidSteps, finishSteps)
		}
	}
	t.Logf("maximum Gauss finish steps after EEA norm crossover: %d", maxFinish)
}

func eeaNormCrossoverBasis(n, k *big.Int) (exactLatticeVector, exactLatticeVector, int, bool) {
	r0 := new(big.Int).Set(n)
	r1 := new(big.Int).Set(k)
	t0 := new(big.Int)
	t1 := big.NewInt(1)
	for step := 0; r1.Sign() != 0 && step < 384; step++ {
		left := exactLatticeVector{}
		left.rho.Set(r0)
		left.tau.Set(t0)
		right := exactLatticeVector{}
		right.rho.Set(r1)
		right.tau.Set(t1)
		if exactNorm2(&right).Cmp(exactNorm2(&left)) >= 0 {
			return left, right, step, true
		}

		quotient := new(big.Int)
		remainder := new(big.Int)
		quotient.QuoRem(r0, r1, remainder)
		t2 := new(big.Int).Mul(quotient, t1)
		t2.Sub(t0, t2)
		r0, r1 = r1, remainder
		t0, t1 = t1, t2
	}
	return exactLatticeVector{}, exactLatticeVector{}, 384, false
}

func bruteOddLInfForModulus(n, k *big.Int) (Candidate, bool) {
	if !n.IsInt64() || !k.IsInt64() {
		return Candidate{}, false
	}
	n64 := n.Int64()
	var best Candidate
	found := false
	for tau64 := -n64 / 2; tau64 <= n64/2; tau64++ {
		if tau64 == 0 || tau64&1 == 0 {
			continue
		}
		tau := big.NewInt(tau64)
		if new(big.Int).GCD(nil, nil, abs(tau), n).Cmp(big.NewInt(1)) != 0 {
			continue
		}
		rho := new(big.Int).Mul(tau, k)
		rho.Mod(rho, n)
		if twice := new(big.Int).Lsh(new(big.Int).Set(rho), 1); twice.Cmp(n) > 0 {
			rho.Sub(rho, n)
		}
		candidate := Candidate{Epsilon: 1}
		candidate.Rho.Set(rho)
		candidate.Tau.Set(tau)
		if !found || better(&candidate, &best) {
			best = candidate
			found = true
		}
	}
	return best, found
}

func uint512Big(value uint512) *big.Int {
	out := new(big.Int)
	for index := len(value) - 1; index >= 0; index-- {
		out.Lsh(out, 64)
		out.Add(out, new(big.Int).SetUint64(value[index]))
	}
	return out
}

func BenchmarkExactGaussOracle(b *testing.B) {
	l := Order()
	keys := make([]*big.Int, 512)
	for index := range keys {
		keys[index] = sampledChallenge(2_100_000+uint64(index), l)
	}
	b.ReportAllocs()
	var result Candidate
	for iteration := 0; iteration < b.N; iteration++ {
		var ok bool
		result, _, ok = bestOddLInfForModulus(ed25519Exponent, keys[iteration%len(keys)])
		if !ok {
			b.Fatal("exact Gauss oracle failed")
		}
	}
	benchmarkSelection = Selection{Candidate: result}
}

func BenchmarkSelectExactGaussFixed(b *testing.B) {
	l := Order()
	keys := make([][32]byte, 512)
	for index := range keys {
		keys[index] = bigToLittle32(b, sampledChallenge(2_600_000+uint64(index), l))
	}
	for _, width := range []WidthLimit{Width128, Width132, Width136} {
		b.Run(benchWidthName(width), func(b *testing.B) {
			b.ReportAllocs()
			var result FixedSelection
			for iteration := 0; iteration < b.N; iteration++ {
				result = SelectExactGaussFixed(keys[iteration%len(keys)], width)
			}
			benchmarkFixedSelection = result
		})
	}
}
