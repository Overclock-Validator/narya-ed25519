package heea8l

import (
	"fmt"
	"math/big"
	"testing"
)

func TestSelectApproxQuotientExactRelation(t *testing.T) {
	l := Order()
	n := Modulus()
	pathological := new(big.Int).Sub(n, big.NewInt(2))
	pathological.Quo(pathological, big.NewInt(10))
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
		pathological,
	}

	check := func(label string, k *big.Int) {
		t.Helper()
		encoded := bigToLittle32(t, k)
		previousAdmission := false
		for _, limit := range []WidthLimit{Width128, Width132, Width136} {
			got := SelectApproxQuotient(encoded, limit)
			oracle := SelectFixed(encoded, limit)
			if got.UseCandidate {
				if got.Fallback != NoFallback || got.Candidate.BitLen() > int(limit) {
					t.Fatalf("%s width %d: invalid admission %+v", label, limit, got)
				}
				checkFixedCandidate(t, n, k, got.Candidate)
				if !got.Candidate.UnitMultiplier() {
					t.Fatalf("%s width %d: non-unit multiplier", label, limit)
				}
				if !oracle.UseCandidate {
					t.Fatalf("%s width %d: approximate selector found candidate missed by oracle", label, limit)
				}
			} else if got.Fallback != FallbackWidthExceeded {
				t.Fatalf("%s width %d: fallback=%v", label, limit, got.Fallback)
			}
			if previousAdmission && !got.UseCandidate {
				t.Fatalf("%s: admissions are not monotone at width %d", label, limit)
			}
			previousAdmission = got.UseCandidate
		}
	}

	for index, k := range edges {
		check(fmt.Sprintf("edge-%d", index), k)
	}
	for sample := uint64(0); sample < 4096; sample++ {
		check(fmt.Sprintf("sample-%d", sample), sampledChallenge(1_500_000+sample, l))
	}
}

func TestSelectApproxQuotientFallbacks(t *testing.T) {
	one := bigToLittle32(t, big.NewInt(1))
	if got := SelectApproxQuotient(one, WidthLimit(129)); got.UseCandidate || got.Fallback != FallbackInvalidWidth {
		t.Fatalf("invalid width selection=%+v", got)
	}
	for name, k := range map[string]*big.Int{
		"order":        Order(),
		"modulus":      Modulus(),
		"order-plus-1": new(big.Int).Add(Order(), big.NewInt(1)),
		"all-ones":     new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1)),
	} {
		got := SelectApproxQuotient(bigToLittle32(t, k), Width128)
		if got.UseCandidate || got.Fallback != FallbackInvalidChallenge {
			t.Fatalf("%s: selection=%+v", name, got)
		}
	}
}

func TestApproxQuotientRowsPreserveRelationAndRange(t *testing.T) {
	n := Modulus()
	l := Order()
	for sample := uint64(0); sample < 1024; sample++ {
		kBig := sampledChallenge(1_600_000+sample, l)
		k := bigToUint256(t, kBig)
		if k.isZero() {
			continue
		}
		rows := [2]approxQuotientRow{
			{rho: signed320FromUint256(fixedModulus)},
			{rho: signed320FromUint256(k), tau: signed320FromUint64(1)},
		}
		bitLengths := [2]int{fixedModulus.bitLen(), k.bitLen()}
		for step := 0; !rows[1].rho.isZero(); step++ {
			if step >= approxQuotientIterationCap {
				t.Fatalf("sample %d exceeded iteration cap", sample)
			}
			checkApproxQuotientRows(t, n, kBig, rows)
			if bitLengths[0] < bitLengths[1] {
				rows[0], rows[1] = rows[1], rows[0]
				bitLengths[0], bitLengths[1] = bitLengths[1], bitLengths[0]
			}
			shift := uint(bitLengths[0] - bitLengths[1])
			sameSign := rows[0].rho.neg == rows[1].rho.neg
			var next approxQuotientRow
			var ok bool
			if sameSign {
				next.rho, ok = subShifted320(rows[0].rho, rows[1].rho, shift)
				if ok {
					next.tau, ok = subShifted320(rows[0].tau, rows[1].tau, shift)
				}
			} else {
				next.rho, ok = addShifted320(rows[0].rho, rows[1].rho, shift)
				if ok {
					next.tau, ok = addShifted320(rows[0].tau, rows[1].tau, shift)
				}
			}
			if !ok || next.rho.mag[4] != 0 || next.tau.mag[4] != 0 {
				t.Fatalf("sample %d step %d overflow", sample, step)
			}
			nextBits := next.rho.bitLen()
			if nextBits > bitLengths[1] {
				rows[0], bitLengths[0] = next, nextBits
			} else {
				rows[0], rows[1] = rows[1], next
				bitLengths[0], bitLengths[1] = bitLengths[1], nextBits
			}
		}
		checkApproxQuotientRows(t, n, kBig, rows)
	}
}

func checkApproxQuotientRows(t *testing.T, n, k *big.Int, rows [2]approxQuotientRow) {
	t.Helper()
	for index, row := range rows {
		if row.rho.mag[4] != 0 || row.tau.mag[4] != 0 {
			t.Fatalf("row %d exceeded 256 bits", index)
		}
		delta := new(big.Int).Mul(signed320Big(row.tau), k)
		delta.Sub(signed320Big(row.rho), delta)
		delta.Mod(delta, n)
		if delta.Sign() != 0 {
			t.Fatalf("row %d relation failed", index)
		}
	}
	determinant := new(big.Int).Mul(signed320Big(rows[0].rho), signed320Big(rows[1].tau))
	term := new(big.Int).Mul(signed320Big(rows[1].rho), signed320Big(rows[0].tau))
	determinant.Sub(determinant, term)
	determinant.Abs(determinant)
	if determinant.Cmp(n) != 0 {
		t.Fatalf("determinant=%s want N=%s", determinant, n)
	}
}

func TestApproxQuotientCoverageSnapshot(t *testing.T) {
	const samples = 8192
	l := Order()
	approxFallbacks := map[WidthLimit]int{Width128: 0, Width132: 0, Width136: 0}
	shiftFallbacks := map[WidthLimit]int{Width128: 0, Width132: 0, Width136: 0}
	oracleFallbacks := map[WidthLimit]int{Width128: 0, Width132: 0, Width136: 0}
	for sample := uint64(0); sample < samples; sample++ {
		encoded := bigToLittle32(t, sampledChallenge(1_700_000+sample, l))
		for _, width := range []WidthLimit{Width128, Width132, Width136} {
			if !SelectApproxQuotient(encoded, width).UseCandidate {
				approxFallbacks[width]++
			}
			if !SelectShiftSubtract(encoded, width).UseCandidate {
				shiftFallbacks[width]++
			}
			if !SelectFixed(encoded, width).UseCandidate {
				oracleFallbacks[width]++
			}
		}
	}
	t.Logf("approximate=%v shift-subtract=%v oracle=%v", approxFallbacks, shiftFallbacks, oracleFallbacks)
	for _, width := range []WidthLimit{Width128, Width132, Width136} {
		if approxFallbacks[width] < oracleFallbacks[width] {
			t.Fatalf("width %d approximate fallback count %d below oracle %d", width, approxFallbacks[width], oracleFallbacks[width])
		}
	}
}

func FuzzSelectApproxQuotient(f *testing.F) {
	l := Order()
	for sample := uint64(0); sample < 16; sample++ {
		encoded := bigToLittle32(f, sampledChallenge(1_800_000+sample, l))
		f.Add(encoded[:])
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) != 32 {
			return
		}
		var encoded [32]byte
		copy(encoded[:], input)
		kFixed := uint256FromBytesLE(encoded)
		if kFixed.cmp(fixedOrder) >= 0 {
			return
		}
		k := little32Big(encoded)
		for _, width := range []WidthLimit{Width128, Width132, Width136} {
			got := SelectApproxQuotient(encoded, width)
			if !got.UseCandidate {
				continue
			}
			if got.Candidate.BitLen() > int(width) || !got.Candidate.UnitMultiplier() {
				t.Fatalf("width %d invalid admission %+v", width, got)
			}
			checkFixedCandidate(t, Modulus(), k, got.Candidate)
		}
	})
}

var benchmarkApproxQuotientSelection FixedSelection

func BenchmarkSelectApproxQuotient(b *testing.B) {
	l := Order()
	inputs := [][32]byte{
		bigToLittle32(b, sampledChallenge(1_900_000, l)),
		bigToLittle32(b, sampledChallenge(1_900_001, l)),
		bigToLittle32(b, sampledChallenge(1_900_002, l)),
	}
	for _, width := range []WidthLimit{Width128, Width132, Width136} {
		for _, selector := range []struct {
			name string
			fn   func([32]byte, WidthLimit) FixedSelection
		}{
			{name: "approx-quotient", fn: SelectApproxQuotient},
			{name: "shift-subtract", fn: SelectShiftSubtract},
			{name: "principal-euclid", fn: SelectEuclidPrincipal},
		} {
			selector := selector
			b.Run(fmt.Sprintf("selector=%s/width=%d", selector.name, width), func(b *testing.B) {
				b.ReportAllocs()
				var result FixedSelection
				for iteration := 0; iteration < b.N; iteration++ {
					result = selector.fn(inputs[iteration%len(inputs)], width)
				}
				benchmarkApproxQuotientSelection = result
				b.ReportMetric(float64(result.Candidate.BitLen()), "candidate_bits")
			})
		}
	}
}
