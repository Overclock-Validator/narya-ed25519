package heea8l

import (
	"math/big"
	"testing"
)

var benchmarkSelection Selection
var benchmarkFixedSelection FixedSelection

func BenchmarkSelect(b *testing.B) {
	admitted := benchmarkChallenge(func(s Selection) bool { return s.UseCandidate })
	ordinaryFallback := benchmarkChallenge(func(s Selection) bool {
		return !s.UseCandidate && s.Fallback == FallbackWidthExceeded
	})
	n := Modulus()
	pathological := new(big.Int).Sub(n, big.NewInt(2))
	pathological.Quo(pathological, big.NewInt(10))

	cases := []struct {
		name  string
		k     *big.Int
		limit WidthLimit
	}{
		{"admitted-W128", admitted, Width128},
		{"ordinary-fallback-W128", ordinaryFallback, Width128},
		{"pathological-fallback-W136", pathological, Width136},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			var result Selection
			for i := 0; i < b.N; i++ {
				result = Select(tc.k, tc.limit)
			}
			benchmarkSelection = result
			b.ReportMetric(float64(result.Candidate.BitLen()), "candidate_bits")
		})
	}
}

func BenchmarkSelectFixed(b *testing.B) {
	admitted := benchmarkChallenge(func(s Selection) bool { return s.UseCandidate })
	ordinaryFallback := benchmarkChallenge(func(s Selection) bool {
		return !s.UseCandidate && s.Fallback == FallbackWidthExceeded
	})
	n := Modulus()
	pathological := new(big.Int).Sub(n, big.NewInt(2))
	pathological.Quo(pathological, big.NewInt(10))

	cases := []struct {
		name  string
		k     *big.Int
		limit WidthLimit
	}{
		{"admitted-W128", admitted, Width128},
		{"ordinary-fallback-W128", ordinaryFallback, Width128},
		{"pathological-fallback-W136", pathological, Width136},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			encoded := bigToLittle32(b, tc.k)
			b.ReportAllocs()
			b.ResetTimer()
			var result FixedSelection
			for i := 0; i < b.N; i++ {
				result = SelectFixed(encoded, tc.limit)
			}
			benchmarkFixedSelection = result
			b.ReportMetric(float64(result.Candidate.BitLen()), "candidate_bits")
		})
	}
}

func BenchmarkSelectFixedDivider(b *testing.B) {
	k := benchmarkChallenge(func(s Selection) bool { return s.UseCandidate })
	encoded := bigToLittle32(b, k)
	kFixed := uint256FromBytesLE(encoded)
	cases := []struct {
		name            string
		selectCandidate func(uint256) FixedSelection
	}{
		{"aligned", func(k uint256) FixedSelection { return selectFixed(k, Width128, divMod256) }},
		{"lehmer-lookahead", func(k uint256) FixedSelection { return selectFixedBatched(k, Width128, divMod256) }},
		{"bitwise-oracle", func(k uint256) FixedSelection { return selectFixed(k, Width128, divMod256BitwiseOracle) }},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			var result FixedSelection
			for i := 0; i < b.N; i++ {
				result = tc.selectCandidate(kFixed)
			}
			benchmarkFixedSelection = result
		})
	}
}

func BenchmarkDivMod256(b *testing.B) {
	typicalDivisor := sampledUint256(300_000)
	typicalDivisor[3] &= 0x1fffffffffffffff
	typicalDivisor[3] |= 0x1000000000000000
	inputs := []struct {
		name        string
		numerator   uint256
		denominator uint256
	}{
		{"typical-small-quotient", fixedModulus, typicalDivisor},
		{"wide-quotient", fixedModulus, uint256{1}},
	}
	dividers := []struct {
		name   string
		divide divide256
	}{
		{"aligned", divMod256},
		{"bitwise-oracle", divMod256BitwiseOracle},
	}
	for _, input := range inputs {
		b.Run(input.name, func(b *testing.B) {
			for _, divider := range dividers {
				b.Run(divider.name, func(b *testing.B) {
					var quotient, remainder uint256
					for i := 0; i < b.N; i++ {
						quotient, remainder = divider.divide(input.numerator, input.denominator)
					}
					benchmarkFixedSelection.Candidate.Rho.Limbs = quotient
					benchmarkFixedSelection.Candidate.Tau.Limbs = remainder
				})
			}
		})
	}
}

func benchmarkChallenge(accept func(Selection) bool) *big.Int {
	l := Order()
	for i := uint64(0); ; i++ {
		k := sampledChallenge(i, l)
		selection := Select(k, Width128)
		if accept(selection) {
			return k
		}
	}
}
