package heea8l

import (
	"math/big"
	"testing"
)

func TestSelectShiftSubtractExactRelation(t *testing.T) {
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
			got := SelectShiftSubtract(encoded, limit)
			oracle := SelectFixed(encoded, limit)
			if got.UseCandidate {
				if got.Fallback != NoFallback {
					t.Fatalf("%s width %d: admitted with fallback %v", label, limit, got.Fallback)
				}
				if got.Candidate.BitLen() > int(limit) {
					t.Fatalf("%s width %d: admitted %d-bit candidate", label, limit, got.Candidate.BitLen())
				}
				checkFixedCandidate(t, n, k, got.Candidate)
				if !oracle.UseCandidate {
					t.Fatalf("%s width %d: fast selector found a candidate missed by exact oracle", label, limit)
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

	for i, k := range edges {
		check("edge-"+big.NewInt(int64(i)).String(), k)
	}
	for i := uint64(0); i < 4096; i++ {
		check("sample-"+new(big.Int).SetUint64(i).String(), sampledChallenge(700_000+i, l))
	}
}

func TestSelectShiftSubtractFallbacksAndPathologicalChallenge(t *testing.T) {
	one := bigToLittle32(t, big.NewInt(1))
	if got := SelectShiftSubtract(one, WidthLimit(129)); got.UseCandidate || got.Fallback != FallbackInvalidWidth {
		t.Fatalf("invalid width selection=%+v", got)
	}
	for name, k := range map[string]*big.Int{
		"order":        Order(),
		"modulus":      Modulus(),
		"order-plus-1": new(big.Int).Add(Order(), big.NewInt(1)),
		"all-ones":     new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1)),
	} {
		got := SelectShiftSubtract(bigToLittle32(t, k), Width128)
		if got.UseCandidate || got.Fallback != FallbackInvalidChallenge {
			t.Fatalf("%s: selection=%+v", name, got)
		}
	}

	n := Modulus()
	pathological := new(big.Int).Sub(n, big.NewInt(2))
	pathological.Quo(pathological, big.NewInt(10))
	encoded := bigToLittle32(t, pathological)
	for _, width := range []WidthLimit{Width128, Width132, Width136} {
		got := SelectShiftSubtract(encoded, width)
		if got.UseCandidate || got.Fallback != FallbackWidthExceeded {
			t.Fatalf("pathological challenge admitted at width %d: %+v", width, got)
		}
	}
}

func TestShiftSubtractFiveLimbArithmeticAgainstBig(t *testing.T) {
	mod320 := new(big.Int).Lsh(big.NewInt(1), 320)
	for i := uint64(0); i < 4096; i++ {
		x := sampledSigned320(800_000 + 2*i)
		y := sampledSigned320(800_000 + 2*i + 1)
		shift := uint(i % 64)

		got, ok := subShifted320(x, y, shift)
		want := signed320Big(x)
		shifted := new(big.Int).Lsh(signed320Big(y), shift)
		want.Sub(want, shifted)
		fits := new(big.Int).Abs(new(big.Int).Set(want)).Cmp(mod320) < 0
		if ok != fits {
			t.Fatalf("sample %d: ok=%v want fits=%v", i, ok, fits)
		}
		if ok && signed320Big(got).Cmp(want) != 0 {
			t.Fatalf("sample %d: got %s want %s", i, signed320Big(got), want)
		}
	}
}

// TestShiftSubtractDeterminantAndRange checks the invariant used to justify
// the fixed width. For positive adjacent remainders with opposite signed
// coefficients,
//
//	|r0*t1-r1*t0| = N
//
// implies r0*|t1|+r1*|t0|=N, hence each coefficient is at most N. The
// power-of-two update preserves the determinant and strictly lowers the
// updated remainder's bit length.
func TestShiftSubtractDeterminantAndRange(t *testing.T) {
	n := Modulus()
	l := Order()
	for sample := uint64(0); sample < 1024; sample++ {
		kBig := sampledChallenge(900_000+sample, l)
		k := bigToUint256(t, kBig)
		if k.isZero() {
			continue
		}
		rows := [2]shiftSubtractRow{
			{rho: fixedModulus},
			{rho: k, tau: signed320FromUint64(1)},
		}
		for step := 0; !rows[0].rho.isZero() && !rows[1].rho.isZero(); step++ {
			if step >= 512 {
				t.Fatalf("sample %d: exceeded 512-step bound", sample)
			}
			checkShiftSubtractRows(t, n, kBig, rows)

			larger, smaller := 0, 1
			if rows[0].rho.cmp(rows[1].rho) < 0 {
				larger, smaller = 1, 0
			}
			oldBits := rows[larger].rho.bitLen()
			shift := oldBits - rows[smaller].rho.bitLen()
			shifted := shl256(rows[smaller].rho, uint(shift))
			if shifted.cmp(rows[larger].rho) > 0 {
				shift--
				shifted = shl256(rows[smaller].rho, uint(shift))
			}
			nextRho, borrow := sub256(rows[larger].rho, shifted)
			if borrow != 0 || nextRho.bitLen() >= oldBits {
				t.Fatalf("sample %d step %d: remainder did not shrink", sample, step)
			}
			nextTau, ok := subShifted320(rows[larger].tau, rows[smaller].tau, uint(shift))
			if !ok || nextTau.mag[4] != 0 {
				t.Fatalf("sample %d step %d: coefficient overflow: %+v", sample, step, nextTau)
			}
			rows[larger] = shiftSubtractRow{rho: nextRho, tau: nextTau}
		}
		checkShiftSubtractRows(t, n, kBig, rows)
	}
}

func TestShiftSubtractMixedTorsionDiscriminator(t *testing.T) {
	l := Order()
	n := Modulus()
	for sample := uint64(0); sample < 256; sample++ {
		k := sampledChallenge(1_000_000+sample, l)
		selection := SelectShiftSubtract(bigToLittle32(t, k), Width136)
		if !selection.UseCandidate {
			continue
		}
		checkFixedCandidate(t, n, k, selection.Candidate)
		tau := fixedSignedBig(selection.Candidate.Tau)
		rho := fixedSignedBig(selection.Candidate.Rho)

		// Product-group model of mixed-order A and R. Both have nonzero
		// prime-order components, while their torsion coordinates vary.
		aPrime := new(big.Int).Add(big.NewInt(1), new(big.Int).SetUint64(sample))
		aPrime.Mod(aPrime, l)
		rPrime := new(big.Int).Add(big.NewInt(9), new(big.Int).SetUint64(3*sample))
		rPrime.Mod(rPrime, l)
		aTorsion := int(sample & 7)
		rTorsion := int((3*sample + 1) & 7)
		s := new(big.Int).SetUint64(11*sample + 5)
		s.Mod(s, l)

		errorPrime := new(big.Int).Mul(k, aPrime)
		errorPrime.Add(errorPrime, rPrime)
		errorPrime.Sub(s, errorPrime)
		errorPrime.Mod(errorPrime, l)
		errorTorsion := mod8(-rTorsion - mod8BigTimesInt(k, aTorsion))

		transformedPrime := new(big.Int).Mul(tau, s)
		term := new(big.Int).Mul(tau, rPrime)
		transformedPrime.Sub(transformedPrime, term)
		term.Mul(rho, aPrime)
		if selection.Candidate.Epsilon < 0 {
			term.Neg(term)
		}
		transformedPrime.Sub(transformedPrime, term)
		transformedPrime.Mod(transformedPrime, l)

		transformedTorsion := mod8(-mod8BigTimesInt(tau, rTorsion) -
			int(selection.Candidate.Epsilon)*mod8BigTimesInt(rho, aTorsion))
		wantPrime := new(big.Int).Mul(tau, errorPrime)
		wantPrime.Mod(wantPrime, l)
		wantTorsion := mod8BigTimesInt(tau, errorTorsion)
		if transformedPrime.Cmp(wantPrime) != 0 || transformedTorsion != wantTorsion {
			t.Fatalf("sample %d: transformed=(%s,%d) want tau*error=(%s,%d)",
				sample, transformedPrime, transformedTorsion, wantPrime, wantTorsion)
		}

		// Odd tau cannot erase any nonzero pure-torsion error.
		for torsionError := 1; torsionError < 8; torsionError++ {
			if mod8BigTimesInt(tau, torsionError) == 0 {
				t.Fatalf("sample %d: odd tau=%s erased torsion error %d", sample, tau, torsionError)
			}
		}
	}
}

func checkShiftSubtractRows(t *testing.T, n, k *big.Int, rows [2]shiftSubtractRow) {
	t.Helper()
	for index, row := range rows {
		if row.tau.mag[4] != 0 || row.tau.bitLen() > 256 {
			t.Fatalf("row %d coefficient exceeded 256 bits: %s", index, signed320Big(row.tau))
		}
		delta := new(big.Int).Mul(signed320Big(row.tau), k)
		delta.Sub(uint256Big(row.rho), delta)
		delta.Mod(delta, n)
		if delta.Sign() != 0 {
			t.Fatalf("row %d relation failed", index)
		}
	}
	determinant := new(big.Int).Mul(uint256Big(rows[0].rho), signed320Big(rows[1].tau))
	term := new(big.Int).Mul(uint256Big(rows[1].rho), signed320Big(rows[0].tau))
	determinant.Sub(determinant, term)
	determinant.Abs(determinant)
	if determinant.Cmp(n) != 0 {
		t.Fatalf("determinant=%s want N=%s", determinant, n)
	}
}

func sampledSigned320(counter uint64) signed320 {
	low := sampledUint256(counter)
	high := sampledUint256(counter + 1)[0]
	return signed320{
		mag: [5]uint64{low[0], low[1], low[2], low[3], high},
		neg: counter&1 != 0,
	}
}

func signed320Big(x signed320) *big.Int {
	result := new(big.Int)
	for i := len(x.mag) - 1; i >= 0; i-- {
		result.Lsh(result, 64)
		result.Add(result, new(big.Int).SetUint64(x.mag[i]))
	}
	if x.neg && result.Sign() != 0 {
		result.Neg(result)
	}
	return result
}

func mod8(x int) int {
	x %= 8
	if x < 0 {
		x += 8
	}
	return x
}

func mod8BigTimesInt(x *big.Int, y int) int {
	x8 := new(big.Int).Mod(new(big.Int).Set(x), big.NewInt(8)).Int64()
	return mod8(int(x8) * y)
}

func TestShiftSubtractCoverageSnapshot(t *testing.T) {
	const samples = 8192
	l := Order()
	fastFallbacks := map[WidthLimit]int{Width128: 0, Width132: 0, Width136: 0}
	oracleFallbacks := map[WidthLimit]int{Width128: 0, Width132: 0, Width136: 0}
	for i := uint64(0); i < samples; i++ {
		encoded := bigToLittle32(t, sampledChallenge(1_100_000+i, l))
		for _, width := range []WidthLimit{Width128, Width132, Width136} {
			if !SelectShiftSubtract(encoded, width).UseCandidate {
				fastFallbacks[width]++
			}
			if !SelectFixed(encoded, width).UseCandidate {
				oracleFallbacks[width]++
			}
		}
	}
	t.Logf("division-free fallbacks=%v exact-oracle fallbacks=%v", fastFallbacks, oracleFallbacks)
	wantFast := map[WidthLimit]int{Width128: 1184, Width132: 6, Width136: 0}
	wantOracle := map[WidthLimit]int{Width128: 868, Width132: 6, Width136: 0}
	for _, width := range []WidthLimit{Width128, Width132, Width136} {
		if fastFallbacks[width] != wantFast[width] || oracleFallbacks[width] != wantOracle[width] {
			t.Fatalf("width %d fallbacks: fast=%d want %d, oracle=%d want %d",
				width, fastFallbacks[width], wantFast[width], oracleFallbacks[width], wantOracle[width])
		}
	}
	if fastFallbacks[Width128] < fastFallbacks[Width132] || fastFallbacks[Width132] < fastFallbacks[Width136] {
		t.Fatalf("fallback counts are not monotone: %v", fastFallbacks)
	}
}

func FuzzSelectShiftSubtract(f *testing.F) {
	l := Order()
	for i := uint64(0); i < 16; i++ {
		encoded := bigToLittle32(f, sampledChallenge(1_300_000+i, l))
		f.Add(encoded[:])
	}
	for _, k := range []*big.Int{
		big.NewInt(0),
		big.NewInt(1),
		new(big.Int).Sub(new(big.Int).Set(l), big.NewInt(1)),
	} {
		encoded := bigToLittle32(f, k)
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
			for _, width := range []WidthLimit{Width128, Width132, Width136} {
				got := SelectShiftSubtract(encoded, width)
				if got.UseCandidate || got.Fallback != FallbackInvalidChallenge {
					t.Fatalf("noncanonical challenge admitted at width %d: %+v", width, got)
				}
			}
			return
		}

		k := little32Big(encoded)
		for _, width := range []WidthLimit{Width128, Width132, Width136} {
			got := SelectShiftSubtract(encoded, width)
			if !got.UseCandidate {
				if got.Fallback != FallbackWidthExceeded {
					t.Fatalf("width %d fallback=%v", width, got.Fallback)
				}
				continue
			}
			if got.Candidate.BitLen() > int(width) {
				t.Fatalf("width %d admitted %d-bit candidate", width, got.Candidate.BitLen())
			}
			checkFixedCandidate(t, Modulus(), k, got.Candidate)
			if oracle := SelectFixed(encoded, width); !oracle.UseCandidate {
				t.Fatalf("width %d: fast candidate missed by exact oracle", width)
			}
		}
	})
}

func little32Big(input [32]byte) *big.Int {
	var reversed [32]byte
	for i := range input {
		reversed[len(input)-1-i] = input[i]
	}
	return new(big.Int).SetBytes(reversed[:])
}

var benchmarkShiftSubtractSelection FixedSelection

func BenchmarkSelectShiftSubtract(b *testing.B) {
	l := Order()
	admitted := bigToLittle32(b, sampledChallenge(1_200_000, l))
	n := Modulus()
	pathological := new(big.Int).Sub(n, big.NewInt(2))
	pathological.Quo(pathological, big.NewInt(10))
	fallback := bigToLittle32(b, pathological)
	// Include an ordinary deterministic W128 miss in addition to the admitted
	// case. The benchmark reports all three admission widths because a wider
	// gate can stop at an earlier row.
	var longSchedule [32]byte
	for i := uint64(0); ; i++ {
		candidate := bigToLittle32(b, sampledChallenge(1_200_001+i, l))
		if !SelectShiftSubtract(candidate, Width128).UseCandidate {
			longSchedule = candidate
			break
		}
	}

	for _, tc := range []struct {
		name  string
		k     [32]byte
		limit WidthLimit
	}{
		{name: "ordinary-W128", k: admitted, limit: Width128},
		{name: "ordinary-W132", k: admitted, limit: Width132},
		{name: "ordinary-W136", k: admitted, limit: Width136},
		{name: "long-schedule-W128", k: longSchedule, limit: Width128},
		{name: "long-schedule-W132", k: longSchedule, limit: Width132},
		{name: "long-schedule-W136", k: longSchedule, limit: Width136},
		{name: "pathological-fallback-W128", k: fallback, limit: Width128},
		{name: "pathological-fallback-W132", k: fallback, limit: Width132},
		{name: "pathological-fallback-W136", k: fallback, limit: Width136},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			var result FixedSelection
			for i := 0; i < b.N; i++ {
				result = SelectShiftSubtract(tc.k, tc.limit)
			}
			benchmarkShiftSubtractSelection = result
			b.ReportMetric(float64(result.Candidate.BitLen()), "candidate_bits")
		})
	}
}
