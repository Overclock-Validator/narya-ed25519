package heea8l

import (
	"math/big"
	"testing"
)

func TestSelectEuclidPrincipalExactRelation(t *testing.T) {
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
			got := SelectEuclidPrincipal(encoded, limit)
			lookahead, _ := selectEuclidPrincipalLookahead(uint256FromBytesLE(encoded), limit)
			if got != lookahead {
				t.Fatalf("%s width %d: exact-divider=%+v lookahead=%+v", label, limit, got, lookahead)
			}
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
					t.Fatalf("%s width %d: principal selector found a candidate missed by exact oracle", label, limit)
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
	for i := uint64(0); i < 8192; i++ {
		check("sample-"+new(big.Int).SetUint64(i).String(), sampledChallenge(1_200_000+i, l))
	}
}

func TestSelectEuclidPrincipalFallbacksAndIterationCap(t *testing.T) {
	one := bigToLittle32(t, big.NewInt(1))
	if got := SelectEuclidPrincipal(one, WidthLimit(129)); got.UseCandidate || got.Fallback != FallbackInvalidWidth {
		t.Fatalf("invalid width selection=%+v", got)
	}
	for name, k := range map[string]*big.Int{
		"order":        Order(),
		"modulus":      Modulus(),
		"order-plus-1": new(big.Int).Add(Order(), big.NewInt(1)),
		"all-ones":     new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1)),
	} {
		got := SelectEuclidPrincipal(bigToLittle32(t, k), Width128)
		if got.UseCandidate || got.Fallback != FallbackInvalidChallenge {
			t.Fatalf("%s: selection=%+v", name, got)
		}
	}

	l := Order()
	for i := uint64(0); i < 8192; i++ {
		k := bigToUint256(t, sampledChallenge(1_300_000+i, l))
		selection, stats := selectEuclidPrincipal(k, Width136)
		if stats.HitCap || stats.Iterations >= principalEuclidIterationCap {
			t.Fatalf("sample %d reached defensive cap: selection=%+v stats=%+v", i, selection, stats)
		}
	}
}

func TestPrincipalEuclidSignedUint64ArithmeticAgainstBig(t *testing.T) {
	mod320 := new(big.Int).Lsh(big.NewInt(1), 320)
	for i := uint64(0); i < 8192; i++ {
		x := sampledSigned320(1_400_000 + 2*i)
		y := sampledSigned320(1_400_000 + 2*i + 1)
		multiplier := sampledUint256(1_500_000 + i)[0]

		gotProduct, productOK := mulSigned320Uint64(y, multiplier)
		wantProduct := new(big.Int).Mul(signed320Big(y), new(big.Int).SetUint64(multiplier))
		productFits := new(big.Int).Abs(new(big.Int).Set(wantProduct)).Cmp(mod320) < 0
		if productOK != productFits {
			t.Fatalf("sample %d product ok=%v want=%v", i, productOK, productFits)
		}
		if productOK && signed320Big(gotProduct).Cmp(wantProduct) != 0 {
			t.Fatalf("sample %d product=%s want=%s", i, signed320Big(gotProduct), wantProduct)
		}

		got, ok := subMulUint64Signed320(x, y, multiplier)
		want := new(big.Int).Sub(signed320Big(x), wantProduct)
		fits := new(big.Int).Abs(new(big.Int).Set(want)).Cmp(mod320) < 0
		if ok != fits {
			t.Fatalf("sample %d subtract ok=%v want=%v", i, ok, fits)
		}
		if ok && signed320Big(got).Cmp(want) != 0 {
			t.Fatalf("sample %d subtract=%s want=%s", i, signed320Big(got), want)
		}
	}
}

func TestUnitMultiplierChecksBothCofactorAndPrimeOrder(t *testing.T) {
	fromUint256 := func(x uint256) signed320 {
		return signed320{mag: [5]uint64{x[0], x[1], x[2], x[3]}}
	}
	if !unitMultiplier320(signed320FromUint64(1)) || !unitMultiplier320(signed320FromUint64(3)) {
		t.Fatal("ordinary odd units were rejected")
	}
	if unitMultiplier320(signed320FromUint64(0)) || unitMultiplier320(signed320FromUint64(2)) {
		t.Fatal("zero/even non-units were accepted")
	}
	if unitMultiplier320(fromUint256(fixedOrder)) {
		t.Fatal("L is odd but not a unit modulo 8L")
	}
	threeL, carry := add256(fixedOrder, fixedOrder)
	if carry != 0 {
		t.Fatal("2L overflowed")
	}
	threeL, carry = add256(threeL, fixedOrder)
	if carry != 0 || unitMultiplier320(fromUint256(threeL)) {
		t.Fatal("3L was accepted as a unit modulo 8L")
	}

	// Model the full Edwards group exponent as Z/L x Z/8. D=(0,4) is
	// order-two: strict rejects it, while every even multiplier erases it.
	if scaledErrorIsZero(big.NewInt(2), big.NewInt(0), 4) != true {
		t.Fatal("even multiplier did not erase the deterministic order-two error")
	}
	if scaledErrorIsZero(big.NewInt(3), big.NewInt(0), 4) {
		t.Fatal("unit multiplier erased the deterministic order-two error")
	}
	// D=(1,0) is prime-order. c0=L is odd, but still erases D.
	if !scaledErrorIsZero(Order(), big.NewInt(1), 0) {
		t.Fatal("L did not erase the deterministic prime-order error")
	}
}

func TestEuclidPrincipalCoverageSnapshot(t *testing.T) {
	const samples = 8192
	l := Order()
	principalFallbacks := map[WidthLimit]int{Width128: 0, Width132: 0, Width136: 0}
	shiftFallbacks := map[WidthLimit]int{Width128: 0, Width132: 0, Width136: 0}
	oracleFallbacks := map[WidthLimit]int{Width128: 0, Width132: 0, Width136: 0}
	for i := uint64(0); i < samples; i++ {
		encoded := bigToLittle32(t, sampledChallenge(1_600_000+i, l))
		for _, width := range []WidthLimit{Width128, Width132, Width136} {
			if !SelectEuclidPrincipal(encoded, width).UseCandidate {
				principalFallbacks[width]++
			}
			if !SelectShiftSubtract(encoded, width).UseCandidate {
				shiftFallbacks[width]++
			}
			if !SelectFixed(encoded, width).UseCandidate {
				oracleFallbacks[width]++
			}
		}
	}
	t.Logf("principal fallbacks=%v shift/subtract fallbacks=%v exact-oracle fallbacks=%v",
		principalFallbacks, shiftFallbacks, oracleFallbacks)
	for _, width := range []WidthLimit{Width128, Width132, Width136} {
		if principalFallbacks[width] < oracleFallbacks[width] {
			t.Fatalf("width %d principal selector beat the exact oracle: principal=%d oracle=%d",
				width, principalFallbacks[width], oracleFallbacks[width])
		}
	}
	if principalFallbacks[Width128] < principalFallbacks[Width132] ||
		principalFallbacks[Width132] < principalFallbacks[Width136] {
		t.Fatalf("principal fallback counts are not monotone: %v", principalFallbacks)
	}
}

func FuzzSelectEuclidPrincipal(f *testing.F) {
	l := Order()
	for i := uint64(0); i < 16; i++ {
		encoded := bigToLittle32(f, sampledChallenge(1_700_000+i, l))
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
				got := SelectEuclidPrincipal(encoded, width)
				if got.UseCandidate || got.Fallback != FallbackInvalidChallenge {
					t.Fatalf("noncanonical challenge admitted at width %d: %+v", width, got)
				}
			}
			return
		}

		k := little32Big(encoded)
		for _, width := range []WidthLimit{Width128, Width132, Width136} {
			got := SelectEuclidPrincipal(encoded, width)
			lookahead, _ := selectEuclidPrincipalLookahead(kFixed, width)
			if got != lookahead {
				t.Fatalf("width %d exact-divider=%+v lookahead=%+v", width, got, lookahead)
			}
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
				t.Fatalf("width %d: principal candidate missed by exact oracle", width)
			}
		}
	})
}

func scaledErrorIsZero(multiplier, prime *big.Int, torsion int) bool {
	primePart := new(big.Int).Mul(multiplier, prime)
	primePart.Mod(primePart, Order())
	torsionPart := new(big.Int).Mul(multiplier, big.NewInt(int64(torsion)))
	torsionPart.Mod(torsionPart, big.NewInt(8))
	return primePart.Sign() == 0 && torsionPart.Sign() == 0
}
