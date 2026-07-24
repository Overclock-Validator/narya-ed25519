package heea8l

import (
	"crypto/sha512"
	"encoding/binary"
	"math/big"
	"testing"
)

func TestSelectFixedMatchesBigOracle(t *testing.T) {
	l := Order()
	n := Modulus()
	pathological := new(big.Int).Sub(n, big.NewInt(2))
	pathological.Quo(pathological, big.NewInt(10))
	edges := []*big.Int{
		big.NewInt(0),
		big.NewInt(1),
		big.NewInt(2),
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
		for _, limit := range []WidthLimit{Width128, Width132, Width136} {
			want := Select(k, limit)
			got := SelectFixed(encoded, limit)
			compareSelections(t, label, k, limit, got, want)
			bitwise := selectFixed(uint256FromBytesLE(encoded), limit, divMod256BitwiseOracle)
			if got != bitwise {
				t.Fatalf("%s k=%s limit=%d: aligned selection=%+v bitwise=%+v", label, k, limit, got, bitwise)
			}
			batched := selectFixedBatched(uint256FromBytesLE(encoded), limit, divMod256)
			if got != batched {
				t.Fatalf("%s k=%s limit=%d: aligned selection=%+v batched=%+v", label, k, limit, got, batched)
			}
			checkFixedCandidate(t, n, k, got.Candidate)
		}
	}

	for i, k := range edges {
		check("edge-"+new(big.Int).SetInt64(int64(i)).String(), k)
	}
	for i := uint64(0); i < 2048; i++ {
		check("sample-"+new(big.Int).SetUint64(i).String(), sampledChallenge(50_000+i, l))
	}
}

func TestSelectFixedBatchedLargeCorpus(t *testing.T) {
	const samples = 8192
	l := Order()
	for i := uint64(0); i < samples; i++ {
		kBig := sampledChallenge(400_000+i, l)
		k := bigToUint256(t, kBig)
		aligned, alignedOK := bestFixedForModulus(fixedModulus, k, divMod256, false)
		batched, batchedOK := bestFixedForModulus(fixedModulus, k, divMod256, true)
		bitwise, bitwiseOK := bestFixedForModulus(fixedModulus, k, divMod256BitwiseOracle, false)
		oracle, oracleOK := bestForModulus(ed25519Exponent, kBig)
		if !alignedOK || alignedOK != batchedOK || alignedOK != bitwiseOK || alignedOK != oracleOK {
			t.Fatalf("sample %d: found flags aligned=%v batched=%v bitwise=%v big=%v", i, alignedOK, batchedOK, bitwiseOK, oracleOK)
		}
		if aligned != batched || aligned != bitwise {
			t.Fatalf("sample %d: fixed candidates differ: aligned=%+v batched=%+v bitwise=%+v", i, aligned, batched, bitwise)
		}
		compareFixedCandidateToBig(t, i, aligned, oracle)
	}
}

func TestSelectFixedBatchedSmallModuliExhaustive(t *testing.T) {
	for _, smallL := range []uint64{3, 5, 7, 11, 13, 17, 19, 23, 29, 31} {
		nBig := new(big.Int).SetUint64(8 * smallL)
		n := uint256{8 * smallL}
		for kval := uint64(0); kval < smallL; kval++ {
			kBig := new(big.Int).SetUint64(kval)
			k := uint256{kval}
			aligned, alignedOK := bestFixedForModulus(n, k, divMod256, false)
			batched, batchedOK := bestFixedForModulus(n, k, divMod256, true)
			bitwise, bitwiseOK := bestFixedForModulus(n, k, divMod256BitwiseOracle, false)
			oracle, oracleOK := bestForModulus(nBig, kBig)
			if alignedOK != batchedOK || alignedOK != bitwiseOK || alignedOK != oracleOK || aligned != batched || aligned != bitwise {
				t.Fatalf("L=%d k=%d: aligned=(%+v,%v) batched=(%+v,%v) bitwise=(%+v,%v) big=%v",
					smallL, kval, aligned, alignedOK, batched, batchedOK, bitwise, bitwiseOK, oracleOK)
			}
			compareFixedCandidateToBig(t, kval, aligned, oracle)
		}
	}
}

func TestQuotientLookaheadRejectsUnsafeProposal(t *testing.T) {
	numerator := uint256{100}
	denominator := uint256{7}
	wantQuotient, wantRemainder := divMod256(numerator, denominator)
	for _, proposal := range []uint64{13, 15} {
		lookahead := quotientLookahead{values: [8]uint64{proposal}, count: 1}
		quotient, remainder := lookahead.next(numerator, denominator, divMod256)
		if quotient != wantQuotient || remainder != wantRemainder {
			t.Fatalf("proposal %d: got (%v,%v), want (%v,%v)", proposal, quotient, remainder, wantQuotient, wantRemainder)
		}
		if lookahead.nextAt != 0 || lookahead.count != 0 {
			t.Fatalf("proposal %d: unsafe queue was not discarded: %+v", proposal, lookahead)
		}
	}
}

func TestDivMod256AllDivisorWidths(t *testing.T) {
	two256 := new(big.Int).Lsh(big.NewInt(1), 256)
	max := new(big.Int).Sub(new(big.Int).Set(two256), big.NewInt(1))
	for width := 1; width <= 256; width++ {
		top := new(big.Int).Lsh(big.NewInt(1), uint(width-1))
		mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(width)), big.NewInt(1))
		pattern := uint256Big(sampledUint256(uint64(90_000 + width)))
		pattern.And(pattern, mask)
		pattern.SetBit(pattern, width-1, 1)

		divisors := []*big.Int{
			new(big.Int).Set(top),
			new(big.Int).SetBit(new(big.Int).Set(top), 0, 1),
			new(big.Int).Set(mask),
			pattern,
		}
		seenDivisors := make(map[uint256]struct{}, len(divisors))
		for _, divisorBig := range divisors {
			divisor := bigToUint256(t, divisorBig)
			if _, duplicate := seenDivisors[divisor]; duplicate {
				continue
			}
			seenDivisors[divisor] = struct{}{}
			if divisor.bitLen() != width {
				t.Fatalf("width %d: divisor has width %d", width, divisor.bitLen())
			}

			numerators := []*big.Int{
				big.NewInt(0),
				new(big.Int).Sub(new(big.Int).Set(divisorBig), big.NewInt(1)),
				new(big.Int).Set(divisorBig),
				new(big.Int).Set(max),
				new(big.Int).Sub(new(big.Int).Set(max), divisorBig),
				uint256Big(sampledUint256(uint64(100_000 + width))),
			}
			if divisorBig.Cmp(max) < 0 {
				numerators = append(numerators, new(big.Int).Add(new(big.Int).Set(divisorBig), big.NewInt(1)))
			}
			twiceMinusOne := new(big.Int).Lsh(new(big.Int).Set(divisorBig), 1)
			twiceMinusOne.Sub(twiceMinusOne, big.NewInt(1))
			if twiceMinusOne.Cmp(two256) < 0 {
				numerators = append(numerators, twiceMinusOne)
			}

			seenNumerators := make(map[uint256]struct{}, len(numerators))
			for _, numeratorBig := range numerators {
				numerator := bigToUint256(t, numeratorBig)
				if _, duplicate := seenNumerators[numerator]; duplicate {
					continue
				}
				seenNumerators[numerator] = struct{}{}
				checkDivisionAgainstOracles(t, numerator, divisor)
			}
		}
	}
}

func TestDivMod256RandomAgainstOracles(t *testing.T) {
	for i := uint64(0); i < 4096; i++ {
		numerator := sampledUint256(200_000 + 2*i)
		denominator := sampledUint256(200_000 + 2*i + 1)
		if denominator.isZero() {
			denominator[0] = 1
		}
		checkDivisionAgainstOracles(t, numerator, denominator)
	}
}

func TestSelectFixedExplicitFallbacks(t *testing.T) {
	one := bigToLittle32(t, big.NewInt(1))
	if got := SelectFixed(one, WidthLimit(129)); got.UseCandidate || got.Fallback != FallbackInvalidWidth {
		t.Fatalf("invalid width selection = %+v", got)
	}

	for name, k := range map[string]*big.Int{
		"order":        Order(),
		"modulus":      Modulus(),
		"all-ones":     new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1)),
		"order-plus-1": new(big.Int).Add(Order(), big.NewInt(1)),
	} {
		got := SelectFixed(bigToLittle32(t, k), Width128)
		if got.UseCandidate || got.Fallback != FallbackInvalidChallenge {
			t.Fatalf("%s: invalid challenge selection = %+v", name, got)
		}
	}
}

func TestFixedArithmeticAgainstBig(t *testing.T) {
	mod256 := new(big.Int).Lsh(big.NewInt(1), 256)
	for i := uint64(0); i < 2048; i++ {
		x := sampledUint256(2 * i)
		y := sampledUint256(2*i + 1)
		xBig := uint256Big(x)
		yBig := uint256Big(y)

		sum, carry := add256(x, y)
		wantSum := new(big.Int).Add(xBig, yBig)
		wantCarry := wantSum.Cmp(mod256) >= 0
		wantSum.Mod(wantSum, mod256)
		if uint256Big(sum).Cmp(wantSum) != 0 || (carry != 0) != wantCarry {
			t.Fatalf("sample %d: add mismatch", i)
		}

		if x.cmp(y) >= 0 {
			difference, borrow := sub256(x, y)
			if borrow != 0 || uint256Big(difference).Cmp(new(big.Int).Sub(xBig, yBig)) != 0 {
				t.Fatalf("sample %d: subtract mismatch", i)
			}
		}

		denominator := y
		if denominator.isZero() {
			denominator[0] = 1
			yBig.SetInt64(1)
		}
		quotient, remainder := divMod256(x, denominator)
		wantQuotient := new(big.Int)
		wantRemainder := new(big.Int)
		wantQuotient.QuoRem(xBig, yBig, wantRemainder)
		if uint256Big(quotient).Cmp(wantQuotient) != 0 || uint256Big(remainder).Cmp(wantRemainder) != 0 {
			t.Fatalf("sample %d: division mismatch", i)
		}

		product, overflow := mul256(x, y)
		wantProduct := new(big.Int).Mul(xBig, yBig)
		wantOverflow := wantProduct.Cmp(mod256) >= 0
		wantProduct.Mod(wantProduct, mod256)
		if overflow != wantOverflow || uint256Big(product).Cmp(wantProduct) != 0 {
			t.Fatalf("sample %d: multiplication mismatch", i)
		}
	}

	max := uint256{^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)}
	if _, overflow := mul256(max, uint256{2}); !overflow {
		t.Fatal("overflowing multiplication was not reported")
	}
}

func TestFixedSignedCoefficientEncoding(t *testing.T) {
	x := SignedCoefficient{
		Limbs:    [4]uint64{0x0123456789abcdef, 0xfedcba9876543210, 0, 1 << 7},
		Negative: true,
	}
	if x.Sign() != -1 || x.BitLen() != 200 {
		t.Fatalf("sign=%d bitlen=%d", x.Sign(), x.BitLen())
	}
	encoded := x.BytesLE()
	if got := binary.LittleEndian.Uint64(encoded[:8]); got != x.Limbs[0] {
		t.Fatalf("low limb=%#x want %#x", got, x.Limbs[0])
	}
	if got := binary.LittleEndian.Uint64(encoded[24:]); got != x.Limbs[3] {
		t.Fatalf("high limb=%#x want %#x", got, x.Limbs[3])
	}
	if got := (SignedCoefficient{Negative: true}).Sign(); got != 0 {
		t.Fatalf("negative zero sign=%d want 0", got)
	}
}

func compareSelections(t *testing.T, label string, k *big.Int, limit WidthLimit, got FixedSelection, want Selection) {
	t.Helper()
	if got.UseCandidate != want.UseCandidate || got.Fallback != want.Fallback {
		t.Fatalf("%s k=%s limit=%d: fixed admission=(%v,%v), oracle=(%v,%v)",
			label, k, limit, got.UseCandidate, got.Fallback, want.UseCandidate, want.Fallback)
	}
	if got.Candidate.Epsilon != want.Candidate.Epsilon ||
		fixedSignedBig(got.Candidate.Rho).Cmp(&want.Candidate.Rho) != 0 ||
		fixedSignedBig(got.Candidate.Tau).Cmp(&want.Candidate.Tau) != 0 {
		t.Fatalf("%s k=%s limit=%d: fixed candidate=(%s,%s,%d), oracle=(%s,%s,%d)",
			label, k, limit,
			fixedSignedBig(got.Candidate.Rho), fixedSignedBig(got.Candidate.Tau), got.Candidate.Epsilon,
			&want.Candidate.Rho, &want.Candidate.Tau, want.Candidate.Epsilon)
	}
	if got.Candidate.BitLen() != want.Candidate.BitLen() {
		t.Fatalf("%s k=%s limit=%d: fixed width=%d oracle=%d",
			label, k, limit, got.Candidate.BitLen(), want.Candidate.BitLen())
	}
}

func compareFixedCandidateToBig(t *testing.T, sample uint64, got fixedCandidate, want Candidate) {
	t.Helper()
	external := got.external()
	if external.Epsilon != want.Epsilon ||
		fixedSignedBig(external.Rho).Cmp(&want.Rho) != 0 ||
		fixedSignedBig(external.Tau).Cmp(&want.Tau) != 0 {
		t.Fatalf("sample %d: fixed candidate=(%s,%s,%d), big=(%s,%s,%d)", sample,
			fixedSignedBig(external.Rho), fixedSignedBig(external.Tau), external.Epsilon,
			&want.Rho, &want.Tau, want.Epsilon)
	}
}

func checkFixedCandidate(t *testing.T, n, k *big.Int, candidate FixedCandidate) {
	t.Helper()
	rho := fixedSignedBig(candidate.Rho)
	tau := fixedSignedBig(candidate.Tau)
	if candidate.Epsilon != 1 && candidate.Epsilon != -1 {
		t.Fatalf("epsilon=%d, want +/-1", candidate.Epsilon)
	}
	if tau.Sign() == 0 || tau.Bit(0) == 0 {
		t.Fatalf("tau=%s, want nonzero odd", tau)
	}
	if gcd := new(big.Int).GCD(nil, nil, new(big.Int).Abs(new(big.Int).Set(tau)), n); gcd.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("gcd(tau,N)=%s, want 1", gcd)
	}
	rhs := new(big.Int).Mul(tau, k)
	if candidate.Epsilon < 0 {
		rhs.Neg(rhs)
	}
	delta := new(big.Int).Sub(rho, rhs)
	delta.Mod(delta, n)
	if delta.Sign() != 0 {
		t.Fatalf("rho=%s is not epsilon*tau*k mod N (tau=%s epsilon=%d k=%s)",
			rho, tau, candidate.Epsilon, k)
	}
}

func sampledUint256(counter uint64) uint256 {
	var input [16]byte
	copy(input[:8], "heea-u256")
	binary.LittleEndian.PutUint64(input[8:], counter)
	digest := sha512.Sum512(input[:])
	var encoded [32]byte
	copy(encoded[:], digest[:32])
	return uint256FromBytesLE(encoded)
}

func checkDivisionAgainstOracles(t *testing.T, numerator, denominator uint256) {
	t.Helper()
	quotient, remainder := divMod256(numerator, denominator)
	oracleQuotient, oracleRemainder := divMod256BitwiseOracle(numerator, denominator)
	if quotient != oracleQuotient || remainder != oracleRemainder {
		t.Fatalf("fixed division mismatch: n=%s d=%s aligned=(%s,%s) bitwise=(%s,%s)",
			uint256Big(numerator), uint256Big(denominator),
			uint256Big(quotient), uint256Big(remainder),
			uint256Big(oracleQuotient), uint256Big(oracleRemainder))
	}

	wantQuotient := new(big.Int)
	wantRemainder := new(big.Int)
	wantQuotient.QuoRem(uint256Big(numerator), uint256Big(denominator), wantRemainder)
	if uint256Big(quotient).Cmp(wantQuotient) != 0 || uint256Big(remainder).Cmp(wantRemainder) != 0 {
		t.Fatalf("math/big division mismatch: n=%s d=%s got=(%s,%s) want=(%s,%s)",
			uint256Big(numerator), uint256Big(denominator),
			uint256Big(quotient), uint256Big(remainder), wantQuotient, wantRemainder)
	}
	if remainder.cmp(denominator) >= 0 {
		t.Fatalf("remainder %s is not below divisor %s", uint256Big(remainder), uint256Big(denominator))
	}
}

func bigToLittle32(t testing.TB, x *big.Int) (out [32]byte) {
	t.Helper()
	if x.Sign() < 0 || x.BitLen() > 256 {
		t.Fatalf("integer does not fit unsigned 256 bits: %s", x)
	}
	bytes := x.Bytes()
	for i := range bytes {
		out[i] = bytes[len(bytes)-1-i]
	}
	return out
}

func bigToUint256(t testing.TB, x *big.Int) uint256 {
	return uint256FromBytesLE(bigToLittle32(t, x))
}

func uint256Big(x uint256) *big.Int {
	var encoded [32]byte
	for i, limb := range x {
		binary.LittleEndian.PutUint64(encoded[8*i:], limb)
	}
	for i, j := 0, len(encoded)-1; i < j; i, j = i+1, j-1 {
		encoded[i], encoded[j] = encoded[j], encoded[i]
	}
	return new(big.Int).SetBytes(encoded[:])
}

func fixedSignedBig(x SignedCoefficient) *big.Int {
	result := uint256Big(uint256(x.Limbs))
	if x.Negative {
		result.Neg(result)
	}
	return result
}
