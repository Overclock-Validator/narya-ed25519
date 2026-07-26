package r43x6

import (
	"bytes"
	stdlibed25519 "crypto/ed25519"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"math/big"
	"math/rand"
	"testing"

	edwardsref "github.com/Overclock-Validator/narya-ed25519/internal/edwards25519"
)

// experimentalNAFTable is deliberately test-only. It is large enough for the
// 16 odd multiples required by a width-6 signed NAF. Keeping the experiment
// here prevents benchmark results on a non-target machine from changing the
// production width-5 selection.
type experimentalNAFTable [16]Point

func newExperimentalNAFTable(q *Point, width uint) (experimentalNAFTable, int) {
	if width < 4 || width > 6 {
		panic("r43x6: experimental variable-base NAF width must be 4, 5, or 6")
	}

	entries := 1 << (width - 2)
	var table experimentalNAFTable
	table[0].Set(q)
	var twiceQ Point
	twiceQ.Double(q)
	for i := 1; i < entries; i++ {
		table[i].Add(&table[i-1], &twiceQ)
	}
	return table, entries
}

func selectExperimentalNAF(table *experimentalNAFTable, entries int, digit int8) Point {
	negative := digit < 0
	if negative {
		digit = -digit
	}
	index := int(digit / 2)
	if digit == 0 || index >= entries {
		panic("r43x6: invalid experimental NAF digit")
	}
	result := table[index]
	if negative {
		result.Negate(&result)
	}
	return result
}

// experimentalDoubleScalarBaseMult includes construction of A's odd-multiple
// table on every call. B retains the production width-8 process-wide table.
func experimentalDoubleScalarBaseMult(a *Scalar, A *Point, b *Scalar, aWidth uint) Point {
	aTable, entries := newExperimentalNAFTable(A, aWidth)
	bTable := basepointNAFTable()
	aNAF := a.nonAdjacentForm(aWidth)
	bNAF := b.nonAdjacentForm(8)

	acc := NewIdentityPoint()
	for i := 255; i >= 0; i-- {
		acc.Double(acc)
		if aNAF[i] != 0 {
			multiple := selectExperimentalNAF(&aTable, entries, aNAF[i])
			acc.Add(acc, &multiple)
		}
		if bNAF[i] != 0 {
			multiple := selectNAF8(bTable, bNAF[i])
			acc.Add(acc, &multiple)
		}
	}
	return *acc
}

func experimentalVerifyMult(s, k *Scalar, A *Point, aWidth uint) Point {
	var minusA Point
	minusA.Negate(A)
	return experimentalDoubleScalarBaseMult(k, &minusA, s, aWidth)
}

// experimentalSignedRadix returns an exact signed-integer recoding. It does
// not reduce modulo the group order, which is essential for mixed-order input
// points. Radix 16 has 64 digits in [-8, 7] (apart from its nonnegative top
// digit); radix 32 has 51 digits in [-16, 15]. Canonical Ed25519 scalars fit in
// 253 bits, so 51 radix-32 digits cover the entire input without truncation.
func experimentalSignedRadix(s *Scalar, radixBits uint) ([64]int8, int) {
	var digits [64]int8
	var count int
	switch radixBits {
	case 4:
		count = 64
	case 5:
		count = 51
	default:
		panic("r43x6: experimental signed radix must be 16 or 32")
	}

	encoded := s.Bytes()
	mask := uint16((1 << radixBits) - 1)
	for i := 0; i < count; i++ {
		bit := uint(i) * radixBits
		byteIndex := int(bit / 8)
		shift := bit % 8
		word := uint16(encoded[byteIndex])
		if byteIndex+1 < len(encoded) {
			word |= uint16(encoded[byteIndex+1]) << 8
		}
		digits[i] = int8((word >> shift) & mask)
	}

	radix := int16(1 << radixBits)
	half := radix / 2
	for i := 0; i < count-1; i++ {
		value := int16(digits[i])
		carry := (value + half) / radix
		digits[i] = int8(value - carry*radix)
		digits[i+1] += int8(carry)
	}
	return digits, count
}

// A projective full table stores A, 2A, ..., 16A. Radix 16 uses its first
// eight entries, while radix 32 uses all 16. This intentionally models the
// straightforward scalar reference for a future lane-parallel kernel; it does
// not claim to model the cost of projective-cached SIMD additions.
type experimentalFullTable [16]Point

func newExperimentalFullTable(q *Point, radixBits uint) (experimentalFullTable, int) {
	var entries int
	switch radixBits {
	case 4:
		entries = 8
	case 5:
		entries = 16
	default:
		panic("r43x6: experimental full-table radix must be 16 or 32")
	}
	var table experimentalFullTable
	table[0].Set(q)
	for i := 1; i < entries; i++ {
		table[i].Add(&table[i-1], q)
	}
	return table, entries
}

func selectExperimentalFullTable(table *experimentalFullTable, entries int, digit int8) Point {
	negative := digit < 0
	if negative {
		digit = -digit
	}
	index := int(digit) - 1
	if index < 0 || index >= entries {
		panic("r43x6: invalid experimental signed-radix digit")
	}
	result := table[index]
	if negative {
		result.Negate(&result)
	}
	return result
}

func experimentalRadixScalarLoop(digits *[64]int8, count int, radixBits uint, table *experimentalFullTable, entries int) Point {
	acc := NewIdentityPoint()
	if digits[count-1] != 0 {
		selected := selectExperimentalFullTable(table, entries, digits[count-1])
		acc.Set(&selected)
	}
	for i := count - 2; i >= 0; i-- {
		for doubling := uint(0); doubling < radixBits; doubling++ {
			acc.Double(acc)
		}
		if digits[i] != 0 {
			selected := selectExperimentalFullTable(table, entries, digits[i])
			acc.Add(acc, &selected)
		}
	}
	return *acc
}

// experimentalRadixScalarMult performs exactly 252 doublings for radix 16 or
// 250 for radix 32, plus one addition for each nonzero lower digit. Table
// construction is included.
func experimentalRadixScalarMult(s *Scalar, q *Point, radixBits uint) Point {
	digits, count := experimentalSignedRadix(s, radixBits)
	table, entries := newExperimentalFullTable(q, radixBits)
	return experimentalRadixScalarLoop(&digits, count, radixBits, &table, entries)
}

// experimentalRadixDoubleScalarBaseMult is a correctness/benchmark bridge,
// not the proposed SIMD schedule. A uses the full projective radix table while
// B deliberately retains the existing width-8 NAF table. The 256-bit loop
// makes the two representations share doublings without asserting anything
// about a future x4 or x8 instruction schedule.
func experimentalRadixDoubleScalarBaseMult(a *Scalar, A *Point, b *Scalar, radixBits uint) Point {
	aDigits, aCount := experimentalSignedRadix(a, radixBits)
	aTable, aEntries := newExperimentalFullTable(A, radixBits)
	bDigits := b.nonAdjacentForm(8)
	bTable := basepointNAFTable()

	acc := NewIdentityPoint()
	for bit := 255; bit >= 0; bit-- {
		acc.Double(acc)
		if bit%int(radixBits) == 0 {
			digitIndex := bit / int(radixBits)
			if digitIndex < aCount && aDigits[digitIndex] != 0 {
				selected := selectExperimentalFullTable(&aTable, aEntries, aDigits[digitIndex])
				acc.Add(acc, &selected)
			}
		}
		if bDigits[bit] != 0 {
			selected := selectNAF8(bTable, bDigits[bit])
			acc.Add(acc, &selected)
		}
	}
	return *acc
}

func experimentalRadixVerifyMult(s, k *Scalar, A *Point, radixBits uint) Point {
	var minusA Point
	minusA.Negate(A)
	return experimentalRadixDoubleScalarBaseMult(k, &minusA, s, radixBits)
}

func TestExperimentalVariableBaseWindowsMatchReferences(t *testing.T) {
	rng := rand.New(rand.NewSource(0x456d57494e))
	torsion := mustReferencePoint(t, pointEdgeEncodings[10])

	for round := 0; round < 48; round++ {
		seedRef, _ := randomScalarPair(t, rng)
		aRef := new(edwardsref.Point).ScalarBaseMult(seedRef)
		if round%2 == 0 {
			aRef.Add(aRef, torsion)
		}
		a := mustPoint(t, aRef.Bytes())
		aScalarRef, aScalar := randomScalarPair(t, rng)
		bScalarRef, bScalar := randomScalarPair(t, rng)

		current := new(Point).VarTimeDoubleScalarBaseMult(aScalar, a, bScalar)
		want := new(edwardsref.Point).VarTimeDoubleScalarBaseMult(aScalarRef, aRef, bScalarRef)
		for _, width := range []uint{4, 5, 6} {
			got := experimentalDoubleScalarBaseMult(aScalar, a, bScalar, width)
			if got.Equal(current) != 1 {
				t.Fatalf("round %d width %d: result differs from production width 5", round, width)
			}
			assertPointMatches(t, fmt.Sprintf("round %d width %d", round, width), &got, want)
		}
	}
}

func TestExperimentalVariableBaseWindowsMatchEdgeCorpus(t *testing.T) {
	scalars := experimentalScalarCorpus(t)
	pairs := [][2]int{{0, 0}, {1, 2}, {2, 1}, {3, 4}, {4, 3}}

	// The first 14 encodings are the canonical torsion points and the
	// permissive aliases exercised by the point decoder's edge corpus.
	for pointIndex, encodedHex := range pointEdgeEncodings[:14] {
		encoded, err := hex.DecodeString(encodedHex)
		if err != nil {
			t.Fatal(err)
		}
		a := mustPoint(t, encoded)
		aRef := mustReferencePoint(t, encodedHex)
		for pairIndex, pair := range pairs {
			aScalarRef, aScalar := scalars[pair[0]].ref, scalars[pair[0]].r43
			bScalarRef, bScalar := scalars[pair[1]].ref, scalars[pair[1]].r43
			current := new(Point).VarTimeDoubleScalarBaseMult(aScalar, a, bScalar)
			want := new(edwardsref.Point).VarTimeDoubleScalarBaseMult(aScalarRef, aRef, bScalarRef)
			for _, width := range []uint{4, 5, 6} {
				got := experimentalDoubleScalarBaseMult(aScalar, a, bScalar, width)
				if got.Equal(current) != 1 {
					t.Fatalf("point %d pair %d width %d: result differs from production width 5", pointIndex, pairIndex, width)
				}
				assertPointMatches(t, fmt.Sprintf("point %d pair %d width %d", pointIndex, pairIndex, width), &got, want)
			}
		}
	}
}

func TestExperimentalSignedRadixReconstructsExactScalar(t *testing.T) {
	for scalarIndex, pair := range experimentalBoundaryScalarCorpus(t) {
		for _, radixBits := range []uint{4, 5} {
			assertExperimentalSignedRadixExact(t, fmt.Sprintf("boundary scalar %d", scalarIndex), pair.r43, radixBits)
		}
	}
}

func TestExperimentalProjectiveRadixMatchesReferences(t *testing.T) {
	rng := rand.New(rand.NewSource(0x5241444958))
	torsion := mustReferencePoint(t, pointEdgeEncodings[10])

	for round := 0; round < 32; round++ {
		seedRef, _ := randomScalarPair(t, rng)
		aRef := new(edwardsref.Point).ScalarBaseMult(seedRef)
		if round%2 == 0 {
			aRef.Add(aRef, torsion)
		}
		a := mustPoint(t, aRef.Bytes())
		aScalarRef, aScalar := randomScalarPair(t, rng)
		bScalarRef, bScalar := randomScalarPair(t, rng)

		wantScalar := new(edwardsref.Point).ScalarMult(aScalarRef, aRef)
		wantDSM := new(edwardsref.Point).VarTimeDoubleScalarBaseMult(aScalarRef, aRef, bScalarRef)
		currentDSM := new(Point).VarTimeDoubleScalarBaseMult(aScalar, a, bScalar)
		for _, radixBits := range []uint{4, 5} {
			gotScalar := experimentalRadixScalarMult(aScalar, a, radixBits)
			assertPointMatches(t, fmt.Sprintf("scalar round %d radix %d", round, 1<<radixBits), &gotScalar, wantScalar)

			gotDSM := experimentalRadixDoubleScalarBaseMult(aScalar, a, bScalar, radixBits)
			if gotDSM.Equal(currentDSM) != 1 {
				t.Fatalf("round %d radix %d DSM differs from production width 5", round, 1<<radixBits)
			}
			assertPointMatches(t, fmt.Sprintf("DSM round %d radix %d", round, 1<<radixBits), &gotDSM, wantDSM)
		}
	}
}

func TestExperimentalProjectiveRadixBoundaryScalarsOnTorsion(t *testing.T) {
	// Exact integer semantics are observable on torsion. Testing the boundary
	// recodings on an order-eight point catches accidental reduction, dropped
	// carries, and a truncated 51st radix-32 digit.
	aRef := mustReferencePoint(t, pointEdgeEncodings[10])
	a := mustPoint(t, aRef.Bytes())
	boundaries := experimentalBoundaryScalarCorpus(t)
	for scalarIndex, pair := range boundaries {
		for _, radixBits := range []uint{4, 5} {
			label := fmt.Sprintf("boundary %d radix %d", scalarIndex, 1<<radixBits)
			assertExperimentalSignedRadixExact(t, label, pair.r43, radixBits)
			want := new(edwardsref.Point).ScalarMult(pair.ref, aRef)
			got := experimentalRadixScalarMult(pair.r43, a, radixBits)
			assertPointMatches(t, label, &got, want)
		}
	}
}

func TestExperimentalProjectiveRadixMixedOrderTorsionComponents(t *testing.T) {
	// Exercise P+T for each of the eight distinct canonical torsion points.
	// Exact reconstruction is asserted first because equality modulo the prime
	// subgroup order would be insufficient on these inputs.
	torsionIndexes := [...]int{0, 1, 2, 4, 10, 11, 12, 13}
	required := experimentalRequiredScalarCorpus(t)
	primeScalar := required[5] // 17
	primeRef := new(edwardsref.Point).ScalarBaseMult(primeScalar.ref)

	for _, torsionIndex := range torsionIndexes {
		torsionRef := mustReferencePoint(t, pointEdgeEncodings[torsionIndex])
		mixedRef := new(edwardsref.Point).Add(primeRef, torsionRef)
		mixed := mustPoint(t, mixedRef.Bytes())
		for scalarIndex, pair := range required {
			bPair := required[(scalarIndex+3)%len(required)]
			for _, radixBits := range []uint{4, 5} {
				label := fmt.Sprintf("torsion-index=%d scalar=%d radix=%d", torsionIndex, scalarIndex, 1<<radixBits)
				assertExperimentalSignedRadixExact(t, label, pair.r43, radixBits)

				wantScalar := new(edwardsref.Point).ScalarMult(pair.ref, mixedRef)
				gotScalar := experimentalRadixScalarMult(pair.r43, mixed, radixBits)
				assertPointMatches(t, "mixed-order scalar "+label, &gotScalar, wantScalar)

				wantDSM := new(edwardsref.Point).VarTimeDoubleScalarBaseMult(pair.ref, mixedRef, bPair.ref)
				currentDSM := new(Point).VarTimeDoubleScalarBaseMult(pair.r43, mixed, bPair.r43)
				gotDSM := experimentalRadixDoubleScalarBaseMult(pair.r43, mixed, bPair.r43, radixBits)
				if gotDSM.Equal(currentDSM) != 1 {
					t.Fatalf("mixed-order %s: DSM differs from production width 5", label)
				}
				assertPointMatches(t, "mixed-order DSM "+label, &gotDSM, wantDSM)
			}
		}
	}
}

func assertExperimentalSignedRadixExact(t *testing.T, label string, scalar *Scalar, radixBits uint) {
	t.Helper()
	want := littleEndianScalarInteger(scalar)
	digits, count := experimentalSignedRadix(scalar, radixBits)
	radix := int64(1 << radixBits)
	got := new(big.Int)
	place := big.NewInt(1)
	for i := 0; i < count; i++ {
		half := int8(1 << (radixBits - 1))
		if i < count-1 && (digits[i] < -half || digits[i] >= half) {
			t.Fatalf("%s: radix %d digit %d out of range: %d", label, 1<<radixBits, i, digits[i])
		}
		if digits[i] < -half || digits[i] > half {
			t.Fatalf("%s: radix %d digit %d cannot be selected from full table: %d", label, 1<<radixBits, i, digits[i])
		}
		term := new(big.Int).Mul(big.NewInt(int64(digits[i])), place)
		got.Add(got, term)
		place.Mul(place, big.NewInt(radix))
	}
	if got.Cmp(want) != 0 {
		t.Fatalf("%s: radix %d did not reconstruct exactly\ngot  %x\nwant %x", label, 1<<radixBits, got, want)
	}
}

type experimentalScalarPair struct {
	ref *edwardsref.Scalar
	r43 *Scalar
}

func experimentalScalarCorpus(t *testing.T) []experimentalScalarPair {
	t.Helper()
	var zero, one, lowDense, alternating, orderMinusOne [32]byte
	one[0] = 1
	for i := 0; i < 16; i++ {
		lowDense[i] = 0xff
		alternating[i] = byte(0xa5 ^ i)
	}
	orderMinusOne = scalarOrder
	for i := range orderMinusOne {
		if orderMinusOne[i] != 0 {
			orderMinusOne[i]--
			break
		}
		orderMinusOne[i] = 0xff
	}

	encoded := [][32]byte{zero, one, orderMinusOne, lowDense, alternating}
	result := make([]experimentalScalarPair, 0, len(encoded))
	for i := range encoded {
		ref, err := edwardsref.NewScalar().SetCanonicalBytes(encoded[i][:])
		if err != nil {
			t.Fatalf("scalar corpus %d rejected by reference: %v", i, err)
		}
		r43, err := new(Scalar).SetCanonicalBytes(encoded[i][:])
		if err != nil {
			t.Fatalf("scalar corpus %d rejected by r43x6: %v", i, err)
		}
		result = append(result, experimentalScalarPair{ref: ref, r43: r43})
	}
	return result
}

func experimentalBoundaryScalarCorpus(t *testing.T) []experimentalScalarPair {
	t.Helper()
	order := littleEndianInteger(scalarOrder[:])
	seen := make(map[[32]byte]struct{})
	var result []experimentalScalarPair
	appendInteger := func(value *big.Int) {
		if value.Sign() < 0 || value.Cmp(order) >= 0 {
			return
		}
		encoded := integerToLittleEndian32(value)
		if _, ok := seen[encoded]; ok {
			return
		}
		seen[encoded] = struct{}{}
		ref, err := edwardsref.NewScalar().SetCanonicalBytes(encoded[:])
		if err != nil {
			t.Fatalf("reference rejected generated boundary scalar: %v", err)
		}
		r43, err := new(Scalar).SetCanonicalBytes(encoded[:])
		if err != nil {
			t.Fatalf("r43x6 rejected generated boundary scalar: %v", err)
		}
		result = append(result, experimentalScalarPair{ref: ref, r43: r43})
	}

	// Named boundary requirements: 0, 1, 2, 15, 16, 17,
	// 2^250-1, 2^250, l-2, and l-1.
	twoTo250 := new(big.Int).Lsh(big.NewInt(1), 250)
	explicit := []*big.Int{
		new(big.Int),
		big.NewInt(1),
		big.NewInt(2),
		big.NewInt(15),
		big.NewInt(16),
		big.NewInt(17),
		new(big.Int).Sub(new(big.Int).Set(twoTo250), big.NewInt(1)),
		new(big.Int).Set(twoTo250),
		new(big.Int).Sub(new(big.Int).Set(order), big.NewInt(2)),
		new(big.Int).Sub(new(big.Int).Set(order), big.NewInt(1)),
	}
	for _, value := range explicit {
		appendInteger(value)
	}
	for _, radixBits := range []uint{4, 5} {
		half := int64(1 << (radixBits - 1))
		values := []int64{1, half - 1, half, half + 1, (1 << radixBits) - 1, 1 << radixBits}
		for shift := uint(0); shift <= 252; shift += radixBits {
			for _, value := range values {
				candidate := new(big.Int).Lsh(big.NewInt(value), shift)
				appendInteger(candidate)
				if candidate.Sign() > 0 {
					appendInteger(new(big.Int).Sub(new(big.Int).Set(candidate), big.NewInt(1)))
				}
			}
		}
	}
	return result
}

func experimentalRequiredScalarCorpus(t *testing.T) []experimentalScalarPair {
	t.Helper()
	all := experimentalBoundaryScalarCorpus(t)
	// The ten required values are inserted first, in the documented order.
	if len(all) < 10 {
		t.Fatal("boundary scalar corpus omitted required values")
	}
	return all[:10]
}

func littleEndianScalarInteger(s *Scalar) *big.Int {
	encoded := s.Bytes()
	return littleEndianInteger(encoded[:])
}

func littleEndianInteger(encoded []byte) *big.Int {
	bigEndian := make([]byte, len(encoded))
	for i := range encoded {
		bigEndian[len(encoded)-1-i] = encoded[i]
	}
	return new(big.Int).SetBytes(bigEndian)
}

func integerToLittleEndian32(value *big.Int) [32]byte {
	bigEndian := value.Bytes()
	var encoded [32]byte
	for i := range bigEndian {
		encoded[i] = bigEndian[len(bigEndian)-1-i]
	}
	return encoded
}

type experimentalVerifyFixture struct {
	pub [32]byte
	msg []byte
	sig [64]byte
}

func newExperimentalVerifyFixture(tb testing.TB, messageSize int) experimentalVerifyFixture {
	tb.Helper()
	var seed [stdlibed25519.SeedSize]byte
	for i := range seed {
		seed[i] = byte(0x42 + i*17)
	}
	privateKey := stdlibed25519.NewKeyFromSeed(seed[:])
	publicKey := privateKey.Public().(stdlibed25519.PublicKey)
	message := make([]byte, messageSize)
	for i := range message {
		message[i] = byte(i*29 + messageSize)
	}
	signature := stdlibed25519.Sign(privateKey, message)

	var fixture experimentalVerifyFixture
	copy(fixture.pub[:], publicKey)
	copy(fixture.sig[:], signature)
	fixture.msg = message
	return fixture
}

func verifyExperimentalWindow(fixture *experimentalVerifyFixture, aWidth uint) bool {
	var a Point
	if _, err := a.SetBytes(fixture.pub[:]); err != nil {
		return false
	}
	var s Scalar
	if _, err := s.SetCanonicalBytes(fixture.sig[32:]); err != nil {
		return false
	}

	h := sha512.New()
	_, _ = h.Write(fixture.sig[:32])
	_, _ = h.Write(fixture.pub[:])
	_, _ = h.Write(fixture.msg)
	var digest [sha512.Size]byte
	h.Sum(digest[:0])
	kRef, err := edwardsref.NewScalar().SetUniformBytes(digest[:])
	if err != nil {
		return false
	}
	var k Scalar
	if _, err := k.SetCanonicalBytes(kRef.Bytes()); err != nil {
		return false
	}

	q := experimentalVerifyMult(&s, &k, &a, aWidth)
	encodedQ := q.Bytes()
	return bytes.Equal(encodedQ[:], fixture.sig[:32])
}

func TestExperimentalWindowCompleteVerification(t *testing.T) {
	for _, size := range []int{64, 200, 1232} {
		fixture := newExperimentalVerifyFixture(t, size)
		for _, width := range []uint{4, 5, 6} {
			if !verifyExperimentalWindow(&fixture, width) {
				t.Fatalf("message size %d width %d rejected a valid signature", size, width)
			}
		}
	}
}

var experimentalPointSink Point
var experimentalTableSink experimentalFullTable

func BenchmarkExperimentalVariableBaseWindows(b *testing.B) {
	fixture := newExperimentalVerifyFixture(b, 64)
	a := mustBenchmarkPoint(b, fixture.pub[:])
	s := mustBenchmarkScalar(b, fixture.sig[32:])
	k := experimentalChallengeScalar(b, &fixture)
	var minusA Point
	minusA.Negate(a)

	for _, width := range []uint{4, 5, 6} {
		b.Run(fmt.Sprintf("width=%d", width), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				experimentalPointSink = experimentalDoubleScalarBaseMult(k, &minusA, s, width)
			}
		})
	}
}

func BenchmarkExperimentalProjectiveRadixTableBuild(b *testing.B) {
	fixture := newExperimentalVerifyFixture(b, 64)
	a := mustBenchmarkPoint(b, fixture.pub[:])
	for _, radixBits := range []uint{4, 5} {
		b.Run(fmt.Sprintf("radix=%d", 1<<radixBits), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				experimentalTableSink, _ = newExperimentalFullTable(a, radixBits)
			}
		})
	}
}

func BenchmarkExperimentalProjectiveRadixScalarLoop(b *testing.B) {
	fixture := newExperimentalVerifyFixture(b, 64)
	a := mustBenchmarkPoint(b, fixture.pub[:])
	k := experimentalChallengeScalar(b, &fixture)
	for _, radixBits := range []uint{4, 5} {
		digits, count := experimentalSignedRadix(k, radixBits)
		table, entries := newExperimentalFullTable(a, radixBits)
		b.Run(fmt.Sprintf("radix=%d", 1<<radixBits), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				experimentalPointSink = experimentalRadixScalarLoop(&digits, count, radixBits, &table, entries)
			}
		})
	}
}

func BenchmarkExperimentalProjectiveRadixScalarMult(b *testing.B) {
	fixture := newExperimentalVerifyFixture(b, 64)
	a := mustBenchmarkPoint(b, fixture.pub[:])
	k := experimentalChallengeScalar(b, &fixture)
	for _, radixBits := range []uint{4, 5} {
		b.Run(fmt.Sprintf("radix=%d", 1<<radixBits), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				experimentalPointSink = experimentalRadixScalarMult(k, a, radixBits)
			}
		})
	}
}

func BenchmarkExperimentalProjectiveRadixDSM(b *testing.B) {
	fixture := newExperimentalVerifyFixture(b, 64)
	a := mustBenchmarkPoint(b, fixture.pub[:])
	s := mustBenchmarkScalar(b, fixture.sig[32:])
	k := experimentalChallengeScalar(b, &fixture)
	var minusA Point
	minusA.Negate(a)
	for _, radixBits := range []uint{4, 5} {
		b.Run(fmt.Sprintf("radix=%d", 1<<radixBits), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				experimentalPointSink = experimentalRadixDoubleScalarBaseMult(k, &minusA, s, radixBits)
			}
		})
	}
}

func BenchmarkExperimentalWindowCompleteVerify(b *testing.B) {
	for _, size := range []int{64, 200, 1232} {
		fixture := newExperimentalVerifyFixture(b, size)
		for _, width := range []uint{4, 5, 6} {
			b.Run(fmt.Sprintf("msg=%d/width=%d", size, width), func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(size))
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if !verifyExperimentalWindow(&fixture, width) {
						b.Fatal("experimental verifier rejected a valid signature")
					}
				}
			})
		}
	}
}

func mustBenchmarkPoint(tb testing.TB, encoded []byte) *Point {
	tb.Helper()
	p, err := new(Point).SetBytes(encoded)
	if err != nil {
		tb.Fatalf("invalid benchmark point: %v", err)
	}
	return p
}

func mustBenchmarkScalar(tb testing.TB, encoded []byte) *Scalar {
	tb.Helper()
	s, err := new(Scalar).SetCanonicalBytes(encoded)
	if err != nil {
		tb.Fatalf("invalid benchmark scalar: %v", err)
	}
	return s
}

func experimentalChallengeScalar(tb testing.TB, fixture *experimentalVerifyFixture) *Scalar {
	tb.Helper()
	h := sha512.New()
	_, _ = h.Write(fixture.sig[:32])
	_, _ = h.Write(fixture.pub[:])
	_, _ = h.Write(fixture.msg)
	digest := h.Sum(nil)
	kRef, err := edwardsref.NewScalar().SetUniformBytes(digest)
	if err != nil {
		tb.Fatal(err)
	}
	return mustBenchmarkScalar(tb, kRef.Bytes())
}
