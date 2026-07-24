package r51x5

import (
	"bytes"
	"fmt"
	"math/big"
	"math/rand"
	"testing"

	edwardsref "github.com/Overclock-Validator/narya/internal/edwards25519"
	"github.com/Overclock-Validator/narya/internal/heea8l"
)

func TestHEEAReduceSignedProductMatchesBigOracle(t *testing.T) {
	l := heea8l.Order()
	boundaries := []*big.Int{
		big.NewInt(0),
		big.NewInt(1),
		big.NewInt(-1),
		new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 127), big.NewInt(1)),
		new(big.Int).Lsh(big.NewInt(1), 127),
		new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1)),
		new(big.Int).Lsh(big.NewInt(1), 128),
		new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1)),
		new(big.Int).Sub(new(big.Int).Set(l), big.NewInt(1)),
		new(big.Int).Neg(new(big.Int).Sub(new(big.Int).Set(l), big.NewInt(1))),
		new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1)),
		new(big.Int).Neg(new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 136), big.NewInt(5))),
	}
	for i, x := range boundaries {
		for j, y := range boundaries {
			if x.BitLen()+y.BitLen() > 512 {
				continue
			}
			assertHEEAReducedProduct(t, fmt.Sprintf("boundary/%d/%d", i, j), x, y, l)
		}
	}

	// Exercise fixed-word carries and every product sign over the actual HEEA
	// width envelope. The oracle uses independent math/big reduction.
	rng := rand.New(rand.NewSource(0x51b4535b117))
	for i := 0; i < 2000; i++ {
		x := new(big.Int).Rand(rng, new(big.Int).Lsh(big.NewInt(1), uint(120+rng.Intn(18))))
		y := new(big.Int).Rand(rng, new(big.Int).Lsh(big.NewInt(1), uint(245+rng.Intn(9))))
		if rng.Intn(2) != 0 {
			x.Neg(x)
		}
		if rng.Intn(2) != 0 {
			y.Neg(y)
		}
		assertHEEAReducedProduct(t, fmt.Sprintf("random/%d", i), x, y, l)
	}

	tooWide := signedMagnitudeFromTestBig(new(big.Int).Lsh(big.NewInt(1), 400))
	alsoWide := signedMagnitudeFromTestBig(new(big.Int).Lsh(big.NewInt(1), 200))
	got := [32]byte{1}
	if heeaReduceSignedProduct(&got, tooWide, alsoWide) {
		t.Fatal("accepted a basepoint product outside the fixed 512-bit boundary")
	}
	if got != ([32]byte{}) {
		t.Fatalf("width fallback left a partial scalar: %x", got)
	}
}

func TestHEEAReduceSignedProductFixedPathDoesNotAllocate(t *testing.T) {
	x := signedMagnitudeFromTestBig(new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 136), big.NewInt(5)))
	y := signedMagnitudeFromTestBig(new(big.Int).Sub(heea8l.Order(), big.NewInt(1)))
	var out [32]byte
	if allocations := testing.AllocsPerRun(1000, func() {
		if !heeaReduceSignedProduct(&out, x, y) {
			panic("HEEA fixed product unexpectedly exceeded 512 bits")
		}
	}); allocations != 0 {
		t.Fatalf("fixed basepoint product allocated %.2f objects", allocations)
	}
}

func TestHEEABaseSplitCoefficientBoundaries127And128(t *testing.T) {
	l := heea8l.Order()
	values := []*big.Int{
		new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 127), big.NewInt(1)),
		new(big.Int).Lsh(big.NewInt(1), 127),
		new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 127), big.NewInt(1)),
		new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1)),
		new(big.Int).Lsh(big.NewInt(1), 128),
		new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1)),
		new(big.Int).Sub(new(big.Int).Set(l), big.NewInt(1)),
	}
	for _, sign := range []int64{-1, 1} {
		for i, value := range values {
			x := new(big.Int).Mul(new(big.Int).Set(value), big.NewInt(sign))
			var reduced [32]byte
			if !heeaReduceSignedProduct(&reduced, signedMagnitudeFromTestBig(x), NewSignedMagnitudeUint64(1, false)) {
				t.Fatalf("case %d sign %d unexpectedly exceeded fixed width", i, sign)
			}
			low := heeaLittleEndianBig(reduced[:16])
			high := heeaLittleEndianBig(reduced[16:])
			reconstructed := new(big.Int).Add(low, new(big.Int).Lsh(high, heeaBaseSplitBit))
			want := new(big.Int).Mod(new(big.Int).Set(x), l)
			if reconstructed.Cmp(want) != 0 {
				t.Fatalf("case %d sign %d split mismatch\ngot  %x\nwant %x", i, sign, reconstructed, want)
			}
		}
	}
}

func TestHEEABaseSplitB128MatchesExactMultiplication(t *testing.T) {
	refs, B := scalarWindowGeneratorX8(t)
	var B128 PointX8
	ExperimentalHEEABaseSplitB128X8(&B128, &B)
	coefficient := new(big.Int).Lsh(big.NewInt(1), heeaBaseSplitBit)
	var want [X8Lanes]*edwardsref.Point
	for lane := range want {
		want[lane] = exactReferenceIntegerMult(refs[lane], coefficient)
	}
	assertMaskedPointX8(t, "HEEA B128", &B128, &want, 0xff)

	var b4Points [X4Lanes]Point
	var want4 [X4Lanes]*edwardsref.Point
	for lane := 0; lane < X4Lanes; lane++ {
		b4Points[lane] = B.Lane(lane + X4Lanes)
		want4[lane] = want[lane+X4Lanes]
	}
	var B4, B1284 PointX4
	B4.SetPoints(&b4Points)
	ExperimentalHEEABaseSplitB128X4(&B1284, &B4)
	assertMaskedPointX4(t, "HEEA B128 x4", &B1284, &want4, 0x0f)
}

func TestHEEABaseSplitEquationX8MatchesExactOracleSignsMasksAndTails(t *testing.T) {
	rng := rand.New(rand.NewSource(0x518b4535b117))
	torsion := referenceTorsionPoints(t)
	aRefs, A := scalarWindowMixedBasesX8(t, rng, &torsion)
	var shifted [X8Lanes]*edwardsref.Point
	for lane := range shifted {
		shifted[lane] = torsion[(lane+3)%X8Lanes]
	}
	rRefs, R := scalarWindowMixedBasesX8(t, rng, &shifted)
	bRefs, B := scalarWindowGeneratorX8(t)
	var B128 PointX8
	ExperimentalHEEABaseSplitB128X8(&B128, &B)

	for scenario := 0; scenario < 2; scenario++ {
		s, tau, rho, epsilon := heeaBaseSplitCoefficientsX8(scenario)
		want := heeaBaseSplitExactWantX8(&bRefs, &rRefs, &aRefs, &s, &tau, &rho, &epsilon)
		for _, radixBits := range []uint{4, 5} {
			for _, active := range []uint8{0, 0x55, 0x81, 0xff} {
				assertHEEABaseSplitX8(t, fmt.Sprintf("scenario=%d/radix=%d/active=%02x", scenario, 1<<radixBits, active), &B, &B128, &R, &A, &s, &tau, &rho, &epsilon, radixBits, active, &want)
			}
		}
		// Every natural tail is checked independently; the other scenario and
		// both radices above cover the full sign and schedule cross-product.
		if scenario == 0 {
			for tail := 0; tail <= X8Lanes; tail++ {
				active := uint8((1 << tail) - 1)
				assertHEEABaseSplitX8(t, fmt.Sprintf("tail=%d", tail), &B, &B128, &R, &A, &s, &tau, &rho, &epsilon, 5, active, &want)
			}
		}
	}
}

func TestHEEABaseSplitEquationX4MatchesExactOracleTails(t *testing.T) {
	rng := rand.New(rand.NewSource(0x514b4535b117))
	torsion := referenceTorsionPoints(t)
	_, A8 := scalarWindowMixedBasesX8(t, rng, &torsion)
	_, R8 := scalarWindowMixedBasesX8(t, rng, &torsion)
	_, B8 := scalarWindowGeneratorX8(t)
	var B1288 PointX8
	ExperimentalHEEABaseSplitB128X8(&B1288, &B8)

	for half := 0; half < 2; half++ {
		s8, tau8, rho8, epsilon8 := heeaBaseSplitCoefficientsX8(half)
		var bPoints, b128Points, rPoints, aPoints [X4Lanes]Point
		var s, tau, rho [X4Lanes]SignedMagnitude
		var epsilon [X4Lanes]int8
		for lane := 0; lane < X4Lanes; lane++ {
			index := half*X4Lanes + lane
			bPoints[lane], b128Points[lane] = B8.Lane(index), B1288.Lane(index)
			rPoints[lane], aPoints[lane] = R8.Lane(index), A8.Lane(index)
			s[lane], tau[lane], rho[lane], epsilon[lane] = s8[index], tau8[index], rho8[index], epsilon8[index]
		}
		var B, B128, R, A PointX4
		B.SetPoints(&bPoints)
		B128.SetPoints(&b128Points)
		R.SetPoints(&rPoints)
		A.SetPoints(&aPoints)
		for _, radixBits := range []uint{4, 5} {
			for tail := 0; tail <= X4Lanes; tail++ {
				active := uint8((1 << tail) - 1)
				var old, got PointX4
				oldMask := HEEAEquationX4(&old, &B, &R, &A, &s, &tau, &rho, &epsilon, radixBits, active)
				gotMask := ExperimentalHEEABaseSplitEquationX4(&got, &B, &B128, &R, &A, &s, &tau, &rho, &epsilon, radixBits, active)
				if gotMask != oldMask || gotMask != active {
					t.Fatalf("half %d radix %d tail %d masks split=%02x old=%02x", half, 1<<radixBits, tail, gotMask, oldMask)
				}
				if equal := got.Equal(&old) & active; equal != active {
					t.Fatalf("half %d radix %d tail %d equality=%02x want=%02x", half, 1<<radixBits, tail, equal, active)
				}
				if inactiveIdentity := got.IsIdentity() &^ active; inactiveIdentity != (^active)&0x0f {
					t.Fatalf("half %d radix %d tail %d inactive identities=%02x", half, 1<<radixBits, tail, inactiveIdentity)
				}
			}
		}
	}
}

func TestHEEABaseSplitEquationInvalidLanesAreAtomicFallbacks(t *testing.T) {
	_, B := scalarWindowGeneratorX8(t)
	R, A := B, B
	var B128 PointX8
	ExperimentalHEEABaseSplitB128X8(&B128, &B)
	s, tau, rho, epsilon := heeaBaseSplitCoefficientsX8(0)
	for invalidLane := 0; invalidLane < X8Lanes; invalidLane++ {
		invalidEpsilon := epsilon
		invalidEpsilon[invalidLane] = 0
		var got PointX8
		wantMask := uint8(0xff &^ (1 << invalidLane))
		if usable := ExperimentalHEEABaseSplitEquationX8(&got, &B, &B128, &R, &A, &s, &tau, &rho, &invalidEpsilon, 5, 0xff); usable != wantMask {
			t.Fatalf("invalid epsilon lane %d usable=%02x want=%02x", invalidLane, usable, wantMask)
		}
		if got.IsIdentity()&(1<<invalidLane) == 0 {
			t.Fatalf("invalid epsilon lane %d did not produce identity", invalidLane)
		}
	}

	tooWide := new(big.Int).Lsh(big.NewInt(1), 400)
	widePartner := new(big.Int).Lsh(big.NewInt(1), 200)
	s[5] = signedMagnitudeFromTestBig(tooWide)
	tau[5] = signedMagnitudeFromTestBig(widePartner)
	var got PointX8
	wantMask := uint8(0xff &^ (1 << 5))
	if usable := ExperimentalHEEABaseSplitEquationX8(&got, &B, &B128, &R, &A, &s, &tau, &rho, &epsilon, 4, 0xff); usable != wantMask {
		t.Fatalf("wide product usable=%02x want=%02x", usable, wantMask)
	}
	if got.IsIdentity()&(1<<5) == 0 {
		t.Fatal("wide-product fallback lane did not produce identity")
	}
}

func TestHEEABaseSplitEquationRandomMatchesOldExactEquation(t *testing.T) {
	rng := rand.New(rand.NewSource(0x51b4535711))
	torsion := referenceTorsionPoints(t)
	_, A := scalarWindowMixedBasesX8(t, rng, &torsion)
	_, R := scalarWindowMixedBasesX8(t, rng, &torsion)
	_, B := scalarWindowGeneratorX8(t)
	var B128 PointX8
	ExperimentalHEEABaseSplitB128X8(&B128, &B)

	for iteration := 0; iteration < 8; iteration++ {
		var s, tau, rho [X8Lanes]SignedMagnitude
		var epsilon [X8Lanes]int8
		for lane := 0; lane < X8Lanes; lane++ {
			sValue := heeaRandomSignedInt(rng, 252)
			tauValue := heeaRandomSignedInt(rng, 136)
			rhoValue := heeaRandomSignedInt(rng, 136)
			s[lane], tau[lane], rho[lane] = signedMagnitudeFromTestBig(sValue), signedMagnitudeFromTestBig(tauValue), signedMagnitudeFromTestBig(rhoValue)
			if rng.Intn(2) == 0 {
				epsilon[lane] = -1
			} else {
				epsilon[lane] = 1
			}
		}
		active := uint8(rng.Intn(256))
		radixBits := uint(4 + iteration%2)
		var old, got PointX8
		oldMask := HEEAEquationX8(&old, &B, &R, &A, &s, &tau, &rho, &epsilon, radixBits, active)
		gotMask := ExperimentalHEEABaseSplitEquationX8(&got, &B, &B128, &R, &A, &s, &tau, &rho, &epsilon, radixBits, active)
		if gotMask != oldMask || gotMask != active {
			t.Fatalf("iteration %d masks split=%02x old=%02x active=%02x", iteration, gotMask, oldMask, active)
		}
		if equal := got.Equal(&old) & active; equal != active {
			t.Fatalf("iteration %d equality=%02x want=%02x", iteration, equal, active)
		}
	}
}

func TestHEEABaseSplitKeepsMixedOrderRAndACoefficientsExact(t *testing.T) {
	torsion := referenceTorsionPoints(t)
	generator := edwardsref.NewGeneratorPoint()
	mixed := new(edwardsref.Point).Add(generator, torsion[4])
	l := heea8l.Order()
	lMinusOne := new(big.Int).Sub(new(big.Int).Set(l), big.NewInt(1))

	var generatorBytes, mixedBytes [X8Lanes][32]byte
	for lane := 0; lane < X8Lanes; lane++ {
		copy(generatorBytes[lane][:], generator.Bytes())
		copy(mixedBytes[lane][:], mixed.Bytes())
	}
	var B, generatorPoint, mixedPoint PointX8
	if B.SetBytes(&generatorBytes) != 0xff || generatorPoint.SetBytes(&generatorBytes) != 0xff || mixedPoint.SetBytes(&mixedBytes) != 0xff {
		t.Fatal("failed to decode mixed-order discriminator fixtures")
	}
	var B128 PointX8
	ExperimentalHEEABaseSplitB128X8(&B128, &B)

	// R discriminator: exact -R differs from the tempting [L-1]R whenever
	// R has a torsion component, even though those coefficients agree mod L.
	var s, tau, rho [X8Lanes]SignedMagnitude
	var epsilon [X8Lanes]int8
	for lane := 0; lane < X8Lanes; lane++ {
		tau[lane] = NewSignedMagnitudeUint64(1, false)
		epsilon[lane] = 1
	}
	var got PointX8
	if usable := ExperimentalHEEABaseSplitEquationX8(&got, &B, &B128, &mixedPoint, &generatorPoint, &s, &tau, &rho, &epsilon, 5, 0xff); usable != 0xff {
		t.Fatalf("R discriminator usable=%02x", usable)
	}
	wantR := exactReferenceIntegerMult(mixed, big.NewInt(-1))
	wrongR := exactReferenceIntegerMult(mixed, lMinusOne)
	if bytes.Equal(wantR.Bytes(), wrongR.Bytes()) {
		t.Fatal("R discriminator failed to distinguish exact -1 from L-1")
	}
	for lane := 0; lane < X8Lanes; lane++ {
		point := got.Lane(lane)
		assertScalarPointMatchesReference(t, fmt.Sprintf("exact R lane %d", lane), &point, wantR)
	}

	// A discriminator: keep the R coefficient exact and change only -rho A
	// to its modulo-L representative. The prime-order R term cancels in the
	// comparison; the mixed-order A torsion exposes the semantic difference.
	for lane := 0; lane < X8Lanes; lane++ {
		rho[lane] = NewSignedMagnitudeUint64(1, false)
	}
	if usable := ExperimentalHEEABaseSplitEquationX8(&got, &B, &B128, &generatorPoint, &mixedPoint, &s, &tau, &rho, &epsilon, 4, 0xff); usable != 0xff {
		t.Fatalf("A discriminator usable=%02x", usable)
	}
	wantA := new(edwardsref.Point).Add(
		exactReferenceIntegerMult(generator, big.NewInt(-1)),
		exactReferenceIntegerMult(mixed, big.NewInt(-1)),
	)
	wrongA := new(edwardsref.Point).Add(
		exactReferenceIntegerMult(generator, big.NewInt(-1)),
		exactReferenceIntegerMult(mixed, lMinusOne),
	)
	if bytes.Equal(wantA.Bytes(), wrongA.Bytes()) {
		t.Fatal("A discriminator failed to distinguish exact -1 from L-1")
	}
	for lane := 0; lane < X8Lanes; lane++ {
		point := got.Lane(lane)
		assertScalarPointMatchesReference(t, fmt.Sprintf("exact A lane %d", lane), &point, wantA)
	}
}

func assertHEEAReducedProduct(t *testing.T, label string, x, y, order *big.Int) {
	t.Helper()
	var got [32]byte
	if !heeaReduceSignedProduct(&got, signedMagnitudeFromTestBig(x), signedMagnitudeFromTestBig(y)) {
		t.Fatalf("%s unexpectedly exceeded fixed width", label)
	}
	want := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Set(x), y), order)
	if value := heeaLittleEndianBig(got[:]); value.Cmp(want) != 0 {
		t.Fatalf("%s mismatch\ngot  %x\nwant %x", label, value, want)
	}
}

func heeaLittleEndianBig(encoded []byte) *big.Int {
	bigEndian := make([]byte, len(encoded))
	for i := range encoded {
		bigEndian[len(encoded)-1-i] = encoded[i]
	}
	return new(big.Int).SetBytes(bigEndian)
}

func heeaBaseSplitCoefficientsX8(scenario int) ([X8Lanes]SignedMagnitude, [X8Lanes]SignedMagnitude, [X8Lanes]SignedMagnitude, [X8Lanes]int8) {
	l := heea8l.Order()
	var s, tau, rho [X8Lanes]SignedMagnitude
	var epsilon [X8Lanes]int8
	for lane := 0; lane < X8Lanes; lane++ {
		combination := scenario*X8Lanes + lane
		sValue := new(big.Int).Sub(new(big.Int).Set(l), big.NewInt(int64(lane+1)))
		tauValue := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), uint(127+lane%2)), big.NewInt(int64(2*lane+1)))
		rhoValue := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), uint(120+lane%9)), big.NewInt(int64(0x51+lane)))
		if combination&1 != 0 {
			sValue.Neg(sValue)
		}
		if combination&2 != 0 {
			tauValue.Neg(tauValue)
		}
		if combination&4 != 0 {
			rhoValue.Neg(rhoValue)
		}
		if combination&8 != 0 {
			epsilon[lane] = -1
		} else {
			epsilon[lane] = 1
		}
		s[lane], tau[lane], rho[lane] = signedMagnitudeFromTestBig(sValue), signedMagnitudeFromTestBig(tauValue), signedMagnitudeFromTestBig(rhoValue)
	}
	return s, tau, rho, epsilon
}

func heeaBaseSplitExactWantX8(bRefs, rRefs, aRefs *[X8Lanes]*edwardsref.Point, s, tau, rho *[X8Lanes]SignedMagnitude, epsilon *[X8Lanes]int8) [X8Lanes]*edwardsref.Point {
	var want [X8Lanes]*edwardsref.Point
	for lane := 0; lane < X8Lanes; lane++ {
		want[lane] = exactReferenceHEEAEquation(
			bRefs[lane], rRefs[lane], aRefs[lane],
			signedMagnitudeToBig(s[lane]), signedMagnitudeToBig(tau[lane]), signedMagnitudeToBig(rho[lane]), epsilon[lane],
		)
	}
	return want
}

func assertHEEABaseSplitX8(t *testing.T, label string, B, B128, R, A *PointX8, s, tau, rho *[X8Lanes]SignedMagnitude, epsilon *[X8Lanes]int8, radixBits uint, active uint8, want *[X8Lanes]*edwardsref.Point) {
	t.Helper()
	var old, got PointX8
	oldMask := HEEAEquationX8(&old, B, R, A, s, tau, rho, epsilon, radixBits, active)
	gotMask := ExperimentalHEEABaseSplitEquationX8(&got, B, B128, R, A, s, tau, rho, epsilon, radixBits, active)
	if gotMask != oldMask || gotMask != active {
		t.Fatalf("%s masks split=%02x old=%02x want=%02x", label, gotMask, oldMask, active)
	}
	if equal := got.Equal(&old) & active; equal != active {
		t.Fatalf("%s old/split equality=%02x want=%02x", label, equal, active)
	}
	assertMaskedPointX8(t, label, &got, want, active)
}

func heeaRandomSignedInt(rng *rand.Rand, bits int) *big.Int {
	value := new(big.Int).Rand(rng, new(big.Int).Lsh(big.NewInt(1), uint(bits)))
	if rng.Intn(2) != 0 {
		value.Neg(value)
	}
	return value
}

var (
	heeaBaseSplitPointX4Sink PointX4
	heeaBaseSplitPointX8Sink PointX8
	heeaBaseSplitMaskSink    uint8
)

func BenchmarkHEEAEquationBaseSplit(b *testing.B) {
	base4, base8, _, _ := scalarWindowBenchmarkFixtures(b)
	B4, R4, A4 := base4, base4, base4
	B8, R8, A8 := base8, base8, base8
	var B1284 PointX4
	var B1288 PointX8
	ExperimentalHEEABaseSplitB128X4(&B1284, &B4)
	ExperimentalHEEABaseSplitB128X8(&B1288, &B8)
	s8, tau8, rho8, epsilon8 := scalarWindowHEEACoefficientsX8()
	var s4, tau4, rho4 [X4Lanes]SignedMagnitude
	var epsilon4 [X4Lanes]int8
	for lane := 0; lane < X4Lanes; lane++ {
		s4[lane], tau4[lane], rho4[lane], epsilon4[lane] = s8[lane], tau8[lane], rho8[lane], epsilon8[lane]
	}

	for _, radixBits := range []uint{4, 5} {
		b.Run(fmt.Sprintf("x4/radix=%d/old-exact-389bit", 1<<radixBits), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				heeaBaseSplitMaskSink = HEEAEquationX4(&heeaBaseSplitPointX4Sink, &B4, &R4, &A4, &s4, &tau4, &rho4, &epsilon4, radixBits, 0x0f)
			}
		})
		b.Run(fmt.Sprintf("x4/radix=%d/base-split-at-128", 1<<radixBits), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				heeaBaseSplitMaskSink = ExperimentalHEEABaseSplitEquationX4(&heeaBaseSplitPointX4Sink, &B4, &B1284, &R4, &A4, &s4, &tau4, &rho4, &epsilon4, radixBits, 0x0f)
			}
		})
		b.Run(fmt.Sprintf("x8/radix=%d/old-exact-389bit", 1<<radixBits), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				heeaBaseSplitMaskSink = HEEAEquationX8(&heeaBaseSplitPointX8Sink, &B8, &R8, &A8, &s8, &tau8, &rho8, &epsilon8, radixBits, 0xff)
			}
		})
		b.Run(fmt.Sprintf("x8/radix=%d/base-split-at-128", 1<<radixBits), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				heeaBaseSplitMaskSink = ExperimentalHEEABaseSplitEquationX8(&heeaBaseSplitPointX8Sink, &B8, &B1288, &R8, &A8, &s8, &tau8, &rho8, &epsilon8, radixBits, 0xff)
			}
		})
	}
}
