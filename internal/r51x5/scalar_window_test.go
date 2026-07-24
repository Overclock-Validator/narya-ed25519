package r51x5

import (
	"fmt"
	"math/big"
	"math/rand"
	"testing"
	"unsafe"

	edwardsref "github.com/Overclock-Validator/narya/internal/edwards25519"
	"github.com/Overclock-Validator/narya/internal/heea8l"
)

func TestRegularRadixRecodingIsExactSignedInteger(t *testing.T) {
	boundaries := scalarWindowBoundaryIntegers()
	for index, value := range boundaries {
		for _, sign := range []int64{1, -1} {
			signed := new(big.Int).Mul(new(big.Int).Set(value), big.NewInt(sign))
			coefficient := signedMagnitudeFromTestBig(signed)
			for _, radixBits := range []uint{4, 5, 6} {
				digits := RecodeRegularRadix(coefficient, radixBits)
				got := reconstructRegularRadix(digits, radixBits)
				if got.Cmp(signed) != 0 {
					t.Fatalf("boundary %d sign %d radix %d reconstruction mismatch\ngot  %x\nwant %x", index, sign, 1<<radixBits, got, signed)
				}
				half := int8(1 << (radixBits - 1))
				for digitIndex, digit := range digits {
					if digit < -half || digit > half {
						t.Fatalf("boundary %d radix %d digit %d outside full table: %d", index, 1<<radixBits, digitIndex, digit)
					}
				}
			}
		}
	}
}

func TestSignedMagnitudeProductPreservesWidthAndSign(t *testing.T) {
	values := []*big.Int{
		big.NewInt(0),
		big.NewInt(17),
		new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 136), big.NewInt(3)),
		new(big.Int).Sub(heea8l.Order(), big.NewInt(1)),
		new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 300), big.NewInt(0x12345)),
	}
	for i, x := range values {
		for j, y := range values {
			for _, xSign := range []int64{1, -1} {
				for _, ySign := range []int64{1, -1} {
					xSigned := new(big.Int).Mul(new(big.Int).Set(x), big.NewInt(xSign))
					ySigned := new(big.Int).Mul(new(big.Int).Set(y), big.NewInt(ySign))
					got := MultiplySignedMagnitudes(signedMagnitudeFromTestBig(xSigned), signedMagnitudeFromTestBig(ySigned))
					want := new(big.Int).Mul(xSigned, ySigned)
					if signedMagnitudeToBig(got).Cmp(want) != 0 {
						t.Fatalf("product %d,%d signs %d,%d mismatch", i, j, xSign, ySign)
					}
				}
			}
		}
	}

	// This is the shape relevant to tau*s and must remain wider than 256 bits.
	tau := signedMagnitudeFromTestBig(new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 136), big.NewInt(5)))
	s := signedMagnitudeFromTestBig(new(big.Int).Sub(heea8l.Order(), big.NewInt(1)))
	product := MultiplySignedMagnitudes(tau, s)
	if product.BitLen() <= 256 {
		t.Fatalf("tau*s unexpectedly truncated to %d bits", product.BitLen())
	}
}

func TestNominalFullTableByteAccounting(t *testing.T) {
	tests := []struct {
		lanes, coordinates int
		radixBits          uint
		want               int
	}{
		{4, 3, 4, 3840},
		{4, 4, 4, 5120},
		{8, 3, 4, 7680},
		{8, 4, 4, 10240},
		{4, 3, 5, 7680},
		{4, 4, 5, 10240},
		{8, 3, 5, 15360},
		{8, 4, 5, 20480},
		{4, 3, 6, 15360},
		{4, 4, 6, 20480},
		{8, 3, 6, 30720},
		{8, 4, 6, 40960},
	}
	for _, test := range tests {
		if got := NominalFullTableBytes(test.lanes, test.coordinates, test.radixBits); got != test.want {
			t.Fatalf("lanes=%d coordinates=%d radix=%d got=%d want=%d", test.lanes, test.coordinates, 1<<test.radixBits, got, test.want)
		}
	}
	var table4 FullTableX4
	if got, want := int(unsafe.Sizeof(table4.points)), NominalFullTableBytes(4, 4, 6); got != want {
		t.Fatalf("x4 radix64 Go point payload=%d nominal four-coordinate=%d", got, want)
	}
	var table8 FullTableX8
	if got, want := int(unsafe.Sizeof(table8.points)), NominalFullTableBytes(8, 4, 6); got != want {
		t.Fatalf("x8 radix64 Go point payload=%d nominal four-coordinate=%d", got, want)
	}
}

func TestFullTablesMatchExactIntegerMultiples(t *testing.T) {
	rng := rand.New(rand.NewSource(0x51ab1e))
	torsion := referenceTorsionPoints(t)
	refs, bases := scalarWindowMixedBasesX8(t, rng, &torsion)
	for _, radixBits := range []uint{4, 5, 6} {
		table := BuildFullTableX8(&bases, radixBits)
		for entry := 0; entry < table.entries; entry++ {
			coefficient := big.NewInt(int64(entry + 1))
			for lane := 0; lane < X8Lanes; lane++ {
				got := table.points[entry].Lane(lane)
				want := exactReferenceIntegerMult(refs[lane], coefficient)
				assertScalarPointMatchesReference(t, fmt.Sprintf("x8 radix %d entry %d lane %d", 1<<radixBits, entry, lane), &got, want)
			}
		}

		var refs4 [X4Lanes]*edwardsref.Point
		var points4 [X4Lanes]Point
		for lane := 0; lane < X4Lanes; lane++ {
			refs4[lane] = refs[lane+4]
			points4[lane] = bases.Lane(lane + 4)
		}
		var bases4 PointX4
		bases4.SetPoints(&points4)
		table4 := BuildFullTableX4(&bases4, radixBits)
		for entry := 0; entry < table4.entries; entry++ {
			for lane := 0; lane < X4Lanes; lane++ {
				got := table4.points[entry].Lane(lane)
				want := exactReferenceIntegerMult(refs4[lane], big.NewInt(int64(entry+1)))
				assertScalarPointMatchesReference(t, fmt.Sprintf("x4 radix %d entry %d lane %d", 1<<radixBits, entry, lane), &got, want)
			}
		}
	}
}

func TestRegularRadixScalarMultX8MasksAndTails(t *testing.T) {
	rng := rand.New(rand.NewSource(0x518ca1a7))
	torsion := referenceTorsionPoints(t)
	refs, bases := scalarWindowMixedBasesX8(t, rng, &torsion)
	values := scalarWindowSignedLaneValues()
	var scalars [X8Lanes]SignedMagnitude
	var want [X8Lanes]*edwardsref.Point
	for lane := 0; lane < X8Lanes; lane++ {
		scalars[lane] = signedMagnitudeFromTestBig(values[lane])
		want[lane] = exactReferenceIntegerMult(refs[lane], values[lane])
	}

	var masks []uint8
	for tail := 0; tail <= X8Lanes; tail++ {
		if tail == X8Lanes {
			masks = append(masks, 0xff)
		} else {
			masks = append(masks, uint8((1<<tail)-1))
		}
	}
	for lane := 0; lane < X8Lanes; lane++ {
		masks = append(masks, uint8(0xff&^(1<<lane)))
	}

	for _, radixBits := range []uint{4, 5, 6} {
		table := BuildFullTableX8(&bases, radixBits)
		recoded := RecodeRegularRadixX8(&scalars, radixBits)
		var loop PointX8
		ScalarMultLoopX8(&loop, &table, &recoded, 0xff)
		assertMaskedPointX8(t, fmt.Sprintf("prebuilt radix %d", 1<<radixBits), &loop, &want, 0xff)

		for _, active := range masks {
			var got PointX8
			ScalarMultX8(&got, &bases, &scalars, radixBits, active)
			assertMaskedPointX8(t, fmt.Sprintf("radix %d active %02x", 1<<radixBits, active), &got, &want, active)
		}
	}
}

func TestRegularRadixScalarMultX4MasksAndTails(t *testing.T) {
	rng := rand.New(rand.NewSource(0x514ca1a7))
	torsion := referenceTorsionPoints(t)
	refs8, bases8 := scalarWindowMixedBasesX8(t, rng, &torsion)
	values := scalarWindowSignedLaneValues()

	for half := 0; half < 2; half++ {
		var refs [X4Lanes]*edwardsref.Point
		var points [X4Lanes]Point
		var scalars [X4Lanes]SignedMagnitude
		var want [X4Lanes]*edwardsref.Point
		for lane := 0; lane < X4Lanes; lane++ {
			index := half*X4Lanes + lane
			refs[lane] = refs8[index]
			points[lane] = bases8.Lane(index)
			scalars[lane] = signedMagnitudeFromTestBig(values[index])
			want[lane] = exactReferenceIntegerMult(refs[lane], values[index])
		}
		var bases PointX4
		bases.SetPoints(&points)
		for _, radixBits := range []uint{4, 5, 6} {
			for tail := 0; tail <= X4Lanes; tail++ {
				active := uint8((1 << tail) - 1)
				var got PointX4
				ScalarMultX4(&got, &bases, &scalars, radixBits, active)
				assertMaskedPointX4(t, fmt.Sprintf("half %d radix %d tail %d", half, 1<<radixBits, tail), &got, &want, active)
			}
			for lane := 0; lane < X4Lanes; lane++ {
				active := uint8(0x0f &^ (1 << lane))
				var got PointX4
				ScalarMultX4(&got, &bases, &scalars, radixBits, active)
				assertMaskedPointX4(t, fmt.Sprintf("half %d radix %d disabled %d", half, 1<<radixBits, lane), &got, &want, active)
			}
		}
	}
}

func TestRegularRadixScalarMultInvalidDecodeLanes(t *testing.T) {
	bad := deterministicInvalidPointEncoding(t)
	generator := edwardsref.NewGeneratorPoint().Bytes()

	var scalars8 [X8Lanes]SignedMagnitude
	for lane := range scalars8 {
		scalars8[lane] = NewSignedMagnitudeUint64(uint64(17+lane), lane%2 != 0)
	}
	for invalidLane := 0; invalidLane < X8Lanes; invalidLane++ {
		var encodings [X8Lanes][32]byte
		for lane := range encodings {
			copy(encodings[lane][:], generator)
		}
		encodings[invalidLane] = bad
		var bases PointX8
		valid := bases.SetBytes(&encodings)
		wantMask := uint8(0xff &^ (1 << invalidLane))
		if valid != wantMask {
			t.Fatalf("x8 invalid lane %d decode mask=%02x want=%02x", invalidLane, valid, wantMask)
		}
		var got PointX8
		ScalarMultX8(&got, &bases, &scalars8, 5, 0xff&valid)
		if identityMask := got.IsIdentity(); identityMask != 1<<invalidLane {
			t.Fatalf("x8 invalid lane %d output identity mask=%02x", invalidLane, identityMask)
		}
	}

	var scalars4 [X4Lanes]SignedMagnitude
	for lane := range scalars4 {
		scalars4[lane] = NewSignedMagnitudeUint64(uint64(23+lane), lane%2 != 0)
	}
	for invalidLane := 0; invalidLane < X4Lanes; invalidLane++ {
		var encodings [X4Lanes][32]byte
		for lane := range encodings {
			copy(encodings[lane][:], generator)
		}
		encodings[invalidLane] = bad
		var bases PointX4
		valid := bases.SetBytes(&encodings)
		wantMask := uint8(0x0f &^ (1 << invalidLane))
		if valid != wantMask {
			t.Fatalf("x4 invalid lane %d decode mask=%02x want=%02x", invalidLane, valid, wantMask)
		}
		var got PointX4
		ScalarMultX4(&got, &bases, &scalars4, 5, 0x0f&valid)
		if identityMask := got.IsIdentity(); identityMask != 1<<invalidLane {
			t.Fatalf("x4 invalid lane %d output identity mask=%02x", invalidLane, identityMask)
		}
	}
}

func TestQSMX8FourExactTerms(t *testing.T) {
	rng := rand.New(rand.NewSource(0x51845d))
	torsion := referenceTorsionPoints(t)
	refs, bases := scalarWindowQSMBasesX8(t, rng, &torsion)
	coefficients, coefficientBig := scalarWindowQSMCoefficientsX8()

	var want [X8Lanes]*edwardsref.Point
	for lane := 0; lane < X8Lanes; lane++ {
		want[lane] = exactReferenceQSMSum(&refs, &coefficientBig, lane)
	}
	for _, radixBits := range []uint{4, 5, 6} {
		for _, active := range []uint8{0, 0x01, 0x07, 0x7f, 0x55, 0xff} {
			var got PointX8
			QSMX8(&got, &bases, &coefficients, radixBits, active)
			assertMaskedPointX8(t, fmt.Sprintf("QSM x8 radix %d active %02x", 1<<radixBits, active), &got, &want, active)
		}
	}
}

func TestQSMX4FourExactTermsAndTails(t *testing.T) {
	rng := rand.New(rand.NewSource(0x51445d))
	torsion := referenceTorsionPoints(t)
	refs8, bases8 := scalarWindowQSMBasesX8(t, rng, &torsion)
	coefficients8, coefficientBig8 := scalarWindowQSMCoefficientsX8()

	for half := 0; half < 2; half++ {
		var refs [QSMTerms][X4Lanes]*edwardsref.Point
		var bases [QSMTerms]PointX4
		var coefficients QSMScalarsX4
		var coefficientBig [QSMTerms][X4Lanes]*big.Int
		for term := 0; term < QSMTerms; term++ {
			var points [X4Lanes]Point
			for lane := 0; lane < X4Lanes; lane++ {
				index := half*X4Lanes + lane
				refs[term][lane] = refs8[term][index]
				points[lane] = bases8[term].Lane(index)
				coefficients[term][lane] = coefficients8[term][index]
				coefficientBig[term][lane] = coefficientBig8[term][index]
			}
			bases[term].SetPoints(&points)
		}
		var want [X4Lanes]*edwardsref.Point
		for lane := 0; lane < X4Lanes; lane++ {
			want[lane] = exactReferenceQSMSumX4(&refs, &coefficientBig, lane)
		}
		for _, radixBits := range []uint{4, 5, 6} {
			for tail := 0; tail <= X4Lanes; tail++ {
				active := uint8((1 << tail) - 1)
				var got PointX4
				QSMX4(&got, &bases, &coefficients, radixBits, active)
				assertMaskedPointX4(t, fmt.Sprintf("QSM x4 half %d radix %d tail %d", half, 1<<radixBits, tail), &got, &want, active)
			}
		}
	}
}

func TestHEEAEquationX8ExactSignedAndInvalidEpsilonLanes(t *testing.T) {
	rng := rand.New(rand.NewSource(0x518eea))
	torsion := referenceTorsionPoints(t)
	aRefs, A := scalarWindowMixedBasesX8(t, rng, &torsion)
	var shiftedTorsion [X8Lanes]*edwardsref.Point
	for lane := 0; lane < X8Lanes; lane++ {
		shiftedTorsion[lane] = torsion[(lane+3)%X8Lanes]
	}
	rRefs, R := scalarWindowMixedBasesX8(t, rng, &shiftedTorsion)
	bRefs, B := scalarWindowGeneratorX8(t)
	s, tau, rho, epsilon := scalarWindowHEEACoefficientsX8()

	var want [X8Lanes]*edwardsref.Point
	for lane := 0; lane < X8Lanes; lane++ {
		want[lane] = exactReferenceHEEAEquation(
			bRefs[lane], rRefs[lane], aRefs[lane],
			signedMagnitudeToBig(s[lane]), signedMagnitudeToBig(tau[lane]), signedMagnitudeToBig(rho[lane]), epsilon[lane],
		)
	}
	for _, radixBits := range []uint{4, 5} {
		for _, active := range []uint8{0x01, 0x0f, 0x7f, 0xff} {
			var got PointX8
			if usable := HEEAEquationX8(&got, &B, &R, &A, &s, &tau, &rho, &epsilon, radixBits, active); usable != active {
				t.Fatalf("radix %d active %02x usable=%02x", 1<<radixBits, active, usable)
			}
			assertMaskedPointX8(t, fmt.Sprintf("HEEA x8 radix %d active %02x", 1<<radixBits, active), &got, &want, active)
		}
	}

	for invalidLane := 0; invalidLane < X8Lanes; invalidLane++ {
		invalidEpsilon := epsilon
		invalidEpsilon[invalidLane] = 0
		var got PointX8
		wantUsable := uint8(0xff &^ (1 << invalidLane))
		if usable := HEEAEquationX8(&got, &B, &R, &A, &s, &tau, &rho, &invalidEpsilon, 5, 0xff); usable != wantUsable {
			t.Fatalf("invalid epsilon lane %d usable=%02x want=%02x", invalidLane, usable, wantUsable)
		}
		assertMaskedPointX8(t, fmt.Sprintf("HEEA invalid epsilon lane %d", invalidLane), &got, &want, wantUsable)
	}
}

func TestHEEAEquationX4ExactSignedAndTails(t *testing.T) {
	rng := rand.New(rand.NewSource(0x514eea))
	torsion := referenceTorsionPoints(t)
	aRefs8, A8 := scalarWindowMixedBasesX8(t, rng, &torsion)
	var shiftedTorsion [X8Lanes]*edwardsref.Point
	for lane := 0; lane < X8Lanes; lane++ {
		shiftedTorsion[lane] = torsion[(lane+1)%X8Lanes]
	}
	rRefs8, R8 := scalarWindowMixedBasesX8(t, rng, &shiftedTorsion)
	bRefs8, B8 := scalarWindowGeneratorX8(t)
	s8, tau8, rho8, epsilon8 := scalarWindowHEEACoefficientsX8()

	for half := 0; half < 2; half++ {
		var aRefs, rRefs, bRefs [X4Lanes]*edwardsref.Point
		var aPoints, rPoints, bPoints [X4Lanes]Point
		var s, tau, rho [X4Lanes]SignedMagnitude
		var epsilon [X4Lanes]int8
		var want [X4Lanes]*edwardsref.Point
		for lane := 0; lane < X4Lanes; lane++ {
			index := half*X4Lanes + lane
			aRefs[lane], rRefs[lane], bRefs[lane] = aRefs8[index], rRefs8[index], bRefs8[index]
			aPoints[lane], rPoints[lane], bPoints[lane] = A8.Lane(index), R8.Lane(index), B8.Lane(index)
			s[lane], tau[lane], rho[lane], epsilon[lane] = s8[index], tau8[index], rho8[index], epsilon8[index]
			want[lane] = exactReferenceHEEAEquation(
				bRefs[lane], rRefs[lane], aRefs[lane],
				signedMagnitudeToBig(s[lane]), signedMagnitudeToBig(tau[lane]), signedMagnitudeToBig(rho[lane]), epsilon[lane],
			)
		}
		var A, R, B PointX4
		A.SetPoints(&aPoints)
		R.SetPoints(&rPoints)
		B.SetPoints(&bPoints)
		for _, radixBits := range []uint{4, 5} {
			for tail := 0; tail <= X4Lanes; tail++ {
				active := uint8((1 << tail) - 1)
				var got PointX4
				if usable := HEEAEquationX4(&got, &B, &R, &A, &s, &tau, &rho, &epsilon, radixBits, active); usable != active {
					t.Fatalf("half %d radix %d tail %d usable=%02x", half, 1<<radixBits, tail, usable)
				}
				assertMaskedPointX4(t, fmt.Sprintf("HEEA x4 half %d radix %d tail %d", half, 1<<radixBits, tail), &got, &want, active)
			}
		}
	}
}

func scalarWindowQSMBasesX8(t *testing.T, rng *rand.Rand, torsion *[X8Lanes]*edwardsref.Point) ([QSMTerms][X8Lanes]*edwardsref.Point, [QSMTerms]PointX8) {
	t.Helper()
	var refs [QSMTerms][X8Lanes]*edwardsref.Point
	var bases [QSMTerms]PointX8
	for term := 0; term < QSMTerms; term++ {
		var termTorsion [X8Lanes]*edwardsref.Point
		for lane := 0; lane < X8Lanes; lane++ {
			termTorsion[lane] = torsion[(lane+term)%X8Lanes]
		}
		refs[term], bases[term] = scalarWindowMixedBasesX8(t, rng, &termTorsion)
	}
	return refs, bases
}

func scalarWindowQSMCoefficientsX8() (QSMScalarsX8, [QSMTerms][X8Lanes]*big.Int) {
	values := scalarWindowBoundaryIntegers()
	var coefficients QSMScalarsX8
	var exact [QSMTerms][X8Lanes]*big.Int
	for term := 0; term < QSMTerms; term++ {
		for lane := 0; lane < X8Lanes; lane++ {
			value := new(big.Int).Set(values[(term*5+lane*2)%len(values)])
			if (term+lane)%2 != 0 {
				value.Neg(value)
			}
			exact[term][lane] = value
			coefficients[term][lane] = signedMagnitudeFromTestBig(value)
		}
	}
	return coefficients, exact
}

func exactReferenceQSMSum(refs *[QSMTerms][X8Lanes]*edwardsref.Point, coefficients *[QSMTerms][X8Lanes]*big.Int, lane int) *edwardsref.Point {
	acc := edwardsref.NewIdentityPoint()
	for term := 0; term < QSMTerms; term++ {
		multiple := exactReferenceIntegerMult(refs[term][lane], coefficients[term][lane])
		acc.Add(acc, multiple)
	}
	return acc
}

func exactReferenceQSMSumX4(refs *[QSMTerms][X4Lanes]*edwardsref.Point, coefficients *[QSMTerms][X4Lanes]*big.Int, lane int) *edwardsref.Point {
	acc := edwardsref.NewIdentityPoint()
	for term := 0; term < QSMTerms; term++ {
		multiple := exactReferenceIntegerMult(refs[term][lane], coefficients[term][lane])
		acc.Add(acc, multiple)
	}
	return acc
}

func scalarWindowGeneratorX8(t *testing.T) ([X8Lanes]*edwardsref.Point, PointX8) {
	t.Helper()
	var refs [X8Lanes]*edwardsref.Point
	var encodings [X8Lanes][32]byte
	for lane := 0; lane < X8Lanes; lane++ {
		refs[lane] = edwardsref.NewGeneratorPoint()
		copy(encodings[lane][:], refs[lane].Bytes())
	}
	var points PointX8
	if mask := points.SetBytes(&encodings); mask != 0xff {
		t.Fatalf("generator valid mask=%02x", mask)
	}
	return refs, points
}

func scalarWindowHEEACoefficientsX8() ([X8Lanes]SignedMagnitude, [X8Lanes]SignedMagnitude, [X8Lanes]SignedMagnitude, [X8Lanes]int8) {
	l := heea8l.Order()
	var s, tau, rho [X8Lanes]SignedMagnitude
	var epsilon [X8Lanes]int8
	for lane := 0; lane < X8Lanes; lane++ {
		sValue := new(big.Int).Sub(new(big.Int).Set(l), big.NewInt(int64(lane+1)))
		tauValue := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), uint(128+lane)), big.NewInt(int64(2*lane+1)))
		rhoValue := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), uint(120+lane)), big.NewInt(int64(0x51+lane)))
		if lane%3 == 1 {
			tauValue.Neg(tauValue)
		}
		if lane%3 == 2 {
			rhoValue.Neg(rhoValue)
		}
		s[lane] = signedMagnitudeFromTestBig(sValue)
		tau[lane] = signedMagnitudeFromTestBig(tauValue)
		rho[lane] = signedMagnitudeFromTestBig(rhoValue)
		if lane%2 == 0 {
			epsilon[lane] = 1
		} else {
			epsilon[lane] = -1
		}
	}
	return s, tau, rho, epsilon
}

func exactReferenceHEEAEquation(B, R, A *edwardsref.Point, s, tau, rho *big.Int, epsilon int8) *edwardsref.Point {
	tauS := new(big.Int).Mul(new(big.Int).Set(tau), s)
	rCoefficient := new(big.Int).Neg(new(big.Int).Set(tau))
	aCoefficient := new(big.Int).Mul(new(big.Int).Set(rho), big.NewInt(int64(-epsilon)))
	bTerm := exactReferenceIntegerMult(B, tauS)
	rTerm := exactReferenceIntegerMult(R, rCoefficient)
	aTerm := exactReferenceIntegerMult(A, aCoefficient)
	bTerm.Add(bTerm, rTerm)
	bTerm.Add(bTerm, aTerm)
	return bTerm
}

var (
	scalarWindowTableX4Sink FullTableX4
	scalarWindowTableX8Sink FullTableX8
	scalarWindowPointX4Sink PointX4
	scalarWindowPointX8Sink PointX8
)

func BenchmarkRegularRadixTableBuild(b *testing.B) {
	base4, base8, _, _ := scalarWindowBenchmarkFixtures(b)
	for _, radixBits := range []uint{4, 5, 6} {
		b.Run(fmt.Sprintf("x4/radix=%d", 1<<radixBits), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				scalarWindowTableX4Sink = BuildFullTableX4(&base4, radixBits)
			}
			b.ReportMetric(float64(NominalFullTableBytes(4, 3, radixBits)), "3coord-table-B")
			b.ReportMetric(float64(NominalFullTableBytes(4, 4, radixBits)), "4coord-table-B")
		})
		b.Run(fmt.Sprintf("x8/radix=%d", 1<<radixBits), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				scalarWindowTableX8Sink = BuildFullTableX8(&base8, radixBits)
			}
			b.ReportMetric(float64(NominalFullTableBytes(8, 3, radixBits)), "3coord-table-B")
			b.ReportMetric(float64(NominalFullTableBytes(8, 4, radixBits)), "4coord-table-B")
		})
	}
}

func BenchmarkRegularRadixScalarLoop(b *testing.B) {
	base4, base8, scalars4, scalars8 := scalarWindowBenchmarkFixtures(b)
	for _, radixBits := range []uint{4, 5, 6} {
		table4 := BuildFullTableX4(&base4, radixBits)
		recoded4 := RecodeRegularRadixX4(&scalars4, radixBits)
		b.Run(fmt.Sprintf("x4/radix=%d", 1<<radixBits), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				ScalarMultLoopX4(&scalarWindowPointX4Sink, &table4, &recoded4, 0x0f)
			}
			b.ReportMetric(float64(NominalFullTableBytes(4, 3, radixBits)), "3coord-table-B")
			b.ReportMetric(float64(NominalFullTableBytes(4, 4, radixBits)), "4coord-table-B")
		})

		table8 := BuildFullTableX8(&base8, radixBits)
		recoded8 := RecodeRegularRadixX8(&scalars8, radixBits)
		b.Run(fmt.Sprintf("x8/radix=%d", 1<<radixBits), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				ScalarMultLoopX8(&scalarWindowPointX8Sink, &table8, &recoded8, 0xff)
			}
			b.ReportMetric(float64(NominalFullTableBytes(8, 3, radixBits)), "3coord-table-B")
			b.ReportMetric(float64(NominalFullTableBytes(8, 4, radixBits)), "4coord-table-B")
		})
	}
}

func scalarWindowBenchmarkFixtures(tb testing.TB) (PointX4, PointX8, [X4Lanes]SignedMagnitude, [X8Lanes]SignedMagnitude) {
	tb.Helper()
	generator := edwardsref.NewGeneratorPoint().Bytes()
	var encoded8 [X8Lanes][32]byte
	for lane := range encoded8 {
		copy(encoded8[lane][:], generator)
	}
	var base8 PointX8
	if mask := base8.SetBytes(&encoded8); mask != 0xff {
		tb.Fatalf("benchmark x8 base mask=%02x", mask)
	}
	var points4 [X4Lanes]Point
	for lane := range points4 {
		points4[lane] = base8.Lane(lane)
	}
	var base4 PointX4
	base4.SetPoints(&points4)

	values := scalarWindowSignedLaneValues()
	var scalars4 [X4Lanes]SignedMagnitude
	var scalars8 [X8Lanes]SignedMagnitude
	for lane := range scalars8 {
		scalars8[lane] = signedMagnitudeFromTestBig(values[lane])
		if lane < X4Lanes {
			scalars4[lane] = scalars8[lane]
		}
	}
	return base4, base8, scalars4, scalars8
}

func scalarWindowSignedLaneValues() [X8Lanes]*big.Int {
	l := heea8l.Order()
	return [X8Lanes]*big.Int{
		big.NewInt(0),
		big.NewInt(17),
		big.NewInt(-16),
		new(big.Int).Lsh(big.NewInt(1), 250),
		new(big.Int).Neg(new(big.Int).Sub(new(big.Int).Set(l), big.NewInt(1))),
		new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1)),
		new(big.Int).Neg(new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 300), big.NewInt(7))),
		new(big.Int).Sub(new(big.Int).Set(l), big.NewInt(2)),
	}
}

func assertMaskedPointX8(t *testing.T, label string, got *PointX8, want *[X8Lanes]*edwardsref.Point, active uint8) {
	t.Helper()
	for lane := 0; lane < X8Lanes; lane++ {
		point := got.Lane(lane)
		if active&(1<<lane) == 0 {
			if point.IsIdentity() != 1 {
				t.Fatalf("%s lane %d inactive output is not identity", label, lane)
			}
			continue
		}
		assertScalarPointMatchesReference(t, fmt.Sprintf("%s lane %d", label, lane), &point, want[lane])
	}
}

func assertMaskedPointX4(t *testing.T, label string, got *PointX4, want *[X4Lanes]*edwardsref.Point, active uint8) {
	t.Helper()
	for lane := 0; lane < X4Lanes; lane++ {
		point := got.Lane(lane)
		if active&(1<<lane) == 0 {
			if point.IsIdentity() != 1 {
				t.Fatalf("%s lane %d inactive output is not identity", label, lane)
			}
			continue
		}
		assertScalarPointMatchesReference(t, fmt.Sprintf("%s lane %d", label, lane), &point, want[lane])
	}
}

func scalarWindowBoundaryIntegers() []*big.Int {
	l := heea8l.Order()
	two250 := new(big.Int).Lsh(big.NewInt(1), 250)
	return []*big.Int{
		big.NewInt(0), big.NewInt(1), big.NewInt(2),
		big.NewInt(7), big.NewInt(8), big.NewInt(9),
		big.NewInt(15), big.NewInt(16), big.NewInt(17),
		big.NewInt(31), big.NewInt(32),
		new(big.Int).Sub(new(big.Int).Set(two250), big.NewInt(1)),
		new(big.Int).Set(two250),
		new(big.Int).Sub(new(big.Int).Set(l), big.NewInt(2)),
		new(big.Int).Sub(new(big.Int).Set(l), big.NewInt(1)),
		new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1)),
		new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 300), big.NewInt(0x12345)),
	}
}

func signedMagnitudeFromTestBig(value *big.Int) SignedMagnitude {
	negative := value.Sign() < 0
	abs := new(big.Int).Abs(new(big.Int).Set(value))
	return signedMagnitudeFromBig(abs, negative)
}

func signedMagnitudeToBig(value SignedMagnitude) *big.Int {
	result := value.absoluteBig()
	if value.negative {
		result.Neg(result)
	}
	return result
}

func reconstructRegularRadix(digits []int8, radixBits uint) *big.Int {
	result := new(big.Int)
	place := big.NewInt(1)
	radix := new(big.Int).Lsh(big.NewInt(1), radixBits)
	for _, digit := range digits {
		term := new(big.Int).Mul(big.NewInt(int64(digit)), place)
		result.Add(result, term)
		place.Mul(place, radix)
	}
	return result
}

func scalarWindowMixedBasesX8(t *testing.T, rng *rand.Rand, torsion *[X8Lanes]*edwardsref.Point) ([X8Lanes]*edwardsref.Point, PointX8) {
	t.Helper()
	var refs [X8Lanes]*edwardsref.Point
	var encodings [X8Lanes][32]byte
	for lane := 0; lane < X8Lanes; lane++ {
		refs[lane] = randomMixedReferencePoint(t, rng, torsion[lane])
		copy(encodings[lane][:], refs[lane].Bytes())
	}
	var points PointX8
	if mask := points.SetBytes(&encodings); mask != 0xff {
		t.Fatalf("mixed base valid mask=%02x", mask)
	}
	return refs, points
}

func exactReferenceIntegerMult(point *edwardsref.Point, coefficient *big.Int) *edwardsref.Point {
	if coefficient.Sign() == 0 {
		return edwardsref.NewIdentityPoint()
	}
	magnitude := new(big.Int).Abs(new(big.Int).Set(coefficient))
	acc := edwardsref.NewIdentityPoint()
	base := new(edwardsref.Point).Set(point)
	for bit := 0; bit < magnitude.BitLen(); bit++ {
		if magnitude.Bit(bit) != 0 {
			acc.Add(acc, base)
		}
		base.Add(base, base)
	}
	if coefficient.Sign() < 0 {
		acc.Negate(acc)
	}
	return acc
}

func assertScalarPointMatchesReference(t *testing.T, label string, got *Point, want *edwardsref.Point) {
	t.Helper()
	gotBytes := got.Bytes()
	if string(gotBytes[:]) != string(want.Bytes()) {
		t.Fatalf("%s mismatch\ngot  %x\nwant %x", label, gotBytes, want.Bytes())
	}
	assertScalarPointInvariant(t, label, got)
}
