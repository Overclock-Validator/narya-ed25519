package r51x5

import (
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"runtime"
	"testing"
	"unsafe"

	edwardsref "github.com/Overclock-Validator/narya-ed25519/internal/edwards25519"
	"github.com/Overclock-Validator/narya-ed25519/internal/heea8l"
)

func TestHEEAFixedRadixRecodingExactBoundariesAndSigns(t *testing.T) {
	l := heea8l.Order()
	values := [X8Lanes]*big.Int{
		big.NewInt(0),
		new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 127), big.NewInt(1)),
		new(big.Int).Lsh(big.NewInt(1), 127),
		new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1)),
		new(big.Int).Lsh(big.NewInt(1), 128),
		new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1)),
		new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 136), big.NewInt(1)),
		new(big.Int).Sub(new(big.Int).Set(l), big.NewInt(1)),
	}
	var scalars [X8Lanes][32]byte
	var negativeMask uint8
	for lane := range scalars {
		scalars[lane] = heeaIFMAEncodeMagnitude(values[lane])
		if lane&1 != 0 {
			negativeMask |= 1 << lane
		}
	}
	for _, radixBits := range []uint{4, 5} {
		var digits heeaFixedRadixDigitsX8
		if valid := recodeHEEAFixedScalarsX8(&digits, &scalars, negativeMask, 0xff, radixBits); valid != 0xff {
			t.Fatalf("radix %d valid=%02x", 1<<radixBits, valid)
		}
		for lane := 0; lane < X8Lanes; lane++ {
			want := new(big.Int).Set(values[lane])
			if negativeMask&(1<<lane) != 0 {
				want.Neg(want)
			}
			if got := reconstructHEEAFixedRadixX8(&digits, lane); got.Cmp(want) != 0 {
				t.Fatalf("radix %d lane %d recoding mismatch\ngot  %x\nwant %x", 1<<radixBits, lane, got, want)
			}
		}
		// The HEEA-sized lanes must not inherit the ordinary 256-bit fixed
		// schedule. L-1 in lane seven is intentionally excluded here.
		maxHEEARounds := (136+int(radixBits)-1)/int(radixBits) + 1
		var short [X8Lanes][32]byte
		copy(short[:], scalars[:])
		short[7] = short[6]
		if valid := recodeHEEAFixedScalarsX8(&digits, &short, negativeMask, 0xff, radixBits); valid != 0xff || int(digits.count) > maxHEEARounds {
			t.Fatalf("radix %d short schedule=(valid=%02x,rounds=%d) max=%d", 1<<radixBits, valid, digits.count, maxHEEARounds)
		}

		var scalars4 [X4Lanes][32]byte
		copy(scalars4[:], scalars[2:2+X4Lanes])
		var digits4 heeaFixedRadixDigitsX4
		if valid := recodeHEEAFixedScalarsX4(&digits4, &scalars4, (negativeMask>>2)&0x0f, 0x0f, radixBits); valid != 0x0f {
			t.Fatalf("x4 radix %d valid=%02x", 1<<radixBits, valid)
		}
		for lane := 0; lane < X4Lanes; lane++ {
			want := new(big.Int).Set(values[lane+2])
			if negativeMask&(1<<(lane+2)) != 0 {
				want.Neg(want)
			}
			if got := reconstructHEEAFixedRadixX4(&digits4, lane); got.Cmp(want) != 0 {
				t.Fatalf("x4 radix %d lane %d mismatch", 1<<radixBits, lane)
			}
		}
	}

	invalid := scalars
	invalid[3] = scalarOrderBytes
	var digits heeaFixedRadixDigitsX8
	if valid := recodeHEEAFixedScalarsX8(&digits, &invalid, negativeMask, 0xff, 5); valid != 0xf7 {
		t.Fatalf("noncanonical lane valid=%02x want=f7", valid)
	}
}

func TestPrepareHEEABaseSplitCoefficientsExactSignsBitsAndSplit(t *testing.T) {
	for scenario := 0; scenario < 2; scenario++ {
		s, tau, rho, epsilon, sExact, tauExact, rhoExact := heeaIFMACoefficientFixture(scenario)
		var coefficients ExperimentalHEEABaseSplitCoefficientsX8
		usable, fallback := ExperimentalPrepareHEEABaseSplitCoefficientsX8(&coefficients, &s, &tau, &rho, &epsilon, 0xff)
		if usable != 0xff || fallback != 0 || coefficients.ValidMask() != 0xff || coefficients.FallbackMask(0xff) != 0 {
			t.Fatalf("scenario %d masks usable=%02x fallback=%02x valid=%02x", scenario, usable, fallback, coefficients.ValidMask())
		}
		for lane := 0; lane < X8Lanes; lane++ {
			ts := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Set(tauExact[lane]), sExact[lane]), heea8l.Order())
			lowMask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), heeaBaseSplitBit), big.NewInt(1))
			want := [QSMTerms]*big.Int{
				new(big.Int).And(new(big.Int).Set(ts), lowMask),
				new(big.Int).Rsh(new(big.Int).Set(ts), heeaBaseSplitBit),
				new(big.Int).Neg(new(big.Int).Set(tauExact[lane])),
				new(big.Int).Mul(new(big.Int).Set(rhoExact[lane]), big.NewInt(int64(-epsilon[lane]))),
			}
			for term := 0; term < QSMTerms; term++ {
				if got := heeaIFMACoefficientBigX8(&coefficients, term, lane); got.Cmp(want[term]) != 0 {
					t.Fatalf("scenario %d lane %d term %d mismatch\ngot  %x\nwant %x", scenario, lane, term, got, want[term])
				}
			}
		}

		var halves [2]ExperimentalHEEABaseSplitCoefficientsX4
		ExperimentalSplitHEEABaseSplitCoefficientsX8(&halves, &coefficients)
		for half := 0; half < 2; half++ {
			if halves[half].ValidMask() != 0x0f {
				t.Fatalf("scenario %d half %d valid=%02x", scenario, half, halves[half].ValidMask())
			}
			for term := 0; term < QSMTerms; term++ {
				for lane := 0; lane < X4Lanes; lane++ {
					if got, want := heeaIFMACoefficientBigX4(&halves[half], term, lane), heeaIFMACoefficientBigX8(&coefficients, term, half*X4Lanes+lane); got.Cmp(want) != 0 {
						t.Fatalf("scenario %d half %d term %d lane %d split mismatch", scenario, half, term, lane)
					}
				}
			}
		}
	}

	// Make the reduced basepoint product itself land on both sides of the
	// split boundary. tau=1 means the prepared value is exactly s.
	boundaries := [X8Lanes]*big.Int{
		new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 127), big.NewInt(1)),
		new(big.Int).Lsh(big.NewInt(1), 127),
		new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 127), big.NewInt(1)),
		new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1)),
		new(big.Int).Lsh(big.NewInt(1), 128),
		new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1)),
		new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 129), big.NewInt(1)),
		new(big.Int).Sub(heea8l.Order(), big.NewInt(1)),
	}
	var s [X8Lanes][32]byte
	var tau, rho [X8Lanes]ExperimentalHEEASignedCoefficient
	var epsilon [X8Lanes]int8
	for lane := range s {
		s[lane] = heeaIFMAEncodeMagnitude(boundaries[lane])
		tau[lane].Magnitude[0] = 1
		epsilon[lane] = 1
	}
	var coefficients ExperimentalHEEABaseSplitCoefficientsX8
	if usable, fallback := ExperimentalPrepareHEEABaseSplitCoefficientsX8(&coefficients, &s, &tau, &rho, &epsilon, 0xff); usable != 0xff || fallback != 0 {
		t.Fatalf("boundary preparation masks=%02x/%02x", usable, fallback)
	}
	for lane := range boundaries {
		reconstructed := new(big.Int).Add(
			heeaIFMACoefficientBigX8(&coefficients, 0, lane),
			new(big.Int).Lsh(heeaIFMACoefficientBigX8(&coefficients, 1, lane), heeaBaseSplitBit),
		)
		if reconstructed.Cmp(boundaries[lane]) != 0 {
			t.Fatalf("boundary lane %d mismatch got=%x want=%x", lane, reconstructed, boundaries[lane])
		}
	}
}

func TestPrepareHEEABaseSplitCoefficientsRangeFailuresEveryLane(t *testing.T) {
	s, tau, rho, epsilon, _, _, _ := heeaIFMACoefficientFixture(0)
	type corrupt func(int, *[X8Lanes][32]byte, *[X8Lanes]ExperimentalHEEASignedCoefficient, *[X8Lanes]ExperimentalHEEASignedCoefficient, *[X8Lanes]int8)
	cases := []struct {
		name    string
		corrupt corrupt
	}{
		{"S>=L", func(lane int, s *[X8Lanes][32]byte, _ *[X8Lanes]ExperimentalHEEASignedCoefficient, _ *[X8Lanes]ExperimentalHEEASignedCoefficient, _ *[X8Lanes]int8) {
			s[lane] = scalarOrderBytes
		}},
		{"abs(tau)>=L", func(lane int, _ *[X8Lanes][32]byte, tau *[X8Lanes]ExperimentalHEEASignedCoefficient, _ *[X8Lanes]ExperimentalHEEASignedCoefficient, _ *[X8Lanes]int8) {
			tau[lane].Magnitude = scalarOrderBytes
		}},
		{"tau=0", func(lane int, _ *[X8Lanes][32]byte, tau *[X8Lanes]ExperimentalHEEASignedCoefficient, _ *[X8Lanes]ExperimentalHEEASignedCoefficient, _ *[X8Lanes]int8) {
			tau[lane] = ExperimentalHEEASignedCoefficient{}
		}},
		{"tau even", func(lane int, _ *[X8Lanes][32]byte, tau *[X8Lanes]ExperimentalHEEASignedCoefficient, _ *[X8Lanes]ExperimentalHEEASignedCoefficient, _ *[X8Lanes]int8) {
			tau[lane] = ExperimentalHEEASignedCoefficient{Negative: tau[lane].Negative}
			tau[lane].Magnitude[0] = 2
		}},
		{"abs(rho)>=L", func(lane int, _ *[X8Lanes][32]byte, _ *[X8Lanes]ExperimentalHEEASignedCoefficient, rho *[X8Lanes]ExperimentalHEEASignedCoefficient, _ *[X8Lanes]int8) {
			rho[lane].Magnitude = scalarOrderBytes
		}},
		{"epsilon", func(lane int, _ *[X8Lanes][32]byte, _ *[X8Lanes]ExperimentalHEEASignedCoefficient, _ *[X8Lanes]ExperimentalHEEASignedCoefficient, epsilon *[X8Lanes]int8) {
			epsilon[lane] = 0
		}},
	}
	for _, test := range cases {
		for lane := 0; lane < X8Lanes; lane++ {
			badS, badTau, badRho, badEpsilon := s, tau, rho, epsilon
			test.corrupt(lane, &badS, &badTau, &badRho, &badEpsilon)
			var coefficients ExperimentalHEEABaseSplitCoefficientsX8
			usable, fallback := ExperimentalPrepareHEEABaseSplitCoefficientsX8(&coefficients, &badS, &badTau, &badRho, &badEpsilon, 0xff)
			wantUsable := uint8(0xff &^ (1 << lane))
			if usable != wantUsable || fallback != 1<<lane || coefficients.ValidMask() != wantUsable {
				t.Fatalf("%s lane %d masks usable=%02x fallback=%02x", test.name, lane, usable, fallback)
			}
			for term := 0; term < QSMTerms; term++ {
				if coefficients.scalars[term][lane] != ([32]byte{}) {
					t.Fatalf("%s lane %d term %d retained partial coefficient", test.name, lane, term)
				}
			}
			if lane < X4Lanes {
				var badS4 [X4Lanes][32]byte
				var badTau4, badRho4 [X4Lanes]ExperimentalHEEASignedCoefficient
				var badEpsilon4 [X4Lanes]int8
				copy(badS4[:], badS[:X4Lanes])
				copy(badTau4[:], badTau[:X4Lanes])
				copy(badRho4[:], badRho[:X4Lanes])
				copy(badEpsilon4[:], badEpsilon[:X4Lanes])
				var coefficients4 ExperimentalHEEABaseSplitCoefficientsX4
				usable4, fallback4 := ExperimentalPrepareHEEABaseSplitCoefficientsX4(&coefficients4, &badS4, &badTau4, &badRho4, &badEpsilon4, 0x0f)
				wantUsable4 := uint8(0x0f &^ (1 << lane))
				if usable4 != wantUsable4 || fallback4 != 1<<lane || coefficients4.ValidMask() != wantUsable4 {
					t.Fatalf("x4 %s lane %d masks usable=%02x fallback=%02x", test.name, lane, usable4, fallback4)
				}
			}
		}
	}

	// An invalid inactive lane is neither usable nor a fallback.
	s[7] = scalarOrderBytes
	var coefficients ExperimentalHEEABaseSplitCoefficientsX8
	if usable, fallback := ExperimentalPrepareHEEABaseSplitCoefficientsX8(&coefficients, &s, &tau, &rho, &epsilon, 0x7f); usable != 0x7f || fallback != 0 {
		t.Fatalf("inactive invalid lane masks=%02x/%02x", usable, fallback)
	}
}

func TestPrepareHEEABaseSplitCoefficientsAndSplitZeroAllocations(t *testing.T) {
	s, tau, rho, epsilon, _, _, _ := heeaIFMACoefficientFixture(0)
	var coefficients ExperimentalHEEABaseSplitCoefficientsX8
	var halves [2]ExperimentalHEEABaseSplitCoefficientsX4
	if allocations := testing.AllocsPerRun(1000, func() {
		usable, fallback := ExperimentalPrepareHEEABaseSplitCoefficientsX8(&coefficients, &s, &tau, &rho, &epsilon, 0xff)
		if usable != 0xff || fallback != 0 {
			panic("unexpected HEEA coefficient fallback")
		}
		ExperimentalSplitHEEABaseSplitCoefficientsX8(&halves, &coefficients)
	}); allocations != 0 {
		t.Fatalf("coefficient preparation allocated %.2f objects", allocations)
	}

	var s4 [X4Lanes][32]byte
	var tau4, rho4 [X4Lanes]ExperimentalHEEASignedCoefficient
	var epsilon4 [X4Lanes]int8
	copy(s4[:], s[:X4Lanes])
	copy(tau4[:], tau[:X4Lanes])
	copy(rho4[:], rho[:X4Lanes])
	copy(epsilon4[:], epsilon[:X4Lanes])
	var coefficients4 ExperimentalHEEABaseSplitCoefficientsX4
	if allocations := testing.AllocsPerRun(1000, func() {
		usable, fallback := ExperimentalPrepareHEEABaseSplitCoefficientsX4(&coefficients4, &s4, &tau4, &rho4, &epsilon4, 0x0f)
		if usable != 0x0f || fallback != 0 {
			panic("unexpected x4 HEEA coefficient fallback")
		}
	}); allocations != 0 {
		t.Fatalf("x4 coefficient preparation allocated %.2f objects", allocations)
	}
}

func TestIFMAHEEABaseSplitModelMatchesScalarAndExactPoints(t *testing.T) {
	rng := rand.New(rand.NewSource(0x1f4a_8eea_5117))
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
		sBytes, tauFixed, rhoFixed, epsilon, sExact, tauExact, rhoExact := heeaIFMACoefficientFixture(scenario)
		sSigned, tauSigned, rhoSigned := heeaIFMASignedMagnitudeInputs(&sExact, &tauExact, &rhoExact)
		want := heeaBaseSplitExactWantX8(&bRefs, &rRefs, &aRefs, &sSigned, &tauSigned, &rhoSigned, &epsilon)
		var coefficients ExperimentalHEEABaseSplitCoefficientsX8
		if usable, fallback := ExperimentalPrepareHEEABaseSplitCoefficientsX8(&coefficients, &sBytes, &tauFixed, &rhoFixed, &epsilon, 0xff); usable != 0xff || fallback != 0 {
			t.Fatalf("scenario %d prepare=%02x/%02x", scenario, usable, fallback)
		}
		for _, radixBits := range []uint{4, 5} {
			var model modelIFMAHEEABaseSplitWorkspaceX8
			if err := model.prepare(&B, &R, &A, radixBits); err != nil {
				t.Fatal(err)
			}
			for _, active := range everyIFMADSMActiveMaskX8() {
				var gotLoose IFMAPointX8
				usable, fallback, err := model.evaluate(&gotLoose, &coefficients, active)
				if err != nil || usable != active || fallback != 0 {
					t.Fatalf("scenario %d radix %d active=%02x model=(%02x,%02x,%v)", scenario, 1<<radixBits, active, usable, fallback, err)
				}
				got := gotLoose.Reduced()
				assertMaskedPointX8(t, fmt.Sprintf("HEEA IFMA model scenario %d radix %d active %02x", scenario, 1<<radixBits, active), &got, &want, active)

				var scalar PointX8
				if scalarMask := ExperimentalHEEABaseSplitEquationX8(&scalar, &B, &B128, &R, &A, &sSigned, &tauSigned, &rhoSigned, &epsilon, radixBits, active); scalarMask != active || got.Equal(&scalar)&active != active {
					t.Fatalf("scenario %d radix %d active=%02x model/scalar mismatch", scenario, 1<<radixBits, active)
				}
			}
			assertIFMAHEEAModelTwoX4MatchesX8(t, &model, &B, &R, &A, &coefficients, radixBits)
		}
	}
}

func TestIFMAHEEAAffineRReconstructionModelAllMasks(t *testing.T) {
	rng := rand.New(rand.NewSource(0x1f4a_aff1_8e00))
	torsion := referenceTorsionPoints(t)
	_, R := scalarWindowMixedBasesX8(t, rng, &torsion)
	affine8 := AffinePointX8{X: R.X, Y: R.Y}
	for maskValue := 0; maskValue <= 0xff; maskValue++ {
		mask := uint8(maskValue)
		var gotLoose IFMAPointX8
		if err := modelHEEAIFMAPointFromAffineX8(&gotLoose, &affine8, mask); err != nil {
			t.Fatalf("x8 mask=%02x reconstruction: %v", mask, err)
		}
		got := gotLoose.Reduced()
		want := heeaIFMAMaskedPointX8(&R, mask)
		if equal := heeaIFMAPointCoordinatesEqualX8(&got, &want); equal != 0xff {
			t.Fatalf("x8 mask=%02x equality=%02x", mask, equal)
		}
	}

	for half := 0; half < 2; half++ {
		R4 := pointX4Half(&R, half)
		affine4 := AffinePointX4{X: R4.X, Y: R4.Y}
		for maskValue := 0; maskValue <= 0x0f; maskValue++ {
			mask := uint8(maskValue)
			var gotLoose IFMAPointX4
			if err := modelHEEAIFMAPointFromAffineX4(&gotLoose, &affine4, mask); err != nil {
				t.Fatalf("x4 half=%d mask=%02x reconstruction: %v", half, mask, err)
			}
			got := gotLoose.Reduced()
			want := heeaIFMAMaskedPointX4(&R4, mask)
			if equal := heeaIFMAPointCoordinatesEqualX4(&got, &want); equal != 0x0f {
				t.Fatalf("x4 half=%d mask=%02x equality=%02x", half, mask, equal)
			}
		}
	}
}

func TestIFMAHEEABaseSplitModelRandomDifferential(t *testing.T) {
	rng := rand.New(rand.NewSource(0x1f4a_8eea_2a11))
	torsion := referenceTorsionPoints(t)
	bRefs, B := scalarWindowGeneratorX8(t)
	rRefs, R := scalarWindowMixedBasesX8(t, rng, &torsion)
	aRefs, A := scalarWindowMixedBasesX8(t, rng, &torsion)
	for iteration := 0; iteration < 8; iteration++ {
		var sBytes [X8Lanes][32]byte
		var tauFixed, rhoFixed [X8Lanes]ExperimentalHEEASignedCoefficient
		var epsilon [X8Lanes]int8
		var sExact, tauExact, rhoExact [X8Lanes]*big.Int
		for lane := 0; lane < X8Lanes; lane++ {
			sExact[lane] = new(big.Int).Rand(rng, new(big.Int).Lsh(big.NewInt(1), 252))
			tauExact[lane] = heeaIFMAForceOddSigned(heeaRandomSignedInt(rng, 136))
			rhoExact[lane] = heeaRandomSignedInt(rng, 136)
			sBytes[lane] = heeaIFMAEncodeMagnitude(sExact[lane])
			tauFixed[lane] = heeaIFMAEncodeSigned(tauExact[lane])
			rhoFixed[lane] = heeaIFMAEncodeSigned(rhoExact[lane])
			if rng.Intn(2) == 0 {
				epsilon[lane] = -1
			} else {
				epsilon[lane] = 1
			}
		}
		var coefficients ExperimentalHEEABaseSplitCoefficientsX8
		if usable, fallback := ExperimentalPrepareHEEABaseSplitCoefficientsX8(&coefficients, &sBytes, &tauFixed, &rhoFixed, &epsilon, 0xff); usable != 0xff || fallback != 0 {
			t.Fatalf("iteration %d prepare=%02x/%02x", iteration, usable, fallback)
		}
		sSigned, tauSigned, rhoSigned := heeaIFMASignedMagnitudeInputs(&sExact, &tauExact, &rhoExact)
		want := heeaBaseSplitExactWantX8(&bRefs, &rRefs, &aRefs, &sSigned, &tauSigned, &rhoSigned, &epsilon)
		active := uint8(rng.Uint32())
		radixBits := uint(4 + iteration%2)
		var model modelIFMAHEEABaseSplitWorkspaceX8
		if err := model.prepare(&B, &R, &A, radixBits); err != nil {
			t.Fatal(err)
		}
		var gotLoose IFMAPointX8
		usable, fallback, err := model.evaluate(&gotLoose, &coefficients, active)
		if err != nil || usable != active || fallback != 0 {
			t.Fatalf("iteration %d model=(%02x,%02x,%v) active=%02x", iteration, usable, fallback, err, active)
		}
		got := gotLoose.Reduced()
		assertMaskedPointX8(t, fmt.Sprintf("HEEA IFMA random %d", iteration), &got, &want, active)
	}
}

func TestIFMAHEEABaseSplitModelKeepsMixedOrderCoefficientsExact(t *testing.T) {
	torsion := referenceTorsionPoints(t)
	generator := edwardsref.NewGeneratorPoint()
	mixed := new(edwardsref.Point).Add(generator, torsion[4])
	var generatorBytes, mixedBytes [X8Lanes][32]byte
	for lane := 0; lane < X8Lanes; lane++ {
		copy(generatorBytes[lane][:], generator.Bytes())
		copy(mixedBytes[lane][:], mixed.Bytes())
	}
	var B, generatorPoint, mixedPoint PointX8
	if B.SetBytes(&generatorBytes) != 0xff || generatorPoint.SetBytes(&generatorBytes) != 0xff || mixedPoint.SetBytes(&mixedBytes) != 0xff {
		t.Fatal("failed to decode mixed-order IFMA fixtures")
	}
	var s [X8Lanes][32]byte
	var tau, rho [X8Lanes]ExperimentalHEEASignedCoefficient
	var epsilon [X8Lanes]int8
	for lane := 0; lane < X8Lanes; lane++ {
		tau[lane].Magnitude[0] = 1
		epsilon[lane] = 1
	}
	var coefficients ExperimentalHEEABaseSplitCoefficientsX8
	ExperimentalPrepareHEEABaseSplitCoefficientsX8(&coefficients, &s, &tau, &rho, &epsilon, 0xff)
	if coefficients.negativeMasks[2] != 0xff {
		t.Fatalf("exact -tau sign mask=%02x want=ff", coefficients.negativeMasks[2])
	}
	var model modelIFMAHEEABaseSplitWorkspaceX8
	if err := model.prepare(&B, &mixedPoint, &generatorPoint, 5); err != nil {
		t.Fatal(err)
	}
	var gotLoose IFMAPointX8
	if usable, fallback, err := model.evaluate(&gotLoose, &coefficients, 0xff); err != nil || usable != 0xff || fallback != 0 {
		t.Fatalf("R discriminator model=(%02x,%02x,%v)", usable, fallback, err)
	}
	wantR := exactReferenceIntegerMult(mixed, big.NewInt(-1))
	wrongR := exactReferenceIntegerMult(mixed, new(big.Int).Sub(heea8l.Order(), big.NewInt(1)))
	if string(wantR.Bytes()) == string(wrongR.Bytes()) {
		t.Fatal("R discriminator did not distinguish exact -1 from L-1")
	}
	got := gotLoose.Reduced()
	for lane := 0; lane < X8Lanes; lane++ {
		point := got.Lane(lane)
		assertScalarPointMatchesReference(t, fmt.Sprintf("IFMA exact R lane %d", lane), &point, wantR)
	}

	for lane := 0; lane < X8Lanes; lane++ {
		rho[lane].Magnitude[0] = 1
	}
	ExperimentalPrepareHEEABaseSplitCoefficientsX8(&coefficients, &s, &tau, &rho, &epsilon, 0xff)
	if coefficients.negativeMasks[3] != 0xff {
		t.Fatalf("exact -epsilon*rho sign mask=%02x want=ff", coefficients.negativeMasks[3])
	}
	if err := model.prepare(&B, &generatorPoint, &mixedPoint, 4); err != nil {
		t.Fatal(err)
	}
	if usable, fallback, err := model.evaluate(&gotLoose, &coefficients, 0xff); err != nil || usable != 0xff || fallback != 0 {
		t.Fatalf("A discriminator model=(%02x,%02x,%v)", usable, fallback, err)
	}
	wantA := new(edwardsref.Point).Add(exactReferenceIntegerMult(generator, big.NewInt(-1)), exactReferenceIntegerMult(mixed, big.NewInt(-1)))
	wrongA := new(edwardsref.Point).Add(exactReferenceIntegerMult(generator, big.NewInt(-1)), exactReferenceIntegerMult(mixed, new(big.Int).Sub(heea8l.Order(), big.NewInt(1))))
	if string(wantA.Bytes()) == string(wrongA.Bytes()) {
		t.Fatal("A discriminator did not distinguish exact -1 from L-1")
	}
	got = gotLoose.Reduced()
	for lane := 0; lane < X8Lanes; lane++ {
		point := got.Lane(lane)
		assertScalarPointMatchesReference(t, fmt.Sprintf("IFMA exact A lane %d", lane), &point, wantA)
	}
}

func TestIFMAHEEABaseSplitModelRangeFallbackMasksAndAtomicOutput(t *testing.T) {
	_, B := scalarWindowGeneratorX8(t)
	R, A := B, B
	s, tau, rho, epsilon, _, _, _ := heeaIFMACoefficientFixture(0)
	var coefficients ExperimentalHEEABaseSplitCoefficientsX8
	ExperimentalPrepareHEEABaseSplitCoefficientsX8(&coefficients, &s, &tau, &rho, &epsilon, 0xff)
	var model modelIFMAHEEABaseSplitWorkspaceX8
	if err := model.prepare(&B, &R, &A, 5); err != nil {
		t.Fatal(err)
	}
	for invalidLane := 0; invalidLane < X8Lanes; invalidLane++ {
		invalid := coefficients
		invalid.scalars[invalidLane%QSMTerms][invalidLane] = scalarOrderBytes
		invalid.validMask = 0xff // force Evaluate's independent range gate
		sentinel := identityIFMAPointX8Value()
		sentinel.X.limbs[0][0] = 7
		got := sentinel
		usable, fallback, err := model.evaluate(&got, &invalid, 0xff)
		wantUsable := uint8(0xff &^ (1 << invalidLane))
		if err != nil || usable != wantUsable || fallback != 1<<invalidLane {
			t.Fatalf("invalid lane %d model=(%02x,%02x,%v)", invalidLane, usable, fallback, err)
		}
		reduced := got.Reduced()
		lanePoint := reduced.Lane(invalidLane)
		if lanePoint.IsIdentity() != 1 {
			t.Fatalf("invalid lane %d output is not identity", invalidLane)
		}
	}
}

func TestExperimentalIFMAHEEABaseSplitUnavailableAndOrdering(t *testing.T) {
	if ExperimentalIFMAAvailable() {
		t.Skip("unavailable-path test")
	}
	var workspace8 ExperimentalIFMAHEEABaseSplitWorkspaceX8
	before8 := workspace8
	var base8 PointX8
	if err := workspace8.PrepareFixedBase(&base8, 5); !errors.Is(err, ErrIFMAUnavailable) || workspace8 != before8 {
		t.Fatalf("x8 unavailable fixed preparation error=%v changed=%v", err, workspace8 != before8)
	}
	workspace8.fixedBasesPrepared = true
	workspace8.variableBasesPrepared = true
	workspace8.radixBits = 5
	beforeAffine8 := workspace8
	var affine8 AffinePointX8
	if err := workspace8.PrepareVariableBasesAffineR(&affine8, &base8, 0xa5); !errors.Is(err, ErrIFMAUnavailable) || workspace8 != beforeAffine8 {
		t.Fatalf("x8 unavailable affine preparation error=%v changed=%v", err, workspace8 != beforeAffine8)
	}
	var coefficients8 ExperimentalHEEABaseSplitCoefficientsX8
	coefficients8.validMask = 0xff
	var out8 IFMAPointX8
	out8.X.limbs[0][0] = 9
	want8 := out8
	if usable, fallback, err := workspace8.Evaluate(&out8, &coefficients8, 0xa5); usable != 0 || fallback != 0xa5 || !errors.Is(err, ErrIFMAUnavailable) || out8 != want8 {
		t.Fatalf("x8 unavailable evaluate=(%02x,%02x,%v) changed=%v", usable, fallback, err, out8 != want8)
	}

	var workspace4 ExperimentalIFMAHEEABaseSplitWorkspaceX4
	before4 := workspace4
	var base4 PointX4
	if err := workspace4.PrepareFixedBase(&base4, 4); !errors.Is(err, ErrIFMAUnavailable) || workspace4 != before4 {
		t.Fatalf("x4 unavailable fixed preparation error=%v changed=%v", err, workspace4 != before4)
	}

	defer func() {
		if recover() == nil {
			t.Fatal("variable-base preparation before fixed base did not panic")
		}
	}()
	_ = workspace4.PrepareVariableBases(&base4, &base4)
}

func TestExperimentalIFMAHEEAAffineRReconstructionHardwareAllMasks(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	rng := rand.New(rand.NewSource(0x1f4a_aff1_8e51))
	torsion := referenceTorsionPoints(t)
	_, R := scalarWindowMixedBasesX8(t, rng, &torsion)
	affine8 := AffinePointX8{X: R.X, Y: R.Y}
	for maskValue := 0; maskValue <= 0xff; maskValue++ {
		mask := uint8(maskValue)
		var gotLoose IFMAPointX8
		if err := heeaIFMAPointFromAffineX8(&gotLoose, &affine8, mask); err != nil {
			t.Fatalf("x8 mask=%02x reconstruction: %v", mask, err)
		}
		got := gotLoose.Reduced()
		want := heeaIFMAMaskedPointX8(&R, mask)
		if equal := heeaIFMAPointCoordinatesEqualX8(&got, &want); equal != 0xff {
			t.Fatalf("x8 mask=%02x equality=%02x", mask, equal)
		}
	}

	for half := 0; half < 2; half++ {
		R4 := pointX4Half(&R, half)
		affine4 := AffinePointX4{X: R4.X, Y: R4.Y}
		for maskValue := 0; maskValue <= 0x0f; maskValue++ {
			mask := uint8(maskValue)
			var gotLoose IFMAPointX4
			if err := heeaIFMAPointFromAffineX4(&gotLoose, &affine4, mask); err != nil {
				t.Fatalf("x4 half=%d mask=%02x reconstruction: %v", half, mask, err)
			}
			got := gotLoose.Reduced()
			want := heeaIFMAMaskedPointX4(&R4, mask)
			if equal := heeaIFMAPointCoordinatesEqualX4(&got, &want); equal != 0x0f {
				t.Fatalf("x4 half=%d mask=%02x equality=%02x", half, mask, equal)
			}
		}
	}
}

func TestExperimentalIFMAHEEABaseSplitHardware(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	rng := rand.New(rand.NewSource(0x1f4a_8eea_4d51))
	torsion := referenceTorsionPoints(t)
	_, B := scalarWindowGeneratorX8(t)
	_, R := scalarWindowMixedBasesX8(t, rng, &torsion)
	_, A := scalarWindowMixedBasesX8(t, rng, &torsion)
	s, tau, rho, epsilon, _, _, _ := heeaIFMACoefficientFixture(0)
	var coefficients ExperimentalHEEABaseSplitCoefficientsX8
	ExperimentalPrepareHEEABaseSplitCoefficientsX8(&coefficients, &s, &tau, &rho, &epsilon, 0xff)
	var coefficients4 [2]ExperimentalHEEABaseSplitCoefficientsX4
	ExperimentalSplitHEEABaseSplitCoefficientsX8(&coefficients4, &coefficients)

	for _, radixBits := range []uint{4, 5} {
		var hardware ExperimentalIFMAHEEABaseSplitWorkspaceX8
		if err := hardware.PrepareAll(&B, &R, &A, radixBits); err != nil {
			t.Fatal(err)
		}
		var model modelIFMAHEEABaseSplitWorkspaceX8
		if err := model.prepare(&B, &R, &A, radixBits); err != nil {
			t.Fatal(err)
		}
		var hardware4 [2]ExperimentalIFMAHEEABaseSplitWorkspaceX4
		for half := 0; half < 2; half++ {
			B4, R4, A4 := pointX4Half(&B, half), pointX4Half(&R, half), pointX4Half(&A, half)
			if err := hardware4[half].PrepareAll(&B4, &R4, &A4, radixBits); err != nil {
				t.Fatal(err)
			}
		}
		for _, active := range everyIFMADSMActiveMaskX8() {
			var got, want IFMAPointX8
			gotUsable, gotFallback, gotErr := hardware.Evaluate(&got, &coefficients, active)
			wantUsable, wantFallback, wantErr := model.evaluate(&want, &coefficients, active)
			gotReduced, wantReduced := got.Reduced(), want.Reduced()
			if gotErr != nil || wantErr != nil || gotUsable != wantUsable || gotFallback != wantFallback || gotReduced.Equal(&wantReduced) != 0xff {
				t.Fatalf("radix %d active=%02x hardware=(%02x,%02x,%v) model=(%02x,%02x,%v)", 1<<radixBits, active, gotUsable, gotFallback, gotErr, wantUsable, wantFallback, wantErr)
			}
			joined, joinedUsable, joinedFallback := evaluateExperimentalIFMAHEEATwoX4(t, &hardware4, &coefficients4, active)
			if joinedUsable != gotUsable || joinedFallback != gotFallback || joined.Equal(&gotReduced) != 0xff {
				t.Fatalf("radix %d active=%02x two-x4=(%02x,%02x) x8=(%02x,%02x)", 1<<radixBits, active, joinedUsable, joinedFallback, gotUsable, gotFallback)
			}
		}

		fixed0, fixed1, fullRTable := hardware.tables[0], hardware.tables[1], hardware.tables[2]
		affineR := AffinePointX8{X: R.X, Y: R.Y}
		for _, decodedValid := range everyIFMADSMActiveMaskX8() {
			if err := hardware.PrepareVariableBasesAffineR(&affineR, &A, decodedValid); err != nil {
				t.Fatal(err)
			}
			if decodedValid == 0xff {
				assertIFMAHEEAFullTableX8Equivalent(t, &hardware.tables[2], &fullRTable)
			}
			var got, want IFMAPointX8
			gotUsable, gotFallback, gotErr := hardware.Evaluate(&got, &coefficients, 0xff)
			wantUsable, _, wantErr := model.evaluate(&want, &coefficients, decodedValid)
			gotReduced, wantReduced := got.Reduced(), want.Reduced()
			if gotErr != nil || wantErr != nil || gotUsable != wantUsable || gotFallback != (0xff&^decodedValid) || gotReduced.Equal(&wantReduced) != 0xff {
				t.Fatalf("radix %d affine decoded=%02x hardware=(%02x,%02x,%v) model=(%02x,%v)", 1<<radixBits, decodedValid, gotUsable, gotFallback, gotErr, wantUsable, wantErr)
			}
		}
		for half := 0; half < 2; half++ {
			B4, R4, A4 := pointX4Half(&B, half), pointX4Half(&R, half), pointX4Half(&A, half)
			affineR4 := AffinePointX4{X: R4.X, Y: R4.Y}
			fullRTable4 := hardware4[half].tables[2]
			var model4 modelIFMAHEEABaseSplitWorkspaceX4
			if err := model4.prepare(&B4, &R4, &A4, radixBits); err != nil {
				t.Fatal(err)
			}
			for maskValue := 0; maskValue <= 0x0f; maskValue++ {
				decodedValid := uint8(maskValue)
				if err := hardware4[half].PrepareVariableBasesAffineR(&affineR4, &A4, decodedValid); err != nil {
					t.Fatal(err)
				}
				if decodedValid == 0x0f {
					assertIFMAHEEAFullTableX4Equivalent(t, &hardware4[half].tables[2], &fullRTable4)
				}
				var got, want IFMAPointX4
				gotUsable, gotFallback, gotErr := hardware4[half].Evaluate(&got, &coefficients4[half], 0x0f)
				wantUsable, _, wantErr := model4.evaluate(&want, &coefficients4[half], decodedValid)
				gotReduced, wantReduced := got.Reduced(), want.Reduced()
				if gotErr != nil || wantErr != nil || gotUsable != wantUsable || gotFallback != (0x0f&^decodedValid) || gotReduced.Equal(&wantReduced) != 0x0f {
					t.Fatalf("radix %d half %d affine decoded=%02x hardware=(%02x,%02x,%v) model=(%02x,%v)", 1<<radixBits, half, decodedValid, gotUsable, gotFallback, gotErr, wantUsable, wantErr)
				}
			}
		}
		if hardware.tables[0] != fixed0 || hardware.tables[1] != fixed1 {
			t.Fatalf("radix %d affine cold R/A preparation changed retained basepoint tables", 1<<radixBits)
		}

		newR, newA := R, A
		newR.Double(&newR)
		newA.Double(&newA)
		if err := hardware.PrepareVariableBases(&newR, &newA); err != nil {
			t.Fatal(err)
		}
		if hardware.tables[0] != fixed0 || hardware.tables[1] != fixed1 {
			t.Fatalf("radix %d cold R/A preparation changed retained basepoint tables", 1<<radixBits)
		}
	}
}

func TestExperimentalIFMAHEEABaseSplitZeroAllocations(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	_, B := scalarWindowGeneratorX8(t)
	R, A := B, B
	R.Double(&R)
	A.Add(&A, &R)
	affineR := AffinePointX8{X: B.X, Y: B.Y}
	s, tau, rho, epsilon, _, _, _ := heeaIFMACoefficientFixture(0)
	var coefficients ExperimentalHEEABaseSplitCoefficientsX8
	ExperimentalPrepareHEEABaseSplitCoefficientsX8(&coefficients, &s, &tau, &rho, &epsilon, 0xff)
	var halves [2]ExperimentalHEEABaseSplitCoefficientsX4
	ExperimentalSplitHEEABaseSplitCoefficientsX8(&halves, &coefficients)
	for _, radixBits := range []uint{4, 5} {
		var workspace ExperimentalIFMAHEEABaseSplitWorkspaceX8
		if err := workspace.PrepareAll(&B, &R, &A, radixBits); err != nil {
			t.Fatal(err)
		}
		var out IFMAPointX8
		if allocations := testing.AllocsPerRun(10, func() {
			if err := workspace.PrepareVariableBases(&R, &A); err != nil {
				panic(err)
			}
			if usable, fallback, err := workspace.Evaluate(&out, &coefficients, 0xff); err != nil || usable != 0xff || fallback != 0 {
				panic("unexpected x8 HEEA evaluation result")
			}
		}); allocations != 0 {
			t.Fatalf("radix %d x8 cold R/A+QSM allocations=%.2f", 1<<radixBits, allocations)
		}
		if allocations := testing.AllocsPerRun(10, func() {
			if err := workspace.PrepareVariableBasesAffineR(&affineR, &A, 0xff); err != nil {
				panic(err)
			}
			if usable, fallback, err := workspace.Evaluate(&out, &coefficients, 0xff); err != nil || usable != 0xff || fallback != 0 {
				panic("unexpected x8 affine-R HEEA evaluation result")
			}
		}); allocations != 0 {
			t.Fatalf("radix %d x8 cold affine-R/A+QSM allocations=%.2f", 1<<radixBits, allocations)
		}

		for half := 0; half < 2; half++ {
			B4, R4, A4 := pointX4Half(&B, half), pointX4Half(&R, half), pointX4Half(&A, half)
			affineR4 := AffinePointX4{X: B4.X, Y: B4.Y}
			var workspace4 ExperimentalIFMAHEEABaseSplitWorkspaceX4
			if err := workspace4.PrepareAll(&B4, &R4, &A4, radixBits); err != nil {
				t.Fatal(err)
			}
			var out4 IFMAPointX4
			if allocations := testing.AllocsPerRun(10, func() {
				if err := workspace4.PrepareVariableBases(&R4, &A4); err != nil {
					panic(err)
				}
				if usable, fallback, err := workspace4.Evaluate(&out4, &halves[half], 0x0f); err != nil || usable != 0x0f || fallback != 0 {
					panic("unexpected x4 HEEA evaluation result")
				}
			}); allocations != 0 {
				t.Fatalf("radix %d x4 half %d cold R/A+QSM allocations=%.2f", 1<<radixBits, half, allocations)
			}
			if allocations := testing.AllocsPerRun(10, func() {
				if err := workspace4.PrepareVariableBasesAffineR(&affineR4, &A4, 0x0f); err != nil {
					panic(err)
				}
				if usable, fallback, err := workspace4.Evaluate(&out4, &halves[half], 0x0f); err != nil || usable != 0x0f || fallback != 0 {
					panic("unexpected x4 affine-R HEEA evaluation result")
				}
			}); allocations != 0 {
				t.Fatalf("radix %d x4 half %d cold affine-R/A+QSM allocations=%.2f", 1<<radixBits, half, allocations)
			}
		}
	}
}

type modelIFMAHEEABaseSplitWorkspaceX4 struct {
	tables    [QSMTerms]IFMAFullTableX4
	digits    [QSMTerms]heeaFixedRadixDigitsX4
	radixBits uint8
}

type modelIFMAHEEABaseSplitWorkspaceX8 struct {
	tables    [QSMTerms]IFMAFullTableX8
	digits    [QSMTerms]heeaFixedRadixDigitsX8
	radixBits uint8
}

func modelHEEAIFMAPointFromAffineX4(out *IFMAPointX4, affine *AffinePointX4, valid uint8) error {
	valid &= 0x0f
	zero := ElementX4{}
	one := broadcastX4(new(Element).One())
	var x, y ElementX4
	decodeSelectX4(&x, &zero, &affine.X, valid)
	decodeSelectX4(&y, &one, &affine.Y, valid)
	var point IFMAPointX4
	point.X.SetReduced(&x)
	point.Y.SetReduced(&y)
	point.Z.SetReduced(&one)
	if err := modelMultiplyComposableX4(&point.T, &point.X, &point.Y); err != nil {
		return err
	}
	*out = point
	return nil
}

func modelHEEAIFMAPointFromAffineX8(out *IFMAPointX8, affine *AffinePointX8, valid uint8) error {
	zero := ElementX8{}
	one := broadcastX8(new(Element).One())
	var x, y ElementX8
	decodeSelectX8(&x, &zero, &affine.X, valid)
	decodeSelectX8(&y, &one, &affine.Y, valid)
	var point IFMAPointX8
	point.X.SetReduced(&x)
	point.Y.SetReduced(&y)
	point.Z.SetReduced(&one)
	if err := modelMultiplyComposableX8(&point.T, &point.X, &point.Y); err != nil {
		return err
	}
	*out = point
	return nil
}

func heeaIFMAMaskedPointX4(point *PointX4, valid uint8) PointX4 {
	out := identityPointX4Value()
	for lane := 0; lane < X4Lanes; lane++ {
		if valid&(1<<lane) == 0 {
			continue
		}
		lanePoint := point.Lane(lane)
		out.SetLane(lane, &lanePoint)
	}
	return out
}

func heeaIFMAMaskedPointX8(point *PointX8, valid uint8) PointX8 {
	out := identityPointX8Value()
	for lane := 0; lane < X8Lanes; lane++ {
		if valid&(1<<lane) == 0 {
			continue
		}
		lanePoint := point.Lane(lane)
		out.SetLane(lane, &lanePoint)
	}
	return out
}

func heeaIFMAPointCoordinatesEqualX4(x, y *PointX4) uint8 {
	var mask uint8
	for lane := 0; lane < X4Lanes; lane++ {
		xLane, yLane := x.Lane(lane), y.Lane(lane)
		if xLane.X.Equal(&yLane.X)&
			xLane.Y.Equal(&yLane.Y)&
			xLane.Z.Equal(&yLane.Z)&
			xLane.T.Equal(&yLane.T) != 0 {
			mask |= 1 << lane
		}
	}
	return mask
}

func heeaIFMAPointCoordinatesEqualX8(x, y *PointX8) uint8 {
	var mask uint8
	for lane := 0; lane < X8Lanes; lane++ {
		xLane, yLane := x.Lane(lane), y.Lane(lane)
		if xLane.X.Equal(&yLane.X)&
			xLane.Y.Equal(&yLane.Y)&
			xLane.Z.Equal(&yLane.Z)&
			xLane.T.Equal(&yLane.T) != 0 {
			mask |= 1 << lane
		}
	}
	return mask
}

func assertIFMAHEEAFullTableX4Equivalent(t *testing.T, got, want *IFMAFullTableX4) {
	t.Helper()
	if got.entries != want.entries || got.radixBits != want.radixBits {
		t.Fatalf("x4 table metadata=(%d,%d) want=(%d,%d)", got.entries, got.radixBits, want.entries, want.radixBits)
	}
	for entry := 0; entry < got.entries; entry++ {
		gotPoint, wantPoint := got.points[entry].Reduced(), want.points[entry].Reduced()
		if equal := gotPoint.Equal(&wantPoint); equal != 0x0f {
			t.Fatalf("x4 table entry %d equality=%02x", entry, equal)
		}
	}
}

func assertIFMAHEEAFullTableX8Equivalent(t *testing.T, got, want *IFMAFullTableX8) {
	t.Helper()
	if got.entries != want.entries || got.radixBits != want.radixBits {
		t.Fatalf("x8 table metadata=(%d,%d) want=(%d,%d)", got.entries, got.radixBits, want.entries, want.radixBits)
	}
	for entry := 0; entry < got.entries; entry++ {
		gotPoint, wantPoint := got.points[entry].Reduced(), want.points[entry].Reduced()
		if equal := gotPoint.Equal(&wantPoint); equal != 0xff {
			t.Fatalf("x8 table entry %d equality=%02x", entry, equal)
		}
	}
}

func (w *modelIFMAHEEABaseSplitWorkspaceX4) prepare(B, R, A *PointX4, radixBits uint) error {
	var B128 PointX4
	ExperimentalHEEABaseSplitB128X4(&B128, B)
	bases := [QSMTerms]PointX4{*B, B128, *R, *A}
	for term := 0; term < QSMTerms; term++ {
		if err := modelBuildIFMAFullTableX4Into(&w.tables[term], &bases[term], radixBits); err != nil {
			return err
		}
	}
	w.radixBits = uint8(radixBits)
	return nil
}

func (w *modelIFMAHEEABaseSplitWorkspaceX8) prepare(B, R, A *PointX8, radixBits uint) error {
	var B128 PointX8
	ExperimentalHEEABaseSplitB128X8(&B128, B)
	bases := [QSMTerms]PointX8{*B, B128, *R, *A}
	for term := 0; term < QSMTerms; term++ {
		if err := modelBuildIFMAFullTableX8Into(&w.tables[term], &bases[term], radixBits); err != nil {
			return err
		}
	}
	w.radixBits = uint8(radixBits)
	return nil
}

func (w *modelIFMAHEEABaseSplitWorkspaceX4) evaluate(out *IFMAPointX4, coefficients *ExperimentalHEEABaseSplitCoefficientsX4, active uint8) (usable, fallback uint8, err error) {
	active &= 0x0f
	usable = active & coefficients.validMask
	for term := 0; term < QSMTerms; term++ {
		usable &= recodeHEEAFixedScalarsX4(&w.digits[term], &coefficients.scalars[term], coefficients.negativeMasks[term], usable, uint(w.radixBits))
	}
	fallback = active &^ usable
	acc := identityIFMAPointX4Value()
	if usable == 0 {
		*out = acc
		return 0, fallback, nil
	}
	maxRounds := heeaIFMAMaxRoundsX4(&w.digits)
	for round := maxRounds - 1; round >= 0; round-- {
		if round != maxRounds-1 {
			for doubling := uint8(0); doubling < w.radixBits; doubling++ {
				if err := ifmaPointDoubleComposableX4(&acc, &acc, modelMultiplyComposableX4); err != nil {
					return 0, active, err
				}
			}
		}
		for term := 0; term < QSMTerms; term++ {
			if round >= int(w.digits[term].count) {
				continue
			}
			digit := &w.digits[term].rounds[round]
			if digit.NonzeroMask&usable == 0 {
				continue
			}
			var selected IFMAPointX4
			SelectIFMAFullTableX4Public(&selected, &w.tables[term], digit, usable)
			if err := ifmaPointAddComposableX4(&acc, &acc, &selected, modelMultiplyComposableX4); err != nil {
				return 0, active, err
			}
		}
	}
	*out = acc
	return usable, fallback, nil
}

func (w *modelIFMAHEEABaseSplitWorkspaceX8) evaluate(out *IFMAPointX8, coefficients *ExperimentalHEEABaseSplitCoefficientsX8, active uint8) (usable, fallback uint8, err error) {
	usable = active & coefficients.validMask
	for term := 0; term < QSMTerms; term++ {
		usable &= recodeHEEAFixedScalarsX8(&w.digits[term], &coefficients.scalars[term], coefficients.negativeMasks[term], usable, uint(w.radixBits))
	}
	fallback = active &^ usable
	acc := identityIFMAPointX8Value()
	if usable == 0 {
		*out = acc
		return 0, fallback, nil
	}
	maxRounds := heeaIFMAMaxRoundsX8(&w.digits)
	for round := maxRounds - 1; round >= 0; round-- {
		if round != maxRounds-1 {
			for doubling := uint8(0); doubling < w.radixBits; doubling++ {
				if err := ifmaPointDoubleComposableX8(&acc, &acc, modelMultiplyComposableX8); err != nil {
					return 0, active, err
				}
			}
		}
		for term := 0; term < QSMTerms; term++ {
			if round >= int(w.digits[term].count) {
				continue
			}
			digit := &w.digits[term].rounds[round]
			if digit.NonzeroMask&usable == 0 {
				continue
			}
			var selected IFMAPointX8
			SelectIFMAFullTableX8Public(&selected, &w.tables[term], digit, usable)
			if err := ifmaPointAddComposableX8(&acc, &acc, &selected, modelMultiplyComposableX8); err != nil {
				return 0, active, err
			}
		}
	}
	*out = acc
	return usable, fallback, nil
}

func assertIFMAHEEAModelTwoX4MatchesX8(t *testing.T, workspace8 *modelIFMAHEEABaseSplitWorkspaceX8, B, R, A *PointX8, coefficients8 *ExperimentalHEEABaseSplitCoefficientsX8, radixBits uint) {
	t.Helper()
	var coefficients4 [2]ExperimentalHEEABaseSplitCoefficientsX4
	ExperimentalSplitHEEABaseSplitCoefficientsX8(&coefficients4, coefficients8)
	var workspaces4 [2]modelIFMAHEEABaseSplitWorkspaceX4
	for half := 0; half < 2; half++ {
		B4, R4, A4 := pointX4Half(B, half), pointX4Half(R, half), pointX4Half(A, half)
		if err := workspaces4[half].prepare(&B4, &R4, &A4, radixBits); err != nil {
			t.Fatal(err)
		}
	}
	for _, active := range everyIFMADSMActiveMaskX8() {
		var wantLoose IFMAPointX8
		wantUsable, wantFallback, err := workspace8.evaluate(&wantLoose, coefficients8, active)
		if err != nil {
			t.Fatal(err)
		}
		var joined PointX8
		var joinedUsable, joinedFallback uint8
		for half := 0; half < 2; half++ {
			var gotLoose IFMAPointX4
			usable, fallback, err := workspaces4[half].evaluate(&gotLoose, &coefficients4[half], (active>>(half*X4Lanes))&0x0f)
			if err != nil {
				t.Fatal(err)
			}
			joinedUsable |= usable << (half * X4Lanes)
			joinedFallback |= fallback << (half * X4Lanes)
			got := gotLoose.Reduced()
			for lane := 0; lane < X4Lanes; lane++ {
				point := got.Lane(lane)
				joined.SetLane(half*X4Lanes+lane, &point)
			}
		}
		want := wantLoose.Reduced()
		if joinedUsable != wantUsable || joinedFallback != wantFallback || joined.Equal(&want) != 0xff {
			t.Fatalf("radix %d active=%02x two-x4=(%02x,%02x) x8=(%02x,%02x)", 1<<radixBits, active, joinedUsable, joinedFallback, wantUsable, wantFallback)
		}
	}
}

func evaluateExperimentalIFMAHEEATwoX4(t *testing.T, workspaces *[2]ExperimentalIFMAHEEABaseSplitWorkspaceX4, coefficients *[2]ExperimentalHEEABaseSplitCoefficientsX4, active uint8) (PointX8, uint8, uint8) {
	t.Helper()
	var joined PointX8
	var joinedUsable, joinedFallback uint8
	for half := 0; half < 2; half++ {
		var loose IFMAPointX4
		usable, fallback, err := workspaces[half].Evaluate(&loose, &coefficients[half], (active>>(half*X4Lanes))&0x0f)
		if err != nil {
			t.Fatal(err)
		}
		joinedUsable |= usable << (half * X4Lanes)
		joinedFallback |= fallback << (half * X4Lanes)
		got := loose.Reduced()
		for lane := 0; lane < X4Lanes; lane++ {
			point := got.Lane(lane)
			joined.SetLane(half*X4Lanes+lane, &point)
		}
	}
	return joined, joinedUsable, joinedFallback
}

func heeaIFMAMaxRoundsX4(digits *[QSMTerms]heeaFixedRadixDigitsX4) int {
	max := 0
	for term := range digits {
		if int(digits[term].count) > max {
			max = int(digits[term].count)
		}
	}
	return max
}

func heeaIFMAMaxRoundsX8(digits *[QSMTerms]heeaFixedRadixDigitsX8) int {
	max := 0
	for term := range digits {
		if int(digits[term].count) > max {
			max = int(digits[term].count)
		}
	}
	return max
}

func reconstructHEEAFixedRadixX4(digits *heeaFixedRadixDigitsX4, lane int) *big.Int {
	result := new(big.Int)
	for round := int(digits.count) - 1; round >= 0; round-- {
		result.Lsh(result, uint(digits.radixBits))
		result.Add(result, big.NewInt(int64(digits.rounds[round].Digit(lane))))
	}
	return result
}

func reconstructHEEAFixedRadixX8(digits *heeaFixedRadixDigitsX8, lane int) *big.Int {
	result := new(big.Int)
	for round := int(digits.count) - 1; round >= 0; round-- {
		result.Lsh(result, uint(digits.radixBits))
		result.Add(result, big.NewInt(int64(digits.rounds[round].Digit(lane))))
	}
	return result
}

func heeaIFMACoefficientFixture(scenario int) ([X8Lanes][32]byte, [X8Lanes]ExperimentalHEEASignedCoefficient, [X8Lanes]ExperimentalHEEASignedCoefficient, [X8Lanes]int8, [X8Lanes]*big.Int, [X8Lanes]*big.Int, [X8Lanes]*big.Int) {
	l := heea8l.Order()
	var s [X8Lanes][32]byte
	var tau, rho [X8Lanes]ExperimentalHEEASignedCoefficient
	var epsilon [X8Lanes]int8
	var sExact, tauExact, rhoExact [X8Lanes]*big.Int
	for lane := 0; lane < X8Lanes; lane++ {
		combination := lane ^ (scenario * 7)
		sExact[lane] = new(big.Int).Sub(new(big.Int).Set(l), big.NewInt(int64(lane+1)))
		tauExact[lane] = new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), uint(127+lane%2)), big.NewInt(int64(2*lane+1)))
		rhoExact[lane] = new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), uint(128+lane)), big.NewInt(int64(0x51+lane)))
		if combination&1 != 0 {
			tauExact[lane].Neg(tauExact[lane])
		}
		if combination&2 != 0 {
			rhoExact[lane].Neg(rhoExact[lane])
		}
		if combination&4 != 0 {
			epsilon[lane] = -1
		} else {
			epsilon[lane] = 1
		}
		s[lane] = heeaIFMAEncodeMagnitude(sExact[lane])
		tau[lane] = heeaIFMAEncodeSigned(tauExact[lane])
		rho[lane] = heeaIFMAEncodeSigned(rhoExact[lane])
	}
	return s, tau, rho, epsilon, sExact, tauExact, rhoExact
}

func heeaIFMASignedMagnitudeInputs(s, tau, rho *[X8Lanes]*big.Int) ([X8Lanes]SignedMagnitude, [X8Lanes]SignedMagnitude, [X8Lanes]SignedMagnitude) {
	var sSigned, tauSigned, rhoSigned [X8Lanes]SignedMagnitude
	for lane := 0; lane < X8Lanes; lane++ {
		sSigned[lane] = signedMagnitudeFromTestBig(s[lane])
		tauSigned[lane] = signedMagnitudeFromTestBig(tau[lane])
		rhoSigned[lane] = signedMagnitudeFromTestBig(rho[lane])
	}
	return sSigned, tauSigned, rhoSigned
}

func heeaIFMAEncodeSigned(value *big.Int) ExperimentalHEEASignedCoefficient {
	negative := value.Sign() < 0
	abs := new(big.Int).Abs(new(big.Int).Set(value))
	return ExperimentalHEEASignedCoefficient{Magnitude: heeaIFMAEncodeMagnitude(abs), Negative: negative && abs.Sign() != 0}
}

func heeaIFMAForceOddSigned(value *big.Int) *big.Int {
	negative := value.Sign() < 0
	abs := new(big.Int).Abs(new(big.Int).Set(value))
	abs.SetBit(abs, 0, 1)
	if negative {
		abs.Neg(abs)
	}
	return abs
}

func heeaIFMAEncodeMagnitude(value *big.Int) [32]byte {
	if value.Sign() < 0 || value.BitLen() > 256 {
		panic("HEEA IFMA test magnitude is outside 256 bits")
	}
	var out [32]byte
	bigEndian := value.Bytes()
	for i := range bigEndian {
		out[i] = bigEndian[len(bigEndian)-1-i]
	}
	return out
}

func heeaIFMACoefficientBigX4(coefficients *ExperimentalHEEABaseSplitCoefficientsX4, term, lane int) *big.Int {
	value := heeaLittleEndianBig(coefficients.scalars[term][lane][:])
	if coefficients.negativeMasks[term]&(1<<lane) != 0 {
		value.Neg(value)
	}
	return value
}

func heeaIFMACoefficientBigX8(coefficients *ExperimentalHEEABaseSplitCoefficientsX8, term, lane int) *big.Int {
	value := heeaLittleEndianBig(coefficients.scalars[term][lane][:])
	if coefficients.negativeMasks[term]&(1<<lane) != 0 {
		value.Neg(value)
	}
	return value
}

var (
	heeaIFMABenchmarkPointX8 IFMAPointX8
	heeaIFMABenchmarkPointX4 [2]IFMAPointX4
	heeaIFMABenchmarkMask    uint8
)

func BenchmarkExperimentalIFMAHEEABaseSplit(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	_, B := scalarWindowGeneratorX8ForBenchmark(b)
	R, A := B, B
	R.Double(&R)
	rEncoded := R.Bytes()
	if valid := R.SetBytes(&rEncoded); valid != 0xff {
		b.Fatalf("benchmark R normalization valid=%02x", valid)
	}
	A.Add(&A, &R)
	s, tau, rho, epsilon, _, _, _ := heeaIFMACoefficientFixture(0)
	var coefficients ExperimentalHEEABaseSplitCoefficientsX8
	ExperimentalPrepareHEEABaseSplitCoefficientsX8(&coefficients, &s, &tau, &rho, &epsilon, 0xff)
	var halves [2]ExperimentalHEEABaseSplitCoefficientsX4
	ExperimentalSplitHEEABaseSplitCoefficientsX8(&halves, &coefficients)
	for _, radixBits := range []uint{4, 5} {
		switch radixBits {
		case 4:
			var x8 ExperimentalIFMAHEEABaseSplitWorkspaceRadix16X8
			var x4 [2]ExperimentalIFMAHEEABaseSplitWorkspaceRadix16X4
			b.Run("x8/radix=16", func(b *testing.B) {
				benchmarkExperimentalIFMAHEEAX8(b, &x8, &B, &R, &A, &s, &tau, &rho, &epsilon, &coefficients, radixBits)
			})
			b.Run("two-x4/radix=16", func(b *testing.B) {
				benchmarkExperimentalIFMAHEEATwoX4(b, &x4, &B, &R, &A, &s, &tau, &rho, &epsilon, &halves, radixBits)
			})
		case 5:
			var x8 ExperimentalIFMAHEEABaseSplitWorkspaceX8
			var x4 [2]ExperimentalIFMAHEEABaseSplitWorkspaceX4
			b.Run("x8/radix=32", func(b *testing.B) {
				benchmarkExperimentalIFMAHEEAX8(b, &x8, &B, &R, &A, &s, &tau, &rho, &epsilon, &coefficients, radixBits)
			})
			b.Run("two-x4/radix=32", func(b *testing.B) {
				benchmarkExperimentalIFMAHEEATwoX4(b, &x4, &B, &R, &A, &s, &tau, &rho, &epsilon, &halves, radixBits)
			})
		}
	}
}

func benchmarkExperimentalIFMAHEEAX8[Storage ifmaFullTableStorageX8](b *testing.B, workspace *experimentalIFMAHEEABaseSplitWorkspaceX8[Storage], B, R, A *PointX8, s *[X8Lanes][32]byte, tau, rho *[X8Lanes]ExperimentalHEEASignedCoefficient, epsilon *[X8Lanes]int8, coefficients *ExperimentalHEEABaseSplitCoefficientsX8, radixBits uint) {
	if err := workspace.PrepareAll(B, R, A, radixBits); err != nil {
		b.Fatal(err)
	}
	affineR := AffinePointX8{X: R.X, Y: R.Y}
	paths := []struct {
		name               string
		prepareVariables   bool
		prepareAffineR     bool
		prepareCoefficient bool
	}{
		{name: "prepared-QSM"},
		{name: "cold-R+A+QSM", prepareVariables: true},
		{name: "cold-affine-R+A+QSM", prepareVariables: true, prepareAffineR: true},
		{name: "coeff+cold-R+A+QSM", prepareVariables: true, prepareCoefficient: true},
		{name: "coeff+cold-affine-R+A+QSM", prepareVariables: true, prepareAffineR: true, prepareCoefficient: true},
	}
	for _, path := range paths {
		b.Run(path.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ReportMetric(float64(2*NominalFullTableBytes(X8Lanes, 4, radixBits)), "active-cold-R+A-tables-B")
			b.ReportMetric(float64(QSMTerms*NominalFullTableBytes(X8Lanes, 4, radixBits)), "active-retained-tables-B")
			b.ReportMetric(float64(unsafe.Sizeof(workspace.tables[0])), "physical-table-B")
			b.ReportMetric(float64(unsafe.Sizeof(*workspace)), "physical-workspace-B")
			for i := 0; i < b.N; i++ {
				if path.prepareCoefficient {
					ExperimentalPrepareHEEABaseSplitCoefficientsX8(coefficients, s, tau, rho, epsilon, 0xff)
				}
				if path.prepareVariables {
					var err error
					if path.prepareAffineR {
						err = workspace.PrepareVariableBasesAffineR(&affineR, A, 0xff)
					} else {
						err = workspace.PrepareVariableBases(R, A)
					}
					if err != nil {
						b.Fatal(err)
					}
				}
				usable, fallback, err := workspace.Evaluate(&heeaIFMABenchmarkPointX8, coefficients, 0xff)
				if err != nil || usable != 0xff || fallback != 0 {
					b.Fatalf("evaluate=(%02x,%02x,%v)", usable, fallback, err)
				}
			}
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*X8Lanes), "ns/signature")
		})
	}
}

func benchmarkExperimentalIFMAHEEATwoX4[Storage ifmaFullTableStorageX4](b *testing.B, workspaces *[2]experimentalIFMAHEEABaseSplitWorkspaceX4[Storage], B, R, A *PointX8, s *[X8Lanes][32]byte, tau, rho *[X8Lanes]ExperimentalHEEASignedCoefficient, epsilon *[X8Lanes]int8, coefficients *[2]ExperimentalHEEABaseSplitCoefficientsX4, radixBits uint) {
	var bases [2][3]PointX4
	var affineR [2]AffinePointX4
	for half := 0; half < 2; half++ {
		bases[half] = [3]PointX4{pointX4Half(B, half), pointX4Half(R, half), pointX4Half(A, half)}
		affineR[half] = AffinePointX4{X: bases[half][1].X, Y: bases[half][1].Y}
		if err := workspaces[half].PrepareAll(&bases[half][0], &bases[half][1], &bases[half][2], radixBits); err != nil {
			b.Fatal(err)
		}
	}
	paths := []struct {
		name               string
		prepareVariables   bool
		prepareAffineR     bool
		prepareCoefficient bool
	}{
		{name: "prepared-QSM"},
		{name: "cold-R+A+QSM", prepareVariables: true},
		{name: "cold-affine-R+A+QSM", prepareVariables: true, prepareAffineR: true},
		{name: "coeff+cold-R+A+QSM", prepareVariables: true, prepareCoefficient: true},
		{name: "coeff+cold-affine-R+A+QSM", prepareVariables: true, prepareAffineR: true, prepareCoefficient: true},
	}
	for _, path := range paths {
		b.Run(path.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ReportMetric(float64(4*NominalFullTableBytes(X4Lanes, 4, radixBits)), "active-cold-R+A-tables-B")
			b.ReportMetric(float64(2*QSMTerms*NominalFullTableBytes(X4Lanes, 4, radixBits)), "active-retained-tables-B")
			b.ReportMetric(float64(2*unsafe.Sizeof(workspaces[0].tables[0])), "physical-tables-per-term-B")
			b.ReportMetric(float64(unsafe.Sizeof(*workspaces)), "physical-workspace-B")
			var coefficients8 ExperimentalHEEABaseSplitCoefficientsX8
			for i := 0; i < b.N; i++ {
				if path.prepareCoefficient {
					ExperimentalPrepareHEEABaseSplitCoefficientsX8(&coefficients8, s, tau, rho, epsilon, 0xff)
					ExperimentalSplitHEEABaseSplitCoefficientsX8(coefficients, &coefficients8)
				}
				for half := 0; half < 2; half++ {
					if path.prepareVariables {
						var err error
						if path.prepareAffineR {
							err = workspaces[half].PrepareVariableBasesAffineR(&affineR[half], &bases[half][2], 0x0f)
						} else {
							err = workspaces[half].PrepareVariableBases(&bases[half][1], &bases[half][2])
						}
						if err != nil {
							b.Fatal(err)
						}
					}
					usable, fallback, err := workspaces[half].Evaluate(&heeaIFMABenchmarkPointX4[half], &coefficients[half], 0x0f)
					if err != nil || usable != 0x0f || fallback != 0 {
						b.Fatalf("half %d evaluate=(%02x,%02x,%v)", half, usable, fallback, err)
					}
				}
			}
			heeaIFMABenchmarkMask = coefficients[0].ValidMask() | coefficients[1].ValidMask()<<X4Lanes
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*X8Lanes), "ns/signature")
		})
	}
}

// scalarWindowGeneratorX8 has a concrete *testing.T parameter. Benchmarks use
// the same generator fixture through this testing.TB-compatible wrapper.
func scalarWindowGeneratorX8ForBenchmark(tb testing.TB) ([X8Lanes]*edwardsref.Point, PointX8) {
	tb.Helper()
	var refs [X8Lanes]*edwardsref.Point
	var encodings [X8Lanes][32]byte
	for lane := 0; lane < X8Lanes; lane++ {
		refs[lane] = edwardsref.NewGeneratorPoint()
		copy(encodings[lane][:], refs[lane].Bytes())
	}
	var points PointX8
	if mask := points.SetBytes(&encodings); mask != 0xff {
		tb.Fatalf("generator valid mask=%02x", mask)
	}
	return refs, points
}
