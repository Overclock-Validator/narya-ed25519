package r51x5

import (
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"runtime"
	"testing"
)

func TestIFMAPointX8SplitX4BitIdentity(t *testing.T) {
	var source IFMAPointX8
	coordinates := []*IFMAElementX8{&source.X, &source.Y, &source.Z, &source.T}
	for coordinate, element := range coordinates {
		for limb := range element.limbs {
			for lane := 0; lane < X8Lanes; lane++ {
				element.limbs[limb][lane] = (uint64(coordinate+1)<<48 | uint64(limb)<<12 | uint64(lane+1)) & (ifmaComposableLimbLimit - 1)
			}
		}
	}

	var split [2]IFMAPointX4
	source.SplitX4(&split)
	for half := range split {
		outputs := []*IFMAElementX4{&split[half].X, &split[half].Y, &split[half].Z, &split[half].T}
		for coordinate, element := range outputs {
			for limb := range element.limbs {
				for lane := 0; lane < X4Lanes; lane++ {
					sourceLane := half*X4Lanes + lane
					if got, want := element.limbs[limb][lane], coordinates[coordinate].limbs[limb][sourceLane]; got != want {
						t.Fatalf("half=%d coordinate=%d limb=%d lane=%d got=%#x want=%#x", half, coordinate, limb, lane, got, want)
					}
				}
			}
		}
	}
}

func TestIFMAComposableAnalyticBounds(t *testing.T) {
	// After splitting each product at bit 52 and moving doubled high halves
	// into the next radix-2^51 degree, degrees 0..9 have these conservative
	// counts of 52-bit terms.
	coefficients := [...]uint64{1, 4, 7, 10, 13, 14, 11, 8, 5, 2}
	folded := [...]uint64{
		coefficients[0] + 19*coefficients[5],
		coefficients[1] + 19*coefficients[6],
		coefficients[2] + 19*coefficients[7],
		coefficients[3] + 19*coefficients[8],
		coefficients[4] + 19*coefficients[9],
	}
	wantFolded := [...]uint64{267, 213, 159, 105, 51}
	if folded != wantFolded {
		t.Fatalf("folded weights=%v want %v", folded, wantFolded)
	}
	for limb, weight := range folded {
		upper := weight << IFMAComposableLimbBits
		if upper >= ifmaProductLimbLimit {
			t.Fatalf("limb %d upper bound %d*2^52 exceeds u61", limb, weight)
		}
	}

	maximum := Limbs{
		ifmaProductLimbLimit - 1,
		ifmaProductLimbLimit - 1,
		ifmaProductLimbLimit - 1,
		ifmaProductLimbLimit - 1,
		ifmaProductLimbLimit - 1,
	}
	normalized, ok := normalizeIFMAProductLane(maximum)
	if !ok {
		t.Fatal("maximum u61 input failed normalization")
	}
	wantLimb0 := (uint64(1) << LimbBits) - 1 + 19*(ifmaFoldCarryMax-1)
	if normalized[0] != wantLimb0 {
		t.Fatalf("maximum limb0=%x want %x", normalized[0], wantLimb0)
	}
	if !IsIFMAMultiplicand(normalized) {
		t.Fatalf("maximum normalization escaped u52: %x", normalized)
	}
	for limb := 1; limb < 5; limb++ {
		want := uint64(1)<<LimbBits + ifmaFoldCarryMax - 2
		if normalized[limb] != want {
			t.Fatalf("maximum limb %d=%x want %x", limb, normalized[limb], want)
		}
	}

	maximumMultiplicand := Limbs{
		ifmaComposableLimbLimit - 1,
		ifmaComposableLimbLimit - 1,
		ifmaComposableLimbLimit - 1,
		ifmaComposableLimbLimit - 1,
		ifmaComposableLimbLimit - 1,
	}
	rawProduct := ifmaLooseLaneModel(maximumMultiplicand, maximumMultiplicand)
	for limb, value := range rawProduct {
		if value >= ifmaProductLimbLimit {
			t.Fatalf("maximum product limb %d escaped u61: %x", limb, value)
		}
	}
	normalizedProduct, ok := normalizeIFMAProductLane(rawProduct)
	if !ok || !IsIFMAMultiplicand(normalizedProduct) {
		t.Fatal("maximum u52 product failed composable normalization")
	}
	wantProduct := new(big.Int).Mul(looseLimbsBig(maximumMultiplicand), looseLimbsBig(maximumMultiplicand))
	wantProduct.Mod(wantProduct, testModulus)
	gotProduct := looseLimbsBig(normalizedProduct)
	gotProduct.Mod(gotProduct, testModulus)
	if gotProduct.Cmp(wantProduct) != 0 {
		t.Fatalf("maximum product got %x want %x", gotProduct, wantProduct)
	}
}

func TestIFMAVectorNormalizerMatchesScalarReference(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	rng := rand.New(rand.NewSource(0x51c4a77))
	for round := 0; round < 2000; round++ {
		var input8 IFMAProductX8
		for limb := range input8 {
			for lane := range input8[limb] {
				switch round {
				case 0:
					input8[limb][lane] = 0
				case 1:
					input8[limb][lane] = ifmaProductLimbLimit - 1
				default:
					input8[limb][lane] = rng.Uint64() & (ifmaProductLimbLimit - 1)
				}
			}
		}
		want8, ok := normalizeIFMAProductX8(&input8)
		if !ok {
			t.Fatalf("round %d: scalar x8 reference rejected proven-u61 input", round)
		}
		var got8 LimbsX8
		ifmaNormalizeProductUncheckedX8(&got8, &input8)
		if got8 != want8 {
			t.Fatalf("round %d: x8 vector normalization mismatch\ngot  %x\nwant %x", round, got8, want8)
		}

		var input4 IFMAProductX4
		for limb := range input4 {
			copy(input4[limb][:], input8[limb][:X4Lanes])
		}
		want4, ok := normalizeIFMAProductX4(&input4)
		if !ok {
			t.Fatalf("round %d: scalar x4 reference rejected proven-u61 input", round)
		}
		var got4 LimbsX4
		ifmaNormalizeProductUncheckedX4(&got4, &input4)
		if got4 != want4 {
			t.Fatalf("round %d: x4 vector normalization mismatch\ngot  %x\nwant %x", round, got4, want4)
		}
	}
}

func TestIFMAComposableVectorOpsEdgesAndAliases(t *testing.T) {
	zero8 := IFMAElementX8{}
	maximum8 := filledIFMAElementX8(ifmaComposableLimbLimit - 1)
	pattern8 := patternedIFMAElementX8(false)
	reverse8 := patternedIFMAElementX8(true)
	tests8 := []struct {
		name string
		x    IFMAElementX8
		y    IFMAElementX8
	}{
		{name: "zero-max", x: zero8, y: maximum8},
		{name: "max-zero", x: maximum8, y: zero8},
		{name: "max-max", x: maximum8, y: maximum8},
		{name: "mixed", x: pattern8, y: reverse8},
	}
	for _, test := range tests8 {
		t.Run("x8/"+test.name, func(t *testing.T) {
			testIFMAComposableVectorOpsX8(t, &test.x, &test.y)
		})
	}

	for group := 0; group < 2; group++ {
		for _, test := range tests8 {
			x4 := ifmaElementX4Half(&test.x, group)
			y4 := ifmaElementX4Half(&test.y, group)
			t.Run(fmt.Sprintf("x4/group=%d/%s", group, test.name), func(t *testing.T) {
				testIFMAComposableVectorOpsX4(t, &x4, &y4)
			})
		}
	}
}

func TestIFMAMaximumComposableMultiplyHardware(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	maximum8 := filledIFMAElementX8(ifmaComposableLimbLimit - 1)
	var raw8, wantRaw8 IFMAProductX8
	ifmaMulRawX8(&raw8, &maximum8.limbs, &maximum8.limbs)
	maximumLane := Limbs{
		ifmaComposableLimbLimit - 1,
		ifmaComposableLimbLimit - 1,
		ifmaComposableLimbLimit - 1,
		ifmaComposableLimbLimit - 1,
		ifmaComposableLimbLimit - 1,
	}
	wantLane := ifmaLooseLaneModel(maximumLane, maximumLane)
	for limb := range wantRaw8 {
		for lane := range wantRaw8[limb] {
			wantRaw8[limb][lane] = wantLane[limb]
		}
	}
	if !isIFMAProductX8(raw8) {
		t.Fatal("maximum x8 hardware raw product escaped u61")
	}
	if raw8 != wantRaw8 {
		t.Fatalf("maximum x8 hardware raw product mismatch\ngot  %x\nwant %x", raw8, wantRaw8)
	}
	want8, ok := normalizeIFMAProductX8(&wantRaw8)
	if !ok {
		t.Fatal("scalar reference rejected maximum x8 raw product")
	}
	var got8 LimbsX8
	ifmaNormalizeProductUncheckedX8(&got8, &raw8)
	if got8 != want8 {
		t.Fatalf("maximum x8 hardware normalized product mismatch\ngot  %x\nwant %x", got8, want8)
	}

	maximum4 := ifmaElementX4Half(&maximum8, 0)
	var raw4, wantRaw4 IFMAProductX4
	ifmaMulRawX4(&raw4, &maximum4.limbs, &maximum4.limbs)
	for limb := range wantRaw4 {
		for lane := range wantRaw4[limb] {
			wantRaw4[limb][lane] = wantLane[limb]
		}
	}
	if !isIFMAProductX4(raw4) {
		t.Fatal("maximum x4 hardware raw product escaped u61")
	}
	if raw4 != wantRaw4 {
		t.Fatalf("maximum x4 hardware raw product mismatch\ngot  %x\nwant %x", raw4, wantRaw4)
	}
	want4, ok := normalizeIFMAProductX4(&wantRaw4)
	if !ok {
		t.Fatal("scalar reference rejected maximum x4 raw product")
	}
	var got4 LimbsX4
	ifmaNormalizeProductUncheckedX4(&got4, &raw4)
	if got4 != want4 {
		t.Fatalf("maximum x4 hardware normalized product mismatch\ngot  %x\nwant %x", got4, want4)
	}
}

func TestIFMAFusedMultiplyNormalizeDifferential(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	rng := rand.New(rand.NewSource(0xf05e_51c4))
	for round := 0; round < 2048; round++ {
		x8 := randomIFMAElementX8(rng)
		y8 := randomIFMAElementX8(rng)
		if round == 0 {
			x8 = filledIFMAElementX8(ifmaComposableLimbLimit - 1)
			y8 = x8
		}

		var raw8 IFMAProductX8
		var want8, got8 LimbsX8
		ifmaMulRawX8(&raw8, &x8.limbs, &y8.limbs)
		ifmaNormalizeProductUncheckedX8(&want8, &raw8)
		ifmaMulNormalizedUncheckedX8(&got8, &x8.limbs, &y8.limbs)
		if got8 != want8 {
			t.Fatalf("round %d: fused x8 differs from split raw+normalize\ngot  %x\nwant %x", round, got8, want8)
		}
		if !isIFMAElementX8(&IFMAElementX8{limbs: got8}) {
			t.Fatalf("round %d: fused x8 output escaped u52", round)
		}

		aliasX8 := x8.limbs
		ifmaMulNormalizedUncheckedX8(&aliasX8, &aliasX8, &y8.limbs)
		if aliasX8 != want8 {
			t.Fatalf("round %d: fused x8 x-alias mismatch", round)
		}
		aliasY8 := y8.limbs
		ifmaMulNormalizedUncheckedX8(&aliasY8, &x8.limbs, &aliasY8)
		if aliasY8 != want8 {
			t.Fatalf("round %d: fused x8 y-alias mismatch", round)
		}

		for group := 0; group < 2; group++ {
			x4 := ifmaElementX4Half(&x8, group)
			y4 := ifmaElementX4Half(&y8, group)
			var raw4 IFMAProductX4
			var want4, got4 LimbsX4
			ifmaMulRawX4(&raw4, &x4.limbs, &y4.limbs)
			ifmaNormalizeProductUncheckedX4(&want4, &raw4)
			ifmaMulNormalizedUncheckedX4(&got4, &x4.limbs, &y4.limbs)
			if got4 != want4 {
				t.Fatalf("round %d group %d: fused x4 differs from split raw+normalize\ngot  %x\nwant %x", round, group, got4, want4)
			}
			if !isIFMAElementX4(&IFMAElementX4{limbs: got4}) {
				t.Fatalf("round %d group %d: fused x4 output escaped u52", round, group)
			}

			aliasX4 := x4.limbs
			ifmaMulNormalizedUncheckedX4(&aliasX4, &aliasX4, &y4.limbs)
			if aliasX4 != want4 {
				t.Fatalf("round %d group %d: fused x4 x-alias mismatch", round, group)
			}
			aliasY4 := y4.limbs
			ifmaMulNormalizedUncheckedX4(&aliasY4, &x4.limbs, &aliasY4)
			if aliasY4 != want4 {
				t.Fatalf("round %d group %d: fused x4 y-alias mismatch", round, group)
			}
		}
	}

	// Exercise the strongest alias: out, x, and y all refer to the same
	// maximum-limb input. This also permanently covers the analytic u61 peak.
	maximum8 := filledIFMAElementX8(ifmaComposableLimbLimit - 1)
	var rawSquare8 IFMAProductX8
	var wantSquare8 LimbsX8
	ifmaMulRawX8(&rawSquare8, &maximum8.limbs, &maximum8.limbs)
	ifmaNormalizeProductUncheckedX8(&wantSquare8, &rawSquare8)
	aliasBoth8 := maximum8.limbs
	ifmaMulNormalizedUncheckedX8(&aliasBoth8, &aliasBoth8, &aliasBoth8)
	if aliasBoth8 != wantSquare8 {
		t.Fatal("maximum x8 out=x=y alias mismatch")
	}

	maximum4 := ifmaElementX4Half(&maximum8, 0)
	var rawSquare4 IFMAProductX4
	var wantSquare4 LimbsX4
	ifmaMulRawX4(&rawSquare4, &maximum4.limbs, &maximum4.limbs)
	ifmaNormalizeProductUncheckedX4(&wantSquare4, &rawSquare4)
	aliasBoth4 := maximum4.limbs
	ifmaMulNormalizedUncheckedX4(&aliasBoth4, &aliasBoth4, &aliasBoth4)
	if aliasBoth4 != wantSquare4 {
		t.Fatal("maximum x4 out=x=y alias mismatch")
	}
}

func TestNormalizeIFMAProductDifferential(t *testing.T) {
	rng := rand.New(rand.NewSource(0x61_52_51))
	for round := 0; round < 4096; round++ {
		var input Limbs
		for limb := range input {
			input[limb] = rng.Uint64() & (ifmaProductLimbLimit - 1)
		}
		if round == 0 {
			for limb := range input {
				input[limb] = ifmaProductLimbLimit - 1
			}
		}
		got, ok := normalizeIFMAProductLane(input)
		if !ok || !IsIFMAMultiplicand(got) {
			t.Fatalf("round %d: normalization failed", round)
		}
		want := looseLimbsBig(input)
		want.Mod(want, testModulus)
		gotBig := looseLimbsBig(got)
		gotBig.Mod(gotBig, testModulus)
		if gotBig.Cmp(want) != 0 {
			t.Fatalf("round %d: got %x want %x", round, gotBig, want)
		}
	}

	outOfRange := Limbs{ifmaProductLimbLimit}
	if _, ok := normalizeIFMAProductLane(outOfRange); ok {
		t.Fatal("accepted a 61-bit input limb")
	}
}

func TestIFMAComposableFieldDifferential(t *testing.T) {
	rng := rand.New(rand.NewSource(0x52_c0_4e))
	for round := 0; round < 2048; round++ {
		x := randomIFMAElementX8(rng)
		y := randomIFMAElementX8(rng)

		var add, sub, neg, product IFMAElementX8
		add.Add(&x, &y)
		sub.Subtract(&x, &y)
		neg.Negate(&x)
		if err := modelMultiplyComposableX8(&product, &x, &y); err != nil {
			t.Fatal(err)
		}
		assertIFMAElementX8Range(t, "add", &add)
		assertIFMAElementX8Range(t, "sub", &sub)
		assertIFMAElementX8Range(t, "neg", &neg)
		assertIFMAElementX8Range(t, "mul", &product)

		for lane := 0; lane < X8Lanes; lane++ {
			xBig := ifmaElementLaneBigX8(&x, lane)
			yBig := ifmaElementLaneBigX8(&y, lane)
			assertIFMALaneEqualsBigX8(t, round, lane, "add", &add,
				new(big.Int).Add(new(big.Int).Set(xBig), yBig))
			assertIFMALaneEqualsBigX8(t, round, lane, "sub", &sub,
				new(big.Int).Sub(new(big.Int).Set(xBig), yBig))
			assertIFMALaneEqualsBigX8(t, round, lane, "neg", &neg,
				new(big.Int).Neg(new(big.Int).Set(xBig)))
			assertIFMALaneEqualsBigX8(t, round, lane, "mul", &product,
				new(big.Int).Mul(new(big.Int).Set(xBig), yBig))
		}

		// Both real SIMD widths use the same range contract and must agree on
		// each four-lane half.
		for group := 0; group < 2; group++ {
			x4 := ifmaElementX4Half(&x, group)
			y4 := ifmaElementX4Half(&y, group)
			var product4 IFMAElementX4
			if err := modelMultiplyComposableX4(&product4, &x4, &y4); err != nil {
				t.Fatal(err)
			}
			for limb := 0; limb < 5; limb++ {
				for lane := 0; lane < X4Lanes; lane++ {
					if product4.limbs[limb][lane] != product.limbs[limb][group*X4Lanes+lane] {
						t.Fatalf("round %d group %d limb %d lane %d: x4/x8 mismatch", round, group, limb, lane)
					}
				}
			}
		}
	}
}

func TestIFMAComposablePointFormulasAndChaining(t *testing.T) {
	rng := rand.New(rand.NewSource(0x51_add_d0b1e))
	torsion := referenceTorsionPoints(t)
	for round := 0; round < 24; round++ {
		var aBytes, bBytes [X8Lanes][32]byte
		for lane := 0; lane < X8Lanes; lane++ {
			a := randomMixedReferencePoint(t, rng, torsion[(round+lane)%X8Lanes])
			b := randomMixedReferencePoint(t, rng, torsion[(round+lane+3)%X8Lanes])
			copy(aBytes[lane][:], a.Bytes())
			copy(bBytes[lane][:], b.Bytes())
		}
		var a, b PointX8
		if a.SetBytes(&aBytes) != 0xff || b.SetBytes(&bBytes) != 0xff {
			t.Fatal("failed to decode point fixtures")
		}
		var looseA, looseB IFMAPointX8
		looseA.SetReduced(&a)
		looseB.SetReduced(&b)

		var gotAdd, gotDouble IFMAPointX8
		if err := ifmaPointAddComposableX8(&gotAdd, &looseA, &looseB, modelMultiplyComposableX8); err != nil {
			t.Fatal(err)
		}
		if err := ifmaPointDoubleComposableX8(&gotDouble, &looseA, modelMultiplyComposableX8); err != nil {
			t.Fatal(err)
		}
		var wantAdd, wantDouble PointX8
		wantAdd.Add(&a, &b)
		wantDouble.Double(&a)
		if reduced := gotAdd.Reduced(); reduced != wantAdd {
			t.Fatalf("round %d: x8 add coordinates differ after reduction", round)
		}
		if reduced := gotDouble.Reduced(); reduced != wantDouble {
			t.Fatalf("round %d: x8 double coordinates differ after reduction", round)
		}
		assertIFMAPointX8Range(t, "add", &gotAdd)
		assertIFMAPointX8Range(t, "double", &gotDouble)

		// Exercise direct reuse as another point-operation input. No Reduced
		// call occurs inside this chain.
		chainLoose := looseA
		chainWant := a
		for step := 0; step < 20; step++ {
			if step&1 == 0 {
				if err := ifmaPointAddComposableX8(&chainLoose, &chainLoose, &looseB, modelMultiplyComposableX8); err != nil {
					t.Fatal(err)
				}
				chainWant.Add(&chainWant, &b)
			} else {
				if err := ifmaPointDoubleComposableX8(&chainLoose, &chainLoose, modelMultiplyComposableX8); err != nil {
					t.Fatal(err)
				}
				chainWant.Double(&chainWant)
			}
			assertIFMAPointX8Range(t, "chain", &chainLoose)
			if reduced := chainLoose.Reduced(); reduced != chainWant {
				t.Fatalf("round %d step %d: chained coordinates differ", round, step)
			}
		}

		// Compare each x4 half through the same formula cores.
		for group := 0; group < 2; group++ {
			a4 := pointX4Half(&a, group)
			b4 := pointX4Half(&b, group)
			var looseA4, looseB4 IFMAPointX4
			looseA4.SetReduced(&a4)
			looseB4.SetReduced(&b4)
			var gotAdd4, gotDouble4 IFMAPointX4
			if err := ifmaPointAddComposableX4(&gotAdd4, &looseA4, &looseB4, modelMultiplyComposableX4); err != nil {
				t.Fatal(err)
			}
			if err := ifmaPointDoubleComposableX4(&gotDouble4, &looseA4, modelMultiplyComposableX4); err != nil {
				t.Fatal(err)
			}
			wantAdd4 := pointX4Half(&wantAdd, group)
			wantDouble4 := pointX4Half(&wantDouble, group)
			if reduced := gotAdd4.Reduced(); reduced != wantAdd4 {
				t.Fatalf("round %d group %d: x4 add differs", round, group)
			}
			if reduced := gotDouble4.Reduced(); reduced != wantDouble4 {
				t.Fatalf("round %d group %d: x4 double differs", round, group)
			}
		}
	}
}

func TestExperimentalIFMAComposableHardware(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	rng := rand.New(rand.NewSource(0x1f4a_c052))
	for round := 0; round < 2048; round++ {
		x := randomIFMAElementX8(rng)
		y := randomIFMAElementX8(rng)
		var got, want IFMAElementX8
		if err := ExperimentalIFMAMultiplyComposableX8(&got, &x, &y); err != nil {
			t.Fatal(err)
		}
		if err := modelMultiplyComposableX8(&want, &x, &y); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("round %d: x8 hardware/model mismatch", round)
		}
		for group := 0; group < 2; group++ {
			x4 := ifmaElementX4Half(&x, group)
			y4 := ifmaElementX4Half(&y, group)
			var got4 IFMAElementX4
			if err := ExperimentalIFMAMultiplyComposableX4(&got4, &x4, &y4); err != nil {
				t.Fatal(err)
			}
			for limb := 0; limb < 5; limb++ {
				for lane := 0; lane < X4Lanes; lane++ {
					if got4.limbs[limb][lane] != got.limbs[limb][group*X4Lanes+lane] {
						t.Fatalf("round %d group %d: x4/x8 hardware mismatch", round, group)
					}
				}
			}
		}
	}

	torsion := referenceTorsionPoints(t)
	for round := 0; round < 32; round++ {
		var aBytes, bBytes [X8Lanes][32]byte
		for lane := 0; lane < X8Lanes; lane++ {
			a := randomMixedReferencePoint(t, rng, torsion[(round+lane)%X8Lanes])
			b := randomMixedReferencePoint(t, rng, torsion[(round+lane+1)%X8Lanes])
			copy(aBytes[lane][:], a.Bytes())
			copy(bBytes[lane][:], b.Bytes())
		}
		var reducedA, reducedB PointX8
		if reducedA.SetBytes(&aBytes) != 0xff || reducedB.SetBytes(&bBytes) != 0xff {
			t.Fatal("failed to decode hardware point fixtures")
		}
		var a, b IFMAPointX8
		a.SetReduced(&reducedA)
		b.SetReduced(&reducedB)
		var gotAdd, wantAdd, gotDouble, wantDouble IFMAPointX8
		if err := ExperimentalIFMAPointAddComposableX8(&gotAdd, &a, &b); err != nil {
			t.Fatal(err)
		}
		if err := ifmaPointAddComposableX8(&wantAdd, &a, &b, modelMultiplyComposableX8); err != nil {
			t.Fatal(err)
		}
		if gotAdd != wantAdd {
			t.Fatalf("round %d: hardware/model point add mismatch", round)
		}
		if err := ExperimentalIFMAPointDoubleComposableX8(&gotDouble, &a); err != nil {
			t.Fatal(err)
		}
		if err := ifmaPointDoubleComposableX8(&wantDouble, &a, modelMultiplyComposableX8); err != nil {
			t.Fatal(err)
		}
		if gotDouble != wantDouble {
			t.Fatalf("round %d: hardware/model point double mismatch", round)
		}
		alias := a
		if err := ExperimentalIFMAPointAddComposableX8(&alias, &alias, &b); err != nil || alias != gotAdd {
			t.Fatalf("round %d: aliased hardware add mismatch: %v", round, err)
		}
	}

	valid := identityIFMAPointX8Value()
	invalid := valid
	invalid.X.limbs[2][7] = ifmaComposableLimbLimit
	sentinel := valid
	sentinel.T.limbs[0][0] = 9
	out := sentinel
	if err := ExperimentalIFMAPointAddComposableX8(&out, &invalid, &valid); !errors.Is(err, errIFMAComposableInputRange) || out != sentinel {
		t.Fatalf("checked point add invalid input=(%v, changed=%v)", err, out != sentinel)
	}
	if err := ExperimentalIFMAPointDoubleComposableX8(&out, &invalid); !errors.Is(err, errIFMAComposableInputRange) || out != sentinel {
		t.Fatalf("checked point double invalid input=(%v, changed=%v)", err, out != sentinel)
	}
}

func TestExperimentalIFMAComposableGate(t *testing.T) {
	if ExperimentalIFMAAvailable() {
		return
	}
	var x, out IFMAElementX8
	out.limbs[0][0] = 7
	want := out
	if err := ExperimentalIFMAMultiplyComposableX8(&out, &x, &x); !errors.Is(err, ErrIFMAUnavailable) {
		t.Fatalf("error=%v want %v", err, ErrIFMAUnavailable)
	}
	if out != want {
		t.Fatal("unavailable composable multiply changed output")
	}
	var point, pointOut IFMAPointX8
	pointOut.X.limbs[0][0] = 9
	wantPoint := pointOut
	if err := ExperimentalIFMAPointAddComposableX8(&pointOut, &point, &point); !errors.Is(err, ErrIFMAUnavailable) {
		t.Fatalf("point error=%v want %v", err, ErrIFMAUnavailable)
	}
	if pointOut != wantPoint {
		t.Fatal("unavailable composable point add changed output")
	}
}

func testIFMAComposableVectorOpsX8(t *testing.T, x, y *IFMAElementX8) {
	t.Helper()
	wantAdd := referenceAddIFMAElementX8(t, x, y)
	wantSubtract := referenceSubtractIFMAElementX8(t, x, y)
	wantNegate := referenceNegateIFMAElementX8(t, x)
	wantSelfAdd := referenceAddIFMAElementX8(t, x, x)
	wantSelfSubtract := referenceSubtractIFMAElementX8(t, x, x)

	var got IFMAElementX8
	got.Add(x, y)
	if got != wantAdd {
		t.Fatalf("non-aliased add mismatch\ngot  %x\nwant %x", got.limbs, wantAdd.limbs)
	}
	aliasX := *x
	aliasX.Add(&aliasX, y)
	if aliasX != wantAdd {
		t.Fatal("add with out == x mismatch")
	}
	aliasY := *y
	aliasY.Add(x, &aliasY)
	if aliasY != wantAdd {
		t.Fatal("add with out == y mismatch")
	}
	self := *x
	self.Add(&self, &self)
	if self != wantSelfAdd {
		t.Fatal("add with x == y == out mismatch")
	}

	got.Subtract(x, y)
	if got != wantSubtract {
		t.Fatalf("non-aliased subtract mismatch\ngot  %x\nwant %x", got.limbs, wantSubtract.limbs)
	}
	aliasX = *x
	aliasX.Subtract(&aliasX, y)
	if aliasX != wantSubtract {
		t.Fatal("subtract with out == x mismatch")
	}
	aliasY = *y
	aliasY.Subtract(x, &aliasY)
	if aliasY != wantSubtract {
		t.Fatal("subtract with out == y mismatch")
	}
	self = *x
	self.Subtract(&self, &self)
	if self != wantSelfSubtract {
		t.Fatal("subtract with x == y == out mismatch")
	}

	got.Negate(x)
	if got != wantNegate {
		t.Fatalf("non-aliased negate mismatch\ngot  %x\nwant %x", got.limbs, wantNegate.limbs)
	}
	aliasX = *x
	aliasX.Negate(&aliasX)
	if aliasX != wantNegate {
		t.Fatal("negate with out == x mismatch")
	}
	if !isIFMAElementX8(&wantAdd) || !isIFMAElementX8(&wantSubtract) || !isIFMAElementX8(&wantNegate) {
		t.Fatal("x8 vector operation escaped u52")
	}
}

func testIFMAComposableVectorOpsX4(t *testing.T, x, y *IFMAElementX4) {
	t.Helper()
	wantAdd := referenceAddIFMAElementX4(t, x, y)
	wantSubtract := referenceSubtractIFMAElementX4(t, x, y)
	wantNegate := referenceNegateIFMAElementX4(t, x)
	wantSelfAdd := referenceAddIFMAElementX4(t, x, x)
	wantSelfSubtract := referenceSubtractIFMAElementX4(t, x, x)

	var got IFMAElementX4
	got.Add(x, y)
	if got != wantAdd {
		t.Fatalf("non-aliased add mismatch\ngot  %x\nwant %x", got.limbs, wantAdd.limbs)
	}
	aliasX := *x
	aliasX.Add(&aliasX, y)
	if aliasX != wantAdd {
		t.Fatal("add with out == x mismatch")
	}
	aliasY := *y
	aliasY.Add(x, &aliasY)
	if aliasY != wantAdd {
		t.Fatal("add with out == y mismatch")
	}
	self := *x
	self.Add(&self, &self)
	if self != wantSelfAdd {
		t.Fatal("add with x == y == out mismatch")
	}

	got.Subtract(x, y)
	if got != wantSubtract {
		t.Fatalf("non-aliased subtract mismatch\ngot  %x\nwant %x", got.limbs, wantSubtract.limbs)
	}
	aliasX = *x
	aliasX.Subtract(&aliasX, y)
	if aliasX != wantSubtract {
		t.Fatal("subtract with out == x mismatch")
	}
	aliasY = *y
	aliasY.Subtract(x, &aliasY)
	if aliasY != wantSubtract {
		t.Fatal("subtract with out == y mismatch")
	}
	self = *x
	self.Subtract(&self, &self)
	if self != wantSelfSubtract {
		t.Fatal("subtract with x == y == out mismatch")
	}

	got.Negate(x)
	if got != wantNegate {
		t.Fatalf("non-aliased negate mismatch\ngot  %x\nwant %x", got.limbs, wantNegate.limbs)
	}
	aliasX = *x
	aliasX.Negate(&aliasX)
	if aliasX != wantNegate {
		t.Fatal("negate with out == x mismatch")
	}
	if !isIFMAElementX4(&wantAdd) || !isIFMAElementX4(&wantSubtract) || !isIFMAElementX4(&wantNegate) {
		t.Fatal("x4 vector operation escaped u52")
	}
}

func referenceAddIFMAElementX8(t testing.TB, x, y *IFMAElementX8) IFMAElementX8 {
	t.Helper()
	var raw IFMAProductX8
	for limb := range raw {
		for lane := range raw[limb] {
			raw[limb][lane] = x.limbs[limb][lane] + y.limbs[limb][lane]
		}
	}
	limbs, ok := normalizeIFMAProductX8(&raw)
	if !ok {
		t.Fatal("x8 add reference escaped normalizer input bound")
	}
	return IFMAElementX8{limbs: limbs}
}

func referenceSubtractIFMAElementX8(t testing.TB, x, y *IFMAElementX8) IFMAElementX8 {
	t.Helper()
	var raw IFMAProductX8
	for limb := range raw {
		bias := ifmaSubtractionBias(limb)
		for lane := range raw[limb] {
			raw[limb][lane] = x.limbs[limb][lane] + bias - y.limbs[limb][lane]
		}
	}
	limbs, ok := normalizeIFMAProductX8(&raw)
	if !ok {
		t.Fatal("x8 subtract reference escaped normalizer input bound")
	}
	return IFMAElementX8{limbs: limbs}
}

func referenceNegateIFMAElementX8(t testing.TB, x *IFMAElementX8) IFMAElementX8 {
	t.Helper()
	return referenceSubtractIFMAElementX8(t, &IFMAElementX8{}, x)
}

func referenceAddIFMAElementX4(t testing.TB, x, y *IFMAElementX4) IFMAElementX4 {
	t.Helper()
	var raw IFMAProductX4
	for limb := range raw {
		for lane := range raw[limb] {
			raw[limb][lane] = x.limbs[limb][lane] + y.limbs[limb][lane]
		}
	}
	limbs, ok := normalizeIFMAProductX4(&raw)
	if !ok {
		t.Fatal("x4 add reference escaped normalizer input bound")
	}
	return IFMAElementX4{limbs: limbs}
}

func referenceSubtractIFMAElementX4(t testing.TB, x, y *IFMAElementX4) IFMAElementX4 {
	t.Helper()
	var raw IFMAProductX4
	for limb := range raw {
		bias := ifmaSubtractionBias(limb)
		for lane := range raw[limb] {
			raw[limb][lane] = x.limbs[limb][lane] + bias - y.limbs[limb][lane]
		}
	}
	limbs, ok := normalizeIFMAProductX4(&raw)
	if !ok {
		t.Fatal("x4 subtract reference escaped normalizer input bound")
	}
	return IFMAElementX4{limbs: limbs}
}

func referenceNegateIFMAElementX4(t testing.TB, x *IFMAElementX4) IFMAElementX4 {
	t.Helper()
	return referenceSubtractIFMAElementX4(t, &IFMAElementX4{}, x)
}

func filledIFMAElementX8(value uint64) IFMAElementX8 {
	var out IFMAElementX8
	for limb := range out.limbs {
		for lane := range out.limbs[limb] {
			out.limbs[limb][lane] = value
		}
	}
	return out
}

func patternedIFMAElementX8(reverse bool) IFMAElementX8 {
	values := [...]uint64{
		0,
		1,
		(uint64(1) << LimbBits) - 1,
		uint64(1) << LimbBits,
		(uint64(1) << LimbBits) + 1,
		ifmaComposableLimbLimit - 2,
		ifmaComposableLimbLimit - 1,
		19,
	}
	var out IFMAElementX8
	for limb := range out.limbs {
		for lane := range out.limbs[limb] {
			index := (3*limb + lane) % len(values)
			if reverse {
				index = len(values) - 1 - index
			}
			out.limbs[limb][lane] = values[index]
		}
	}
	return out
}

func randomIFMAElementX8(rng *rand.Rand) IFMAElementX8 {
	var out IFMAElementX8
	for limb := range out.limbs {
		for lane := range out.limbs[limb] {
			out.limbs[limb][lane] = rng.Uint64() & (ifmaComposableLimbLimit - 1)
		}
	}
	return out
}

func looseLimbsBig(limbs Limbs) *big.Int {
	out := new(big.Int)
	for limb := len(limbs) - 1; limb >= 0; limb-- {
		out.Lsh(out, LimbBits)
		out.Add(out, new(big.Int).SetUint64(limbs[limb]))
	}
	return out
}

func ifmaElementLaneBigX8(x *IFMAElementX8, lane int) *big.Int {
	var limbs Limbs
	for limb := range limbs {
		limbs[limb] = x.limbs[limb][lane]
	}
	return looseLimbsBig(limbs)
}

func assertIFMALaneEqualsBigX8(t *testing.T, round, lane int, label string, got *IFMAElementX8, want *big.Int) {
	t.Helper()
	want.Mod(want, testModulus)
	reducedLanes := got.Reduced()
	reduced := reducedLanes.Lane(lane)
	if gotBig := elementBig(&reduced); gotBig.Cmp(want) != 0 {
		t.Fatalf("round %d lane %d %s: got %x want %x", round, lane, label, gotBig, want)
	}
}

func assertIFMAElementX8Range(t *testing.T, label string, x *IFMAElementX8) {
	t.Helper()
	if !isIFMAElementX8(x) {
		t.Fatalf("%s escaped u52", label)
	}
}

func assertIFMAPointX8Range(t *testing.T, label string, p *IFMAPointX8) {
	t.Helper()
	assertIFMAElementX8Range(t, label+" X", &p.X)
	assertIFMAElementX8Range(t, label+" Y", &p.Y)
	assertIFMAElementX8Range(t, label+" Z", &p.Z)
	assertIFMAElementX8Range(t, label+" T", &p.T)
}

func ifmaElementX4Half(x *IFMAElementX8, group int) IFMAElementX4 {
	var out IFMAElementX4
	for limb := range out.limbs {
		copy(out.limbs[limb][:], x.limbs[limb][group*X4Lanes:(group+1)*X4Lanes])
	}
	return out
}

func pointX4Half(x *PointX8, group int) PointX4 {
	var points [X4Lanes]Point
	for lane := range points {
		points[lane] = x.Lane(group*X4Lanes + lane)
	}
	var out PointX4
	out.SetPoints(&points)
	return out
}

var (
	benchmarkComposableElementX8Sink IFMAElementX8
	benchmarkComposableElementX4Sink [2]IFMAElementX4
	benchmarkComposablePointX8Sink   IFMAPointX8
	benchmarkComposablePointX4Sink   [2]IFMAPointX4
	benchmarkNormalizedLimbsX8Sink   LimbsX8
	benchmarkNormalizedLimbsX4Sink   [2]LimbsX4
)

func BenchmarkIFMAVectorNormalize(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	var input8 IFMAProductX8
	for limb := range input8 {
		for lane := range input8[limb] {
			input8[limb][lane] = (uint64(limb+1)*0x51_0000 + uint64(lane)*0x1001) & (ifmaProductLimbLimit - 1)
		}
	}
	var input4 [2]IFMAProductX4
	for group := range input4 {
		for limb := range input4[group] {
			copy(input4[group][limb][:], input8[limb][group*X4Lanes:(group+1)*X4Lanes])
		}
	}

	b.Run("x8-zmm-u61", func(b *testing.B) {
		var out LimbsX8
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ifmaNormalizeProductUncheckedX8(&out, &input8)
		}
		benchmarkNormalizedLimbsX8Sink = out
	})
	b.Run("two-x4-ymm-u61", func(b *testing.B) {
		var out [2]LimbsX4
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for group := range out {
				ifmaNormalizeProductUncheckedX4(&out[group], &input4[group])
			}
		}
		benchmarkNormalizedLimbsX4Sink = out
	})
}

func BenchmarkIFMAFusedMultiplyNormalize(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	reducedX8, reducedY8, reducedX4, reducedY4 := benchmarkIFMAInputs(b)

	b.Run("x4/split-raw-normalize", func(b *testing.B) {
		var raw IFMAProductX4
		var out LimbsX4
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ifmaMulRawX4(&raw, &reducedX4[0].limbs, &reducedY4[0].limbs)
			ifmaNormalizeProductUncheckedX4(&out, &raw)
		}
		benchmarkNormalizedLimbsX4Sink[0] = out
	})
	b.Run("x4/fused", func(b *testing.B) {
		var out LimbsX4
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ifmaMulNormalizedUncheckedX4(&out, &reducedX4[0].limbs, &reducedY4[0].limbs)
		}
		benchmarkNormalizedLimbsX4Sink[0] = out
	})

	b.Run("x8/split-raw-normalize", func(b *testing.B) {
		var raw IFMAProductX8
		var out LimbsX8
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ifmaMulRawX8(&raw, &reducedX8.limbs, &reducedY8.limbs)
			ifmaNormalizeProductUncheckedX8(&out, &raw)
		}
		benchmarkNormalizedLimbsX8Sink = out
	})
	b.Run("x8/fused", func(b *testing.B) {
		var out LimbsX8
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ifmaMulNormalizedUncheckedX8(&out, &reducedX8.limbs, &reducedY8.limbs)
		}
		benchmarkNormalizedLimbsX8Sink = out
	})
}

func BenchmarkExperimentalIFMAComposable(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	reducedX8, reducedY8, reducedX4, reducedY4 := benchmarkIFMAInputs(b)
	var x8, y8 IFMAElementX8
	x8.SetReduced(&reducedX8)
	y8.SetReduced(&reducedY8)
	var x4, y4 [2]IFMAElementX4
	for group := range x4 {
		x4[group].SetReduced(&reducedX4[group])
		y4[group].SetReduced(&reducedY4[group])
	}

	b.Run("field-multiply/x8-zmm-u52", func(b *testing.B) {
		var out IFMAElementX8
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := ExperimentalIFMAMultiplyComposableX8(&out, &x8, &y8); err != nil {
				b.Fatal(err)
			}
		}
		benchmarkComposableElementX8Sink = out
	})
	b.Run("field-multiply/two-x4-ymm-u52", func(b *testing.B) {
		var out [2]IFMAElementX4
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for group := range out {
				if err := ExperimentalIFMAMultiplyComposableX4(&out[group], &x4[group], &y4[group]); err != nil {
					b.Fatal(err)
				}
			}
		}
		benchmarkComposableElementX4Sink = out
	})

	reducedA8, reducedB8, reducedA4, reducedB4 := benchmarkMixedPointInputs(b)
	var a8, b8 IFMAPointX8
	a8.SetReduced(&reducedA8)
	b8.SetReduced(&reducedB8)
	var a4, b4 [2]IFMAPointX4
	for group := range a4 {
		a4[group].SetReduced(&reducedA4[group])
		b4[group].SetReduced(&reducedB4[group])
	}
	b.Run("point-add/x8-zmm-u52", func(b *testing.B) {
		var out IFMAPointX8
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := ExperimentalIFMAPointAddComposableX8(&out, &a8, &b8); err != nil {
				b.Fatal(err)
			}
		}
		benchmarkComposablePointX8Sink = out
	})
	b.Run("point-add/two-x4-ymm-u52", func(b *testing.B) {
		var out [2]IFMAPointX4
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for group := range out {
				if err := ExperimentalIFMAPointAddComposableX4(&out[group], &a4[group], &b4[group]); err != nil {
					b.Fatal(err)
				}
			}
		}
		benchmarkComposablePointX4Sink = out
	})
	b.Run("point-double/x8-zmm-u52", func(b *testing.B) {
		var out IFMAPointX8
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := ExperimentalIFMAPointDoubleComposableX8(&out, &a8); err != nil {
				b.Fatal(err)
			}
		}
		benchmarkComposablePointX8Sink = out
	})
	b.Run("point-double/two-x4-ymm-u52", func(b *testing.B) {
		var out [2]IFMAPointX4
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for group := range out {
				if err := ExperimentalIFMAPointDoubleComposableX4(&out[group], &a4[group]); err != nil {
					b.Fatal(err)
				}
			}
		}
		benchmarkComposablePointX4Sink = out
	})
}
