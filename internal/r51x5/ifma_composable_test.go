package r51x5

import (
	"errors"
	"math/big"
	"math/rand"
	"runtime"
	"testing"
)

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
	if normalized[0] != ifmaPostCarryLimb0Limit-1 {
		t.Fatalf("maximum limb0=%x want %x", normalized[0], ifmaPostCarryLimb0Limit-1)
	}
	if !IsIFMAMultiplicand(normalized) {
		t.Fatalf("maximum normalization escaped u52: %x", normalized)
	}
	for limb := 1; limb < 5; limb++ {
		if normalized[limb] >= 1<<LimbBits {
			t.Fatalf("limb %d not tightly carried: %x", limb, normalized[limb])
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

func modelMultiplyComposableX8(out, x, y *IFMAElementX8) error {
	if !isIFMAElementX8(x) || !isIFMAElementX8(y) {
		return errIFMAComposableInputRange
	}
	var raw IFMAProductX8
	for lane := 0; lane < X8Lanes; lane++ {
		var xl, yl Limbs
		for limb := range xl {
			xl[limb] = x.limbs[limb][lane]
			yl[limb] = y.limbs[limb][lane]
		}
		product := ifmaLooseLaneModel(xl, yl)
		for limb := range product {
			raw[limb][lane] = product[limb]
		}
	}
	normalized, ok := normalizeIFMAProductX8(&raw)
	if !ok {
		return errIFMAOutputRange
	}
	out.limbs = normalized
	return nil
}

func modelMultiplyComposableX4(out, x, y *IFMAElementX4) error {
	if !isIFMAElementX4(x) || !isIFMAElementX4(y) {
		return errIFMAComposableInputRange
	}
	var raw IFMAProductX4
	for lane := 0; lane < X4Lanes; lane++ {
		var xl, yl Limbs
		for limb := range xl {
			xl[limb] = x.limbs[limb][lane]
			yl[limb] = y.limbs[limb][lane]
		}
		product := ifmaLooseLaneModel(xl, yl)
		for limb := range product {
			raw[limb][lane] = product[limb]
		}
	}
	normalized, ok := normalizeIFMAProductX4(&raw)
	if !ok {
		return errIFMAOutputRange
	}
	out.limbs = normalized
	return nil
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
)

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
