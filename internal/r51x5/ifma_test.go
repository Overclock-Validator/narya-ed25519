package r51x5

import (
	"errors"
	"math/big"
	"math/bits"
	"math/rand"
	"runtime"
	"testing"
)

func ifmaLooseLaneModel(x, y Limbs) Limbs {
	const mask52 = uint64(1<<52) - 1
	var low, high [9]uint64
	for i := range x {
		for j := range y {
			hi, lo := bits.Mul64(x[i], y[j])
			degree := i + j
			low[degree] += lo & mask52
			high[degree] += lo>>52 | hi<<12
		}
	}

	var coefficients [10]uint64
	for degree := range low {
		coefficients[degree] += low[degree]
		coefficients[degree+1] += 2 * high[degree]
	}
	return Limbs{
		coefficients[0] + 19*coefficients[5],
		coefficients[1] + 19*coefficients[6],
		coefficients[2] + 19*coefficients[7],
		coefficients[3] + 19*coefficients[8],
		coefficients[4] + 19*coefficients[9],
	}
}

func ifmaLooseX8Model(x, y *ElementX8) IFMALooseX8 {
	var out IFMALooseX8
	for lane := 0; lane < X8Lanes; lane++ {
		xLane, yLane := x.Lane(lane), y.Lane(lane)
		loose := ifmaLooseLaneModel(xLane.Limbs(), yLane.Limbs())
		for limb := range loose {
			out[limb][lane] = loose[limb]
		}
	}
	return out
}

func ifmaLooseX4Model(x, y *ElementX4) IFMALooseX4 {
	var out IFMALooseX4
	for lane := 0; lane < X4Lanes; lane++ {
		xLane, yLane := x.Lane(lane), y.Lane(lane)
		loose := ifmaLooseLaneModel(xLane.Limbs(), yLane.Limbs())
		for limb := range loose {
			out[limb][lane] = loose[limb]
		}
	}
	return out
}

func TestIFMALooseAnalyticBound(t *testing.T) {
	// A coefficient receives at most five low 52-bit halves and at most five
	// doubled high halves. A folded limb is lowDegree + 19*highDegree.
	lowContribution := uint64(5) * ((uint64(1) << 52) - 1)
	highContribution := uint64(5) * (2 * ((uint64(1) << 50) - 1))
	coefficientBound := lowContribution + highContribution
	foldedBound := uint64(20) * coefficientBound
	if coefficientBound >= 1<<55 {
		t.Fatalf("coefficient proof exceeded u55: %x", coefficientBound)
	}
	if foldedBound >= ifmaLooseLimbLimit {
		t.Fatalf("folded proof exceeded u%d: %x", IFMALooseLimbBits, foldedBound)
	}
}

func TestIFMALooseModelAndReduction(t *testing.T) {
	boundary := []*big.Int{
		big.NewInt(0),
		big.NewInt(1),
		big.NewInt(2),
		big.NewInt(19),
		new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 51), big.NewInt(1)),
		new(big.Int).Lsh(big.NewInt(1), 51),
		new(big.Int).Sub(new(big.Int).Set(testModulus), big.NewInt(2)),
		new(big.Int).Sub(new(big.Int).Set(testModulus), big.NewInt(1)),
	}

	var x8, y8 [X8Lanes]Element
	for lane := range x8 {
		x8[lane] = elementFromBig(t, boundary[lane])
		y8[lane] = elementFromBig(t, boundary[len(boundary)-1-lane])
	}
	checkLooseModelX8(t, "boundary", &x8, &y8)

	rng := rand.New(rand.NewSource(0x51_1f4a_8))
	for round := 0; round < 2048; round++ {
		for lane := range x8 {
			x8[lane], _ = randomElement(t, rng)
			y8[lane], _ = randomElement(t, rng)
		}
		checkLooseModelX8(t, "random", &x8, &y8)
	}
}

func TestIFMALooseWorstReducedOperands(t *testing.T) {
	pMinusOne := elementFromBig(t, new(big.Int).Sub(new(big.Int).Set(testModulus), big.NewInt(1)))
	loose := ifmaLooseLaneModel(pMinusOne.Limbs(), pMinusOne.Limbs())
	for limb, value := range loose {
		if value >= ifmaLooseLimbLimit {
			t.Fatalf("(p-1)^2 limb %d exceeded u%d: %x", limb, IFMALooseLimbBits, value)
		}
	}

	var x, y [X8Lanes]Element
	for lane := range x {
		x[lane] = pMinusOne
		y[lane] = pMinusOne
	}
	checkLooseModelX8(t, "(p-1)^2", &x, &y)
}

func checkLooseModelX8(t *testing.T, label string, x, y *[X8Lanes]Element) {
	t.Helper()
	var vx, vy ElementX8
	vx.SetElements(x)
	vy.SetElements(y)
	raw := ifmaLooseX8Model(&vx, &vy)
	if !IsIFMALooseX8(raw) {
		t.Fatalf("%s: model exceeded u%d: %#v", label, IFMALooseLimbBits, raw)
	}
	reduced, ok := reduceIFMALooseX8(&raw)
	if !ok || !IsReducedX8(reduced) {
		t.Fatalf("%s: model reduction failed", label)
	}
	for lane := range x {
		var want Element
		want.Multiply(&x[lane], &y[lane])
		var got Element
		for limb := range got.limbs {
			got.limbs[limb] = reduced[limb][lane]
		}
		if got != want {
			t.Fatalf("%s lane %d: got %#v want %#v", label, lane, got.Limbs(), want.Limbs())
		}
	}

	var raw4 IFMALooseX4
	for limb := range raw4 {
		copy(raw4[limb][:], raw[limb][:X4Lanes])
	}
	if !IsIFMALooseX4(raw4) {
		t.Fatalf("%s: x4 projection exceeded u%d", label, IFMALooseLimbBits)
	}
	reduced4, ok := reduceIFMALooseX4(&raw4)
	if !ok || !IsReducedX4(reduced4) {
		t.Fatalf("%s: x4 model reduction failed", label)
	}
	for limb := range reduced4 {
		for lane := 0; lane < X4Lanes; lane++ {
			if reduced4[limb][lane] != reduced[limb][lane] {
				t.Fatalf("%s: x4/x8 reduction differs at limb %d lane %d", label, limb, lane)
			}
		}
	}
}

func TestIFMALooseRangeRejection(t *testing.T) {
	var raw8 IFMALooseX8
	raw8[4][7] = ifmaLooseLimbLimit
	if IsIFMALooseX8(raw8) {
		t.Fatal("x8 accepted a 60-bit limb")
	}
	if _, ok := reduceIFMALooseX8(&raw8); ok {
		t.Fatal("x8 reduced an out-of-contract limb")
	}

	var raw4 IFMALooseX4
	raw4[1][3] = ifmaLooseLimbLimit
	if IsIFMALooseX4(raw4) {
		t.Fatal("x4 accepted a 60-bit limb")
	}
	if _, ok := reduceIFMALooseX4(&raw4); ok {
		t.Fatal("x4 reduced an out-of-contract limb")
	}
}

func TestReduceArbitraryIFMALoose(t *testing.T) {
	rng := rand.New(rand.NewSource(0x60_51_8))
	for round := 0; round < 2048; round++ {
		var raw IFMALooseX8
		for limb := range raw {
			for lane := range raw[limb] {
				raw[limb][lane] = rng.Uint64() & (ifmaLooseLimbLimit - 1)
			}
		}
		if round == 0 {
			for limb := range raw {
				for lane := range raw[limb] {
					raw[limb][lane] = ifmaLooseLimbLimit - 1
				}
			}
		}

		reduced, ok := reduceIFMALooseX8(&raw)
		if !ok || !IsReducedX8(reduced) {
			t.Fatalf("round %d: reduction rejected in-range loose limbs", round)
		}
		for lane := 0; lane < X8Lanes; lane++ {
			want := new(big.Int)
			for limb := 4; limb >= 0; limb-- {
				want.Lsh(want, LimbBits)
				want.Add(want, new(big.Int).SetUint64(raw[limb][lane]))
			}
			want.Mod(want, testModulus)

			var got Element
			for limb := range got.limbs {
				got.limbs[limb] = reduced[limb][lane]
			}
			if value := elementBig(&got); value.Cmp(want) != 0 {
				t.Fatalf("round %d lane %d: got %x want %x", round, lane, value, want)
			}
		}
	}
}

func TestExperimentalIFMAGate(t *testing.T) {
	if ExperimentalIFMAAvailable() {
		return
	}
	var one Element
	one.One()
	var lanes8 [X8Lanes]Element
	for lane := range lanes8 {
		lanes8[lane] = one
	}
	var x8, out8 ElementX8
	x8.SetElements(&lanes8)
	out8.SetElements(&lanes8)
	want8 := out8
	if err := ExperimentalIFMAMultiplyX8(&out8, &x8, &x8); !errors.Is(err, ErrIFMAUnavailable) {
		t.Fatalf("x8 error=%v want %v", err, ErrIFMAUnavailable)
	}
	if out8 != want8 {
		t.Fatal("unavailable x8 call changed output")
	}
	var raw8 IFMALooseX8
	raw8[0][0] = 7
	wantRaw8 := raw8
	if err := ExperimentalIFMAMultiplyLooseX8(&raw8, &x8, &x8); !errors.Is(err, ErrIFMAUnavailable) {
		t.Fatalf("raw x8 error=%v want %v", err, ErrIFMAUnavailable)
	}
	if raw8 != wantRaw8 {
		t.Fatal("unavailable raw x8 call changed output")
	}

	var lanes4 [X4Lanes]Element
	copy(lanes4[:], lanes8[:X4Lanes])
	var x4, out4 ElementX4
	x4.SetElements(&lanes4)
	out4.SetElements(&lanes4)
	want4 := out4
	if err := ExperimentalIFMAMultiplyX4(&out4, &x4, &x4); !errors.Is(err, ErrIFMAUnavailable) {
		t.Fatalf("x4 error=%v want %v", err, ErrIFMAUnavailable)
	}
	if out4 != want4 {
		t.Fatal("unavailable x4 call changed output")
	}
}

func TestExperimentalIFMAMultiplyX8X4(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	pMinusOne := elementFromBig(t, new(big.Int).Sub(new(big.Int).Set(testModulus), big.NewInt(1)))
	var worstX, worstY [X8Lanes]Element
	for lane := range worstX {
		worstX[lane] = pMinusOne
		worstY[lane] = pMinusOne
	}
	checkHardwareIFMAX8X4(t, 9_999, &worstX, &worstY)

	var valid8, bad8, unchanged8 ElementX8
	valid8.SetElements(&worstX)
	bad8 = valid8
	bad8.limbs[2][6] = 1 << LimbBits
	unchanged8 = valid8
	before8 := unchanged8
	if err := ExperimentalIFMAMultiplyX8(&unchanged8, &bad8, &valid8); !errors.Is(err, errIFMAInputRange) {
		t.Fatalf("x8 invalid-input error=%v want %v", err, errIFMAInputRange)
	}
	if unchanged8 != before8 {
		t.Fatal("x8 invalid input changed output")
	}

	var worst4 [X4Lanes]Element
	copy(worst4[:], worstX[:X4Lanes])
	var valid4, bad4, unchanged4 ElementX4
	valid4.SetElements(&worst4)
	bad4 = valid4
	bad4.limbs[4][3] = 1 << LimbBits
	unchanged4 = valid4
	before4 := unchanged4
	if err := ExperimentalIFMAMultiplyX4(&unchanged4, &valid4, &bad4); !errors.Is(err, errIFMAInputRange) {
		t.Fatalf("x4 invalid-input error=%v want %v", err, errIFMAInputRange)
	}
	if unchanged4 != before4 {
		t.Fatal("x4 invalid input changed output")
	}

	rng := rand.New(rand.NewSource(0x8_4_1f4a_51))
	for round := 0; round < 4096; round++ {
		var x, y [X8Lanes]Element
		for lane := range x {
			x[lane], _ = randomElement(t, rng)
			y[lane], _ = randomElement(t, rng)
		}
		checkHardwareIFMAX8X4(t, round, &x, &y)
	}

	// Isolate every lane so lane mapping, zero lanes, and the two x4 group
	// boundaries are independently exercised.
	for active := 0; active < X8Lanes; active++ {
		var x, y [X8Lanes]Element
		x[active] = elementFromBig(t, big.NewInt(int64(0x100+active)))
		y[active] = elementFromBig(t, big.NewInt(int64(0x200+active)))
		checkHardwareIFMAX8X4(t, 10_000+active, &x, &y)
	}
}

func checkHardwareIFMAX8X4(t *testing.T, round int, x, y *[X8Lanes]Element) {
	t.Helper()
	var vx, vy, got8 ElementX8
	vx.SetElements(x)
	vy.SetElements(y)
	wantRaw8 := ifmaLooseX8Model(&vx, &vy)
	var gotRaw8 IFMALooseX8
	if err := ExperimentalIFMAMultiplyLooseX8(&gotRaw8, &vx, &vy); err != nil {
		t.Fatalf("round %d: raw x8: %v", round, err)
	}
	if gotRaw8 != wantRaw8 {
		t.Fatalf("round %d: raw x8 mismatch\ngot  %#v\nwant %#v", round, gotRaw8, wantRaw8)
	}
	if err := ExperimentalIFMAMultiplyX8(&got8, &vx, &vy); err != nil {
		t.Fatalf("round %d: x8: %v", round, err)
	}
	for lane := range x {
		var want Element
		want.Multiply(&x[lane], &y[lane])
		if got := got8.Lane(lane); got != want {
			t.Fatalf("round %d lane %d: x8 got %#v want %#v", round, lane, got.Limbs(), want.Limbs())
		}
	}

	aliasX8 := vx
	if err := ExperimentalIFMAMultiplyX8(&aliasX8, &aliasX8, &vy); err != nil || aliasX8 != got8 {
		t.Fatalf("round %d: x8 x-alias err=%v", round, err)
	}
	aliasY8 := vy
	if err := ExperimentalIFMAMultiplyX8(&aliasY8, &vx, &aliasY8); err != nil || aliasY8 != got8 {
		t.Fatalf("round %d: x8 y-alias err=%v", round, err)
	}
	var square8 ElementX8
	if err := ExperimentalIFMASquareX8(&square8, &vx); err != nil {
		t.Fatalf("round %d: x8 square: %v", round, err)
	}

	for group := 0; group < 2; group++ {
		var sx, sy [X4Lanes]Element
		copy(sx[:], x[group*X4Lanes:(group+1)*X4Lanes])
		copy(sy[:], y[group*X4Lanes:(group+1)*X4Lanes])
		var vx4, vy4, got4 ElementX4
		vx4.SetElements(&sx)
		vy4.SetElements(&sy)
		wantRaw4 := ifmaLooseX4Model(&vx4, &vy4)
		var gotRaw4 IFMALooseX4
		if err := ExperimentalIFMAMultiplyLooseX4(&gotRaw4, &vx4, &vy4); err != nil {
			t.Fatalf("round %d group %d: raw x4: %v", round, group, err)
		}
		if gotRaw4 != wantRaw4 {
			t.Fatalf("round %d group %d: raw x4 mismatch", round, group)
		}
		if err := ExperimentalIFMAMultiplyX4(&got4, &vx4, &vy4); err != nil {
			t.Fatalf("round %d group %d: x4: %v", round, group, err)
		}
		for lane := 0; lane < X4Lanes; lane++ {
			if got4.Lane(lane) != got8.Lane(group*X4Lanes+lane) {
				t.Fatalf("round %d group %d lane %d: x4/x8 mismatch", round, group, lane)
			}
		}
		aliasX4 := vx4
		if err := ExperimentalIFMAMultiplyX4(&aliasX4, &aliasX4, &vy4); err != nil || aliasX4 != got4 {
			t.Fatalf("round %d group %d: x4 x-alias err=%v", round, group, err)
		}
		aliasY4 := vy4
		if err := ExperimentalIFMAMultiplyX4(&aliasY4, &vx4, &aliasY4); err != nil || aliasY4 != got4 {
			t.Fatalf("round %d group %d: x4 y-alias err=%v", round, group, err)
		}
	}
}

func benchmarkIFMAInputs(b *testing.B) (ElementX8, ElementX8, [2]ElementX4, [2]ElementX4) {
	b.Helper()
	rng := rand.New(rand.NewSource(0x51_8_4))
	var x, y [X8Lanes]Element
	for lane := range x {
		x[lane] = randomBenchmarkElement(rng)
		y[lane] = randomBenchmarkElement(rng)
	}
	var x8, y8 ElementX8
	x8.SetElements(&x)
	y8.SetElements(&y)
	var x4, y4 [2]ElementX4
	for group := range x4 {
		var sx, sy [X4Lanes]Element
		copy(sx[:], x[group*X4Lanes:(group+1)*X4Lanes])
		copy(sy[:], y[group*X4Lanes:(group+1)*X4Lanes])
		x4[group].SetElements(&sx)
		y4[group].SetElements(&sy)
	}
	return x8, y8, x4, y4
}

func randomBenchmarkElement(rng *rand.Rand) Element {
	var encoded [32]byte
	_, _ = rng.Read(encoded[:])
	encoded[31] &= 0x7f
	var out Element
	_, _ = out.SetBytes(encoded[:])
	return out
}

func BenchmarkExperimentalIFMAMultiply(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	x8, y8, x4, y4 := benchmarkIFMAInputs(b)

	b.Run("x8-zmm/kernel-only-u60", func(b *testing.B) {
		var out IFMAProductX8
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ifmaMulRawX8(&out, &x8.limbs, &y8.limbs)
		}
	})
	b.Run("x8-zmm/checked-u60", func(b *testing.B) {
		var out IFMALooseX8
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := ExperimentalIFMAMultiplyLooseX8(&out, &x8, &y8); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("x8-zmm/canonical", func(b *testing.B) {
		var out ElementX8
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := ExperimentalIFMAMultiplyX8(&out, &x8, &y8); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("two-x4-ymm/kernel-only-u60", func(b *testing.B) {
		var out [2]IFMAProductX4
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for group := range out {
				ifmaMulRawX4(&out[group], &x4[group].limbs, &y4[group].limbs)
			}
		}
	})
	b.Run("two-x4-ymm/checked-u60", func(b *testing.B) {
		var out [2]IFMALooseX4
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for group := range out {
				if err := ExperimentalIFMAMultiplyLooseX4(&out[group], &x4[group], &y4[group]); err != nil {
					b.Fatal(err)
				}
			}
		}
	})
	b.Run("two-x4-ymm/canonical", func(b *testing.B) {
		var out [2]ElementX4
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for group := range out {
				if err := ExperimentalIFMAMultiplyX4(&out[group], &x4[group], &y4[group]); err != nil {
					b.Fatal(err)
				}
			}
		}
	})
	b.Run("scalar-oracle-x8", func(b *testing.B) {
		var out ElementX8
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			out.Multiply(&x8, &y8)
		}
	})
}
