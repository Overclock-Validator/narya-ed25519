package r51x5

import (
	"math/rand"
	"runtime"
	"testing"
)

func TestExperimentalFixedBaseStage2TailX8Differential(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	base, _ := fixedBaseGenerator(t)
	table := BuildExperimentalFixedBaseCombTable(&base, 8)
	rng := rand.New(rand.NewSource(0xb451_7a11_0008))
	for iteration := 0; iteration < 512; iteration++ {
		var scalars [X8Lanes][32]byte
		for lane := range scalars {
			scalars[lane] = randomCanonicalFixedBaseScalar(t, rng)
		}
		active := uint8(rng.Uint32())
		var want, got IFMAPointX8
		wantMask, err := fixedBaseCombScalarMultSeparateX8(&want, table, &scalars, active)
		if err != nil {
			t.Fatal(err)
		}
		gotMask, err := ExperimentalIFMAFixedBaseCombScalarMultX8(&got, table, &scalars, active)
		if err != nil {
			t.Fatal(err)
		}
		if gotMask != wantMask || got.Reduced() != want.Reduced() {
			t.Fatalf("iteration %d active=%02x: fixed-base tail mismatch", iteration, active)
		}
	}
}

func BenchmarkExperimentalFixedBaseStage2TailX8(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	base, _ := fixedBaseGenerator(b)
	table := BuildExperimentalFixedBaseCombTable(&base, 8)
	rng := rand.New(rand.NewSource(0xb451_7a11_0008))
	var scalars [X8Lanes][32]byte
	for lane := range scalars {
		scalars[lane] = randomCanonicalFixedBaseScalar(b, rng)
	}

	b.Run("separate", func(b *testing.B) {
		var out IFMAPointX8
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := fixedBaseCombScalarMultSeparateX8(&out, table, &scalars, 0xff); err != nil {
				b.Fatal(err)
			}
		}
		benchmarkFixedBaseCombIFMAPointX8 = out
	})
	b.Run("tail", func(b *testing.B) {
		var out IFMAPointX8
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := ExperimentalIFMAFixedBaseCombScalarMultX8(&out, table, &scalars, 0xff); err != nil {
				b.Fatal(err)
			}
		}
		benchmarkFixedBaseCombIFMAPointX8 = out
	})
}

func addFixedBaseIFMACachedWorkspaceSeparateX8(
	out, point *IFMAPointX8,
	cached *fixedBaseIFMACachedX8,
	workspace *fixedBaseIFMAAddScratchX8,
) error {
	ifmaSubtractComposableUncheckedX8(&workspace.yMinusX, &point.Y, &point.X)
	ifmaAddComposableUncheckedX8(&workspace.yPlusX, &point.Y, &point.X)
	stage2 := &workspace.stage2
	ifmaMulRawX8(&stage2[0], &workspace.yMinusX.limbs, &cached.YMinusX.limbs)
	ifmaMulRawX8(&stage2[1], &workspace.yPlusX.limbs, &cached.YPlusX.limbs)
	ifmaMulRawX8(&stage2[2], &point.T.limbs, &cached.T2D.limbs)
	stage2[3] = IFMAProductX8(point.Z.limbs)
	ifmaNielsStage2X8(stage2)
	ifmaPointFinalProductsUncheckedX8(out, &stage2[0])
	return nil
}

func fixedBaseCombScalarMultSeparateX8(
	out *IFMAPointX8,
	table *ExperimentalFixedBaseCombTable,
	scalars *[X8Lanes][32]byte,
	active uint8,
) (uint8, error) {
	var digits fixedBaseDigitsX8
	usable := recodeFixedBaseScalarsX8(&digits, scalars, active, uint(table.radixBits))
	acc := identityIFMAPointX8Value()
	var doubleWorkspace ifmaPointDoubleWorkspaceX8
	var addWorkspace fixedBaseIFMAAddScratchX8
	if usable == 0 {
		*out = acc
		return 0, nil
	}
	for position := 0; position < int(table.positions); position++ {
		round := 2*position + 1
		if round >= int(digits.count) || digits.rounds[round].NonzeroMask&usable == 0 {
			continue
		}
		var selected fixedBaseIFMACachedX8
		selectFixedBaseIFMACachedUncheckedX8(&selected, table, position, &digits.rounds[round], usable)
		if err := addFixedBaseIFMACachedWorkspaceSeparateX8(&acc, &acc, &selected, &addWorkspace); err != nil {
			return 0, err
		}
	}
	for doubling := uint8(0); doubling < table.radixBits; doubling++ {
		if err := ifmaPointDoubleComposableWorkspaceStaticX8(&acc, &acc, &doubleWorkspace); err != nil {
			return 0, err
		}
	}
	for position := 0; position < int(table.positions); position++ {
		round := 2 * position
		if digits.rounds[round].NonzeroMask&usable == 0 {
			continue
		}
		var selected fixedBaseIFMACachedX8
		selectFixedBaseIFMACachedUncheckedX8(&selected, table, position, &digits.rounds[round], usable)
		if err := addFixedBaseIFMACachedWorkspaceSeparateX8(&acc, &acc, &selected, &addWorkspace); err != nil {
			return 0, err
		}
	}
	*out = acc
	return usable, nil
}
