package r51x5

import (
	"runtime"
	"testing"
	"unsafe"
)

// ifmaAffineNielsX8 is the three-coordinate form of a cached point. It saves
// one multiply per mixed addition and 25% of the selected table bytes, but its
// cold builder must batch-invert the projective table's Z coordinates.
type ifmaAffineNielsX8 struct {
	YPlusX  IFMAElementX8
	YMinusX IFMAElementX8
	T2D     IFMAElementX8
}

type ifmaAffineNielsVariableWorkspaceX8 struct {
	table    [16]ifmaAffineNielsX8
	prefix   [16]IFMAElementX8
	inverseZ [16]IFMAElementX8
	digits   FixedRadixDigitsX8
	prepared bool
}

func (workspace *ifmaAffineNielsVariableWorkspaceX8) Prepare(base *PointX8) error {
	if !ExperimentalIFMAAvailable() {
		return ErrIFMAUnavailable
	}
	workspace.prepared = false
	var projective ifmaProjectiveNielsGroupedReferenceWorkspaceX8
	if err := projective.Prepare(base); err != nil {
		return err
	}
	workspace.prefix[0] = projective.table.points[0].Z
	for entry := 1; entry < len(projective.table.points); entry++ {
		if err := ifmaMultiplyComposableUncheckedX8(
			&workspace.prefix[entry],
			&workspace.prefix[entry-1],
			&projective.table.points[entry].Z,
		); err != nil {
			return err
		}
	}
	total := workspace.prefix[len(workspace.prefix)-1].Reduced()
	for lane := 0; lane < X8Lanes; lane++ {
		totalLane := total.Lane(lane)
		if totalLane.IsZero() != 0 {
			return errIFMABatchEncodeZeroZ
		}
	}
	var inverseProduct IFMAElementX8
	if err := invertIFMAX8Experiment(&inverseProduct, &workspace.prefix[len(workspace.prefix)-1]); err != nil {
		return err
	}
	for entry := len(projective.table.points) - 1; entry > 0; entry-- {
		if err := ifmaMultiplyComposableUncheckedX8(
			&workspace.inverseZ[entry],
			&inverseProduct,
			&workspace.prefix[entry-1],
		); err != nil {
			return err
		}
		if err := ifmaMultiplyComposableUncheckedX8(
			&inverseProduct,
			&inverseProduct,
			&projective.table.points[entry].Z,
		); err != nil {
			return err
		}
	}
	workspace.inverseZ[0] = inverseProduct

	for entry := range workspace.table {
		source := &projective.table.points[entry]
		inverseZ := &workspace.inverseZ[entry]
		if err := ifmaMultiplyComposableUncheckedX8(&workspace.table[entry].YPlusX, &source.YPlusX, inverseZ); err != nil {
			return err
		}
		if err := ifmaMultiplyComposableUncheckedX8(&workspace.table[entry].YMinusX, &source.YMinusX, inverseZ); err != nil {
			return err
		}
		if err := ifmaMultiplyComposableUncheckedX8(&workspace.table[entry].T2D, &source.T2D, inverseZ); err != nil {
			return err
		}
	}
	workspace.prepared = true
	return nil
}

func (workspace *ifmaAffineNielsVariableWorkspaceX8) Evaluate(out *IFMAPointX8, scalar *[X8Lanes][32]byte, negativeMask, active uint8) (uint8, error) {
	if !workspace.prepared {
		panic("r51x5: affine Niels x8 experiment is not prepared")
	}
	usable := RecodeCanonicalScalarsX8(&workspace.digits, scalar, negativeMask, active, 5)
	acc := identityIFMAPointX8Value()
	if usable == 0 {
		*out = acc
		return 0, nil
	}
	for round := workspace.digits.RoundCount() - 1; round >= 0; round-- {
		if round != workspace.digits.RoundCount()-1 {
			for doubling := 0; doubling < 5; doubling++ {
				if err := ifmaPointDoubleComposableStaticX8(&acc, &acc); err != nil {
					return 0, err
				}
			}
		}
		digit := workspace.digits.Round(round)
		if digit.NonzeroMask&usable == 0 {
			continue
		}
		var selected ifmaAffineNielsX8
		selectIFMAAffineNielsX8(&selected, &workspace.table, digit, usable)
		if err := ifmaPointAddAffineNielsX8(&acc, &acc, &selected); err != nil {
			return 0, err
		}
	}
	*out = acc
	return usable, nil
}

func ifmaPointAddAffineNielsX8(out, point *IFMAPointX8, cached *ifmaAffineNielsX8) error {
	var yMinusX, yPlusX IFMAElementX8
	yMinusX.Subtract(&point.Y, &point.X)
	yPlusX.Add(&point.Y, &point.X)
	var A, B, C, D, E, F, G, H IFMAElementX8
	if err := ifmaMultiplyComposableUncheckedX8(&A, &yMinusX, &cached.YMinusX); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX8(&B, &yPlusX, &cached.YPlusX); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX8(&C, &point.T, &cached.T2D); err != nil {
		return err
	}
	D.Add(&point.Z, &point.Z)
	E.Subtract(&B, &A)
	F.Subtract(&D, &C)
	G.Add(&D, &C)
	H.Add(&B, &A)
	var result IFMAPointX8
	if err := ifmaMultiplyComposableUncheckedX8(&result.X, &E, &F); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX8(&result.Y, &G, &H); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX8(&result.T, &E, &H); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX8(&result.Z, &F, &G); err != nil {
		return err
	}
	*out = result
	return nil
}

func selectIFMAAffineNielsX8(out *ifmaAffineNielsX8, table *[16]ifmaAffineNielsX8, round *RadixRoundX8, active uint8) {
	lookupMask := round.NonzeroMask & active
	negativeMask := round.NegativeMask & lookupMask
	for lane := 0; lane < X8Lanes; lane++ {
		laneMask := uint8(1 << lane)
		if lookupMask&laneMask == 0 {
			setIdentityIFMAAffineNielsLaneX8(out, lane)
			continue
		}
		source := &table[int(round.Magnitude[lane])-1]
		for limb := range modulusLimbs {
			out.YPlusX.limbs[limb][lane] = source.YPlusX.limbs[limb][lane]
			out.YMinusX.limbs[limb][lane] = source.YMinusX.limbs[limb][lane]
			out.T2D.limbs[limb][lane] = source.T2D.limbs[limb][lane]
		}
	}
	for limb := range modulusLimbs {
		for lane := 0; lane < X8Lanes; lane++ {
			if negativeMask&(1<<lane) != 0 {
				out.YPlusX.limbs[limb][lane], out.YMinusX.limbs[limb][lane] =
					out.YMinusX.limbs[limb][lane], out.YPlusX.limbs[limb][lane]
			}
		}
	}
	conditionalNegateIFMAElementX8(&out.T2D, negativeMask)
}

func setIdentityIFMAAffineNielsLaneX8(out *ifmaAffineNielsX8, lane int) {
	for limb := range modulusLimbs {
		out.YPlusX.limbs[limb][lane] = 0
		out.YMinusX.limbs[limb][lane] = 0
		out.T2D.limbs[limb][lane] = 0
	}
	out.YPlusX.limbs[0][lane] = 1
	out.YMinusX.limbs[0][lane] = 1
}

func invertIFMAX8Experiment(z, x *IFMAElementX8) error {
	base := *x
	var x2, x9, x11 IFMAElementX8
	if err := ifmaMultiplyComposableUncheckedX8(&x2, &base, &base); err != nil {
		return err
	}
	if err := repeatedSquareMultiplyIFMAX8Experiment(&x9, &x2, &base, 2); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX8(&x11, &x9, &x2); err != nil {
		return err
	}
	var x5, x10, x20, x40, x50, x100, x200, x250 IFMAElementX8
	if err := repeatedSquareMultiplyIFMAX8Experiment(&x5, &x11, &x9, 1); err != nil {
		return err
	}
	if err := repeatedSquareMultiplyIFMAX8Experiment(&x10, &x5, &x5, 5); err != nil {
		return err
	}
	if err := repeatedSquareMultiplyIFMAX8Experiment(&x20, &x10, &x10, 10); err != nil {
		return err
	}
	if err := repeatedSquareMultiplyIFMAX8Experiment(&x40, &x20, &x20, 20); err != nil {
		return err
	}
	if err := repeatedSquareMultiplyIFMAX8Experiment(&x50, &x40, &x10, 10); err != nil {
		return err
	}
	if err := repeatedSquareMultiplyIFMAX8Experiment(&x100, &x50, &x50, 50); err != nil {
		return err
	}
	if err := repeatedSquareMultiplyIFMAX8Experiment(&x200, &x100, &x100, 100); err != nil {
		return err
	}
	if err := repeatedSquareMultiplyIFMAX8Experiment(&x250, &x200, &x50, 50); err != nil {
		return err
	}
	return repeatedSquareMultiplyIFMAX8Experiment(z, &x250, &x11, 5)
}

func repeatedSquareMultiplyIFMAX8Experiment(out, x, y *IFMAElementX8, count int) error {
	*out = *x
	for index := 0; index < count; index++ {
		if err := ifmaMultiplyComposableUncheckedX8(out, out, out); err != nil {
			return err
		}
	}
	return ifmaMultiplyComposableUncheckedX8(out, out, y)
}

func TestIFMAAffineNielsVariableX8Differential(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	_, variable, _, scalars := fixedBaseCombDSMFixtures(t)
	var projective ifmaProjectiveNielsGroupedReferenceWorkspaceX8
	if err := projective.Prepare(&variable); err != nil {
		t.Fatal(err)
	}
	var affine ifmaAffineNielsVariableWorkspaceX8
	if err := affine.Prepare(&variable); err != nil {
		t.Fatal(err)
	}
	for active := 0; active < 256; active++ {
		for _, negative := range []uint8{0, uint8(active), 0xa5} {
			var got, want IFMAPointX8
			gotMask, gotErr := affine.Evaluate(&got, &scalars, negative, uint8(active))
			wantMask, wantErr := projective.Evaluate(&want, &scalars, negative, uint8(active))
			if gotErr != nil || wantErr != nil {
				t.Fatalf("active=%02x negative=%02x errors=%v/%v", active, negative, gotErr, wantErr)
			}
			gotReduced, wantReduced := got.Reduced(), want.Reduced()
			if gotMask != wantMask || gotReduced.Bytes() != wantReduced.Bytes() {
				t.Fatalf("active=%02x negative=%02x masks=%02x/%02x", active, negative, gotMask, wantMask)
			}
		}
	}
	var out IFMAPointX8
	if allocations := testing.AllocsPerRun(20, func() {
		if err := affine.Prepare(&variable); err != nil {
			panic(err)
		}
		if _, err := affine.Evaluate(&out, &scalars, 0xff, 0xff); err != nil {
			panic(err)
		}
	}); allocations != 0 {
		t.Fatalf("cold prepare+evaluate allocations=%v", allocations)
	}
}

var benchmarkIFMAAffineNielsX8Sink IFMAPointX8

func BenchmarkIFMAAffineNielsVariableX8(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	_, variable, _, scalars := fixedBaseCombDSMFixtures(b)
	var projective ifmaProjectiveNielsGroupedReferenceWorkspaceX8
	if err := projective.Prepare(&variable); err != nil {
		b.Fatal(err)
	}
	var affine ifmaAffineNielsVariableWorkspaceX8
	if err := affine.Prepare(&variable); err != nil {
		b.Fatal(err)
	}
	for _, path := range []string{"prepared-loop", "cold-table+loop"} {
		b.Run("representation=projective-niels/"+path, func(b *testing.B) {
			var out IFMAPointX8
			b.ReportAllocs()
			b.ReportMetric(float64(unsafe.Sizeof(projective)), "workspace-B")
			for i := 0; i < b.N; i++ {
				if path == "cold-table+loop" {
					if err := projective.Prepare(&variable); err != nil {
						b.Fatal(err)
					}
				}
				if _, err := projective.Evaluate(&out, &scalars, 0xff, 0xff); err != nil {
					b.Fatal(err)
				}
			}
			benchmarkIFMAAffineNielsX8Sink = out
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*X8Lanes), "ns/signature")
		})
		b.Run("representation=affine-niels/"+path, func(b *testing.B) {
			var out IFMAPointX8
			b.ReportAllocs()
			b.ReportMetric(float64(unsafe.Sizeof(affine)), "workspace-B")
			for i := 0; i < b.N; i++ {
				if path == "cold-table+loop" {
					if err := affine.Prepare(&variable); err != nil {
						b.Fatal(err)
					}
				}
				if _, err := affine.Evaluate(&out, &scalars, 0xff, 0xff); err != nil {
					b.Fatal(err)
				}
			}
			benchmarkIFMAAffineNielsX8Sink = out
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*X8Lanes), "ns/signature")
		})
	}
}
