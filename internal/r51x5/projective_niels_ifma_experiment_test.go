package r51x5

import (
	"runtime"
	"testing"
	"unsafe"
)

// ifmaProjectiveNielsX8 is a test-only table entry for a projective cached
// Edwards point. Precomputing Y+X, Y-X, and 2dT removes two field
// multiplications from every variable-base addition while retaining Z and
// therefore avoiding an inversion during the cold table build.
type ifmaProjectiveNielsX8 struct {
	YPlusX  IFMAElementX8
	YMinusX IFMAElementX8
	Z       IFMAElementX8
	T2D     IFMAElementX8
}

type ifmaProjectiveNielsTableX8 struct {
	points [16]ifmaProjectiveNielsX8
}

type ifmaProjectiveNielsVariableWorkspaceX8 struct {
	table    ifmaProjectiveNielsTableX8
	digits   FixedRadixDigitsX8
	prepared bool
}

func ifmaProjectiveNielsFromPointX8(out *ifmaProjectiveNielsX8, point *IFMAPointX8) error {
	var result ifmaProjectiveNielsX8
	result.YPlusX.Add(&point.Y, &point.X)
	result.YMinusX.Subtract(&point.Y, &point.X)
	result.Z = point.Z
	if err := ifmaMultiplyComposableUncheckedX8(&result.T2D, &point.T, &ifmaCurve2DX8); err != nil {
		return err
	}
	*out = result
	return nil
}

func ifmaPointAddProjectiveNielsX8(out, point *IFMAPointX8, cached *ifmaProjectiveNielsX8) error {
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
	if err := ifmaMultiplyComposableUncheckedX8(&D, &point.Z, &cached.Z); err != nil {
		return err
	}
	D.Add(&D, &D)
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

func (workspace *ifmaProjectiveNielsVariableWorkspaceX8) Prepare(base *PointX8) error {
	if !ExperimentalIFMAAvailable() {
		return ErrIFMAUnavailable
	}
	workspace.prepared = false
	var current IFMAPointX8
	current.SetReduced(base)
	if err := ifmaProjectiveNielsFromPointX8(&workspace.table.points[0], &current); err != nil {
		return err
	}
	baseCached := workspace.table.points[0]
	for entry := 1; entry < len(workspace.table.points); entry++ {
		if err := ifmaPointAddProjectiveNielsX8(&current, &current, &baseCached); err != nil {
			return err
		}
		if err := ifmaProjectiveNielsFromPointX8(&workspace.table.points[entry], &current); err != nil {
			return err
		}
	}
	workspace.prepared = true
	return nil
}

func (workspace *ifmaProjectiveNielsVariableWorkspaceX8) Evaluate(out *IFMAPointX8, scalar *[X8Lanes][32]byte, negativeMask, active uint8) (uint8, error) {
	if !workspace.prepared {
		panic("r51x5: projective Niels experiment is not prepared")
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
		var selected ifmaProjectiveNielsX8
		selectIFMAProjectiveNielsX8(&selected, &workspace.table, digit, usable)
		if err := ifmaPointAddProjectiveNielsX8(&acc, &acc, &selected); err != nil {
			return 0, err
		}
	}
	*out = acc
	return usable, nil
}

func selectIFMAProjectiveNielsX8(out *ifmaProjectiveNielsX8, table *ifmaProjectiveNielsTableX8, round *RadixRoundX8, active uint8) {
	lookupMask := round.NonzeroMask & active
	negativeMask := round.NegativeMask & lookupMask
	for lane := 0; lane < X8Lanes; lane++ {
		laneMask := uint8(1 << lane)
		if lookupMask&laneMask == 0 {
			setIdentityIFMAProjectiveNielsLaneX8(out, lane)
			continue
		}
		source := &table.points[int(round.Magnitude[lane])-1]
		for limb := range modulusLimbs {
			out.YPlusX.limbs[limb][lane] = source.YPlusX.limbs[limb][lane]
			out.YMinusX.limbs[limb][lane] = source.YMinusX.limbs[limb][lane]
			out.Z.limbs[limb][lane] = source.Z.limbs[limb][lane]
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

func setIdentityIFMAProjectiveNielsLaneX8(out *ifmaProjectiveNielsX8, lane int) {
	for limb := range modulusLimbs {
		out.YPlusX.limbs[limb][lane] = 0
		out.YMinusX.limbs[limb][lane] = 0
		out.Z.limbs[limb][lane] = 0
		out.T2D.limbs[limb][lane] = 0
	}
	out.YPlusX.limbs[0][lane] = 1
	out.YMinusX.limbs[0][lane] = 1
	out.Z.limbs[0][lane] = 1
}

func TestIFMAProjectiveNielsVariableX8Differential(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	_, variable, _, scalars := fixedBaseCombDSMFixtures(t)
	var current ExperimentalIFMAVariableBaseWorkspaceX8
	if err := current.Prepare(&variable, 5); err != nil {
		t.Fatal(err)
	}
	var niels ifmaProjectiveNielsVariableWorkspaceX8
	if err := niels.Prepare(&variable); err != nil {
		t.Fatal(err)
	}
	for active := 0; active < 256; active++ {
		for _, negative := range []uint8{0, uint8(active), 0xa5} {
			var got, want IFMAPointX8
			gotMask, gotErr := niels.Evaluate(&got, &scalars, negative, uint8(active))
			wantMask, wantErr := current.Evaluate(&want, &scalars, negative, uint8(active))
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
		if err := niels.Prepare(&variable); err != nil {
			panic(err)
		}
		if _, err := niels.Evaluate(&out, &scalars, 0xff, 0xff); err != nil {
			panic(err)
		}
	}); allocations != 0 {
		t.Fatalf("cold prepare+evaluate allocations=%v", allocations)
	}
}

var benchmarkIFMAProjectiveNielsX8Sink IFMAPointX8

func BenchmarkIFMAProjectiveNielsVariableX8(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	_, variable, _, scalars := fixedBaseCombDSMFixtures(b)
	var current ExperimentalIFMAVariableBaseWorkspaceX8
	if err := current.Prepare(&variable, 5); err != nil {
		b.Fatal(err)
	}
	var niels ifmaProjectiveNielsVariableWorkspaceX8
	if err := niels.Prepare(&variable); err != nil {
		b.Fatal(err)
	}

	for _, path := range []string{"prepared-loop", "cold-table+loop"} {
		b.Run("representation=extended/"+path, func(b *testing.B) {
			var out IFMAPointX8
			b.ReportAllocs()
			b.ReportMetric(float64(unsafe.Sizeof(current)), "workspace-B")
			for i := 0; i < b.N; i++ {
				if path == "cold-table+loop" {
					if err := current.Prepare(&variable, 5); err != nil {
						b.Fatal(err)
					}
				}
				if _, err := current.Evaluate(&out, &scalars, 0xff, 0xff); err != nil {
					b.Fatal(err)
				}
			}
			benchmarkIFMAProjectiveNielsX8Sink = out
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*X8Lanes), "ns/signature")
		})
		b.Run("representation=projective-niels/"+path, func(b *testing.B) {
			var out IFMAPointX8
			b.ReportAllocs()
			b.ReportMetric(float64(unsafe.Sizeof(niels)), "workspace-B")
			for i := 0; i < b.N; i++ {
				if path == "cold-table+loop" {
					if err := niels.Prepare(&variable); err != nil {
						b.Fatal(err)
					}
				}
				if _, err := niels.Evaluate(&out, &scalars, 0xff, 0xff); err != nil {
					b.Fatal(err)
				}
			}
			benchmarkIFMAProjectiveNielsX8Sink = out
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*X8Lanes), "ns/signature")
		})
	}
}
