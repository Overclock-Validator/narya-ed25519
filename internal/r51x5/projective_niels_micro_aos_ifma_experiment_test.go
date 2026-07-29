package r51x5

import (
	"math/rand"
	"runtime"
	"testing"
	"unsafe"
)

func TestIFMAProjectiveNielsPreSignedMicroAoSStoreTransposeX8(t *testing.T) {
	if runtime.GOARCH == "amd64" && !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	var point IFMAProjectiveNielsX8
	coordinates := [...]*IFMAElementX8{&point.YPlusX, &point.YMinusX, &point.Z, &point.T2D}
	for coordinate, element := range coordinates {
		for limb := range modulusLimbs {
			for lane := 0; lane < X8Lanes; lane++ {
				element.limbs[limb][lane] = uint64(1 + coordinate*1000 + limb*100 + lane)
			}
		}
	}
	var negativeT2D IFMAElementX8
	ifmaNegateComposableUncheckedX8(&negativeT2D, &point.T2D)

	const poison = uint64(0xdeadbeef51a05)
	var got ifmaProjectiveNielsPreSignedMicroAoSTableX8
	for lane := range got {
		for sign := range got[lane] {
			for entry := range got[lane][sign] {
				for limb := range got[lane][sign][entry] {
					got[lane][sign][entry][limb] = [4]uint64{poison, poison, poison, poison}
				}
			}
		}
	}
	want := got
	for entry := range 16 {
		ifmaProjectiveNielsPreSignedMicroAoSStoreTransposeX8(&got, uint64(entry), &point, &negativeT2D)
		for lane := 0; lane < X8Lanes; lane++ {
			for limb := range modulusLimbs {
				want[lane][0][entry][limb] = [4]uint64{
					point.YPlusX.limbs[limb][lane],
					point.YMinusX.limbs[limb][lane],
					point.Z.limbs[limb][lane],
					point.T2D.limbs[limb][lane],
				}
				want[lane][1][entry][limb] = [4]uint64{
					point.YMinusX.limbs[limb][lane],
					point.YPlusX.limbs[limb][lane],
					point.Z.limbs[limb][lane],
					negativeT2D.limbs[limb][lane],
				}
			}
		}
		if got != want {
			t.Fatalf("entry %d transpose mismatch", entry)
		}
	}
}

func storeIFMAProjectiveNielsPreSignedMicroAoSEntryScalarOracleX8(
	table *ifmaProjectiveNielsPreSignedMicroAoSTableX8,
	entry int,
	point *IFMAProjectiveNielsX8,
) {
	var negativeT2D IFMAElementX8
	ifmaNegateComposableUncheckedX8(&negativeT2D, &point.T2D)
	for lane := 0; lane < X8Lanes; lane++ {
		for limb := range modulusLimbs {
			table[lane][0][entry][limb] = [4]uint64{
				point.YPlusX.limbs[limb][lane],
				point.YMinusX.limbs[limb][lane],
				point.Z.limbs[limb][lane],
				point.T2D.limbs[limb][lane],
			}
			table[lane][1][entry][limb] = [4]uint64{
				point.YMinusX.limbs[limb][lane],
				point.YPlusX.limbs[limb][lane],
				point.Z.limbs[limb][lane],
				negativeT2D.limbs[limb][lane],
			}
		}
	}
}

func prepareIFMAProjectiveNielsPreSignedMicroAoSScalarStoreX8(
	workspace *ExperimentalIFMAProjectiveNielsPreSignedMicroAoSVariableBaseWorkspaceX8,
	base *PointX8,
) error {
	if !ExperimentalIFMAAvailable() {
		return ErrIFMAUnavailable
	}
	workspace.prepared = false
	var current IFMAPointX8
	var addWorkspace ifmaPointAddProjectiveNielsScratchX8
	current.SetReduced(base)
	var baseCached IFMAProjectiveNielsX8
	if err := ifmaProjectiveNielsFromPointX8(&baseCached, &current); err != nil {
		return err
	}
	for entry := 0; entry < len(workspace.table[0][0]); entry++ {
		var cached IFMAProjectiveNielsX8
		if entry == 0 {
			cached = baseCached
		} else {
			if err := ifmaProjectiveNielsFromPointX8(&cached, &current); err != nil {
				return err
			}
		}
		storeIFMAProjectiveNielsPreSignedMicroAoSEntryScalarOracleX8(&workspace.table, entry, &cached)
		if entry+1 < len(workspace.table[0][0]) {
			if err := ifmaPointAddProjectiveNielsWorkspaceX8(
				&current,
				&current,
				&baseCached,
				&addWorkspace,
			); err != nil {
				return err
			}
		}
	}
	workspace.prepared = true
	return nil
}

func TestIFMAProjectiveNielsPreSignedMicroAoSTransposePrepareX8(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	_, variable, _, scalars := fixedBaseCombDSMFixtures(t)
	var current, candidate ExperimentalIFMAProjectiveNielsPreSignedMicroAoSVariableBaseWorkspaceX8
	if err := current.Prepare(&variable, 5); err != nil {
		t.Fatal(err)
	}
	if err := prepareIFMAProjectiveNielsPreSignedMicroAoSScalarStoreX8(&candidate, &variable); err != nil {
		t.Fatal(err)
	}
	if candidate.table != current.table {
		t.Fatal("transpose-store prepare differs from scalar-store table")
	}
	var got, want IFMAPointX8
	gotMask, gotErr := candidate.Evaluate(&got, &scalars, 0xa5, 0xff)
	wantMask, wantErr := current.Evaluate(&want, &scalars, 0xa5, 0xff)
	if gotErr != nil || wantErr != nil {
		t.Fatalf("evaluate errors=%v/%v", gotErr, wantErr)
	}
	gotReduced, wantReduced := got.Reduced(), want.Reduced()
	if gotMask != wantMask || gotReduced.Bytes() != wantReduced.Bytes() {
		t.Fatalf("evaluate masks=%02x/%02x", gotMask, wantMask)
	}
}

func TestIFMAProjectiveNielsPreSignedMicroAoSX8RandomMixedOrder(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	rng := rand.New(rand.NewSource(0x51_a05_2026))
	torsion := referenceTorsionPoints(t)
	activeMasks := []uint8{0x01, 0x55, 0xa5, 0xfe, 0xff}
	for round := 0; round < 64; round++ {
		_, base := scalarWindowMixedBasesX8(t, rng, &torsion)
		var scalars [X8Lanes][32]byte
		for lane := range scalars {
			scalars[lane] = randomCanonicalFixedBaseScalar(t, rng)
		}
		var reference ExperimentalIFMAProjectiveNielsVariableBaseWorkspaceX8
		if err := reference.Prepare(&base, 5); err != nil {
			t.Fatal(err)
		}
		var candidate ExperimentalIFMAProjectiveNielsPreSignedMicroAoSVariableBaseWorkspaceX8
		if err := candidate.Prepare(&base, 5); err != nil {
			t.Fatal(err)
		}
		for _, active := range activeMasks {
			negative := uint8(rng.Uint32()) & active
			var got, want IFMAPointX8
			gotMask, gotErr := candidate.Evaluate(&got, &scalars, negative, active)
			wantMask, wantErr := reference.Evaluate(&want, &scalars, negative, active)
			if gotErr != nil || wantErr != nil {
				t.Fatalf("round=%d active=%02x negative=%02x errors=%v/%v", round, active, negative, gotErr, wantErr)
			}
			gotReduced, wantReduced := got.Reduced(), want.Reduced()
			if gotMask != wantMask || gotReduced.Bytes() != wantReduced.Bytes() {
				t.Fatalf("round=%d active=%02x negative=%02x masks=%02x/%02x", round, active, negative, gotMask, wantMask)
			}
		}
	}
}

func TestIFMAProjectiveNielsPreSignedMicroAoSX8PureTorsion(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	torsion := referenceTorsionPoints(t)
	var encoded [X8Lanes][32]byte
	for lane := range encoded {
		copy(encoded[lane][:], torsion[lane].Bytes())
	}
	var base PointX8
	if mask := base.SetBytes(&encoded); mask != 0xff {
		t.Fatalf("torsion decode mask=%02x", mask)
	}
	var scalars [X8Lanes][32]byte
	for lane := range scalars {
		scalars[lane][0] = byte(lane + 1)
	}
	var reference ExperimentalIFMAProjectiveNielsVariableBaseWorkspaceX8
	if err := reference.Prepare(&base, 5); err != nil {
		t.Fatal(err)
	}
	var candidate ExperimentalIFMAProjectiveNielsPreSignedMicroAoSVariableBaseWorkspaceX8
	if err := candidate.Prepare(&base, 5); err != nil {
		t.Fatal(err)
	}
	for _, negative := range []uint8{0, 0x55, 0xff} {
		var got, want IFMAPointX8
		gotMask, gotErr := candidate.Evaluate(&got, &scalars, negative, 0xff)
		wantMask, wantErr := reference.Evaluate(&want, &scalars, negative, 0xff)
		if gotErr != nil || wantErr != nil {
			t.Fatalf("negative=%02x errors=%v/%v", negative, gotErr, wantErr)
		}
		gotReduced, wantReduced := got.Reduced(), want.Reduced()
		if gotMask != wantMask || gotReduced.Bytes() != wantReduced.Bytes() {
			t.Fatalf("negative=%02x masks=%02x/%02x", negative, gotMask, wantMask)
		}
	}
}

func TestIFMAProjectiveNielsMicroAoSX8Differential(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	_, variable, _, scalars := fixedBaseCombDSMFixtures(t)
	var current ExperimentalIFMAProjectiveNielsVariableBaseWorkspaceX8
	if err := current.Prepare(&variable, 5); err != nil {
		t.Fatal(err)
	}
	var candidate ExperimentalIFMAProjectiveNielsMicroAoSVariableBaseWorkspaceX8
	if err := candidate.Prepare(&variable, 5); err != nil {
		t.Fatal(err)
	}
	var preSigned ExperimentalIFMAProjectiveNielsPreSignedMicroAoSVariableBaseWorkspaceX8
	if err := preSigned.Prepare(&variable, 5); err != nil {
		t.Fatal(err)
	}
	for active := 0; active < 256; active++ {
		for _, negative := range []uint8{0, uint8(active), 0xa5, 0xff} {
			var got, gotPreSigned, want IFMAPointX8
			gotMask, gotErr := candidate.Evaluate(&got, &scalars, negative, uint8(active))
			preSignedMask, preSignedErr := preSigned.Evaluate(&gotPreSigned, &scalars, negative, uint8(active))
			wantMask, wantErr := current.Evaluate(&want, &scalars, negative, uint8(active))
			if gotErr != nil || preSignedErr != nil || wantErr != nil {
				t.Fatalf("active=%02x negative=%02x errors=%v/%v/%v", active, negative, gotErr, preSignedErr, wantErr)
			}
			gotReduced, preSignedReduced, wantReduced := got.Reduced(), gotPreSigned.Reduced(), want.Reduced()
			if gotMask != wantMask || gotReduced.Bytes() != wantReduced.Bytes() {
				t.Fatalf("active=%02x negative=%02x masks=%02x/%02x", active, negative, gotMask, wantMask)
			}
			if preSignedMask != wantMask || preSignedReduced.Bytes() != wantReduced.Bytes() {
				t.Fatalf("pre-signed active=%02x negative=%02x masks=%02x/%02x", active, negative, preSignedMask, wantMask)
			}
		}
	}
	var out IFMAPointX8
	if allocations := testing.AllocsPerRun(20, func() {
		if err := candidate.Prepare(&variable, 5); err != nil {
			panic(err)
		}
		if _, err := candidate.Evaluate(&out, &scalars, 0xff, 0xff); err != nil {
			panic(err)
		}
	}); allocations != 0 {
		t.Fatalf("cold prepare+evaluate allocations=%v", allocations)
	}
	if allocations := testing.AllocsPerRun(20, func() {
		if err := preSigned.Prepare(&variable, 5); err != nil {
			panic(err)
		}
		if _, err := preSigned.Evaluate(&out, &scalars, 0xff, 0xff); err != nil {
			panic(err)
		}
	}); allocations != 0 {
		t.Fatalf("pre-signed cold prepare+evaluate allocations=%v", allocations)
	}
}

var benchmarkIFMAProjectiveNielsMicroAoSX8Sink IFMAPointX8
var benchmarkIFMAProjectiveNielsMicroAoSStoreX8Sink ifmaProjectiveNielsPreSignedMicroAoSTableX8

func BenchmarkIFMAProjectiveNielsPreSignedMicroAoSStoreX8(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	_, variable, _, _ := fixedBaseCombDSMFixtures(b)
	var current IFMAPointX8
	current.SetReduced(&variable)
	var point IFMAProjectiveNielsX8
	if err := ifmaProjectiveNielsFromPointX8(&point, &current); err != nil {
		b.Fatal(err)
	}

	b.Run("scalar-store", func(b *testing.B) {
		var table ifmaProjectiveNielsPreSignedMicroAoSTableX8
		b.ReportAllocs()
		for i := range b.N {
			storeIFMAProjectiveNielsPreSignedMicroAoSEntryScalarOracleX8(&table, i&15, &point)
		}
		benchmarkIFMAProjectiveNielsMicroAoSStoreX8Sink = table
	})
	b.Run("transpose-store", func(b *testing.B) {
		var table ifmaProjectiveNielsPreSignedMicroAoSTableX8
		var negativeT2D IFMAElementX8
		b.ReportAllocs()
		for i := range b.N {
			ifmaNegateComposableUncheckedX8(&negativeT2D, &point.T2D)
			ifmaProjectiveNielsPreSignedMicroAoSStoreTransposeX8(&table, uint64(i&15), &point, &negativeT2D)
		}
		benchmarkIFMAProjectiveNielsMicroAoSStoreX8Sink = table
	})
}

func BenchmarkIFMAProjectiveNielsMicroAoSX8(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	_, variable, _, scalars := fixedBaseCombDSMFixtures(b)
	var current ExperimentalIFMAProjectiveNielsVariableBaseWorkspaceX8
	if err := current.Prepare(&variable, 5); err != nil {
		b.Fatal(err)
	}
	var candidate ExperimentalIFMAProjectiveNielsMicroAoSVariableBaseWorkspaceX8
	if err := candidate.Prepare(&variable, 5); err != nil {
		b.Fatal(err)
	}
	var preSigned ExperimentalIFMAProjectiveNielsPreSignedMicroAoSVariableBaseWorkspaceX8
	if err := preSigned.Prepare(&variable, 5); err != nil {
		b.Fatal(err)
	}
	var preSignedScalar ExperimentalIFMAProjectiveNielsPreSignedMicroAoSVariableBaseWorkspaceX8
	if err := prepareIFMAProjectiveNielsPreSignedMicroAoSScalarStoreX8(&preSignedScalar, &variable); err != nil {
		b.Fatal(err)
	}
	for _, path := range []string{"prepared-loop", "cold-table+loop"} {
		b.Run("layout=grouped-soa/"+path, func(b *testing.B) {
			var out IFMAPointX8
			b.ReportAllocs()
			b.ReportMetric(float64(unsafe.Sizeof(current)), "workspace-B")
			for range b.N {
				if path == "cold-table+loop" {
					if err := current.Prepare(&variable, 5); err != nil {
						b.Fatal(err)
					}
				}
				if _, err := current.Evaluate(&out, &scalars, 0xff, 0xff); err != nil {
					b.Fatal(err)
				}
			}
			benchmarkIFMAProjectiveNielsMicroAoSX8Sink = out
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*X8Lanes), "ns/signature")
		})
		b.Run("layout=micro-aos/"+path, func(b *testing.B) {
			var out IFMAPointX8
			b.ReportAllocs()
			b.ReportMetric(float64(unsafe.Sizeof(candidate)), "workspace-B")
			for range b.N {
				if path == "cold-table+loop" {
					if err := candidate.Prepare(&variable, 5); err != nil {
						b.Fatal(err)
					}
				}
				if _, err := candidate.Evaluate(&out, &scalars, 0xff, 0xff); err != nil {
					b.Fatal(err)
				}
			}
			benchmarkIFMAProjectiveNielsMicroAoSX8Sink = out
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*X8Lanes), "ns/signature")
		})
		b.Run("layout=presigned-micro-aos/"+path, func(b *testing.B) {
			var out IFMAPointX8
			b.ReportAllocs()
			b.ReportMetric(float64(unsafe.Sizeof(preSigned)), "workspace-B")
			for range b.N {
				if path == "cold-table+loop" {
					if err := preSigned.Prepare(&variable, 5); err != nil {
						b.Fatal(err)
					}
				}
				if _, err := preSigned.Evaluate(&out, &scalars, 0xff, 0xff); err != nil {
					b.Fatal(err)
				}
			}
			benchmarkIFMAProjectiveNielsMicroAoSX8Sink = out
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*X8Lanes), "ns/signature")
		})
		if path == "cold-table+loop" {
			b.Run("layout=presigned-micro-aos-scalar-store/"+path, func(b *testing.B) {
				var out IFMAPointX8
				b.ReportAllocs()
				b.ReportMetric(float64(unsafe.Sizeof(preSignedScalar)), "workspace-B")
				for range b.N {
					if err := prepareIFMAProjectiveNielsPreSignedMicroAoSScalarStoreX8(
						&preSignedScalar,
						&variable,
					); err != nil {
						b.Fatal(err)
					}
					if _, err := preSignedScalar.Evaluate(&out, &scalars, 0xff, 0xff); err != nil {
						b.Fatal(err)
					}
				}
				benchmarkIFMAProjectiveNielsMicroAoSX8Sink = out
				b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*X8Lanes), "ns/signature")
			})
		}
	}
}
