package r51x5

import (
	"math/rand"
	"runtime"
	"testing"
	"unsafe"
)

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
	}
}
