package r51x5

import (
	"runtime"
	"testing"
	"unsafe"
)

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
	for active := 0; active < 256; active++ {
		for _, negative := range []uint8{0, uint8(active), 0xa5, 0xff} {
			var got, want IFMAPointX8
			gotMask, gotErr := candidate.Evaluate(&got, &scalars, negative, uint8(active))
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
		if err := candidate.Prepare(&variable, 5); err != nil {
			panic(err)
		}
		if _, err := candidate.Evaluate(&out, &scalars, 0xff, 0xff); err != nil {
			panic(err)
		}
	}); allocations != 0 {
		t.Fatalf("cold prepare+evaluate allocations=%v", allocations)
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
	}
}
