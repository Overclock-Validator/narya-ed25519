package r51x5

import (
	"errors"
	"fmt"
	"runtime"
	"testing"
)

func TestIFMADecodeComposableModelEveryMaskAndPermissiveAliasX8(t *testing.T) {
	vectors := decode2IFMAEdgeEncodings(t)
	var encoded [X8Lanes][32]byte
	copy(encoded[:], vectors[:X8Lanes])
	for active := 0; active < 1<<X8Lanes; active++ {
		checkIFMADecodeComposableX8(t, fmt.Sprintf("active=%02x", active), &encoded, uint8(active), false)
	}
	for start := 0; start < len(vectors); start += X8Lanes {
		for lane := range encoded {
			encoded[lane] = vectors[(start+lane)%len(vectors)]
		}
		checkIFMADecodeComposableX8(t, fmt.Sprintf("alias-start=%d", start), &encoded, 0xff, false)
	}
}

func TestIFMADecodeComposableHardwareEveryMaskX8(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	vectors := decode2IFMAEdgeEncodings(t)
	var encoded [X8Lanes][32]byte
	copy(encoded[:], vectors[:X8Lanes])
	for active := 0; active < 1<<X8Lanes; active++ {
		checkIFMADecodeComposableX8(t, fmt.Sprintf("active=%02x", active), &encoded, uint8(active), true)
	}
}

func TestIFMADecodeComposableErrorAtomicX8(t *testing.T) {
	generator := newGeneratorEncodingForTest(t)
	var encoded [X8Lanes][32]byte
	for lane := range encoded {
		encoded[lane] = generator
	}
	var sentinel IFMAPointX8
	sentinel.Y = ifmaCurve2DX8
	sentinel.Z = ifmaCurve2DX8
	countOps := decode2IFMAOpsX8{}
	var counted IFMAPointX8
	if _, err := decodeComposableIFMAX8(&counted, &encoded, 0xff, &countOps); err != nil {
		t.Fatal(err)
	}
	for _, failAt := range []int{1, countOps.calls / 2, countOps.calls} {
		got := sentinel
		ops := decode2IFMAOpsX8{failAt: failAt}
		valid, err := decodeComposableIFMAX8(&got, &encoded, 0xff, &ops)
		if !errors.Is(err, errIFMAOutputRange) || valid != 0 {
			t.Fatalf("failure=%d returned (%02x,%v)", failAt, valid, err)
		}
		if got != sentinel {
			t.Fatalf("failure=%d changed output", failAt)
		}
	}
}

func TestIFMADecodeComposableZeroAllocX8(t *testing.T) {
	generator := newGeneratorEncodingForTest(t)
	var encoded [X8Lanes][32]byte
	for lane := range encoded {
		encoded[lane] = generator
	}
	var out IFMAPointX8
	if allocs := testing.AllocsPerRun(20, func() {
		if _, err := decodeComposableIFMAModelX8(&out, &encoded, 0xff); err != nil {
			panic(err)
		}
	}); allocs != 0 {
		t.Fatalf("model allocated %.2f objects", allocs)
	}
	if ExperimentalIFMAAvailable() {
		if allocs := testing.AllocsPerRun(20, func() {
			if _, err := ExperimentalIFMADecodeComposableX8(&out, &encoded, 0xff); err != nil {
				panic(err)
			}
		}); allocs != 0 {
			t.Fatalf("hardware API allocated %.2f objects", allocs)
		}
	}
}

func TestIFMADecodeComposablePrepareDifferentialX8(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	generator := newGeneratorEncodingForTest(t)
	var encoded [X8Lanes][32]byte
	for lane := range encoded {
		encoded[lane] = generator
	}
	var reduced PointX8
	reducedMask, err := ExperimentalIFMADecodeX8(&reduced, &encoded, 0xff)
	if err != nil {
		t.Fatal(err)
	}
	var composable IFMAPointX8
	composableMask, err := ExperimentalIFMADecodeComposableX8(&composable, &encoded, 0xff)
	if err != nil {
		t.Fatal(err)
	}
	if reducedMask != composableMask {
		t.Fatalf("decode masks=%02x/%02x", reducedMask, composableMask)
	}

	var reducedWorkspace, composableWorkspace ExperimentalIFMAProjectiveNielsPreSignedMicroAoSVariableBaseWorkspaceX8
	if err := reducedWorkspace.Prepare(&reduced, 5); err != nil {
		t.Fatal(err)
	}
	if err := composableWorkspace.PrepareComposable(&composable, 5); err != nil {
		t.Fatal(err)
	}
	var scalars [X8Lanes][32]byte
	for lane := range scalars {
		scalars[lane][0] = byte(lane + 1)
	}
	var got, want IFMAPointX8
	gotMask, gotErr := composableWorkspace.Evaluate(&got, &scalars, 0xa5, composableMask)
	wantMask, wantErr := reducedWorkspace.Evaluate(&want, &scalars, 0xa5, reducedMask)
	if gotErr != nil || wantErr != nil {
		t.Fatalf("evaluate errors=%v/%v", gotErr, wantErr)
	}
	gotReduced, wantReduced := got.Reduced(), want.Reduced()
	if gotMask != wantMask || gotReduced.Bytes() != wantReduced.Bytes() {
		t.Fatalf("evaluate masks=%02x/%02x", gotMask, wantMask)
	}
}

func checkIFMADecodeComposableX8(
	t *testing.T,
	label string,
	encoded *[X8Lanes][32]byte,
	active uint8,
	hardware bool,
) {
	t.Helper()
	var got IFMAPointX8
	var gotMask uint8
	var err error
	if hardware {
		gotMask, err = ExperimentalIFMADecodeComposableX8(&got, encoded, active)
	} else {
		gotMask, err = decodeComposableIFMAModelX8(&got, encoded, active)
	}
	if err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	want, wantMask := referenceDecodeIFMAX8(encoded, active)
	gotReduced := got.Reduced()
	if gotMask != wantMask || gotReduced != want {
		t.Fatalf("%s: mask=%02x want=%02x or point differs", label, gotMask, wantMask)
	}
	if !isIFMAElementX8(&got.X) || !isIFMAElementX8(&got.Y) ||
		!isIFMAElementX8(&got.Z) || !isIFMAElementX8(&got.T) {
		t.Fatalf("%s: output escaped composable u52 range", label)
	}
}

var benchmarkIFMADecodeComposableX8Sink IFMAPointX8

func BenchmarkExperimentalIFMADecodeComposableX8(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	generator := newGeneratorEncodingForTest(b)
	var encoded [X8Lanes][32]byte
	for lane := range encoded {
		encoded[lane] = generator
	}
	b.Run("reduced-output+import", func(b *testing.B) {
		var reduced PointX8
		var imported IFMAPointX8
		b.ReportAllocs()
		for range b.N {
			if _, err := ExperimentalIFMADecodeX8(&reduced, &encoded, 0xff); err != nil {
				b.Fatal(err)
			}
			imported.SetReduced(&reduced)
		}
		benchmarkIFMADecodeComposableX8Sink = imported
	})
	b.Run("composable-output", func(b *testing.B) {
		var composable IFMAPointX8
		b.ReportAllocs()
		for range b.N {
			if _, err := ExperimentalIFMADecodeComposableX8(&composable, &encoded, 0xff); err != nil {
				b.Fatal(err)
			}
		}
		benchmarkIFMADecodeComposableX8Sink = composable
	})
	b.Run("reduced-output+table", func(b *testing.B) {
		var reduced PointX8
		var workspace ExperimentalIFMAProjectiveNielsPreSignedMicroAoSVariableBaseWorkspaceX8
		b.ReportAllocs()
		for range b.N {
			if _, err := ExperimentalIFMADecodeX8(&reduced, &encoded, 0xff); err != nil {
				b.Fatal(err)
			}
			if err := workspace.Prepare(&reduced, 5); err != nil {
				b.Fatal(err)
			}
		}
		benchmarkIFMADecodeComposableX8Sink.SetReduced(&reduced)
	})
	b.Run("composable-output+table", func(b *testing.B) {
		var composable IFMAPointX8
		var workspace ExperimentalIFMAProjectiveNielsPreSignedMicroAoSVariableBaseWorkspaceX8
		b.ReportAllocs()
		for range b.N {
			if _, err := ExperimentalIFMADecodeComposableX8(&composable, &encoded, 0xff); err != nil {
				b.Fatal(err)
			}
			if err := workspace.PrepareComposable(&composable, 5); err != nil {
				b.Fatal(err)
			}
		}
		benchmarkIFMADecodeComposableX8Sink = composable
	})
}
