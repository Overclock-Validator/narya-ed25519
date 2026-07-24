package r51x5

import (
	"errors"
	"fmt"
	"testing"
)

func TestIFMADecodeModelEveryMaskAndPermissiveAlias(t *testing.T) {
	vectors := decode2IFMAEdgeEncodings(t)
	var encoded8 [X8Lanes][32]byte
	copy(encoded8[:], vectors[:X8Lanes])
	for active := 0; active < 1<<X8Lanes; active++ {
		checkIFMADecodeModelX8(t, fmt.Sprintf("active=%02x", active), &encoded8, uint8(active))
	}
	for start := 0; start < len(vectors); start += X8Lanes {
		for lane := range encoded8 {
			encoded8[lane] = vectors[(start+lane)%len(vectors)]
		}
		checkIFMADecodeModelX8(t, fmt.Sprintf("alias-start=%d", start), &encoded8, 0xff)
	}

	var encoded4 [X4Lanes][32]byte
	copy(encoded4[:], encoded8[:X4Lanes])
	for active := 0; active < 1<<X4Lanes; active++ {
		checkIFMADecodeModelX4(t, fmt.Sprintf("active=%x", active), &encoded4, uint8(active))
	}
}

func TestIFMADecodeErrorLeavesOutputUnchanged(t *testing.T) {
	generator := newGeneratorEncodingForTest(t)
	var encoded8 [X8Lanes][32]byte
	for lane := range encoded8 {
		encoded8[lane] = generator
	}
	var sentinel8 PointX8
	if sentinel8.SetBytes(&encoded8) != 0xff {
		t.Fatal("sentinel x8 decode failed")
	}
	countOps8 := decode2IFMAOpsX8{}
	var counted8 PointX8
	if _, err := decodeIFMAX8(&counted8, &encoded8, 0xff, &countOps8); err != nil {
		t.Fatal(err)
	}
	for _, failAt := range []int{1, countOps8.calls / 2, countOps8.calls} {
		for _, unchecked := range []bool{false, true} {
			got := sentinel8
			ops := decode2IFMAOpsX8{uncheckedInputs: unchecked, failAt: failAt}
			valid, err := decodeIFMAX8(&got, &encoded8, 0xff, &ops)
			if !errors.Is(err, errIFMAOutputRange) || valid != 0 {
				t.Fatalf("x8 unchecked=%v failure=%d returned (%02x,%v)", unchecked, failAt, valid, err)
			}
			if got != sentinel8 {
				t.Fatalf("x8 unchecked=%v failure=%d changed output", unchecked, failAt)
			}
		}
	}

	var encoded4 [X4Lanes][32]byte
	copy(encoded4[:], encoded8[:X4Lanes])
	var sentinel4 PointX4
	if sentinel4.SetBytes(&encoded4) != 0x0f {
		t.Fatal("sentinel x4 decode failed")
	}
	countOps4 := decode2IFMAOpsX4{}
	var counted4 PointX4
	if _, err := decodeIFMAX4(&counted4, &encoded4, 0x0f, &countOps4); err != nil {
		t.Fatal(err)
	}
	for _, failAt := range []int{1, countOps4.calls / 2, countOps4.calls} {
		for _, unchecked := range []bool{false, true} {
			got := sentinel4
			ops := decode2IFMAOpsX4{uncheckedInputs: unchecked, failAt: failAt}
			valid, err := decodeIFMAX4(&got, &encoded4, 0x0f, &ops)
			if !errors.Is(err, errIFMAOutputRange) || valid != 0 {
				t.Fatalf("x4 unchecked=%v failure=%d returned (%x,%v)", unchecked, failAt, valid, err)
			}
			if got != sentinel4 {
				t.Fatalf("x4 unchecked=%v failure=%d changed output", unchecked, failAt)
			}
		}
	}
}

func TestIFMADecodeUnavailableLeavesOutputUnchanged(t *testing.T) {
	if ExperimentalIFMAAvailable() {
		t.Skip("requires a target without the complete IFMA feature set")
	}
	var encoded8 [X8Lanes][32]byte
	want8 := *NewIdentityPointX8()
	got8 := want8
	valid8, err := ExperimentalIFMADecodeX8(&got8, &encoded8, 0xff)
	if !errors.Is(err, ErrIFMAUnavailable) || valid8 != 0 || got8 != want8 {
		t.Fatalf("x8 unavailable result=(%02x,%v), changed=%v", valid8, err, got8 != want8)
	}

	var encoded4 [X4Lanes][32]byte
	want4 := *NewIdentityPointX4()
	got4 := want4
	valid4, err := ExperimentalIFMADecodeX4(&got4, &encoded4, 0x0f)
	if !errors.Is(err, ErrIFMAUnavailable) || valid4 != 0 || got4 != want4 {
		t.Fatalf("x4 unavailable result=(%x,%v), changed=%v", valid4, err, got4 != want4)
	}
}

func TestIFMADecodeZeroAlloc(t *testing.T) {
	generator := newGeneratorEncodingForTest(t)
	var encoded8 [X8Lanes][32]byte
	for lane := range encoded8 {
		encoded8[lane] = generator
	}
	var out8 PointX8
	if allocs := testing.AllocsPerRun(20, func() {
		if _, err := decodeIFMAModelX8(&out8, &encoded8, 0xff); err != nil {
			panic(err)
		}
	}); allocs != 0 {
		t.Fatalf("x8 model allocated %.2f objects", allocs)
	}

	var encoded4 [X4Lanes][32]byte
	copy(encoded4[:], encoded8[:X4Lanes])
	var out4 PointX4
	if allocs := testing.AllocsPerRun(20, func() {
		if _, err := decodeIFMAModelX4(&out4, &encoded4, 0x0f); err != nil {
			panic(err)
		}
	}); allocs != 0 {
		t.Fatalf("x4 model allocated %.2f objects", allocs)
	}

	if ExperimentalIFMAAvailable() {
		if allocs := testing.AllocsPerRun(20, func() {
			if _, err := ExperimentalIFMADecodeX8(&out8, &encoded8, 0xff); err != nil {
				panic(err)
			}
		}); allocs != 0 {
			t.Fatalf("x8 hardware API allocated %.2f objects", allocs)
		}
		if allocs := testing.AllocsPerRun(20, func() {
			if _, err := ExperimentalIFMADecodeX4(&out4, &encoded4, 0x0f); err != nil {
				panic(err)
			}
		}); allocs != 0 {
			t.Fatalf("x4 hardware API allocated %.2f objects", allocs)
		}
	}
}

func TestIFMADecodeHardwareEveryMaskMatchesReference(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("requires AVX-512 IFMA")
	}
	vectors := decode2IFMAEdgeEncodings(t)
	var encoded8 [X8Lanes][32]byte
	copy(encoded8[:], vectors[:X8Lanes])
	for active := 0; active < 1<<X8Lanes; active++ {
		var got PointX8
		gotMask, err := ExperimentalIFMADecodeX8(&got, &encoded8, uint8(active))
		if err != nil {
			t.Fatal(err)
		}
		want, wantMask := referenceDecodeIFMAX8(&encoded8, uint8(active))
		if gotMask != wantMask || got != want {
			t.Fatalf("x8 active=%02x hardware differs from reference", active)
		}
	}

	var encoded4 [X4Lanes][32]byte
	copy(encoded4[:], encoded8[:X4Lanes])
	for active := 0; active < 1<<X4Lanes; active++ {
		var got PointX4
		gotMask, err := ExperimentalIFMADecodeX4(&got, &encoded4, uint8(active))
		if err != nil {
			t.Fatal(err)
		}
		want, wantMask := referenceDecodeIFMAX4(&encoded4, uint8(active))
		if gotMask != wantMask || got != want {
			t.Fatalf("x4 active=%x hardware differs from reference", active)
		}
	}
}

func checkIFMADecodeModelX8(t *testing.T, label string, encoded *[X8Lanes][32]byte, active uint8) {
	t.Helper()
	var got PointX8
	gotMask, err := decodeIFMAModelX8(&got, encoded, active)
	if err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	want, wantMask := referenceDecodeIFMAX8(encoded, active)
	if gotMask != wantMask || got != want {
		t.Fatalf("%s: model mask=%02x want=%02x or point differs", label, gotMask, wantMask)
	}
	if !IsReducedX8(got.X.limbs) || !IsReducedX8(got.Y.limbs) || !IsReducedX8(got.Z.limbs) || !IsReducedX8(got.T.limbs) {
		t.Fatalf("%s: model output is not reduced", label)
	}
}

func checkIFMADecodeModelX4(t *testing.T, label string, encoded *[X4Lanes][32]byte, active uint8) {
	t.Helper()
	var got PointX4
	gotMask, err := decodeIFMAModelX4(&got, encoded, active)
	if err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	want, wantMask := referenceDecodeIFMAX4(encoded, active)
	if gotMask != wantMask || got != want {
		t.Fatalf("%s: model mask=%x want=%x or point differs", label, gotMask, wantMask)
	}
	if !IsReducedX4(got.X.limbs) || !IsReducedX4(got.Y.limbs) || !IsReducedX4(got.Z.limbs) || !IsReducedX4(got.T.limbs) {
		t.Fatalf("%s: model output is not reduced", label)
	}
}

func referenceDecodeIFMAX8(encoded *[X8Lanes][32]byte, active uint8) (PointX8, uint8) {
	result := NewIdentityPointX8()
	var valid uint8
	for lane := 0; lane < X8Lanes; lane++ {
		if active&(1<<lane) == 0 {
			continue
		}
		var point Point
		if _, err := point.SetBytes(encoded[lane][:]); err == nil {
			result.SetLane(lane, &point)
			valid |= 1 << lane
		}
	}
	return *result, valid
}

func referenceDecodeIFMAX4(encoded *[X4Lanes][32]byte, active uint8) (PointX4, uint8) {
	result := NewIdentityPointX4()
	var valid uint8
	active &= 0x0f
	for lane := 0; lane < X4Lanes; lane++ {
		if active&(1<<lane) == 0 {
			continue
		}
		var point Point
		if _, err := point.SetBytes(encoded[lane][:]); err == nil {
			result.SetLane(lane, &point)
			valid |= 1 << lane
		}
	}
	return *result, valid
}

var (
	benchmarkIFMADecodeOneX4Point PointX4
	benchmarkIFMADecodeOneX4Mask  uint8
)

// BenchmarkExperimentalIFMADecodeOneX4 supplies the single-A side of the
// paired-decode crossover measurement. Keep its fixture and active mask equal
// to BenchmarkExperimentalIFMADecode2NoT/x4/paired-interleaved/active=4 so
// their difference measures the marginal overlapped R work.
func BenchmarkExperimentalIFMADecodeOneX4(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skip("requires AVX-512 IFMA")
	}
	generator := newGeneratorEncodingForTest(b)
	var encoded [X4Lanes][32]byte
	for lane := range encoded {
		encoded[lane] = generator
		encoded[lane][31] ^= byte(lane&1) << 7
	}
	b.ReportAllocs()
	var point PointX4
	var valid uint8
	for iteration := 0; iteration < b.N; iteration++ {
		var err error
		valid, err = ExperimentalIFMADecodeX4(&point, &encoded, 0x0f)
		if err != nil {
			b.Fatal(err)
		}
	}
	benchmarkIFMADecodeOneX4Point = point
	benchmarkIFMADecodeOneX4Mask = valid
}
