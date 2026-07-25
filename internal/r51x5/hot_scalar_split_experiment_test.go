package r51x5

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"testing"
	"unsafe"

	edwardsref "github.com/Overclock-Validator/narya/internal/edwards25519"
)

// This file is a test-only gate for a narrow hot-key hypothesis. For a
// canonical challenge k, write
//
//	k = k0 + 2^64*k1 + 2^128*k2 + 2^192*k3.
//
// Packing A, [2^64]A, [2^128]A, and [2^192]A into the four signature-parallel
// lanes lets the existing r51 IFMA point layer evaluate the four 64-bit scalar
// multiplications with one short shared doubling chain. The four resulting
// points are then summed in two IFMA point-add stages. This is exact integer
// arithmetic, including when A has a torsion component: -k is represented by
// signed digits and is never replaced by L-k.
//
// Nothing in this file is reachable from verifier dispatch or the public key
// cache. In particular, the benchmarks deliberately distinguish the compact
// 640-byte shifted-base record from a much larger ready window table.

const hotScalarSplitAdmissionDoubles = 3 * 64

type hotScalarSplitFixture struct {
	a         Point
	aRef      *edwardsref.Point
	bases     PointX4
	scalar    [32]byte
	chunks    [X4Lanes][32]byte
	oneActive PointX4
}

func newHotScalarSplitFixture(tb testing.TB) hotScalarSplitFixture {
	tb.Helper()

	// Use a prime-order point plus an order-eight point. A pure prime-order
	// fixture would not detect an accidental replacement of exact -k by L-k.
	var primeScalarBytes [32]byte
	primeScalarBytes[0] = 37
	primeScalar, err := edwardsref.NewScalar().SetCanonicalBytes(primeScalarBytes[:])
	if err != nil {
		tb.Fatal(err)
	}
	prime := new(edwardsref.Point).ScalarBaseMult(primeScalar)
	torsionEncoding, err := hex.DecodeString(pointTestEncodings[10])
	if err != nil {
		tb.Fatal(err)
	}
	torsion, err := new(edwardsref.Point).SetBytes(torsionEncoding)
	if err != nil {
		tb.Fatal(err)
	}
	aRef := new(edwardsref.Point).Add(prime, torsion)

	var a Point
	if _, err := a.SetBytes(aRef.Bytes()); err != nil {
		tb.Fatalf("decode mixed-order A: %v", err)
	}

	rng := rand.New(rand.NewSource(0x51486f74))
	scalar := randomCanonicalFixedBaseScalar(tb, rng)
	var fixture hotScalarSplitFixture
	fixture.a = a
	fixture.aRef = aRef
	fixture.bases = hotScalarSplitShiftedBases(&a)
	fixture.scalar = scalar
	hotScalarSplitChunks(&fixture.chunks, &scalar)

	oneActivePoints := [X4Lanes]Point{
		a,
		*NewIdentityPoint(),
		*NewIdentityPoint(),
		*NewIdentityPoint(),
	}
	fixture.oneActive.SetPoints(&oneActivePoints)
	return fixture
}

// hotScalarSplitShiftedBases is the proposed compact cache payload. PointX4
// is exactly 640 bytes on the supported 64-bit targets. The caller must still
// retain the exact original 32 public-key bytes for hashing and cache-key
// equality; those bytes are reported separately by the footprint gate.
func hotScalarSplitShiftedBases(a *Point) PointX4 {
	var points [X4Lanes]Point
	points[0] = *a
	for lane := 1; lane < X4Lanes; lane++ {
		points[lane] = points[lane-1]
		for doubling := 0; doubling < 64; doubling++ {
			fixedBasePointDouble(&points[lane], &points[lane])
		}
	}
	var result PointX4
	result.SetPoints(&points)
	return result
}

func hotScalarSplitChunks(out *[X4Lanes][32]byte, scalar *[32]byte) {
	*out = [X4Lanes][32]byte{}
	for lane := 0; lane < X4Lanes; lane++ {
		copy(out[lane][:8], scalar[lane*8:(lane+1)*8])
	}
}

// hotScalarSplitEvaluateModel exercises the same dynamic signed recoder,
// table selection, and short loop through the reduced scalar point oracle. It
// runs on every platform, independently of the AVX-512 gate.
func hotScalarSplitEvaluateModel(out *Point, bases *PointX4, chunks *[X4Lanes][32]byte, radixBits uint) uint8 {
	var table FullTableX4
	buildFullTableX4Into(&table, bases, radixBits)

	var digits heeaFixedRadixDigitsX4
	usable := recodeHEEAFixedScalarsX4(&digits, chunks, 0x0f, 0x0f, radixBits)
	acc := identityPointX4Value()
	for round := int(digits.count) - 1; round >= 0; round-- {
		if round != int(digits.count)-1 {
			for doubling := uint(0); doubling < radixBits; doubling++ {
				acc.Double(&acc)
			}
		}
		digit := &digits.rounds[round]
		if digit.NonzeroMask&usable == 0 {
			continue
		}
		var selected PointX4
		SelectFullTableX4Public(&selected, &table, digit, usable)
		acc.Add(&acc, &selected)
	}

	points := acc.Points()
	var pair01, pair23, total Point
	fixedBasePointAdd(&pair01, &points[0], &points[1])
	fixedBasePointAdd(&pair23, &points[2], &points[3])
	fixedBasePointAdd(&total, &pair01, &pair23)
	*out = total
	return usable
}

// hotScalarSplitEvaluateIFMAX4 evaluates the four short signed scalar
// multiplications from a ready table, then performs a SIMD horizontal point
// sum. Storage is radix-specific so a radix-16 experiment does not retain and
// clear the unused radix-32/radix-64 capacity.
func hotScalarSplitEvaluateIFMAX4[Storage ifmaFullTableStorageX4](out *IFMAPointX4, table *ifmaFullTableX4[Storage], chunks *[X4Lanes][32]byte, radixBits uint) (uint8, error) {
	var digits heeaFixedRadixDigitsX4
	usable := recodeHEEAFixedScalarsX4(&digits, chunks, 0x0f, 0x0f, radixBits)
	acc := identityIFMAPointX4Value()
	for round := int(digits.count) - 1; round >= 0; round-- {
		if round != int(digits.count)-1 {
			for doubling := uint(0); doubling < radixBits; doubling++ {
				if err := ifmaPointDoubleComposableStaticX4(&acc, &acc); err != nil {
					return 0, err
				}
			}
		}
		digit := &digits.rounds[round]
		if digit.NonzeroMask&usable == 0 {
			continue
		}
		var selected IFMAPointX4
		selectIFMAFullTableX4PublicUncheckedNoAlias(&selected, table, digit, usable)
		if err := ifmaPointAddComposableStaticX4(&acc, &acc, &selected); err != nil {
			return 0, err
		}
	}
	if err := hotScalarSplitHorizontalSumIFMAX4(out, &acc); err != nil {
		return 0, err
	}
	return usable, nil
}

// hotScalarSplitEvaluateCurrentIFMAX4 is the exact comparison schedule used
// by the current warm, one-active-lane arbitrary-base path: a canonical
// 252-bit scalar, the full fixed round count, and exact signed -k digits.
func hotScalarSplitEvaluateCurrentIFMAX4[Storage ifmaFullTableStorageX4](out *IFMAPointX4, table *ifmaFullTableX4[Storage], scalar *[32]byte, radixBits uint) (uint8, error) {
	var scalars [X4Lanes][32]byte
	scalars[0] = *scalar
	var digits FixedRadixDigitsX4
	usable := RecodeCanonicalScalarsX4(&digits, &scalars, 0x01, 0x01, radixBits)
	acc := identityIFMAPointX4Value()
	for round := digits.RoundCount() - 1; round >= 0; round-- {
		if round != digits.RoundCount()-1 {
			for doubling := uint(0); doubling < radixBits; doubling++ {
				if err := ifmaPointDoubleComposableStaticX4(&acc, &acc); err != nil {
					return 0, err
				}
			}
		}
		digit := digits.Round(round)
		if digit.NonzeroMask&usable == 0 {
			continue
		}
		var selected IFMAPointX4
		selectIFMAFullTableX4PublicUncheckedNoAlias(&selected, table, digit, usable)
		if err := ifmaPointAddComposableStaticX4(&acc, &acc, &selected); err != nil {
			return 0, err
		}
	}
	*out = acc
	return usable, nil
}

// hotScalarSplitHorizontalSumIFMAX4 computes the sum of the four point lanes
// without leaving the composable IFMA domain. The first add forms (0+1) and
// (2+3); the second add combines those pairs. Every output lane contains the
// same total, so callers can consume lane zero at the final scalar boundary.
func hotScalarSplitHorizontalSumIFMAX4(out, points *IFMAPointX4) error {
	var swapped, pairs, swappedPairs IFMAPointX4
	hotScalarSplitPermutePointX4(&swapped, points, [X4Lanes]uint8{1, 0, 3, 2})
	if err := ifmaPointAddComposableStaticX4(&pairs, points, &swapped); err != nil {
		return err
	}
	hotScalarSplitPermutePointX4(&swappedPairs, &pairs, [X4Lanes]uint8{2, 3, 0, 1})
	return ifmaPointAddComposableStaticX4(out, &pairs, &swappedPairs)
}

func hotScalarSplitPermutePointX4(out, point *IFMAPointX4, permutation [X4Lanes]uint8) {
	hotScalarSplitPermuteElementX4(&out.X, &point.X, permutation)
	hotScalarSplitPermuteElementX4(&out.Y, &point.Y, permutation)
	hotScalarSplitPermuteElementX4(&out.Z, &point.Z, permutation)
	hotScalarSplitPermuteElementX4(&out.T, &point.T, permutation)
}

func hotScalarSplitPermuteElementX4(out, element *IFMAElementX4, permutation [X4Lanes]uint8) {
	source := *element
	for limb := range source.limbs {
		for lane, sourceLane := range permutation {
			out.limbs[limb][lane] = source.limbs[limb][sourceLane]
		}
	}
}

func TestExperimentalHotScalarSplitShiftedBases(t *testing.T) {
	fixture := newHotScalarSplitFixture(t)
	want := new(edwardsref.Point).Set(fixture.aRef)
	for lane := 0; lane < X4Lanes; lane++ {
		if lane != 0 {
			for doubling := 0; doubling < 64; doubling++ {
				want.Add(want, want)
			}
		}
		got := fixture.bases.Lane(lane)
		assertScalarPointMatchesReference(t, fmt.Sprintf("shifted base lane %d", lane), &got, want)
	}
}

func TestExperimentalHotScalarSplitExactMixedOrder(t *testing.T) {
	fixture := newHotScalarSplitFixture(t)
	tests := hotScalarSplitBoundaryScalars(t)
	rng := rand.New(rand.NewSource(0x5145ca1a))
	for i := 0; i < 32; i++ {
		tests = append(tests, randomCanonicalFixedBaseScalar(t, rng))
	}

	for index := range tests {
		scalarBytes := tests[index]
		scalar, err := edwardsref.NewScalar().SetCanonicalBytes(scalarBytes[:])
		if err != nil {
			t.Fatalf("case %d scalar: %v", index, err)
		}
		want := new(edwardsref.Point).ScalarMult(scalar, fixture.aRef)
		want.Negate(want)

		var chunks [X4Lanes][32]byte
		hotScalarSplitChunks(&chunks, &scalarBytes)
		for _, radixBits := range []uint{4, 5, 6} {
			var model Point
			if mask := hotScalarSplitEvaluateModel(&model, &fixture.bases, &chunks, radixBits); mask != 0x0f {
				t.Fatalf("case %d radix %d model mask=%02x", index, 1<<radixBits, mask)
			}
			assertScalarPointMatchesReference(t, fmt.Sprintf("case %d radix %d model", index, 1<<radixBits), &model, want)

			if ExperimentalIFMAAvailable() {
				hotScalarSplitAssertHardware(t, radixBits, &fixture.bases, &chunks, want)
			}
		}
	}
}

func TestExperimentalHotScalarSplitDoesNotUseLMinusK(t *testing.T) {
	fixture := newHotScalarSplitFixture(t)
	var one [32]byte
	one[0] = 1
	oneScalar, err := edwardsref.NewScalar().SetCanonicalBytes(one[:])
	if err != nil {
		t.Fatal(err)
	}
	wantExact := new(edwardsref.Point).ScalarMult(oneScalar, fixture.aRef)
	wantExact.Negate(wantExact)

	lMinusOne := scalarOrderBytes
	decrementLittleEndian(&lMinusOne)
	lMinusOneScalar, err := edwardsref.NewScalar().SetCanonicalBytes(lMinusOne[:])
	if err != nil {
		t.Fatal(err)
	}
	wrongModuloRepresentative := new(edwardsref.Point).ScalarMult(lMinusOneScalar, fixture.aRef)
	if string(wantExact.Bytes()) == string(wrongModuloRepresentative.Bytes()) {
		t.Fatal("mixed-order fixture failed to distinguish exact -1 from L-1")
	}

	var chunks [X4Lanes][32]byte
	hotScalarSplitChunks(&chunks, &one)
	for _, radixBits := range []uint{4, 5, 6} {
		var got Point
		if mask := hotScalarSplitEvaluateModel(&got, &fixture.bases, &chunks, radixBits); mask != 0x0f {
			t.Fatalf("radix %d mask=%02x", 1<<radixBits, mask)
		}
		assertScalarPointMatchesReference(t, fmt.Sprintf("radix %d exact -1", 1<<radixBits), &got, wantExact)
		if gotBytes := got.Bytes(); string(gotBytes[:]) == string(wrongModuloRepresentative.Bytes()) {
			t.Fatalf("radix %d used the modulo-L representative", 1<<radixBits)
		}
	}
}

func TestExperimentalHotScalarSplitFootprint(t *testing.T) {
	const rawKeyBytes = uintptr(32)
	if got, want := unsafe.Sizeof(PointX4{}), uintptr(640); got != want {
		t.Fatalf("shifted-base payload=%d want %d", got, want)
	}
	tests := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"radix16", unsafe.Sizeof(IFMAFullTableRadix16X4{}), 5136},
		{"radix32", unsafe.Sizeof(IFMAFullTableX4{}), 10256},
		{"radix64", unsafe.Sizeof(IFMAFullTableRadix64X4{}), 20496},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.got != test.want {
				t.Fatalf("ready table=%d want %d", test.got, test.want)
			}
		})
	}
	if got, want := unsafe.Sizeof(PointX4{})+rawKeyBytes, uintptr(672); got != want {
		t.Fatalf("shifted bases plus exact raw key=%d want %d", got, want)
	}
}

func TestExperimentalHotScalarSplitZeroAllocations(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("requires AVX-512 IFMA")
	}
	fixture := newHotScalarSplitFixture(t)
	hotScalarSplitZeroAllocWidth[ifmaFullTableStorageRadix16X4](t, 4, &fixture)
	hotScalarSplitZeroAllocWidth[ifmaFullTableStorageRadix32X4](t, 5, &fixture)
	hotScalarSplitZeroAllocWidth[ifmaFullTableStorageRadix64X4](t, 6, &fixture)
}

func hotScalarSplitZeroAllocWidth[Storage ifmaFullTableStorageX4](t *testing.T, radixBits uint, fixture *hotScalarSplitFixture) {
	t.Helper()
	var splitTable, currentTable ifmaFullTableX4[Storage]
	if err := buildIFMAFullTableX4Into(&splitTable, &fixture.bases, radixBits); err != nil {
		t.Fatal(err)
	}
	if err := buildIFMAFullTableX4Into(&currentTable, &fixture.oneActive, radixBits); err != nil {
		t.Fatal(err)
	}
	var out IFMAPointX4
	if allocs := testing.AllocsPerRun(20, func() {
		if _, err := hotScalarSplitEvaluateCurrentIFMAX4(&out, &currentTable, &fixture.scalar, radixBits); err != nil {
			panic(err)
		}
	}); allocs != 0 {
		t.Fatalf("radix %d current allocations=%v", 1<<radixBits, allocs)
	}
	if allocs := testing.AllocsPerRun(20, func() {
		if _, err := hotScalarSplitEvaluateIFMAX4(&out, &splitTable, &fixture.chunks, radixBits); err != nil {
			panic(err)
		}
	}); allocs != 0 {
		t.Fatalf("radix %d ready allocations=%v", 1<<radixBits, allocs)
	}
	if allocs := testing.AllocsPerRun(20, func() {
		if err := buildIFMAFullTableX4Into(&splitTable, &fixture.bases, radixBits); err != nil {
			panic(err)
		}
		if _, err := hotScalarSplitEvaluateIFMAX4(&out, &splitTable, &fixture.chunks, radixBits); err != nil {
			panic(err)
		}
	}); allocs != 0 {
		t.Fatalf("radix %d build+evaluate allocations=%v", 1<<radixBits, allocs)
	}
}

func hotScalarSplitAssertHardware(t *testing.T, radixBits uint, bases *PointX4, chunks *[X4Lanes][32]byte, want *edwardsref.Point) {
	t.Helper()
	switch radixBits {
	case 4:
		hotScalarSplitAssertHardwareWidth[ifmaFullTableStorageRadix16X4](t, radixBits, bases, chunks, want)
	case 5:
		hotScalarSplitAssertHardwareWidth[ifmaFullTableStorageRadix32X4](t, radixBits, bases, chunks, want)
	case 6:
		hotScalarSplitAssertHardwareWidth[ifmaFullTableStorageRadix64X4](t, radixBits, bases, chunks, want)
	default:
		t.Fatalf("unsupported radix bits %d", radixBits)
	}
}

func hotScalarSplitAssertHardwareWidth[Storage ifmaFullTableStorageX4](t *testing.T, radixBits uint, bases *PointX4, chunks *[X4Lanes][32]byte, want *edwardsref.Point) {
	t.Helper()
	var table ifmaFullTableX4[Storage]
	if err := buildIFMAFullTableX4Into(&table, bases, radixBits); err != nil {
		t.Fatal(err)
	}
	var got IFMAPointX4
	if mask, err := hotScalarSplitEvaluateIFMAX4(&got, &table, chunks, radixBits); err != nil || mask != 0x0f {
		t.Fatalf("radix %d hardware mask=%02x err=%v", 1<<radixBits, mask, err)
	}
	reduced := got.Reduced()
	for lane := 0; lane < X4Lanes; lane++ {
		point := reduced.Lane(lane)
		assertScalarPointMatchesReference(t, fmt.Sprintf("radix %d horizontal lane %d", 1<<radixBits, lane), &point, want)
	}
}

func hotScalarSplitBoundaryScalars(t *testing.T) [][32]byte {
	t.Helper()
	values := make([][32]byte, 0, 12)
	values = append(values, [32]byte{})
	var one [32]byte
	one[0] = 1
	values = append(values, one)
	var low64Max [32]byte
	for index := 0; index < 8; index++ {
		low64Max[index] = 0xff
	}
	values = append(values, low64Max)
	for _, bit := range []int{64, 128, 192} {
		var value [32]byte
		value[bit/8] = 1
		values = append(values, value)
	}
	// Exercise a carry out of the top radix-16 and radix-32 digit in each
	// full 64-bit chunk while remaining below L.
	for chunk := 0; chunk < 3; chunk++ {
		var value [32]byte
		for index := chunk * 8; index < (chunk+1)*8; index++ {
			value[index] = 0xff
		}
		values = append(values, value)
	}
	lMinusOne := scalarOrderBytes
	decrementLittleEndian(&lMinusOne)
	values = append(values, lMinusOne)
	return values
}

var (
	benchmarkHotScalarSplitIFMASink IFMAPointX4
	benchmarkHotScalarSplitBases    PointX4
	benchmarkHotScalarSplitMask     uint8
)

func BenchmarkExperimentalHotScalarSplitAX4(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skip("requires AVX-512 IFMA")
	}
	fixture := newHotScalarSplitFixture(b)
	hotScalarSplitBenchmarkWidth[ifmaFullTableStorageRadix16X4](b, 4, &fixture, unsafe.Sizeof(IFMAFullTableRadix16X4{}))
	hotScalarSplitBenchmarkWidth[ifmaFullTableStorageRadix32X4](b, 5, &fixture, unsafe.Sizeof(IFMAFullTableX4{}))
	hotScalarSplitBenchmarkWidth[ifmaFullTableStorageRadix64X4](b, 6, &fixture, unsafe.Sizeof(IFMAFullTableRadix64X4{}))
}

func hotScalarSplitBenchmarkWidth[Storage ifmaFullTableStorageX4](b *testing.B, radixBits uint, fixture *hotScalarSplitFixture, tableBytes uintptr) {
	b.Helper()
	name := fmt.Sprintf("radix=%d", 1<<radixBits)
	var splitTable, currentTable ifmaFullTableX4[Storage]
	if err := buildIFMAFullTableX4Into(&splitTable, &fixture.bases, radixBits); err != nil {
		b.Fatal(err)
	}
	if err := buildIFMAFullTableX4Into(&currentTable, &fixture.oneActive, radixBits); err != nil {
		b.Fatal(err)
	}

	b.Run(name+"/current-one-active-ready-table", func(b *testing.B) {
		var out IFMAPointX4
		b.ReportAllocs()
		b.ReportMetric(float64(tableBytes), "ready-table-B")
		b.ReportMetric(float64(fixedScalarRoundCount(radixBits)), "rounds/op")
		b.ResetTimer()
		for iteration := 0; iteration < b.N; iteration++ {
			mask, err := hotScalarSplitEvaluateCurrentIFMAX4(&out, &currentTable, &fixture.scalar, radixBits)
			if err != nil {
				b.Fatal(err)
			}
			benchmarkHotScalarSplitMask = mask
		}
		benchmarkHotScalarSplitIFMASink = out
	})

	b.Run(name+"/split4-base-cache-build-table", func(b *testing.B) {
		var out IFMAPointX4
		b.ReportAllocs()
		b.ReportMetric(float64(unsafe.Sizeof(PointX4{})), "base-cache-B")
		b.ReportMetric(float64(unsafe.Sizeof(PointX4{})+32), "base-cache+raw-key-B")
		b.ReportMetric(float64(tableBytes), "scratch-table-B")
		b.ResetTimer()
		for iteration := 0; iteration < b.N; iteration++ {
			if err := buildIFMAFullTableX4Into(&splitTable, &fixture.bases, radixBits); err != nil {
				b.Fatal(err)
			}
			mask, err := hotScalarSplitEvaluateIFMAX4(&out, &splitTable, &fixture.chunks, radixBits)
			if err != nil {
				b.Fatal(err)
			}
			benchmarkHotScalarSplitMask = mask
		}
		benchmarkHotScalarSplitIFMASink = out
	})

	b.Run(name+"/split4-ready-table", func(b *testing.B) {
		var out IFMAPointX4
		b.ReportAllocs()
		b.ReportMetric(float64(tableBytes), "ready-table-B")
		b.ReportMetric(float64(tableBytes+32), "ready-table+raw-key-B")
		b.ResetTimer()
		for iteration := 0; iteration < b.N; iteration++ {
			mask, err := hotScalarSplitEvaluateIFMAX4(&out, &splitTable, &fixture.chunks, radixBits)
			if err != nil {
				b.Fatal(err)
			}
			benchmarkHotScalarSplitMask = mask
		}
		benchmarkHotScalarSplitIFMASink = out
	})
}

func BenchmarkExperimentalHotScalarSplitAdmissionX4(b *testing.B) {
	fixture := newHotScalarSplitFixture(b)
	b.Run("shifted-bases-192-doubles", func(b *testing.B) {
		b.ReportAllocs()
		b.ReportMetric(hotScalarSplitAdmissionDoubles, "doublings/op")
		b.ReportMetric(float64(unsafe.Sizeof(PointX4{})), "base-cache-B")
		b.ResetTimer()
		for iteration := 0; iteration < b.N; iteration++ {
			benchmarkHotScalarSplitBases = hotScalarSplitShiftedBases(&fixture.a)
		}
	})
	if !ExperimentalIFMAAvailable() {
		return
	}
	hotScalarSplitBenchmarkAdmissionWidth[ifmaFullTableStorageRadix16X4](b, 4, &fixture, unsafe.Sizeof(IFMAFullTableRadix16X4{}))
	hotScalarSplitBenchmarkAdmissionWidth[ifmaFullTableStorageRadix32X4](b, 5, &fixture, unsafe.Sizeof(IFMAFullTableX4{}))
	hotScalarSplitBenchmarkAdmissionWidth[ifmaFullTableStorageRadix64X4](b, 6, &fixture, unsafe.Sizeof(IFMAFullTableRadix64X4{}))
}

func hotScalarSplitBenchmarkAdmissionWidth[Storage ifmaFullTableStorageX4](b *testing.B, radixBits uint, fixture *hotScalarSplitFixture, tableBytes uintptr) {
	b.Helper()
	b.Run(fmt.Sprintf("shifted-bases+ready-table/radix=%d", 1<<radixBits), func(b *testing.B) {
		var table ifmaFullTableX4[Storage]
		b.ReportAllocs()
		b.ReportMetric(hotScalarSplitAdmissionDoubles, "doublings/op")
		b.ReportMetric(float64(tableBytes), "ready-table-B")
		b.ReportMetric(float64(tableBytes+32), "ready-table+raw-key-B")
		b.ResetTimer()
		for iteration := 0; iteration < b.N; iteration++ {
			bases := hotScalarSplitShiftedBases(&fixture.a)
			if err := buildIFMAFullTableX4Into(&table, &bases, radixBits); err != nil {
				b.Fatal(err)
			}
			benchmarkHotScalarSplitBases = bases
		}
	})
}
