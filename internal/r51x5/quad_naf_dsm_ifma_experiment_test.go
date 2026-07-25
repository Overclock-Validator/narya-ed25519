package r51x5

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"testing"
	"unsafe"
)

// The width-5 variable-base/width-8 fixed-base NAF schedule below mirrors the
// mature generic verifier's public-scalar schedule. The coordinate-parallel
// vector orientation is independent experimental work with acknowledged
// curve25519-dalek/curve25519-voi prior art; see NOTICE.

// quadNAFTable5X4 holds exactly the eight positive odd multiples needed by a
// width-5 NAF. Signed selection is applied from this positive table in the
// public-scalar loop, matching the mature table shape rather than doubling
// the cache footprint with a second copy of every entry.
type quadNAFTable5X4 struct {
	positive [8]quadPackedCachedPointX4
}

// quadNAFTable8X4 is the fixed-base counterpart. Its 64 positive odd
// multiples are prepared outside the cold-A benchmark, as they would be for
// the process-wide Ed25519 generator table in a complete verifier.
type quadNAFTable8X4 struct {
	positive [64]quadPackedCachedPointX4
}

func buildQuadNAFEntriesX4(
	positive []quadPackedCachedPointX4,
	base *Point,
	ops quadDSMOperationsX4,
) error {
	if len(positive) == 0 {
		panic("r51x5: invalid quad NAF table storage")
	}

	current := new(quadPackedPointX4).setReduced(base)
	if err := quadCachePackedPointX4(&positive[0], current, ops); err != nil {
		return err
	}

	// The NAF table is P, 3P, 5P, ... . Build 2P once, cache it once, and
	// advance the projective current point by that cached addend.
	twice := *current
	if err := ops.double(&twice, &twice); err != nil {
		return err
	}
	var twiceCached quadPackedCachedPointX4
	if err := quadCachePackedPointX4(&twiceCached, &twice, ops); err != nil {
		return err
	}
	for entry := 1; entry < len(positive); entry++ {
		if err := ops.addCached(current, current, &twiceCached); err != nil {
			return err
		}
		if err := quadCachePackedPointX4(&positive[entry], current, ops); err != nil {
			return err
		}
	}
	return nil
}

func buildQuadNAFTable5X4(out *quadNAFTable5X4, base *Point, ops quadDSMOperationsX4) error {
	return buildQuadNAFEntriesX4(out.positive[:], base, ops)
}

func buildQuadNAFTable8X4(out *quadNAFTable8X4, base *Point, ops quadDSMOperationsX4) error {
	return buildQuadNAFEntriesX4(out.positive[:], base, ops)
}

func selectQuadNAFEntryX4(
	negative *quadPackedCachedPointX4,
	positive []quadPackedCachedPointX4,
	digit int8,
) *quadPackedCachedPointX4 {
	if digit == 0 || digit&1 == 0 {
		panic("r51x5: invalid quad NAF digit")
	}
	index := int(digit)
	if index < 0 {
		index = -index
	}
	index /= 2
	if index >= len(positive) {
		panic("r51x5: quad NAF digit exceeds table")
	}
	if digit < 0 {
		quadNegateCachedPointX4(negative, &positive[index])
		return negative
	}
	return &positive[index]
}

// recodeQuadCanonicalNAFX4 computes a width-w non-adjacent form directly
// from a canonical Ed25519 scalar encoding. The fifth zero word makes the
// cross-word window at the top explicit and prevents an edge read special
// case. This is exact integer recoding; it never reduces modulo l.
func recodeQuadCanonicalNAFX4(out *[256]int8, scalar *[32]byte, width uint) bool {
	*out = [256]int8{}
	if width < 2 || width > 8 {
		panic("r51x5: quad NAF width must be between 2 and 8")
	}
	if !canonicalScalarBytes(scalar) {
		return false
	}

	var words [5]uint64
	for index := 0; index < 4; index++ {
		words[index] = binary.LittleEndian.Uint64(scalar[index*8:])
	}
	radix := uint64(1 << width)
	mask := radix - 1
	for position, carry := uint(0), uint64(0); position < 256; {
		word := position / 64
		bit := position % 64
		var buffer uint64
		if bit < 64-width {
			buffer = words[word] >> bit
		} else {
			buffer = words[word]>>bit | words[word+1]<<(64-bit)
		}
		window := carry + buffer&mask
		if window&1 == 0 {
			position++
			continue
		}
		if window < radix/2 {
			carry = 0
			out[position] = int8(window)
		} else {
			carry = 1
			out[position] = int8(window) - int8(radix)
		}
		position += width
	}
	return true
}

// evaluateQuadNAFVerifyX4 computes the cofactorless verification side
// [s]B-[k]A with exact signed-integer semantics. In particular, it negates
// the width-5 digits rather than replacing -k with l-k; that distinction is
// observable for mixed-order public keys.
func evaluateQuadNAFVerifyX4(
	out *quadPackedPointX4,
	aTable *quadNAFTable5X4,
	bTable *quadNAFTable8X4,
	s, k *[32]byte,
	ops quadDSMOperationsX4,
) (bool, error) {
	var aNAF, bNAF [256]int8
	valid := recodeQuadCanonicalNAFX4(&aNAF, k, 5)
	valid = recodeQuadCanonicalNAFX4(&bNAF, s, 8) && valid
	acc := quadPackedIdentityValueX4()
	if !valid {
		*out = acc
		return false, nil
	}

	high := 255
	for ; high >= 0 && aNAF[high] == 0 && bNAF[high] == 0; high-- {
	}
	for bit := high; bit >= 0; bit-- {
		// This retains the mature NAF schedule's initial identity doubling.
		// It is algebraically redundant, but keeping the schedule aligned makes
		// the first hardware comparison easier to interpret.
		if err := ops.double(&acc, &acc); err != nil {
			return false, err
		}
		if aNAF[bit] != 0 {
			var negative quadPackedCachedPointX4
			selected := selectQuadNAFEntryX4(&negative, aTable.positive[:], -aNAF[bit])
			if err := ops.addCached(&acc, &acc, selected); err != nil {
				return false, err
			}
		}
		if bNAF[bit] != 0 {
			var negative quadPackedCachedPointX4
			selected := selectQuadNAFEntryX4(&negative, bTable.positive[:], bNAF[bit])
			if err := ops.addCached(&acc, &acc, selected); err != nil {
				return false, err
			}
		}
	}
	*out = acc
	return true, nil
}

func TestExperimentalCoordinateParallelNAFVerifyX4(t *testing.T) {
	fixture := newQuadDSMFixtureX4(t)
	modelOps := quadDSMOperationsX4{}
	var modelA quadNAFTable5X4
	var modelB quadNAFTable8X4
	if err := buildQuadNAFTable5X4(&modelA, &fixture.a, modelOps); err != nil {
		t.Fatal(err)
	}
	if err := buildQuadNAFTable8X4(&modelB, &fixture.b, modelOps); err != nil {
		t.Fatal(err)
	}

	// Include zero, l-1, and dense random canonical scalars. The public key
	// fixture is mixed-order, so every successful comparison also checks that
	// -k was interpreted as an integer rather than silently reduced to l-k.
	var scalarPairs [66][2][32]byte
	scalarPairs[1][0] = scalarOrderBytes
	scalarPairs[1][1] = scalarOrderBytes
	decrementLittleEndianX4Test(&scalarPairs[1][0])
	decrementLittleEndianX4Test(&scalarPairs[1][1])
	rng := rand.New(rand.NewSource(0x514e4146))
	for index := 2; index < len(scalarPairs); index++ {
		_, _ = rng.Read(scalarPairs[index][0][:])
		_, _ = rng.Read(scalarPairs[index][1][:])
		// Values below 2^252 are strictly below l and therefore canonical.
		scalarPairs[index][0][31] &= 0x0f
		scalarPairs[index][1][31] &= 0x0f
	}

	var hardwareA quadNAFTable5X4
	var hardwareB quadNAFTable8X4
	hardware := ExperimentalIFMAAvailable()
	if hardware {
		hardwareOps := quadDSMOperationsX4{hardware: true}
		if err := buildQuadNAFTable5X4(&hardwareA, &fixture.a, hardwareOps); err != nil {
			t.Fatal(err)
		}
		if err := buildQuadNAFTable8X4(&hardwareB, &fixture.b, hardwareOps); err != nil {
			t.Fatal(err)
		}
	}

	for index := range scalarPairs {
		var scalars FixedDSMScalarsX4
		scalars[0][0] = scalarPairs[index][0]
		scalars[1][0] = scalarPairs[index][1]
		want := quadDSMReferenceScalarsX4(&fixture, &scalars)

		var model quadPackedPointX4
		valid, err := evaluateQuadNAFVerifyX4(
			&model, &modelA, &modelB,
			&scalarPairs[index][0], &scalarPairs[index][1], modelOps,
		)
		if err != nil || !valid {
			t.Fatalf("case %d model=(%v,%v)", index, valid, err)
		}
		modelPoint := model.reduced()
		modelEncoding := modelPoint.Bytes()
		if !bytes.Equal(modelEncoding[:], want.Bytes()) {
			t.Fatalf("case %d model/reference mismatch\ngot  %x\nwant %x", index, modelEncoding, want.Bytes())
		}

		if hardware {
			var got quadPackedPointX4
			valid, err = evaluateQuadNAFVerifyX4(
				&got, &hardwareA, &hardwareB,
				&scalarPairs[index][0], &scalarPairs[index][1],
				quadDSMOperationsX4{hardware: true},
			)
			if err != nil || !valid {
				t.Fatalf("case %d hardware=(%v,%v)", index, valid, err)
			}
			gotPoint := got.reduced()
			if gotPoint.Bytes() != modelEncoding {
				t.Fatalf("case %d hardware/model mismatch", index)
			}
		}
	}

	invalid := scalarOrderBytes
	var out quadPackedPointX4
	if valid, err := evaluateQuadNAFVerifyX4(&out, &modelA, &modelB, &invalid, &scalarPairs[0][1], modelOps); err != nil || valid {
		t.Fatalf("noncanonical s=(%v,%v), want (false,nil)", valid, err)
	}
	if out != quadPackedIdentityValueX4() {
		t.Fatal("noncanonical scalar did not fail closed to identity")
	}
}

func decrementLittleEndianX4Test(value *[32]byte) {
	for index := range value {
		if value[index] != 0 {
			value[index]--
			return
		}
		value[index] = 0xff
	}
	panic("r51x5: cannot decrement zero")
}

func TestExperimentalCoordinateParallelNAFVerifyX4ZeroAllocations(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("AVX-512 IFMA is unavailable")
	}
	fixture := newQuadDSMFixtureX4(t)
	ops := quadDSMOperationsX4{hardware: true}
	var aTable quadNAFTable5X4
	var bTable quadNAFTable8X4
	if err := buildQuadNAFTable5X4(&aTable, &fixture.a, ops); err != nil {
		t.Fatal(err)
	}
	if err := buildQuadNAFTable8X4(&bTable, &fixture.b, ops); err != nil {
		t.Fatal(err)
	}
	s := fixture.scalars[0][0]
	k := fixture.scalars[1][0]
	var out quadPackedPointX4
	if allocs := testing.AllocsPerRun(20, func() {
		if valid, err := evaluateQuadNAFVerifyX4(&out, &aTable, &bTable, &s, &k, ops); err != nil {
			panic(err)
		} else if !valid {
			panic("r51x5: canonical NAF scalar rejected")
		}
	}); allocs != 0 {
		t.Fatalf("prepared allocations=%v want 0", allocs)
	}
	if allocs := testing.AllocsPerRun(20, func() {
		if err := buildQuadNAFTable5X4(&aTable, &fixture.a, ops); err != nil {
			panic(err)
		}
		if valid, err := evaluateQuadNAFVerifyX4(&out, &aTable, &bTable, &s, &k, ops); err != nil {
			panic(err)
		} else if !valid {
			panic("r51x5: canonical NAF scalar rejected")
		}
	}); allocs != 0 {
		t.Fatalf("cold-A allocations=%v want 0", allocs)
	}
	benchmarkQuadNAFPointSink = out
}

var (
	benchmarkQuadNAFPointSink  quadPackedPointX4
	benchmarkQuadNAFTable5Sink quadNAFTable5X4
)

func BenchmarkExperimentalCoordinateParallelNAFVerifyX4(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skip("AVX-512 IFMA is unavailable")
	}
	fixture := newQuadDSMFixtureX4(b)
	ops := quadDSMOperationsX4{hardware: true}
	var aTable quadNAFTable5X4
	var bTable quadNAFTable8X4
	if err := buildQuadNAFTable5X4(&aTable, &fixture.a, ops); err != nil {
		b.Fatal(err)
	}
	if err := buildQuadNAFTable8X4(&bTable, &fixture.b, ops); err != nil {
		b.Fatal(err)
	}
	s := fixture.scalars[0][0]
	k := fixture.scalars[1][0]

	b.Run("stage=prepared/path=quad-naf/a-width=5/b-width=8", func(b *testing.B) {
		var out quadPackedPointX4
		b.ReportAllocs()
		b.ReportMetric(float64(unsafe.Sizeof(aTable)), "A-table-B")
		b.ReportMetric(float64(unsafe.Sizeof(bTable)), "B-table-B")
		b.ResetTimer()
		for iteration := 0; iteration < b.N; iteration++ {
			if valid, err := evaluateQuadNAFVerifyX4(&out, &aTable, &bTable, &s, &k, ops); err != nil {
				b.Fatal(err)
			} else if !valid {
				b.Fatal("canonical NAF scalar rejected")
			}
		}
		benchmarkQuadNAFPointSink = out
	})

	b.Run("stage=cold-A/path=quad-naf/a-width=5/b-width=8", func(b *testing.B) {
		var out quadPackedPointX4
		var coldA quadNAFTable5X4
		b.ReportAllocs()
		b.ReportMetric(float64(unsafe.Sizeof(coldA)), "A-table-B")
		b.ReportMetric(float64(unsafe.Sizeof(bTable)), "B-table-B")
		b.ResetTimer()
		for iteration := 0; iteration < b.N; iteration++ {
			if err := buildQuadNAFTable5X4(&coldA, &fixture.a, ops); err != nil {
				b.Fatal(err)
			}
			if valid, err := evaluateQuadNAFVerifyX4(&out, &coldA, &bTable, &s, &k, ops); err != nil {
				b.Fatal(err)
			} else if !valid {
				b.Fatal("canonical NAF scalar rejected")
			}
		}
		benchmarkQuadNAFPointSink = out
		benchmarkQuadNAFTable5Sink = coldA
	})

	// Keep the existing coordinate-parallel regular-radix candidates in the
	// same benchmark invocation so benchstat sees identical process and clock
	// conditions. B and prepared A tables are setup work; the cold-A rows
	// rebuild only A, matching the NAF rows above.
	for _, radixBits := range []uint{5, 6} {
		var tables [DSMTerms]quadSignedCachedTableX4
		if err := buildQuadSignedCachedTableX4(&tables[0], &fixture.b, radixBits, ops); err != nil {
			b.Fatal(err)
		}
		if err := buildQuadSignedCachedTableX4(&tables[1], &fixture.a, radixBits, ops); err != nil {
			b.Fatal(err)
		}
		name := "radix=32"
		if radixBits == 6 {
			name = "radix=64"
		}
		b.Run("stage=prepared/path=quad-regular/"+name, func(b *testing.B) {
			var out quadPackedPointX4
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				if _, err := evaluateQuadFixedDSMX4(&out, &tables, &fixture.scalars, &fixture.signs, radixBits, ops); err != nil {
					b.Fatal(err)
				}
			}
			benchmarkQuadNAFPointSink = out
		})
		b.Run("stage=cold-A/path=quad-regular/"+name, func(b *testing.B) {
			var out quadPackedPointX4
			var coldA quadSignedCachedTableX4
			localTables := [DSMTerms]quadSignedCachedTableX4{tables[0], coldA}
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				if err := buildQuadSignedCachedTableX4(&localTables[1], &fixture.a, radixBits, ops); err != nil {
					b.Fatal(err)
				}
				if _, err := evaluateQuadFixedDSMX4(&out, &localTables, &fixture.scalars, &fixture.signs, radixBits, ops); err != nil {
					b.Fatal(err)
				}
			}
			benchmarkQuadNAFPointSink = out
			benchmarkQuadDSMTableSink = localTables[1]
		})
	}
}
