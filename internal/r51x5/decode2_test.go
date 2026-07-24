package r51x5

import (
	"fmt"
	"math/rand"
	"testing"
)

func TestDecode2NoTX8MatchesIndependentDecoders(t *testing.T) {
	rng := rand.New(rand.NewSource(0xd2a851))
	invalid := deterministicInvalidPointEncoding(t)
	generator := newGeneratorEncodingForTest(t)
	negativeZero := [32]byte{1}
	negativeZero[31] = 0x80
	pAlias := [32]byte{0xed}
	for i := 1; i < 31; i++ {
		pAlias[i] = 0xff
	}
	pAlias[31] = 0x7f

	var aBytes, rBytes [X8Lanes][32]byte
	edges := [][32]byte{generator, invalid, negativeZero, pAlias}
	for lane := 0; lane < X8Lanes; lane++ {
		aBytes[lane] = edges[lane%len(edges)]
		rBytes[lane] = edges[(lane+2)%len(edges)]
		if lane&1 != 0 {
			aBytes[lane][31] ^= 0x80
		}
		if lane&2 != 0 {
			rBytes[lane][31] ^= 0x80
		}
	}

	masks := []uint8{0, 1, 3, 7, 0x0f, 0x1f, 0x3f, 0x7f, 0xff, 0x55, 0xaa}
	for lane := 0; lane < X8Lanes; lane++ {
		masks = append(masks, 0xff&^(1<<lane))
	}
	for _, active := range masks {
		checkDecode2X8(t, fmt.Sprintf("edges/active=%02x", active), &aBytes, &rBytes, active)
	}

	for round := 0; round < 128; round++ {
		for lane := 0; lane < X8Lanes; lane++ {
			_, _ = rng.Read(aBytes[lane][:])
			_, _ = rng.Read(rBytes[lane][:])
		}
		active := uint8(rng.Uint32())
		checkDecode2X8(t, fmt.Sprintf("random/%d", round), &aBytes, &rBytes, active)
	}
}

func TestDecode2NoTX4MatchesIndependentDecoders(t *testing.T) {
	rng := rand.New(rand.NewSource(0xd2a451))
	for round := 0; round < 128; round++ {
		var aBytes, rBytes [X4Lanes][32]byte
		for lane := 0; lane < X4Lanes; lane++ {
			_, _ = rng.Read(aBytes[lane][:])
			_, _ = rng.Read(rBytes[lane][:])
		}
		for _, active := range []uint8{0, 1, 3, 7, 0x0f, 5, 10, uint8(rng.Uint32()) & 0x0f} {
			checkDecode2X4(t, fmt.Sprintf("round=%d/active=%x", round, active), &aBytes, &rBytes, active)
		}
	}
}

func TestDecode2NoTX8MatchesTwoX4Groups(t *testing.T) {
	rng := rand.New(rand.NewSource(0xd284d284))
	for round := 0; round < 64; round++ {
		var a8, r8 [X8Lanes][32]byte
		for lane := 0; lane < X8Lanes; lane++ {
			_, _ = rng.Read(a8[lane][:])
			_, _ = rng.Read(r8[lane][:])
		}
		active := uint8(rng.Uint32())
		var aPoint8 PointX8
		var rPoint8 AffinePointX8
		aValid8, rValid8 := Decode2NoTX8(&aPoint8, &rPoint8, &a8, &r8, active)
		for half := 0; half < 2; half++ {
			var a4, r4 [X4Lanes][32]byte
			for lane := 0; lane < X4Lanes; lane++ {
				a4[lane] = a8[half*X4Lanes+lane]
				r4[lane] = r8[half*X4Lanes+lane]
			}
			halfActive := (active >> (half * X4Lanes)) & 0x0f
			var aPoint4 PointX4
			var rPoint4 AffinePointX4
			aValid4, rValid4 := Decode2NoTX4(&aPoint4, &rPoint4, &a4, &r4, halfActive)
			if aValid4 != (aValid8>>(half*X4Lanes))&0x0f || rValid4 != (rValid8>>(half*X4Lanes))&0x0f {
				t.Fatalf("round %d half %d masks differ: x8=(%02x,%02x) x4=(%x,%x)", round, half, aValid8, rValid8, aValid4, rValid4)
			}
			for lane := 0; lane < X4Lanes; lane++ {
				wantA := aPoint8.Lane(half*X4Lanes + lane)
				gotA := aPoint4.Lane(lane)
				if gotA != wantA {
					t.Fatalf("round %d half %d lane %d A coordinates differ", round, half, lane)
				}
				gotRX, gotRY := rPoint4.X.Lane(lane), rPoint4.Y.Lane(lane)
				wantRX := rPoint8.X.Lane(half*X4Lanes + lane)
				wantRY := rPoint8.Y.Lane(half*X4Lanes + lane)
				if gotRX != wantRX || gotRY != wantRY {
					t.Fatalf("round %d half %d lane %d R coordinates differ", round, half, lane)
				}
			}
		}
	}
}

func checkDecode2X8(t *testing.T, label string, aBytes, rBytes *[X8Lanes][32]byte, active uint8) {
	t.Helper()
	var a PointX8
	var r AffinePointX8
	aValid, rValid := Decode2NoTX8(&a, &r, aBytes, rBytes, active)
	if aValid&^active != 0 || rValid&^active != 0 {
		t.Fatalf("%s: valid masks exceed active: active=%02x A=%02x R=%02x", label, active, aValid, rValid)
	}
	for lane := 0; lane < X8Lanes; lane++ {
		checkDecode2Lane(t, fmt.Sprintf("%s/lane=%d", label, lane), aBytes[lane][:], rBytes[lane][:], active&(1<<lane) != 0, aValid&(1<<lane) != 0, rValid&(1<<lane) != 0, a.Lane(lane), r.X.Lane(lane), r.Y.Lane(lane))
	}
}

func checkDecode2X4(t *testing.T, label string, aBytes, rBytes *[X4Lanes][32]byte, active uint8) {
	t.Helper()
	var a PointX4
	var r AffinePointX4
	aValid, rValid := Decode2NoTX4(&a, &r, aBytes, rBytes, active)
	if aValid&^active != 0 || rValid&^active != 0 {
		t.Fatalf("%s: valid masks exceed active: active=%x A=%x R=%x", label, active, aValid, rValid)
	}
	for lane := 0; lane < X4Lanes; lane++ {
		checkDecode2Lane(t, fmt.Sprintf("%s/lane=%d", label, lane), aBytes[lane][:], rBytes[lane][:], active&(1<<lane) != 0, aValid&(1<<lane) != 0, rValid&(1<<lane) != 0, a.Lane(lane), r.X.Lane(lane), r.Y.Lane(lane))
	}
}

func checkDecode2Lane(t *testing.T, label string, aBytes, rBytes []byte, active, aValid, rValid bool, gotA Point, gotRX, gotRY Element) {
	t.Helper()
	if !active {
		if aValid || rValid || gotA.IsIdentity() != 1 || !gotRX.limbs.isZeroForTest() || !gotRY.limbs.isZeroForTest() {
			t.Fatalf("%s: inactive lane was not neutralized", label)
		}
		return
	}
	var wantA, wantR Point
	_, aErr := wantA.SetBytes(aBytes)
	_, rErr := wantR.SetBytes(rBytes)
	if aValid != (aErr == nil) || rValid != (rErr == nil) {
		t.Fatalf("%s: validity differs: got=(%v,%v) errors=(%v,%v)", label, aValid, rValid, aErr, rErr)
	}
	if aErr == nil {
		if gotA != wantA {
			t.Fatalf("%s: A coordinates differ\ngot=%x\nwant=%x", label, gotA.Bytes(), wantA.Bytes())
		}
		assertScalarPointInvariant(t, label+"/A", &gotA)
	} else if gotA.IsIdentity() != 1 {
		t.Fatalf("%s: invalid A lane is not identity", label)
	}
	if rErr == nil {
		if gotRX != wantR.X || gotRY != wantR.Y {
			t.Fatalf("%s: affine R differs", label)
		}
	} else if !gotRX.limbs.isZeroForTest() || !gotRY.limbs.isZeroForTest() {
		t.Fatalf("%s: invalid R lane was not zeroed", label)
	}
}

func (x Limbs) isZeroForTest() bool { return x == (Limbs{}) }

// newGeneratorEncodingForTest returns the canonical basepoint encoding while
// keeping test construction independent of crypto/ed25519 key generation.
func newGeneratorEncodingForTest(t testing.TB) [32]byte {
	t.Helper()
	generator := [32]byte{
		0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
		0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
		0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
		0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
	}
	var point Point
	if _, err := point.SetBytes(generator[:]); err != nil {
		t.Fatal(err)
	}
	return generator
}

var (
	benchmarkDecode2A8     PointX8
	benchmarkDecode2R8     AffinePointX8
	benchmarkDecode2Masks8 [2]uint8
)

func BenchmarkDecode2NoTWidths(b *testing.B) {
	generator := newGeneratorEncodingForTest(b)
	var a8, r8 [X8Lanes][32]byte
	for lane := 0; lane < X8Lanes; lane++ {
		a8[lane], r8[lane] = generator, generator
		a8[lane][31] ^= byte(lane&1) << 7
		r8[lane][31] ^= byte((lane>>1)&1) << 7
	}

	b.Run("independent-8x2", func(b *testing.B) {
		b.ReportAllocs()
		var outA PointX8
		var outR AffinePointX8
		for i := 0; i < b.N; i++ {
			for lane := 0; lane < X8Lanes; lane++ {
				var a, r Point
				_, _ = a.SetBytes(a8[lane][:])
				_, _ = r.SetBytes(r8[lane][:])
				outA.SetLane(lane, &a)
				outR.X.SetLane(lane, &r.X)
				outR.Y.SetLane(lane, &r.Y)
			}
		}
		benchmarkDecode2A8, benchmarkDecode2R8 = outA, outR
	})
	b.Run("one-x8", func(b *testing.B) {
		b.ReportAllocs()
		var a PointX8
		var r AffinePointX8
		var av, rv uint8
		for i := 0; i < b.N; i++ {
			av, rv = Decode2NoTX8(&a, &r, &a8, &r8, 0xff)
		}
		benchmarkDecode2A8, benchmarkDecode2R8 = a, r
		benchmarkDecode2Masks8 = [2]uint8{av, rv}
	})
	b.Run("two-x4", func(b *testing.B) {
		b.ReportAllocs()
		var outA PointX8
		var outR AffinePointX8
		var masks [2]uint8
		for i := 0; i < b.N; i++ {
			for half := 0; half < 2; half++ {
				var a4, r4 [X4Lanes][32]byte
				for lane := 0; lane < X4Lanes; lane++ {
					a4[lane] = a8[half*X4Lanes+lane]
					r4[lane] = r8[half*X4Lanes+lane]
				}
				var a PointX4
				var r AffinePointX4
				av, rv := Decode2NoTX4(&a, &r, &a4, &r4, 0x0f)
				masks[0] |= av << (half * X4Lanes)
				masks[1] |= rv << (half * X4Lanes)
				for lane := 0; lane < X4Lanes; lane++ {
					point := a.Lane(lane)
					outA.SetLane(half*X4Lanes+lane, &point)
					rx, ry := r.X.Lane(lane), r.Y.Lane(lane)
					outR.X.SetLane(half*X4Lanes+lane, &rx)
					outR.Y.SetLane(half*X4Lanes+lane, &ry)
				}
			}
		}
		benchmarkDecode2A8, benchmarkDecode2R8 = outA, outR
		benchmarkDecode2Masks8 = masks
	})
}
