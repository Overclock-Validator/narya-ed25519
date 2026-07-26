package r51x5

import (
	"math/rand"
	"testing"
)

func TestFixedScalarWindowReaderEveryOffset(t *testing.T) {
	rng := rand.New(rand.NewSource(0x51_b17_2026))
	for sample := 0; sample < 256; sample++ {
		var scalar [32]byte
		_, _ = rng.Read(scalar[:])
		for _, width := range []uint8{4, 5, 6} {
			reader := fixedScalarWindowReader{scalar: &scalar}
			for bit := 0; bit < fixedScalarRoundCount(uint(width))*int(width); bit += int(width) {
				var want uint16
				for offset := uint8(0); offset < width; offset++ {
					sourceBit := bit + int(offset)
					if sourceBit < 256 && scalar[sourceBit>>3]&(1<<uint(sourceBit&7)) != 0 {
						want |= 1 << offset
					}
				}
				if got := reader.window(width); got != want {
					t.Fatalf("sample=%d width=%d bit=%d got=%x want=%x", sample, width, bit, got, want)
				}
			}
		}
	}
}

func TestFixedScalarRecodingMatchesArbitraryWidthReference(t *testing.T) {
	rng := rand.New(rand.NewSource(0x51f1ced))
	for round := 0; round < 512; round++ {
		var scalars8 [X8Lanes][32]byte
		for lane := range scalars8 {
			for {
				_, _ = rng.Read(scalars8[lane][:])
				scalars8[lane][31] &= 0x1f
				if canonicalScalarBytes(&scalars8[lane]) {
					break
				}
			}
		}
		active := uint8(rng.Uint32())
		negative := uint8(rng.Uint32())
		for _, radixBits := range []uint{4, 5, 6} {
			var fixed8 FixedRadixDigitsX8
			if valid := RecodeCanonicalScalarsX8(&fixed8, &scalars8, negative, active, radixBits); valid != active {
				t.Fatalf("round %d radix %d valid=%02x active=%02x", round, 1<<radixBits, valid, active)
			}
			for lane := 0; lane < X8Lanes; lane++ {
				var want []int8
				if active&(1<<lane) != 0 {
					want = RecodeRegularRadix(NewSignedMagnitude(scalars8[lane][:], negative&(1<<lane) != 0), radixBits)
				}
				if len(want) > fixed8.RoundCount() {
					t.Fatalf("round %d radix %d lane %d reference has %d digits, fixed storage has %d", round, 1<<radixBits, lane, len(want), fixed8.RoundCount())
				}
				gotDigits := make([]int8, fixed8.RoundCount())
				for digit := 0; digit < fixed8.RoundCount(); digit++ {
					wantDigit := int8(0)
					if digit < len(want) {
						wantDigit = want[digit]
					}
					gotDigits[digit] = fixed8.Round(digit).Digit(lane)
					if got := gotDigits[digit]; got != wantDigit {
						t.Fatalf("round %d radix %d lane %d digit %d got=%d want=%d", round, 1<<radixBits, lane, digit, got, wantDigit)
					}
				}
				if active&(1<<lane) != 0 {
					wantInteger := signedMagnitudeToBig(NewSignedMagnitude(scalars8[lane][:], negative&(1<<lane) != 0))
					if gotInteger := reconstructRegularRadix(gotDigits, radixBits); gotInteger.Cmp(wantInteger) != 0 {
						t.Fatalf("round %d radix %d lane %d fixed reconstruction got=%x want=%x", round, 1<<radixBits, lane, gotInteger, wantInteger)
					}
				}
			}

			for half := 0; half < 2; half++ {
				var scalars4 [X4Lanes][32]byte
				for lane := range scalars4 {
					scalars4[lane] = scalars8[half*X4Lanes+lane]
				}
				var fixed4 FixedRadixDigitsX4
				halfActive := (active >> (half * X4Lanes)) & 0x0f
				halfNegative := (negative >> (half * X4Lanes)) & 0x0f
				if valid := RecodeCanonicalScalarsX4(&fixed4, &scalars4, halfNegative, halfActive, radixBits); valid != halfActive {
					t.Fatalf("round %d half %d radix %d valid=%x active=%x", round, half, 1<<radixBits, valid, halfActive)
				}
				for digit := 0; digit < fixed4.RoundCount(); digit++ {
					for lane := 0; lane < X4Lanes; lane++ {
						if got, want := fixed4.Round(digit).Digit(lane), fixed8.Round(digit).Digit(half*X4Lanes+lane); got != want {
							t.Fatalf("round %d half %d radix %d lane %d digit %d x4=%d x8=%d", round, half, 1<<radixBits, lane, digit, got, want)
						}
					}
				}
			}
		}
	}
}

func TestFixedScalarRecodingRejectsNonCanonicalAndMasksInactive(t *testing.T) {
	var scalars [X8Lanes][32]byte
	scalars[0] = scalarOrderBytes
	scalars[1] = scalarOrderBytes
	scalars[1][0]++
	scalars[2] = scalarOrderBytes
	scalars[2][0]--
	scalars[3][0] = 1
	// Lane four is noncanonical but inactive and must remain empty.
	scalars[4] = scalarOrderBytes

	for _, radixBits := range []uint{4, 5, 6} {
		var got FixedRadixDigitsX8
		valid := RecodeCanonicalScalarsX8(&got, &scalars, 0xff, 0x0f, radixBits)
		if valid != 0x0c {
			t.Fatalf("radix %d valid=%02x want=0c", 1<<radixBits, valid)
		}
		for round := 0; round < got.RoundCount(); round++ {
			for _, lane := range []int{0, 1, 4, 5, 6, 7} {
				if digit := got.Round(round).Digit(lane); digit != 0 {
					t.Fatalf("radix %d round %d lane %d invalid/inactive digit=%d", 1<<radixBits, round, lane, digit)
				}
			}
		}
	}
}

func TestFixedScalarRoundAccessAndRadixValidation(t *testing.T) {
	var scalars [X4Lanes][32]byte
	var got FixedRadixDigitsX4
	for _, test := range []struct {
		radixBits uint
		rounds    int
	}{
		{4, 64},
		{5, 51},
		{6, 43},
	} {
		if valid := RecodeCanonicalScalarsX4(&got, &scalars, 0, 0x0f, test.radixBits); valid != 0x0f {
			t.Fatalf("radix %d zero scalar validity=%x", 1<<test.radixBits, valid)
		}
		if got.RoundCount() != test.rounds || got.RadixBits() != test.radixBits {
			t.Fatalf("radix %d fixed metadata rounds=%d radixBits=%d", 1<<test.radixBits, got.RoundCount(), got.RadixBits())
		}
	}
	for _, index := range []int{-1, got.RoundCount()} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("Round(%d) did not panic", index)
				}
			}()
			_ = got.Round(index)
		}()
	}
	defer func() {
		if recover() == nil {
			t.Fatal("unsupported radix did not panic")
		}
	}()
	RecodeCanonicalScalarsX4(&got, &scalars, 0, 0x0f, 3)
}

var benchmarkFixedDigitsX8 FixedRadixDigitsX8

func BenchmarkFixedScalarRecodingX8(b *testing.B) {
	var scalars [X8Lanes][32]byte
	for lane := range scalars {
		scalars[lane][0] = byte(lane + 1)
		scalars[lane][15] = byte(17 * lane)
		scalars[lane][31] = 0x0f
	}
	for _, radixBits := range []uint{4, 5, 6} {
		b.Run(map[uint]string{4: "radix16", 5: "radix32", 6: "radix64"}[radixBits], func(b *testing.B) {
			b.ReportAllocs()
			var out FixedRadixDigitsX8
			for i := 0; i < b.N; i++ {
				RecodeCanonicalScalarsX8(&out, &scalars, 0xaa, 0xff, radixBits)
			}
			benchmarkFixedDigitsX8 = out
		})
	}
}
