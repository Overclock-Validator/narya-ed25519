package r51x5

import (
	"math/big"
	"math/rand"
	"testing"
	"unsafe"
)

func littleEndianScalarBigX8Test(encoded *[32]byte) *big.Int {
	reversed := make([]byte, len(encoded))
	for index := range encoded {
		reversed[len(encoded)-1-index] = encoded[index]
	}
	return new(big.Int).SetBytes(reversed)
}

func TestAsymmetricFixedB10RecodingX8Exact(t *testing.T) {
	rng := rand.New(rand.NewSource(0xb10a_51f8))
	var lMinusOne = scalarOrderBytes
	for index := range lMinusOne {
		if lMinusOne[index] != 0 {
			lMinusOne[index]--
			break
		}
		lMinusOne[index] = 0xff
	}
	edges := [][32]byte{{}, {1}, lMinusOne, scalarOrderBytes}
	for bit := 0; bit < 253; bit++ {
		var scalar [32]byte
		scalar[bit/8] = 1 << uint(bit&7)
		edges = append(edges, scalar)
	}
	for iteration := 0; iteration < 2_000; iteration++ {
		edges = append(edges, randomCanonicalFixedBaseScalar(t, rng))
	}

	for base := 0; base < len(edges); base += X8Lanes {
		var scalars [X8Lanes][32]byte
		for lane := range scalars {
			scalars[lane] = edges[(base+lane)%len(edges)]
		}
		for _, active := range []uint8{0x00, 0x01, 0x55, 0xaa, 0xff} {
			var digits asymmetricFixedB10DigitsX8
			gotMask := recodeAsymmetricFixedB10ScalarsX8(&digits, &scalars, active)
			var wantMask uint8
			for lane := range scalars {
				laneMask := uint8(1 << lane)
				if active&laneMask != 0 && canonicalScalarBytes(&scalars[lane]) {
					wantMask |= laneMask
				}
			}
			if gotMask != wantMask {
				t.Fatalf("base=%d active=%02x mask=%02x want=%02x", base, active, gotMask, wantMask)
			}

			for lane := range scalars {
				got := new(big.Int)
				place := big.NewInt(1)
				for round := range digits.rounds {
					digit := int64(digits.rounds[round].Magnitude[lane])
					if digits.rounds[round].NegativeMask&(1<<lane) != 0 {
						digit = -digit
					}
					got.Add(got, new(big.Int).Mul(big.NewInt(digit), place))
					place.Lsh(place, 10)
				}
				want := new(big.Int)
				if wantMask&(1<<lane) != 0 {
					want = littleEndianScalarBigX8Test(&scalars[lane])
				}
				if got.Cmp(want) != 0 {
					t.Fatalf("base=%d active=%02x lane=%d recoded=%s want=%s", base, active, lane, got, want)
				}
			}
		}
	}
}

func TestAsymmetricFixedB10RecodingX8ClearsOnReuse(t *testing.T) {
	var digits asymmetricFixedB10DigitsX8
	for round := range digits.rounds {
		digits.rounds[round].Magnitude = [X8Lanes]uint16{1, 1, 1, 1, 1, 1, 1, 1}
		digits.rounds[round].NonzeroMask = 0xff
		digits.rounds[round].NegativeMask = 0xff
	}
	var scalars [X8Lanes][32]byte
	if got := recodeAsymmetricFixedB10ScalarsX8(&digits, &scalars, 0); got != 0 {
		t.Fatalf("inactive mask=%02x want=00", got)
	}
	if digits != (asymmetricFixedB10DigitsX8{}) {
		t.Fatal("inactive recode retained stale digits")
	}
}

func evaluateSeparateFixedBNielsX8Experiment(
	out *IFMAPointX8,
	variable *ExperimentalIFMAProjectiveNielsPreSignedMicroAoSVariableBaseWorkspaceX8,
	fixed *ExperimentalFixedBaseCombTable,
	s, k *[X8Lanes][32]byte,
	active uint8,
) (uint8, error) {
	var aTerm, bTerm IFMAPointX8
	usableA, err := variable.Evaluate(&aTerm, k, active, active)
	if err != nil {
		return 0, err
	}
	usableB, err := ExperimentalIFMAFixedBaseCombScalarMultX8(&bTerm, fixed, s, active)
	if err != nil {
		return 0, err
	}
	usable := usableA & usableB
	if err := ExperimentalIFMAPointAddComposableX8(out, &aTerm, &bTerm); err != nil {
		return 0, err
	}
	return usable, nil
}

func asymmetricFixedBNielsX8Fixture(tb testing.TB) (
	*ExperimentalIFMAProjectiveNielsPreSignedMicroAoSVariableBaseWorkspaceX8,
	*ExperimentalFixedBaseCombTable,
	*IFMAAsymmetricFixedB10TableX8,
	[X8Lanes][32]byte,
	[X8Lanes][32]byte,
) {
	tb.Helper()
	b, a, s, k := fixedBaseCombDSMFixtures(tb)
	variable := new(ExperimentalIFMAProjectiveNielsPreSignedMicroAoSVariableBaseWorkspaceX8)
	if err := variable.Prepare(&a, 5); err != nil {
		tb.Fatal(err)
	}
	bPoint := b.Lane(0)
	return variable, BuildExperimentalFixedBaseCombTable(&bPoint, 8), BuildIFMAAsymmetricFixedB10TableX8(&bPoint), s, k
}

func TestAsymmetricFixedBNielsX8Experiment(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("requires AVX-512 IFMA")
	}
	variable, fixedControl, fixedCandidate, s, k := asymmetricFixedBNielsX8Fixture(t)
	for _, active := range []uint8{0x01, 0x55, 0xfe, 0xff} {
		var controlLoose, candidateLoose IFMAPointX8
		controlMask, controlErr := evaluateSeparateFixedBNielsX8Experiment(&controlLoose, variable, fixedControl, &s, &k, active)
		candidateMask, candidateErr := IFMAAsymmetricFixedB10EvaluateX8(&candidateLoose, variable, fixedCandidate, &s, &k, active)
		if controlErr != nil || candidateErr != nil || controlMask != candidateMask {
			t.Fatalf("active=%02x control=(%02x,%v) candidate=(%02x,%v)", active, controlMask, controlErr, candidateMask, candidateErr)
		}
		control, candidate := controlLoose.Reduced(), candidateLoose.Reduced()
		if control.Equal(&candidate)&active != active {
			t.Fatalf("active=%02x merged result differs projectively", active)
		}
	}
}

var (
	benchmarkAsymmetricFixedBNielsPointX8 IFMAPointX8
	benchmarkAsymmetricFixedBNielsMaskX8  uint8
)

func BenchmarkAsymmetricFixedBNielsX8Experiment(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skip("requires AVX-512 IFMA")
	}
	variable, fixedControl, fixedCandidate, s, k := asymmetricFixedBNielsX8Fixture(b)
	for _, implementation := range []struct {
		name string
		run  func(*IFMAPointX8) (uint8, error)
	}{
		{"separate-radix256-comb", func(out *IFMAPointX8) (uint8, error) {
			return evaluateSeparateFixedBNielsX8Experiment(out, variable, fixedControl, &s, &k, 0xff)
		}},
		{"merged-B10", func(out *IFMAPointX8) (uint8, error) {
			return IFMAAsymmetricFixedB10EvaluateX8(out, variable, fixedCandidate, &s, &k, 0xff)
		}},
	} {
		implementation := implementation
		b.Run("implementation="+implementation.name, func(b *testing.B) {
			var out IFMAPointX8
			var mask uint8
			b.ReportAllocs()
			if implementation.name == "merged-B10" {
				b.ReportMetric(float64(unsafe.Sizeof(*fixedCandidate)), "B-table-bytes")
			}
			b.ResetTimer()
			for range b.N {
				var err error
				mask, err = implementation.run(&out)
				if err != nil || mask != 0xff {
					b.Fatalf("evaluate=(%02x,%v)", mask, err)
				}
			}
			benchmarkAsymmetricFixedBNielsPointX8 = out
			benchmarkAsymmetricFixedBNielsMaskX8 = mask
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*X8Lanes), "ns/signature")
		})
	}
}

func TestAsymmetricFixedBNielsX8TableSize(t *testing.T) {
	if got, want := unsafe.Sizeof(IFMAAsymmetricFixedB10TableX8{}), uintptr(512*2*5*3*8); got != want {
		t.Fatalf("signed B10 table bytes=%d want=%d", got, want)
	}
}
