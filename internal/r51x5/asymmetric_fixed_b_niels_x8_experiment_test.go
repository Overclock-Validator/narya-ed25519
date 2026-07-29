package r51x5

import (
	"testing"
	"unsafe"
)

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
	*ExperimentalIFMAAsymmetricFixedB10TableX8,
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
	return variable, BuildExperimentalFixedBaseCombTable(&bPoint, 8), BuildExperimentalIFMAAsymmetricFixedB10TableX8(&bPoint), s, k
}

func TestAsymmetricFixedBNielsX8Experiment(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("requires AVX-512 IFMA")
	}
	variable, fixedControl, fixedCandidate, s, k := asymmetricFixedBNielsX8Fixture(t)
	for _, active := range []uint8{0x01, 0x55, 0xfe, 0xff} {
		var controlLoose, candidateLoose IFMAPointX8
		controlMask, controlErr := evaluateSeparateFixedBNielsX8Experiment(&controlLoose, variable, fixedControl, &s, &k, active)
		candidateMask, candidateErr := ExperimentalIFMAAsymmetricFixedB10EvaluateX8(&candidateLoose, variable, fixedCandidate, &s, &k, active)
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
			return ExperimentalIFMAAsymmetricFixedB10EvaluateX8(out, variable, fixedCandidate, &s, &k, 0xff)
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
	if got, want := unsafe.Sizeof(ExperimentalIFMAAsymmetricFixedB10TableX8{}), uintptr(512*2*5*3*8); got != want {
		t.Fatalf("signed B10 table bytes=%d want=%d", got, want)
	}
}
