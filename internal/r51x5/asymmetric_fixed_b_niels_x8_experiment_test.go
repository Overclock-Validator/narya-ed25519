package r51x5

import (
	"testing"
	"unsafe"
)

// asymmetricFixedBSignedTableX8Experiment is a one-row, process-shared
// signed table for the fixed generator. Unlike the production two-row comb,
// it uses the 250 doublings already required by the radix-32 variable-base
// term. Width ten therefore needs only 26 fixed-base additions and no
// separate fixed-base doubling chain or final point addition.
type asymmetricFixedBSignedTableX8Experiment struct {
	points [512]fixedBaseIFMASignedAffineCached
}

type asymmetricFixedBRoundX8Experiment struct {
	Magnitude    [X8Lanes]uint16
	NonzeroMask  uint8
	NegativeMask uint8
}

type asymmetricFixedBDigitsX8Experiment struct {
	rounds [26]asymmetricFixedBRoundX8Experiment
}

func buildAsymmetricFixedBSignedTableX8Experiment(base *Point) *asymmetricFixedBSignedTableX8Experiment {
	table := new(asymmetricFixedBSignedTableX8Experiment)
	multiple := *base
	for entry := range table.points {
		var cached fixedBaseAffineCached
		fixedBaseCacheAffine(&cached, &multiple)
		storeFixedBaseIFMASignedAffineCached(&table.points[entry], &cached)
		if entry+1 < len(table.points) {
			fixedBasePointAdd(&multiple, &multiple, base)
		}
	}
	return table
}

func recodeAsymmetricFixedBScalarsX8Experiment(
	out *asymmetricFixedBDigitsX8Experiment,
	scalars *[X8Lanes][32]byte,
	active uint8,
) uint8 {
	*out = asymmetricFixedBDigitsX8Experiment{}
	var usable uint8
	for lane := 0; lane < X8Lanes; lane++ {
		laneMask := uint8(1 << lane)
		if active&laneMask == 0 || !canonicalScalarBytes(&scalars[lane]) {
			continue
		}
		usable |= laneMask
		words := asymmetricFixedBScalarWords(&scalars[lane])
		carry := int32(0)
		for round := range out.rounds {
			digit := int32(asymmetricFixedBScalarWordBits(&words, round*10, 10)) + carry
			carry = (digit + 512) >> 10
			digit -= carry << 10
			negative := digit < 0
			if negative {
				digit = -digit
			}
			out.rounds[round].Magnitude[lane] = uint16(digit)
			if digit != 0 {
				out.rounds[round].NonzeroMask |= laneMask
			}
			if negative {
				out.rounds[round].NegativeMask |= laneMask
			}
		}
		if carry != 0 {
			panic("r51x5: canonical scalar exceeded x8 asymmetric B10 schedule")
		}
	}
	return usable
}

func selectAsymmetricFixedBSignedX8Experiment(
	out *fixedBaseIFMACachedX8,
	table *asymmetricFixedBSignedTableX8Experiment,
	round *asymmetricFixedBRoundX8Experiment,
	active uint8,
) {
	lookupMask := round.NonzeroMask & active
	p0 := &ifmaAffine3MicroAoSIdentityEntryExperiment
	p1, p2, p3, p4, p5, p6, p7 := p0, p0, p0, p0, p0, p0, p0
	pointers := [X8Lanes]**ifmaAffine3MicroAoSEntryExperiment{&p0, &p1, &p2, &p3, &p4, &p5, &p6, &p7}
	for lane := 0; lane < X8Lanes; lane++ {
		laneMask := uint8(1 << lane)
		if lookupMask&laneMask == 0 {
			continue
		}
		magnitude := round.Magnitude[lane]
		if magnitude == 0 || magnitude > uint16(len(table.points)) {
			panic("r51x5: x8 asymmetric B10 digit outside table")
		}
		sign := fixedBasePublicSign(round.NegativeMask, laneMask)
		*pointers[lane] = &table.points[int(magnitude)-1][sign]
	}
	ifmaAffine3MicroAoSTransposeSelectExperimentX8(out, p0, p1, p2, p3, p4, p5, p6, p7)
}

func evaluateAsymmetricFixedBNielsX8Experiment(
	out *IFMAPointX8,
	variable *ExperimentalIFMAProjectiveNielsPreSignedMicroAoSVariableBaseWorkspaceX8,
	fixed *asymmetricFixedBSignedTableX8Experiment,
	s, k *[X8Lanes][32]byte,
	active uint8,
) (uint8, error) {
	if !ExperimentalIFMAAvailable() {
		return 0, ErrIFMAUnavailable
	}
	usable := RecodeCanonicalScalarsX8(&variable.digits, k, active, active, 5)
	var bDigits asymmetricFixedBDigitsX8Experiment
	usable &= recodeAsymmetricFixedBScalarsX8Experiment(&bDigits, s, active)
	acc := identityIFMAPointX8Value()
	if usable == 0 {
		*out = acc
		return 0, nil
	}

	var doubleWorkspace ifmaPointDoubleWorkspaceX8
	var aAddWorkspace ifmaPointAddProjectiveNielsScratchX8
	var bAddWorkspace fixedBaseIFMAAddScratchX8
	for exponent := 250; exponent >= 0; exponent-- {
		if exponent != 250 {
			if err := ifmaPointDoubleComposableWorkspaceStaticX8(&acc, &acc, &doubleWorkspace); err != nil {
				return 0, err
			}
		}
		if exponent%10 == 0 {
			round := &bDigits.rounds[exponent/10]
			if round.NonzeroMask&usable != 0 {
				var selected fixedBaseIFMACachedX8
				selectAsymmetricFixedBSignedX8Experiment(&selected, fixed, round, usable)
				if err := addFixedBaseIFMACachedWorkspaceX8(&acc, &acc, &selected, &bAddWorkspace); err != nil {
					return 0, err
				}
			}
		}
		if exponent%5 == 0 {
			round := variable.digits.Round(exponent / 5)
			if round.NonzeroMask&usable != 0 {
				var selected IFMAProjectiveNielsX8
				selectIFMAProjectiveNielsPreSignedMicroAoSX8(&selected, &variable.table, round, usable)
				if err := ifmaPointAddProjectiveNielsWorkspaceX8(&acc, &acc, &selected, &aAddWorkspace); err != nil {
					return 0, err
				}
			}
		}
	}
	*out = acc
	return usable, nil
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
	*asymmetricFixedBSignedTableX8Experiment,
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
	return variable, BuildExperimentalFixedBaseCombTable(&bPoint, 8), buildAsymmetricFixedBSignedTableX8Experiment(&bPoint), s, k
}

func TestAsymmetricFixedBNielsX8Experiment(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("requires AVX-512 IFMA")
	}
	variable, fixedControl, fixedCandidate, s, k := asymmetricFixedBNielsX8Fixture(t)
	for _, active := range []uint8{0x01, 0x55, 0xfe, 0xff} {
		var controlLoose, candidateLoose IFMAPointX8
		controlMask, controlErr := evaluateSeparateFixedBNielsX8Experiment(&controlLoose, variable, fixedControl, &s, &k, active)
		candidateMask, candidateErr := evaluateAsymmetricFixedBNielsX8Experiment(&candidateLoose, variable, fixedCandidate, &s, &k, active)
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
			return evaluateAsymmetricFixedBNielsX8Experiment(out, variable, fixedCandidate, &s, &k, 0xff)
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
	if got, want := unsafe.Sizeof(asymmetricFixedBSignedTableX8Experiment{}), uintptr(512*2*5*3*8); got != want {
		t.Fatalf("signed B10 table bytes=%d want=%d", got, want)
	}
}
