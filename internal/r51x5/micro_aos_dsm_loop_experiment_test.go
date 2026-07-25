package r51x5

import (
	"math/rand"
	"testing"

	edwardsref "github.com/Overclock-Validator/narya/internal/edwards25519"
)

// evaluateIFMAMicroAoSPreparedRadix64DSMX4 is the complete prepared-loop A/B
// counterpart of experimentalIFMAFixedDSMWorkspaceX4.Evaluate. Keep the two
// schedules deliberately identical: the only intended difference is the
// grouped-SoA selector versus the per-key micro-AoS selector.
func evaluateIFMAMicroAoSPreparedRadix64DSMX4(
	out *IFMAPointX4,
	workspace *ExperimentalIFMAFixedDSMWorkspaceRadix64X4,
	tables *[DSMTerms][X4Lanes]ifmaMicroAoSPerKeyTableExperiment,
	scalars *FixedDSMScalarsX4,
	negativeMasks *[DSMTerms]uint8,
	active uint8,
) (uint8, error) {
	if !workspace.fixedBasePrepared || !workspace.variableBasePrepared {
		panic("r51x5: micro-AoS DSM workspace is not prepared")
	}
	if !ExperimentalIFMAAvailable() {
		return 0, ErrIFMAUnavailable
	}
	active &= 0x0f
	usable := active
	for term := 0; term < DSMTerms; term++ {
		usable &= RecodeCanonicalScalarsX4(&workspace.digits[term], &scalars[term], negativeMasks[term], active, 6)
	}
	acc := identityIFMAPointX4Value()
	if usable == 0 {
		*out = acc
		return 0, nil
	}

	rounds := workspace.digits[0].RoundCount()
	for round := rounds - 1; round >= 0; round-- {
		if round != rounds-1 {
			for doubling := 0; doubling < 6; doubling++ {
				if err := ifmaPointDoubleComposableStaticX4(&acc, &acc); err != nil {
					return 0, err
				}
			}
		}
		for term := 0; term < DSMTerms; term++ {
			digit := workspace.digits[term].Round(round)
			if digit.NonzeroMask&usable == 0 {
				continue
			}
			var selected IFMAPointX4
			selectIFMAMicroAoSUncheckedExperimentX4(&selected, &tables[term], digit, usable)
			if err := ifmaPointAddComposableStaticX4(&acc, &acc, &selected); err != nil {
				return 0, err
			}
		}
	}
	*out = acc
	return usable, nil
}

func importIFMAMicroAoSDSMTableExperimentX4(workspace *ExperimentalIFMAFixedDSMWorkspaceRadix64X4) [DSMTerms][X4Lanes]ifmaMicroAoSPerKeyTableExperiment {
	var tables [DSMTerms][X4Lanes]ifmaMicroAoSPerKeyTableExperiment
	for term := 0; term < DSMTerms; term++ {
		tables[term] = importIFMAMicroAoSTablesExperimentX4(&workspace.tables[term])
	}
	return tables
}

func TestIFMAMicroAoSPreparedRadix64DSMX4ExactMixedOrderAndAllMasks(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("requires AVX-512 IFMA target")
	}
	rng := rand.New(rand.NewSource(0x51a05d5a64))
	torsion := referenceTorsionPoints(t)
	refs, bases8 := scalarWindowQSMBasesX8(t, rng, &torsion)
	for term := 0; term < DSMTerms; term++ {
		bases8[term] = randomProjectiveScaleX8(t, rng, &bases8[term])
	}
	bases4 := [DSMTerms]PointX4{
		pointX4Half(&bases8[0], 0),
		pointX4Half(&bases8[1], 0),
	}

	var workspace ExperimentalIFMAFixedDSMWorkspaceRadix64X4
	if err := workspace.PrepareBoth(&bases4, 6); err != nil {
		t.Fatal(err)
	}
	microTables := importIFMAMicroAoSDSMTableExperimentX4(&workspace)

	for iteration := 0; iteration < 16; iteration++ {
		scalars8, signs8, exact := randomIFMAFixedDSMScalars(rng)
		// Force an exact -1 coefficient in one mixed-order lane. Replacing it
		// with L-1 would retain a nonzero torsion error.
		if iteration == 0 {
			scalars8[1][0] = [32]byte{1}
			exact[1][0] = signedMagnitudeToBig(NewSignedMagnitude(scalars8[1][0][:], true))
		}
		want8 := exactIFMAFixedDSMWant(&refs, &exact)
		var want4 [X4Lanes]*edwardsref.Point
		copy(want4[:], want8[:X4Lanes])

		var scalars4 FixedDSMScalarsX4
		var signs4 [DSMTerms]uint8
		for term := 0; term < DSMTerms; term++ {
			copy(scalars4[term][:], scalars8[term][:X4Lanes])
			signs4[term] = signs8[term] & 0x0f
		}
		for active := uint8(0); active < 1<<X4Lanes; active++ {
			var current, micro IFMAPointX4
			currentMask, currentErr := workspace.Evaluate(&current, &scalars4, &signs4, active)
			microMask, microErr := evaluateIFMAMicroAoSPreparedRadix64DSMX4(&micro, &workspace, &microTables, &scalars4, &signs4, active)
			if currentErr != nil || microErr != nil || currentMask != active || microMask != active {
				t.Fatalf("iteration=%d active=%02x current=(%02x,%v) micro=(%02x,%v)", iteration, active, currentMask, currentErr, microMask, microErr)
			}
			if current != micro {
				t.Fatalf("iteration=%d active=%02x loose point differs", iteration, active)
			}
			currentReduced := current.Reduced()
			assertMaskedPointX4(t, "micro-AoS exact mixed-order DSM", &currentReduced, &want4, active)
		}
	}
}

func TestIFMAMicroAoSPreparedRadix64DSMX4InvalidScalarFailClosed(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("requires AVX-512 IFMA target")
	}
	_, bases8, _, _ := scalarWindowBenchmarkFixtures(t)
	variable8 := bases8
	variable8.Double(&variable8)
	bases4 := [DSMTerms]PointX4{
		pointX4Half(&bases8, 0),
		pointX4Half(&variable8, 0),
	}
	var workspace ExperimentalIFMAFixedDSMWorkspaceRadix64X4
	if err := workspace.PrepareBoth(&bases4, 6); err != nil {
		t.Fatal(err)
	}
	microTables := importIFMAMicroAoSDSMTableExperimentX4(&workspace)
	var scalars FixedDSMScalarsX4
	for term := range scalars {
		for lane := range scalars[term] {
			scalars[term][lane][0] = byte(1 + term + lane)
			scalars[term][lane][31] = 0x0f
		}
	}
	signs := [DSMTerms]uint8{0, 0x0f}
	for invalidLane := 0; invalidLane < X4Lanes; invalidLane++ {
		invalid := scalars
		invalid[invalidLane&1][invalidLane] = scalarOrderBytes
		var current, micro IFMAPointX4
		currentMask, currentErr := workspace.Evaluate(&current, &invalid, &signs, 0x0f)
		microMask, microErr := evaluateIFMAMicroAoSPreparedRadix64DSMX4(&micro, &workspace, &microTables, &invalid, &signs, 0x0f)
		wantMask := uint8(0x0f &^ (1 << invalidLane))
		if currentErr != nil || microErr != nil || currentMask != wantMask || microMask != wantMask {
			t.Fatalf("invalid lane=%d current=(%02x,%v) micro=(%02x,%v) want=%02x", invalidLane, currentMask, currentErr, microMask, microErr, wantMask)
		}
		if current != micro {
			t.Fatalf("invalid lane=%d loose point differs", invalidLane)
		}
		microReduced := micro.Reduced()
		if got := microReduced.Lane(invalidLane); got.IsIdentity() != 1 {
			t.Fatalf("invalid lane=%d did not fail closed to identity", invalidLane)
		}
	}
}

func TestIFMAMicroAoSPreparedRadix64DSMX4ZeroAllocations(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("requires AVX-512 IFMA target")
	}
	workspace, microTables, scalars, signs := newIFMAMicroAoSPreparedRadix64DSMX4BenchmarkFixture(t)
	var current, micro IFMAPointX4
	if allocs := testing.AllocsPerRun(20, func() {
		if _, err := workspace.Evaluate(&current, &scalars, &signs, 0x0f); err != nil {
			panic(err)
		}
	}); allocs != 0 {
		t.Fatalf("current grouped-SoA loop allocations=%v want=0", allocs)
	}
	if allocs := testing.AllocsPerRun(20, func() {
		if _, err := evaluateIFMAMicroAoSPreparedRadix64DSMX4(&micro, &workspace, &microTables, &scalars, &signs, 0x0f); err != nil {
			panic(err)
		}
	}); allocs != 0 {
		t.Fatalf("micro-AoS loop allocations=%v want=0", allocs)
	}
}

func newIFMAMicroAoSPreparedRadix64DSMX4BenchmarkFixture(tb testing.TB) (
	ExperimentalIFMAFixedDSMWorkspaceRadix64X4,
	[DSMTerms][X4Lanes]ifmaMicroAoSPerKeyTableExperiment,
	FixedDSMScalarsX4,
	[DSMTerms]uint8,
) {
	tb.Helper()
	_, bases8, _, _ := scalarWindowBenchmarkFixtures(tb)
	variable8 := bases8
	variable8.Double(&variable8)
	bases4 := [DSMTerms]PointX4{
		pointX4Half(&bases8, 0),
		pointX4Half(&variable8, 0),
	}
	var workspace ExperimentalIFMAFixedDSMWorkspaceRadix64X4
	if err := workspace.PrepareBoth(&bases4, 6); err != nil {
		tb.Fatal(err)
	}
	microTables := importIFMAMicroAoSDSMTableExperimentX4(&workspace)
	var scalars FixedDSMScalarsX4
	for term := range scalars {
		for lane := range scalars[term] {
			for index := range scalars[term][lane] {
				scalars[term][lane][index] = byte(1 + term*71 + lane*37 + index*19)
			}
			// Any value below 2^252 is canonical. Dense lower bytes make the
			// loop charge realistic selection and addition work in nearly every
			// radix-64 round instead of benchmarking mostly doublings.
			scalars[term][lane][31] = 0x0f
		}
	}
	return workspace, microTables, scalars, [DSMTerms]uint8{0, 0x0f}
}

var (
	benchmarkIFMAMicroAoSDSMPointSink IFMAPointX4
	benchmarkIFMAMicroAoSDSMMaskSink  uint8
)

func BenchmarkIFMAMicroAoSPreparedRadix64DSMX4(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skip("requires AVX-512 IFMA target")
	}
	workspace, microTables, scalars, signs := newIFMAMicroAoSPreparedRadix64DSMX4BenchmarkFixture(b)
	b.Run("implementation=current-grouped-soa", func(b *testing.B) {
		var out IFMAPointX4
		var mask uint8
		b.ReportAllocs()
		b.ResetTimer()
		for iteration := 0; iteration < b.N; iteration++ {
			var err error
			mask, err = workspace.Evaluate(&out, &scalars, &signs, 0x0f)
			if err != nil {
				b.Fatal(err)
			}
		}
		benchmarkIFMAMicroAoSDSMPointSink = out
		benchmarkIFMAMicroAoSDSMMaskSink = mask
		b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*X4Lanes), "ns/signature")
	})
	b.Run("implementation=micro-aos-transpose", func(b *testing.B) {
		var out IFMAPointX4
		var mask uint8
		b.ReportAllocs()
		b.ResetTimer()
		for iteration := 0; iteration < b.N; iteration++ {
			var err error
			mask, err = evaluateIFMAMicroAoSPreparedRadix64DSMX4(&out, &workspace, &microTables, &scalars, &signs, 0x0f)
			if err != nil {
				b.Fatal(err)
			}
		}
		benchmarkIFMAMicroAoSDSMPointSink = out
		benchmarkIFMAMicroAoSDSMMaskSink = mask
		b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*X4Lanes), "ns/signature")
	})
}
