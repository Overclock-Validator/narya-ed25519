package r51x5

import (
	"fmt"
	"testing"
	"unsafe"
)

// heterogeneousPartialCombConstructionFixtureExperiment deliberately retains
// only the source points. Every benchmark arm constructs its own table from
// these exact same bases inside the timed region.
type heterogeneousPartialCombConstructionFixtureExperiment struct {
	bX4     PointX4
	aX4     PointX4
	bPoint  Point
	aPoint  Point
	scalars FixedDSMScalarsX4
	signs   [DSMTerms]uint8
}

func newHeterogeneousPartialCombConstructionFixtureExperiment(tb testing.TB) heterogeneousPartialCombConstructionFixtureExperiment {
	tb.Helper()
	bX8, aX8, s8, k8 := fixedBaseCombDSMFixtures(tb)
	bX4, aX4 := pointX4Half(&bX8, 0), pointX4Half(&aX8, 0)
	var scalars FixedDSMScalarsX4
	copy(scalars[0][:], s8[:X4Lanes])
	copy(scalars[1][:], k8[:X4Lanes])
	return heterogeneousPartialCombConstructionFixtureExperiment{
		bX4:     bX4,
		aX4:     aX4,
		bPoint:  bX4.Lane(0),
		aPoint:  aX4.Lane(0),
		scalars: scalars,
		signs:   [DSMTerms]uint8{0, 0x0f},
	}
}

func buildRegularRadix64MicroAoSGroupExperiment(base *PointX4) ([X4Lanes]ifmaMicroAoSPerKeyTableExperiment, error) {
	var grouped IFMAFullTableRadix64X4
	if err := buildIFMAFullTableX4Into(&grouped, base, 6); err != nil {
		return [X4Lanes]ifmaMicroAoSPerKeyTableExperiment{}, err
	}
	return importIFMAMicroAoSTablesExperimentX4(&grouped), nil
}

func regularRadix64X4PayloadBytesExperiment() int {
	return regularRadixEntries(6) * int(unsafe.Sizeof(IFMAPointX4{}))
}

func regularRadix64MicroAoSGroupPayloadBytesExperiment() int {
	return X4Lanes * regularRadixEntries(6) * int(unsafe.Sizeof(ifmaMicroAoSPointEntryExperiment{}))
}

// This test makes the construction benchmark's correctness boundary explicit:
// freshly constructed candidate tables must feed an online evaluator that
// matches the current exact signed-integer DSM control. The broader
// heterogeneous-partial-comb tests independently compare that control against
// the Edwards reference on mixed-order points and every active mask.
func TestHeterogeneousPartialCombConstructionFeedsCurrentExactOracleExperiment(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("requires AVX-512 IFMA target")
	}
	fixture := newHeterogeneousPartialCombConstructionFixtureExperiment(t)

	regularA, err := buildRegularRadix64MicroAoSGroupExperiment(&fixture.aX4)
	if err != nil {
		t.Fatal(err)
	}
	regularB := buildAsymmetricFixedBTableExperiment(&fixture.bPoint, 10)
	partialA := buildHeterogeneousPartialCombATablesX4Experiment(&fixture.aX4, heterogeneousPartialCombA6R9Experiment)
	partialB8 := buildHeterogeneousPartialCombTableExperiment(&fixture.bPoint, heterogeneousPartialCombB8R3Experiment)
	partialB10 := buildHeterogeneousPartialCombTableExperiment(&fixture.bPoint, heterogeneousPartialCombB10R5Experiment)

	for active := uint8(0); active < 1<<X4Lanes; active++ {
		var controlLoose IFMAPointX4
		controlMask, controlErr := evaluateAsymmetricFixedBDensePreparedRadix64DSMX4(
			&controlLoose,
			&regularA,
			regularB,
			&fixture.scalars,
			&fixture.signs,
			active,
		)
		if controlErr != nil || controlMask != active {
			t.Fatalf("active=%02x control=(%02x,%v)", active, controlMask, controlErr)
		}
		control := controlLoose.Reduced()
		for _, candidate := range []struct {
			name  string
			table *heterogeneousPartialCombTableExperiment
		}{
			{name: "A6r9-B8r3", table: partialB8},
			{name: "A6r9-B10r5", table: partialB10},
		} {
			var gotLoose IFMAPointX4
			mask, candidateErr := evaluateHeterogeneousPartialCombDSMX4Experiment(
				&gotLoose,
				&partialA,
				candidate.table,
				&fixture.scalars,
				&fixture.signs,
				active,
			)
			if candidateErr != nil || mask != controlMask {
				t.Fatalf("active=%02x candidate=%s got=(%02x,%v) control=%02x", active, candidate.name, mask, candidateErr, controlMask)
			}
			got := gotLoose.Reduced()
			if !asymmetricFixedBProjectivelyEqual(&got, &control, active) {
				t.Fatalf("active=%02x candidate=%s current exact oracle mismatch", active, candidate.name)
			}
		}
	}
}

var (
	benchmarkHeterogeneousPartialCombBuildTableSink       *heterogeneousPartialCombTableExperiment
	benchmarkHeterogeneousPartialCombBuildAGroupSink      [X4Lanes]*heterogeneousPartialCombTableExperiment
	benchmarkHeterogeneousPartialCombBuildRegularFullSink IFMAFullTableRadix64X4
	benchmarkHeterogeneousPartialCombBuildRegularAoSSink  [X4Lanes]ifmaMicroAoSPerKeyTableExperiment
	benchmarkHeterogeneousPartialCombBuildAsymmetricSink  *asymmetricFixedBTableExperiment
)

func reportHeterogeneousPartialCombConstructionMetricsExperiment(
	b *testing.B,
	builds int,
	keysPerBuild int,
	retainedBytes int,
) {
	b.Helper()
	elapsed := float64(b.Elapsed().Nanoseconds())
	b.ReportMetric(elapsed/float64(builds), "ns/build")
	b.ReportMetric(float64(retainedBytes), "retained-table-bytes")
	if keysPerBuild > 0 {
		b.ReportMetric(float64(keysPerBuild), "keys/build")
		b.ReportMetric(elapsed/float64(builds*keysPerBuild), "ns/key")
	}
}

// BenchmarkHeterogeneousPartialCombConstructionExperiment is a construction-
// only gate. It deliberately excludes recoding and online DSM evaluation.
// B tables are process-shared candidates, while A tables are per key; callers
// must preserve that distinction when deriving cache admission or amortization
// policy. In particular, these rows are not complete-verifier measurements.
func BenchmarkHeterogeneousPartialCombConstructionExperiment(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skip("requires AVX-512 IFMA target")
	}
	fixture := newHeterogeneousPartialCombConstructionFixtureExperiment(b)

	b.Run("term=A/design=partial-A6r9/scope=one-key", func(b *testing.B) {
		var table *heterogeneousPartialCombTableExperiment
		payload := heterogeneousPartialCombA6R9Experiment.rowCount() *
			heterogeneousPartialCombA6R9Experiment.entriesPerRow() *
			int(unsafe.Sizeof(ifmaAffine3MicroAoSEntryExperiment{}))
		b.ReportAllocs()
		b.ResetTimer()
		for iteration := 0; iteration < b.N; iteration++ {
			table = buildHeterogeneousPartialCombTableExperiment(&fixture.aPoint, heterogeneousPartialCombA6R9Experiment)
		}
		b.StopTimer()
		benchmarkHeterogeneousPartialCombBuildTableSink = table
		reportHeterogeneousPartialCombConstructionMetricsExperiment(b, b.N, 1, payload)
	})

	b.Run("term=A/design=partial-A6r9/scope=x4-group", func(b *testing.B) {
		var tables [X4Lanes]*heterogeneousPartialCombTableExperiment
		payload := X4Lanes * heterogeneousPartialCombA6R9Experiment.rowCount() *
			heterogeneousPartialCombA6R9Experiment.entriesPerRow() *
			int(unsafe.Sizeof(ifmaAffine3MicroAoSEntryExperiment{}))
		b.ReportAllocs()
		b.ResetTimer()
		for iteration := 0; iteration < b.N; iteration++ {
			tables = buildHeterogeneousPartialCombATablesX4Experiment(&fixture.aX4, heterogeneousPartialCombA6R9Experiment)
		}
		b.StopTimer()
		benchmarkHeterogeneousPartialCombBuildAGroupSink = tables
		reportHeterogeneousPartialCombConstructionMetricsExperiment(b, b.N, X4Lanes, payload)
	})

	for _, candidate := range []struct {
		name string
		spec heterogeneousPartialCombSpecExperiment
	}{
		{name: "partial-B8r3", spec: heterogeneousPartialCombB8R3Experiment},
		{name: "partial-B10r5", spec: heterogeneousPartialCombB10R5Experiment},
	} {
		candidate := candidate
		b.Run(fmt.Sprintf("term=B/design=%s/scope=process-shared", candidate.name), func(b *testing.B) {
			var table *heterogeneousPartialCombTableExperiment
			payload := candidate.spec.rowCount() * candidate.spec.entriesPerRow() *
				int(unsafe.Sizeof(ifmaAffine3MicroAoSEntryExperiment{}))
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				table = buildHeterogeneousPartialCombTableExperiment(&fixture.bPoint, candidate.spec)
			}
			b.StopTimer()
			benchmarkHeterogeneousPartialCombBuildTableSink = table
			reportHeterogeneousPartialCombConstructionMetricsExperiment(b, b.N, 0, payload)
		})
	}

	for _, control := range []struct {
		term         string
		name         string
		base         *PointX4
		keysPerBuild int
	}{
		{term: "A", name: "regular-A6", base: &fixture.aX4, keysPerBuild: X4Lanes},
		// B is one process-shared point replicated into four SIMD lanes. It is
		// not four independently reusable keys, so ns/key would be misleading.
		{term: "B", name: "regular-B6", base: &fixture.bX4},
	} {
		control := control
		b.Run(fmt.Sprintf("term=%s/design=%s/scope=x4-group-projective", control.term, control.name), func(b *testing.B) {
			var table IFMAFullTableRadix64X4
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				if err := buildIFMAFullTableX4Into(&table, control.base, 6); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			benchmarkHeterogeneousPartialCombBuildRegularFullSink = table
			reportHeterogeneousPartialCombConstructionMetricsExperiment(b, b.N, control.keysPerBuild, regularRadix64X4PayloadBytesExperiment())
			b.ReportMetric(X4Lanes, "lanes/build")
		})

		b.Run(fmt.Sprintf("term=%s/design=%s/scope=x4-group-micro-aos", control.term, control.name), func(b *testing.B) {
			var tables [X4Lanes]ifmaMicroAoSPerKeyTableExperiment
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				var err error
				tables, err = buildRegularRadix64MicroAoSGroupExperiment(control.base)
				if err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			benchmarkHeterogeneousPartialCombBuildRegularAoSSink = tables
			reportHeterogeneousPartialCombConstructionMetricsExperiment(b, b.N, control.keysPerBuild, regularRadix64MicroAoSGroupPayloadBytesExperiment())
			b.ReportMetric(X4Lanes, "lanes/build")
		})
	}

	b.Run("term=B/design=control-shared-B10-dense/scope=process-shared", func(b *testing.B) {
		var table *asymmetricFixedBTableExperiment
		entries := 1 << (10 - 1)
		densePayload := entries * int(unsafe.Sizeof(ifmaAffine3MicroAoSEntryExperiment{}))
		// The current experiment retains both the scalar affine-cached source
		// and its dense copy. Report both rather than hiding the build-only copy.
		retainedPayload := densePayload + entries*int(unsafe.Sizeof(fixedBaseAffineCached{}))
		b.ReportAllocs()
		b.ResetTimer()
		for iteration := 0; iteration < b.N; iteration++ {
			table = buildAsymmetricFixedBTableExperiment(&fixture.bPoint, 10)
		}
		b.StopTimer()
		benchmarkHeterogeneousPartialCombBuildAsymmetricSink = table
		reportHeterogeneousPartialCombConstructionMetricsExperiment(b, b.N, 0, retainedPayload)
		b.ReportMetric(float64(densePayload), "online-table-bytes")
	})
}
