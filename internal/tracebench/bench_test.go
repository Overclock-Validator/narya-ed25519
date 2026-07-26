package tracebench

import (
	stdlibed25519 "crypto/ed25519"
	"testing"
	"time"

	narya "github.com/Overclock-Validator/narya-ed25519/ed25519"
	"github.com/Overclock-Validator/narya-ed25519/internal/mithriltracev3"
)

func TestSerializedReplayIncludesBuildCostAndNeverPromotesProductionCache(t *testing.T) {
	if err := narya.SetBackend("generic"); err != nil {
		t.Fatal(err)
	}
	trace := repeatedValidTrace(t, 9, 1)
	report, err := Run(trace, Config{
		Samples:                2,
		Warmups:                1,
		MinimumSampleDuration:  time.Nanosecond,
		MinimumRecords:         1,
		CacheBytes:             narya.DefaultMaxTableBytes,
		RepresentativeAttested: true,
		PinnedCoreAttested:     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Variants) != 3 || len(report.Comparisons) != 2 {
		t.Fatalf("report shape = %+v", report)
	}
	for _, variant := range report.Variants {
		if variant.Semantic.KnownOutcomeMismatches != 0 || variant.Semantic.CrossVariantMismatches != 0 {
			t.Fatalf("semantic mismatch in %+v", variant)
		}
	}
	cache := report.Variants[2]
	if cache.CacheStats.Tables != 1 || cache.CacheStats.Hits != 1 || cache.CacheStats.Misses != 8 {
		t.Fatalf("cache preflight stats = %+v", cache.CacheStats)
	}
	if report.GenericCacheEvidence.Qualifying {
		t.Fatalf("short diagnostic unexpectedly qualified: %+v", report.GenericCacheEvidence)
	}
	if report.ProductionCacheGate.Qualifying || report.ProductionCacheGate.Status != "pending_backend_native_cache" {
		t.Fatalf("production gate = %+v", report.ProductionCacheGate)
	}
	if report.Workload.Ordering != serializedOrderingLabel || report.Workload.SerializedReplayBoundary == "" || report.Workload.SIMDBatching == "" {
		t.Fatalf("replay boundary = %+v", report.Workload)
	}
	if !report.Execution.Serialized || !report.Execution.PinnedCoreAttested || report.Execution.AllocationAccounting == "" {
		t.Fatalf("execution metadata = %+v", report.Execution)
	}
	for _, variant := range report.Variants {
		if variant.MedianMallocs < 0 || variant.MedianBytes < 0 {
			t.Fatalf("allocation metrics = %+v", variant)
		}
	}
	if !contains(report.GenericCacheEvidence.Reasons, "fewer_than_10_timing_samples") || !contains(report.GenericCacheEvidence.Reasons, "timing_samples_shorter_than_3_seconds") {
		t.Fatalf("diagnostic reasons = %v", report.GenericCacheEvidence.Reasons)
	}
}

func TestDiagnosticQualificationRejectsTraceValidityGaps(t *testing.T) {
	tests := []struct {
		name       string
		trace      *mithriltracev3.Trace
		attested   bool
		minimum    int
		wantReason string
	}{
		{"unattested", repeatedValidTrace(t, 9, 1), false, 1, "representative_trace_not_attested"},
		{"truncated", repeatedValidTrace(t, 9, 2), true, 1, "trace_has_truncated_prefix_and_unknown_initial_cache_state"},
		{"too-small", repeatedValidTrace(t, 9, 1), true, 10, "retained_verification_count_below_minimum"},
		{"unknown", traceWithUnknownTail(t), true, 1, "trace_contains_unknown_completion_outcomes"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			report, err := Run(tc.trace, Config{
				Samples:                1,
				Warmups:                1,
				MinimumSampleDuration:  time.Nanosecond,
				MinimumRecords:         tc.minimum,
				RepresentativeAttested: tc.attested,
				PinnedCoreAttested:     true,
			})
			if err != nil {
				t.Fatal(err)
			}
			if !contains(report.Workload.DiagnosticIneligibility, tc.wantReason) {
				t.Fatalf("reasons %v do not contain %q", report.Workload.DiagnosticIneligibility, tc.wantReason)
			}
		})
	}
}

func TestDiagnosticQualificationRequiresExternalPinningAttestation(t *testing.T) {
	report, err := Run(repeatedValidTrace(t, 9, 1), Config{
		Samples:                1,
		Warmups:                1,
		MinimumSampleDuration:  time.Nanosecond,
		MinimumRecords:         1,
		RepresentativeAttested: true,
		PinnedCoreAttested:     false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !contains(report.Workload.DiagnosticIneligibility, "fixed_core_execution_not_attested") {
		t.Fatalf("pinning reasons = %v", report.Workload.DiagnosticIneligibility)
	}
}

func TestSemanticMismatchFailsBeforeTiming(t *testing.T) {
	trace := repeatedValidTrace(t, 9, 1)
	trace.Verifications[0].Outcome = mithriltracev3.OutcomeInvalid
	if _, err := Run(trace, Config{Samples: 10, MinimumSampleDuration: 3 * time.Second}); err == nil {
		t.Fatal("recorded predicate mismatch reached timing")
	}
}

func TestEmptyTraceIsRejected(t *testing.T) {
	trace := &mithriltracev3.Trace{Summary: mithriltracev3.Summary{
		Type:   "summary",
		Schema: mithriltracev3.Schema,
		Mode:   mithriltracev3.ModeDisabled,
	}}
	if _, err := Run(trace, Config{}); err == nil {
		t.Fatal("empty trace reached timing")
	}
}

func TestComparisonRequiresLower95Threshold(t *testing.T) {
	baseline := syntheticVariant("baseline", []float64{99, 100, 100, 101, 100, 99, 101, 100, 100, 100})
	fast := syntheticVariant("fast", []float64{89, 90, 90, 91, 90, 89, 91, 90, 90, 90})
	close := syntheticVariant("close", []float64{98.5, 99, 99.5, 100, 99, 98.5, 100, 99, 99.5, 99})
	if result := compare(baseline, fast); !result.MeetsThresholdAtLower95 || result.Lower95SpeedupPercent < CacheGainThreshold {
		t.Fatalf("fast comparison = %+v", result)
	}
	if result := compare(baseline, close); result.MeetsThresholdAtLower95 {
		t.Fatalf("close comparison = %+v", result)
	}
}

func TestPairedBootstrapPreservesRoundCorrelation(t *testing.T) {
	baseline := []float64{100, 1000, 110, 1100, 120, 1200, 130, 1300, 140, 1400}
	candidate := make([]float64, len(baseline))
	for i := range baseline {
		candidate[i] = baseline[i] * 0.9
	}
	lower := pairedBootstrapLower95(baseline, candidate)
	if lower < 9.999 || lower > 10.001 {
		t.Fatalf("paired lower bound = %f, want 10%%", lower)
	}
}

func repeatedValidTrace(t *testing.T, count int, firstSequence uint64) *mithriltracev3.Trace {
	t.Helper()
	pub, private, err := stdlibed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("representative-exact-message")
	signature := stdlibed25519.Sign(private, message)
	trace := &mithriltracev3.Trace{
		Summary: mithriltracev3.Summary{
			Type:                  "summary",
			Schema:                mithriltracev3.Schema,
			Enabled:               true,
			Mode:                  mithriltracev3.ModePassive,
			Capacity:              uint64(count),
			VerificationAttempts:  firstSequence + uint64(count) - 1,
			ObservedEvents:        uint64(2 * count),
			RetainedVerifications: count,
		},
		Verifications: make([]mithriltracev3.Verification, count),
	}
	for i := range trace.Verifications {
		v := &trace.Verifications[i]
		v.Sequence = firstSequence + uint64(i)
		v.BeginEventSequence = uint64(2*i + 1)
		v.CompletionEventSequence = uint64(2*i + 2)
		v.Source = "replay"
		copy(v.PublicKey[:], pub)
		copy(v.Signature[:], signature)
		v.Message = append([]byte(nil), message...)
		v.Outcome = mithriltracev3.OutcomeValid
		if i > 0 {
			v.ExactDuplicate = true
			v.PublicKeyReused = true
			v.ReuseDistance = 1
		}
	}
	if err := trace.Validate(); err != nil {
		t.Fatal(err)
	}
	return trace
}

func traceWithUnknownTail(t *testing.T) *mithriltracev3.Trace {
	trace := repeatedValidTrace(t, 9, 1)
	last := &trace.Verifications[len(trace.Verifications)-1]
	last.CompletionEventSequence = 0
	last.Outcome = mithriltracev3.OutcomeUnknown
	if err := trace.Validate(); err != nil {
		t.Fatal(err)
	}
	return trace
}

func syntheticVariant(name string, values []float64) VariantReport {
	samples := make([]TimingSample, len(values))
	for i, value := range values {
		samples[i].NanosecondsPerVerification = value
	}
	return VariantReport{Name: name, Samples: samples}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
