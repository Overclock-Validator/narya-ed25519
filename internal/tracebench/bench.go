// Package tracebench performs an offline, serialized verifier replay over
// exact Mithril schema-v3 inputs. It is measurement infrastructure, not a
// production cache policy or a substitute for an end-to-end Mithril replay.
package tracebench

import (
	stdlibed25519 "crypto/ed25519"
	"fmt"
	"runtime"
	"runtime/debug"
	"sort"
	"sync/atomic"
	"time"

	narya "github.com/Overclock-Validator/narya/ed25519"
	"github.com/Overclock-Validator/narya/internal/mithriltracev3"
)

const (
	Schema                  = "narya-sigverify-tracebench-v1"
	CacheGainThreshold      = 2.0
	ReleaseSamples          = 10
	ReleaseMinimumDuration  = 3 * time.Second
	DefaultMinimumRecords   = 10_000
	bootstrapReplicates     = 20_000
	serializedOrderingLabel = "retained_verification_begin_order"
)

type Config struct {
	Samples                int
	Warmups                int
	MinimumSampleDuration  time.Duration
	MinimumRecords         int
	CacheBytes             int64
	RepresentativeAttested bool
	PinnedCoreAttested     bool
}

type WorkloadReport struct {
	InputSchema              string                        `json:"input_schema"`
	CollectionMode           mithriltracev3.CollectionMode `json:"collection_mode"`
	Ordering                 string                        `json:"ordering"`
	RetainedVerifications    int                           `json:"retained_verifications"`
	VerificationAttempts     uint64                        `json:"verification_attempts"`
	KnownOutcomes            int                           `json:"known_outcomes"`
	UnknownOutcomes          int                           `json:"unknown_outcomes"`
	DistinctPublicKeys       int                           `json:"distinct_public_keys"`
	PublicKeyReuseRecords    int                           `json:"public_key_reuse_records"`
	ExactDuplicateRecords    int                           `json:"exact_duplicate_records"`
	RetainedMessageBytes     uint64                        `json:"retained_message_bytes"`
	TruncatedPrefix          bool                          `json:"truncated_prefix"`
	RepresentativeAttested   bool                          `json:"representative_attested"`
	DiagnosticEligible       bool                          `json:"diagnostic_eligible"`
	DiagnosticIneligibility  []string                      `json:"diagnostic_ineligibility,omitempty"`
	SerializedReplayBoundary string                        `json:"serialized_replay_boundary"`
	SIMDBatching             string                        `json:"simd_batching"`
}

type SemanticReport struct {
	KnownOutcomeMismatches int `json:"known_outcome_mismatches"`
	CrossVariantMismatches int `json:"cross_variant_mismatches"`
}

type TimingSample struct {
	NanosecondsPerVerification float64 `json:"ns_per_verification"`
	ElapsedNanoseconds         int64   `json:"elapsed_ns"`
	Passes                     int     `json:"passes"`
	Verifications              uint64  `json:"verifications"`
	MallocsPerVerification     float64 `json:"mallocs_per_verification"`
	BytesPerVerification       float64 `json:"bytes_allocated_per_verification"`
}

type VariantReport struct {
	Name           string           `json:"name"`
	Implementation string           `json:"implementation"`
	CacheMode      string           `json:"cache_mode"`
	Semantic       SemanticReport   `json:"semantic"`
	Samples        []TimingSample   `json:"samples"`
	MedianNS       float64          `json:"median_ns_per_verification"`
	MinimumNS      float64          `json:"minimum_ns_per_verification"`
	MaximumNS      float64          `json:"maximum_ns_per_verification"`
	MedianMallocs  float64          `json:"median_mallocs_per_verification"`
	MaximumMallocs float64          `json:"maximum_mallocs_per_verification"`
	MedianBytes    float64          `json:"median_bytes_allocated_per_verification"`
	MaximumBytes   float64          `json:"maximum_bytes_allocated_per_verification"`
	CacheStats     CacheStatsReport `json:"cache_stats,omitempty"`
}

type CacheStatsReport struct {
	Tables     int64 `json:"tables"`
	TableBytes int64 `json:"table_bytes"`
	Hits       int64 `json:"hits"`
	Misses     int64 `json:"misses"`
}

type ComparisonReport struct {
	Baseline                string  `json:"baseline"`
	Candidate               string  `json:"candidate"`
	MedianSpeedupPercent    float64 `json:"median_speedup_percent"`
	Lower95SpeedupPercent   float64 `json:"lower_95_speedup_percent"`
	ThresholdPercent        float64 `json:"threshold_percent"`
	MeetsThresholdAtLower95 bool    `json:"meets_threshold_at_lower_95"`
	EvidenceEligible        bool    `json:"evidence_eligible"`
	EvidenceStatus          string  `json:"evidence_status"`
}

type ExecutionReport struct {
	Serialized           bool   `json:"serialized"`
	GOMAXPROCS           int    `json:"gomaxprocs"`
	PinnedCoreAttested   bool   `json:"pinned_core_attested"`
	PinningVerification  string `json:"pinning_verification"`
	AllocationAccounting string `json:"allocation_accounting"`
	BuildVersion         string `json:"build_version"`
	BuildVCSRevision     string `json:"build_vcs_revision,omitempty"`
	BuildVCSModified     string `json:"build_vcs_modified,omitempty"`
}

type DiagnosticGate struct {
	Scope            string   `json:"scope"`
	Qualifying       bool     `json:"qualifying"`
	Status           string   `json:"status"`
	ThresholdPercent float64  `json:"threshold_percent"`
	Reasons          []string `json:"reasons,omitempty"`
}

type ProductionGate struct {
	Scope            string   `json:"scope"`
	Qualifying       bool     `json:"qualifying"`
	Status           string   `json:"status"`
	ThresholdPercent float64  `json:"threshold_percent"`
	Reasons          []string `json:"reasons"`
}

type Report struct {
	Schema               string             `json:"schema"`
	InputSHA256          string             `json:"input_sha256,omitempty"`
	GoVersion            string             `json:"go_version"`
	GOOS                 string             `json:"goos"`
	GOARCH               string             `json:"goarch"`
	Backend              string             `json:"narya_backend"`
	Execution            ExecutionReport    `json:"execution"`
	Samples              int                `json:"sample_count"`
	Warmups              int                `json:"warmup_count"`
	MinimumSampleNanos   int64              `json:"minimum_sample_ns"`
	CacheBytes           int64              `json:"cache_max_table_bytes"`
	Workload             WorkloadReport     `json:"workload"`
	Variants             []VariantReport    `json:"variants"`
	Comparisons          []ComparisonReport `json:"comparisons"`
	GenericCacheEvidence DiagnosticGate     `json:"generic_cache_diagnostic"`
	ProductionCacheGate  ProductionGate     `json:"production_r51_cache_gate"`
}

type verifierVariant struct {
	name           string
	implementation string
	cacheMode      string
	runPass        func([]mithriltracev3.Verification) (uint64, narya.CacheStats)
}

var timingSink atomic.Uint64

func normalizeConfig(c Config) (Config, error) {
	if c.Samples == 0 {
		c.Samples = ReleaseSamples
	}
	if c.Warmups == 0 {
		c.Warmups = 1
	}
	if c.MinimumSampleDuration == 0 {
		c.MinimumSampleDuration = ReleaseMinimumDuration
	}
	if c.MinimumRecords == 0 {
		c.MinimumRecords = DefaultMinimumRecords
	}
	if c.CacheBytes == 0 {
		c.CacheBytes = narya.DefaultMaxTableBytes
	}
	if c.Samples < 1 || c.Warmups < 0 || c.MinimumSampleDuration < 0 || c.MinimumRecords < 1 || c.CacheBytes < 1 {
		return c, fmt.Errorf("tracebench: invalid samples/warmups/duration/minimum-records/cache-bytes")
	}
	return c, nil
}

// Run verifies every retained input semantically before timing it, then
// measures stdlib, uncached Narya strict, and a fresh-per-pass Narya Cache in
// rotating order. A cache pass starts empty so table construction and
// admission are included in its cost.
func Run(trace *mithriltracev3.Trace, config Config) (*Report, error) {
	if trace == nil {
		return nil, fmt.Errorf("tracebench: nil trace")
	}
	if err := trace.Validate(); err != nil {
		return nil, err
	}
	config, err := normalizeConfig(config)
	if err != nil {
		return nil, err
	}
	if len(trace.Verifications) == 0 {
		return nil, fmt.Errorf("tracebench: trace has no retained verifications")
	}
	if narya.ActiveBackend() != "generic" {
		return nil, fmt.Errorf("tracebench: only the current generic cache backend is supported")
	}

	variants := []verifierVariant{
		{
			name:           "stdlib-baseline",
			implementation: "crypto/ed25519.Verify",
			cacheMode:      "none",
			runPass: func(records []mithriltracev3.Verification) (uint64, narya.CacheStats) {
				var valid uint64
				for i := range records {
					v := &records[i]
					if stdlibed25519.Verify(v.PublicKey[:], v.Message, v.Signature[:]) {
						valid++
					}
				}
				return valid, narya.CacheStats{}
			},
		},
		{
			name:           "narya-cold-strict",
			implementation: "narya.VerifyStrict",
			cacheMode:      "none",
			runPass: func(records []mithriltracev3.Verification) (uint64, narya.CacheStats) {
				var valid uint64
				for i := range records {
					v := &records[i]
					if narya.VerifyStrict(v.PublicKey[:], v.Message, v.Signature[:]) {
						valid++
					}
				}
				return valid, narya.CacheStats{}
			},
		},
		{
			name:           "narya-cache-strict",
			implementation: "narya.Cache.VerifyStrict",
			cacheMode:      "fresh_cache_per_trace_pass",
			runPass: func(records []mithriltracev3.Verification) (uint64, narya.CacheStats) {
				cache := &narya.Cache{MaxTableBytes: config.CacheBytes}
				var valid uint64
				for i := range records {
					v := &records[i]
					if cache.VerifyStrict(&v.PublicKey, v.Message, v.Signature[:]) {
						valid++
					}
				}
				return valid, cache.Stats()
			},
		},
	}

	preflight := make([][]bool, len(variants))
	cacheStats := narya.CacheStats{}
	for i, variant := range variants {
		preflight[i], cacheStats = semanticPass(variant, trace.Verifications, config.CacheBytes)
		if i != len(variants)-1 {
			cacheStats = narya.CacheStats{}
		}
	}

	known, unknown := 0, 0
	semantic := make([]SemanticReport, len(variants))
	for recordIndex := range trace.Verifications {
		v := &trace.Verifications[recordIndex]
		if v.Outcome == mithriltracev3.OutcomeUnknown {
			unknown++
		} else {
			known++
			want := v.Outcome == mithriltracev3.OutcomeValid
			for variantIndex := range variants {
				if preflight[variantIndex][recordIndex] != want {
					semantic[variantIndex].KnownOutcomeMismatches++
				}
			}
		}
		for variantIndex := 1; variantIndex < len(variants); variantIndex++ {
			if preflight[variantIndex][recordIndex] != preflight[0][recordIndex] {
				semantic[variantIndex].CrossVariantMismatches++
			}
		}
	}
	for i := range semantic {
		if semantic[i].KnownOutcomeMismatches != 0 || semantic[i].CrossVariantMismatches != 0 {
			return nil, fmt.Errorf("tracebench: semantic preflight failed for %s: recorded=%d cross-variant=%d; refusing to time a predicate mismatch", variants[i].name, semantic[i].KnownOutcomeMismatches, semantic[i].CrossVariantMismatches)
		}
	}

	for range config.Warmups {
		for _, variant := range variants {
			valid, _ := variant.runPass(trace.Verifications)
			timingSink.Add(valid)
		}
	}

	timings := make([][]TimingSample, len(variants))
	for round := 0; round < config.Samples; round++ {
		for offset := range variants {
			variantIndex := (round + offset) % len(variants)
			runtime.GC()
			timings[variantIndex] = append(timings[variantIndex], measure(variants[variantIndex], trace.Verifications, config.MinimumSampleDuration))
		}
	}

	keys := make(map[[32]byte]struct{})
	var reused, duplicates int
	var retainedMessageBytes uint64
	for i := range trace.Verifications {
		v := &trace.Verifications[i]
		keys[v.PublicKey] = struct{}{}
		retainedMessageBytes += uint64(len(v.Message))
		if v.PublicKeyReused {
			reused++
		}
		if v.ExactDuplicate {
			duplicates++
		}
	}
	buildVersion, vcsRevision, vcsModified := buildProvenance()
	report := &Report{
		Schema:    Schema,
		GoVersion: runtime.Version(),
		GOOS:      runtime.GOOS,
		GOARCH:    runtime.GOARCH,
		Backend:   narya.ActiveBackend(),
		Execution: ExecutionReport{
			Serialized:           true,
			GOMAXPROCS:           runtime.GOMAXPROCS(0),
			PinnedCoreAttested:   config.PinnedCoreAttested,
			PinningVerification:  "external attestation only; run under taskset and retain host/cpuset metadata",
			AllocationAccounting: "runtime.MemStats deltas around each timed sample; process-wide and noisier than testing.B allocation counters",
			BuildVersion:         buildVersion,
			BuildVCSRevision:     vcsRevision,
			BuildVCSModified:     vcsModified,
		},
		Samples:            config.Samples,
		Warmups:            config.Warmups,
		MinimumSampleNanos: int64(config.MinimumSampleDuration),
		CacheBytes:         config.CacheBytes,
		Workload: WorkloadReport{
			InputSchema:              trace.Summary.Schema,
			CollectionMode:           trace.Summary.Mode,
			Ordering:                 serializedOrderingLabel,
			RetainedVerifications:    len(trace.Verifications),
			VerificationAttempts:     trace.Summary.VerificationAttempts,
			KnownOutcomes:            known,
			UnknownOutcomes:          unknown,
			DistinctPublicKeys:       len(keys),
			PublicKeyReuseRecords:    reused,
			ExactDuplicateRecords:    duplicates,
			RetainedMessageBytes:     retainedMessageBytes,
			TruncatedPrefix:          trace.TruncatedPrefix(),
			RepresentativeAttested:   config.RepresentativeAttested,
			SerializedReplayBoundary: "verifier-only; original concurrency, queueing, SIMD packing, and Mithril wall time are not reproduced",
			SIMDBatching:             "disabled; one strict signature call at a time to isolate the current generic key-cache effect",
		},
	}
	for i, variant := range variants {
		values := sampleValues(timings[i])
		mallocs := sampleMallocValues(timings[i])
		bytesAllocated := sampleByteValues(timings[i])
		variantReport := VariantReport{
			Name:           variant.name,
			Implementation: variant.implementation,
			CacheMode:      variant.cacheMode,
			Semantic:       semantic[i],
			Samples:        timings[i],
			MedianNS:       median(values),
			MinimumNS:      values[0],
			MaximumNS:      values[len(values)-1],
			MedianMallocs:  median(mallocs),
			MaximumMallocs: mallocs[len(mallocs)-1],
			MedianBytes:    median(bytesAllocated),
			MaximumBytes:   bytesAllocated[len(bytesAllocated)-1],
		}
		if i == len(variants)-1 {
			variantReport.CacheStats = CacheStatsReport{
				Tables:     cacheStats.Tables,
				TableBytes: cacheStats.TableBytes,
				Hits:       cacheStats.Hits,
				Misses:     cacheStats.Misses,
			}
		}
		report.Variants = append(report.Variants, variantReport)
	}

	report.Comparisons = []ComparisonReport{
		compare(report.Variants[0], report.Variants[1]),
		compare(report.Variants[1], report.Variants[2]),
	}
	cacheComparison := report.Comparisons[1]
	reasons := diagnosticIneligibility(trace, config, semantic, cacheStats)
	report.Comparisons[0].EvidenceStatus = "timing_diagnostic_only"
	report.Comparisons[1].EvidenceEligible = len(reasons) == 0
	if len(reasons) == 0 {
		report.Comparisons[1].EvidenceStatus = "representative_generic_cache_measurement"
	} else {
		report.Comparisons[1].EvidenceStatus = "non_qualifying_workload_or_setup"
	}
	report.Workload.DiagnosticEligible = len(reasons) == 0
	report.Workload.DiagnosticIneligibility = append([]string(nil), reasons...)
	if len(reasons) == 0 && !cacheComparison.MeetsThresholdAtLower95 {
		reasons = append(reasons, "generic_cache_lower_95_speedup_below_2_percent")
	}
	report.GenericCacheEvidence = DiagnosticGate{
		Scope:            "serialized_generic_backend_cache_diagnostic_only",
		Qualifying:       len(reasons) == 0,
		ThresholdPercent: CacheGainThreshold,
		Reasons:          reasons,
	}
	if report.GenericCacheEvidence.Qualifying {
		report.GenericCacheEvidence.Status = "qualifying_generic_diagnostic"
	} else {
		report.GenericCacheEvidence.Status = "non_qualifying"
	}
	report.ProductionCacheGate = ProductionGate{
		Scope:            "selected_r51_backend_native_table_and_gather_path",
		Qualifying:       false,
		Status:           "pending_backend_native_cache",
		ThresholdPercent: CacheGainThreshold,
		Reasons: []string{
			"current Cache timing covers generic Edwards tables, not the selected r51 table representation, packing, or gather path",
			"serialized verifier replay is not the required end-to-end Mithril trace A/B",
		},
	}
	return report, nil
}

func semanticPass(variant verifierVariant, records []mithriltracev3.Verification, cacheBytes int64) ([]bool, narya.CacheStats) {
	result := make([]bool, len(records))
	var stats narya.CacheStats
	if variant.cacheMode == "fresh_cache_per_trace_pass" {
		// Preserve the exact cache state progression while retaining each
		// individual verdict for comparison.
		cache := &narya.Cache{MaxTableBytes: cacheBytes}
		for i := range records {
			v := &records[i]
			result[i] = cache.VerifyStrict(&v.PublicKey, v.Message, v.Signature[:])
		}
		stats = cache.Stats()
		return result, stats
	}
	for i := range records {
		v := &records[i]
		switch variant.name {
		case "stdlib-baseline":
			result[i] = stdlibed25519.Verify(v.PublicKey[:], v.Message, v.Signature[:])
		case "narya-cold-strict":
			result[i] = narya.VerifyStrict(v.PublicKey[:], v.Message, v.Signature[:])
		default:
			panic("tracebench: unknown verifier variant")
		}
	}
	return result, stats
}

func measure(variant verifierVariant, records []mithriltracev3.Verification, minimum time.Duration) TimingSample {
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()
	passes := 0
	var valid uint64
	for {
		passValid, _ := variant.runPass(records)
		valid += passValid
		passes++
		if time.Since(start) >= minimum {
			break
		}
	}
	elapsed := time.Since(start)
	runtime.ReadMemStats(&after)
	verifications := uint64(passes) * uint64(len(records))
	timingSink.Add(valid)
	return TimingSample{
		NanosecondsPerVerification: float64(elapsed.Nanoseconds()) / float64(verifications),
		ElapsedNanoseconds:         elapsed.Nanoseconds(),
		Passes:                     passes,
		Verifications:              verifications,
		MallocsPerVerification:     float64(after.Mallocs-before.Mallocs) / float64(verifications),
		BytesPerVerification:       float64(after.TotalAlloc-before.TotalAlloc) / float64(verifications),
	}
}

func diagnosticIneligibility(trace *mithriltracev3.Trace, config Config, semantics []SemanticReport, stats narya.CacheStats) []string {
	var reasons []string
	if !config.RepresentativeAttested {
		reasons = append(reasons, "representative_trace_not_attested")
	}
	if !config.PinnedCoreAttested {
		reasons = append(reasons, "fixed_core_execution_not_attested")
	}
	if runtime.GOMAXPROCS(0) != 1 {
		reasons = append(reasons, "gomaxprocs_is_not_1")
	}
	if !trace.Summary.Enabled {
		reasons = append(reasons, "trace_collection_disabled")
	}
	if trace.TruncatedPrefix() {
		reasons = append(reasons, "trace_has_truncated_prefix_and_unknown_initial_cache_state")
	}
	if len(trace.Verifications) < config.MinimumRecords {
		reasons = append(reasons, "retained_verification_count_below_minimum")
	}
	for i := range trace.Verifications {
		if trace.Verifications[i].Outcome == mithriltracev3.OutcomeUnknown {
			reasons = append(reasons, "trace_contains_unknown_completion_outcomes")
			break
		}
	}
	if config.Samples < ReleaseSamples {
		reasons = append(reasons, "fewer_than_10_timing_samples")
	}
	if config.MinimumSampleDuration < ReleaseMinimumDuration {
		reasons = append(reasons, "timing_samples_shorter_than_3_seconds")
	}
	for i := range semantics {
		if semantics[i].KnownOutcomeMismatches != 0 || semantics[i].CrossVariantMismatches != 0 {
			reasons = append(reasons, "recorded_or_cross_variant_outcome_mismatch")
			break
		}
	}
	if stats.Tables == 0 || stats.Hits == 0 {
		reasons = append(reasons, "trace_produced_no_generic_cache_tables_or_hits")
	}
	return reasons
}

func sampleValues(samples []TimingSample) []float64 {
	values := make([]float64, len(samples))
	for i := range samples {
		values[i] = samples[i].NanosecondsPerVerification
	}
	sort.Float64s(values)
	return values
}

func sampleMallocValues(samples []TimingSample) []float64 {
	values := make([]float64, len(samples))
	for i := range samples {
		values[i] = samples[i].MallocsPerVerification
	}
	sort.Float64s(values)
	return values
}

func sampleByteValues(samples []TimingSample) []float64 {
	values := make([]float64, len(samples))
	for i := range samples {
		values[i] = samples[i].BytesPerVerification
	}
	sort.Float64s(values)
	return values
}

func median(sorted []float64) float64 {
	n := len(sorted)
	if n&1 == 1 {
		return sorted[n/2]
	}
	return (sorted[n/2-1] + sorted[n/2]) / 2
}

func compare(baseline, candidate VariantReport) ComparisonReport {
	baselineValues := rawSampleValues(baseline.Samples)
	candidateValues := rawSampleValues(candidate.Samples)
	medianSpeedup := speedup(medianCopy(baselineValues), medianCopy(candidateValues))
	lower := pairedBootstrapLower95(baselineValues, candidateValues)
	return ComparisonReport{
		Baseline:                baseline.Name,
		Candidate:               candidate.Name,
		MedianSpeedupPercent:    medianSpeedup,
		Lower95SpeedupPercent:   lower,
		ThresholdPercent:        CacheGainThreshold,
		MeetsThresholdAtLower95: lower >= CacheGainThreshold,
	}
}

func speedup(baseline, candidate float64) float64 {
	return 100 * (1 - candidate/baseline)
}

func pairedBootstrapLower95(baseline, candidate []float64) float64 {
	if len(baseline) != len(candidate) {
		panic("tracebench: paired timing sample counts differ")
	}
	distribution := make([]float64, bootstrapReplicates)
	rng := xorshift64{state: 0x6e617279612d7631}
	b := make([]float64, len(baseline))
	c := make([]float64, len(candidate))
	for replicate := range distribution {
		for i := range b {
			index := rng.index(len(baseline))
			b[i] = baseline[index]
			c[i] = candidate[index]
		}
		sort.Float64s(b)
		sort.Float64s(c)
		distribution[replicate] = speedup(median(b), median(c))
	}
	sort.Float64s(distribution)
	return distribution[bootstrapReplicates*25/1000]
}

func rawSampleValues(samples []TimingSample) []float64 {
	values := make([]float64, len(samples))
	for i := range samples {
		values[i] = samples[i].NanosecondsPerVerification
	}
	return values
}

func medianCopy(values []float64) float64 {
	copyOfValues := append([]float64(nil), values...)
	sort.Float64s(copyOfValues)
	return median(copyOfValues)
}

func buildProvenance() (version, revision, modified string) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown", "", ""
	}
	version = info.Main.Version
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			revision = setting.Value
		case "vcs.modified":
			modified = setting.Value
		}
	}
	return version, revision, modified
}

type xorshift64 struct{ state uint64 }

func (x *xorshift64) next() uint64 {
	x.state ^= x.state << 13
	x.state ^= x.state >> 7
	x.state ^= x.state << 17
	return x.state
}

func (x *xorshift64) index(n int) int { return int(x.next() % uint64(n)) }
