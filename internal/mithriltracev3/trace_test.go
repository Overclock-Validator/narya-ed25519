package mithriltracev3

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestParseExactSchemaV3(t *testing.T) {
	input := encodeTestTrace(t, 1, false, false)
	trace, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if trace.Summary.Schema != Schema || trace.TruncatedPrefix() || len(trace.Verifications) != 1 {
		t.Fatalf("trace = %+v", trace)
	}
	v := trace.Verifications[0]
	if v.Outcome != OutcomeValid || !bytes.Equal(v.Message, []byte("message")) || v.Sequence != 1 {
		t.Fatalf("verification = %+v", v)
	}
}

func TestParseRejectsSchemaAndRecordDrift(t *testing.T) {
	valid := encodeTestTrace(t, 1, false, false)
	tests := []struct {
		name string
		edit func(string) string
	}{
		{"schema", func(s string) string { return strings.Replace(s, Schema, "mithril-sigverify-v4", 1) }},
		{"unknown-field", func(s string) string {
			return strings.Replace(s, `"type":"summary"`, `"type":"summary","new_field":1`, 1)
		}},
		{"uppercase-hex", func(s string) string {
			return strings.Replace(s, strings.Repeat("11", 32), "0A"+strings.Repeat("11", 31), 1)
		}},
		{"bad-key", func(s string) string { return strings.Replace(s, strings.Repeat("11", 32), "11", 1) }},
		{"noncanonical-base64", func(s string) string { return strings.Replace(s, `bWVzc2FnZQ==`, `bWVzc2FnZQ`, 1) }},
		{"bad-outcome", func(s string) string { return strings.Replace(s, `"outcome":"valid"`, `"outcome":"maybe"`, 1) }},
		{"bad-source", func(s string) string { return strings.Replace(s, `"source":"replay"`, `"source":"bogus"`, 1) }},
		{"reuse-over-capacity", func(s string) string {
			s = strings.Replace(s, `"public_key_reused":false`, `"public_key_reused":true`, 1)
			return strings.Replace(s, `"reuse_distance":0`, `"reuse_distance":2`, 1)
		}},
		{"wrong-retained-suffix", func(s string) string {
			s = strings.Replace(s, `"capacity":1`, `"capacity":2`, 1)
			return strings.Replace(s, `"verification_attempts":1`, `"verification_attempts":2`, 1)
		}},
		{"duplicate-event", func(s string) string {
			return strings.Replace(s, `"completion_event_sequence":2`, `"completion_event_sequence":1`, 1)
		}},
		{"trailing-record", func(s string) string { return s + "{}\n" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse(strings.NewReader(tc.edit(valid))); err == nil {
				t.Fatal("malformed trace parsed")
			}
		})
	}
}

func TestParseAllowsExplicitUnknownAndTruncatedSuffix(t *testing.T) {
	input := encodeTestTrace(t, 2, true, true)
	trace, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if !trace.TruncatedPrefix() || trace.Verifications[0].Sequence != 2 || trace.Verifications[0].Outcome != OutcomeUnknown {
		t.Fatalf("trace = %+v", trace)
	}
}

func TestValidateAuthoritativeDispatchBoundary(t *testing.T) {
	valid := &Trace{
		Summary: Summary{
			Type:               "summary",
			Schema:             Schema,
			Enabled:            true,
			Mode:               ModePassive,
			Capacity:           1,
			ObservedEvents:     2,
			RetainedDispatches: 1,
		},
		Dispatches: []Dispatch{{
			DispatchID:         1,
			ClaimEventSequence: 1,
			ReadyEventSequence: 2,
			Mode:               ModePassive,
			Source:             "replay",
			SignatureLanes:     1,
			JobSignatures:      []uint16{1},
		}},
	}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}

	badLaneSum := *valid
	badLaneSum.Dispatches = append([]Dispatch(nil), valid.Dispatches...)
	badLaneSum.Dispatches[0].SignatureLanes = 2
	if err := badLaneSum.Validate(); err == nil {
		t.Fatal("dispatch with a bad lane sum validated")
	}

	unready := *valid
	unready.Dispatches = append([]Dispatch(nil), valid.Dispatches...)
	unready.Dispatches[0].ReadyEventSequence = 0
	if err := unready.Validate(); err == nil {
		t.Fatal("unready dispatch with lane metadata validated")
	}

	passiveMultiJob := *valid
	passiveMultiJob.Dispatches = append([]Dispatch(nil), valid.Dispatches...)
	passiveMultiJob.Dispatches[0].SignatureLanes = 2
	passiveMultiJob.Dispatches[0].JobSignatures = []uint16{1, 1}
	if err := passiveMultiJob.Validate(); err == nil {
		t.Fatal("passive multi-job dispatch validated")
	}
}

func encodeTestTrace(t *testing.T, attempts uint64, unknown, truncated bool) string {
	t.Helper()
	sequence := uint64(1)
	if truncated {
		sequence = attempts
	} else {
		attempts = 1
	}
	summary := Summary{
		Type:                  "summary",
		Schema:                Schema,
		Enabled:               true,
		Mode:                  ModePassive,
		Capacity:              1,
		VerificationAttempts:  attempts,
		ObservedEvents:        2,
		RetainedVerifications: 1,
	}
	outcome := "valid"
	completion := uint64(2)
	if unknown {
		outcome = "unknown"
		completion = 0
	}
	record := verificationJSON{
		Type:                    "verification",
		Sequence:                sequence,
		BeginEventSequence:      1,
		CompletionEventSequence: completion,
		Source:                  "replay",
		PublicKey:               hex.EncodeToString(bytes.Repeat([]byte{0x11}, 32)),
		Signature:               hex.EncodeToString(bytes.Repeat([]byte{0x22}, 64)),
		Message:                 base64.StdEncoding.EncodeToString([]byte("message")),
		Outcome:                 outcome,
	}
	var out strings.Builder
	for _, value := range []any{summary, record} {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		out.Write(encoded)
		out.WriteByte('\n')
	}
	return out.String()
}
