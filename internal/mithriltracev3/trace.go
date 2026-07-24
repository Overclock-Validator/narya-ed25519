// Package mithriltracev3 strictly parses the exact-input records emitted by
// Mithril's mithril-sigverify-v3 telemetry exporter. It intentionally lives in
// offline tooling: importing this package does not couple either verifier or
// Mithril production code to the other project.
//
// Parse and Validate mirror mithril/pkg/sigverifytrace/trace.go. Keep their
// canonical encodings, source vocabulary, bounded-ring invariants, dispatch
// validation, and lane correlation synchronized when the schema changes. The
// fixtures in trace_test.go exercise the same acceptance/rejection boundary.
package mithriltracev3

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const Schema = "mithril-sigverify-v3"

type CollectionMode string

const (
	ModeDisabled             CollectionMode = "disabled"
	ModePassive              CollectionMode = "passive"
	ModeSchedulingSimulation CollectionMode = "scheduling_simulation"
)

type Outcome uint8

const (
	OutcomeUnknown Outcome = iota
	OutcomeValid
	OutcomeInvalid
)

func (o Outcome) String() string {
	switch o {
	case OutcomeValid:
		return "valid"
	case OutcomeInvalid:
		return "invalid"
	default:
		return "unknown"
	}
}

func (o Outcome) MarshalJSON() ([]byte, error) { return json.Marshal(o.String()) }

type Summary struct {
	Type                     string         `json:"type"`
	Schema                   string         `json:"schema"`
	Enabled                  bool           `json:"enabled"`
	Mode                     CollectionMode `json:"collection_mode"`
	Capacity                 uint64         `json:"capacity"`
	Transactions             uint64         `json:"transactions"`
	Signatures               uint64         `json:"signatures"`
	MessageBytes             uint64         `json:"message_bytes"`
	VerificationAttempts     uint64         `json:"verification_attempts"`
	ObservedEvents           uint64         `json:"observed_events"`
	RetainedVerifications    int            `json:"retained_verifications"`
	RetainedDispatches       int            `json:"retained_dispatches"`
	ExactDuplicateHits       uint64         `json:"exact_duplicate_hits"`
	PublicKeyReuseHits       uint64         `json:"public_key_reuse_hits"`
	QueueSamples             uint64         `json:"queue_samples"`
	QueueOccupancySum        uint64         `json:"queue_occupancy_sum"`
	QueueOccupancyMax        uint64         `json:"queue_occupancy_max"`
	BatchSamples             uint64         `json:"batch_samples"`
	NaturalBatchWidthSum     uint64         `json:"natural_batch_width_sum"`
	NaturalBatchWidthMax     uint64         `json:"natural_batch_width_max"`
	SignaturesPerTransaction [19]uint64     `json:"signatures_per_transaction"`
	MessageSize              [9]uint64      `json:"message_size"`
	ReuseDistance            [19]uint64     `json:"reuse_distance"`
	QueueOccupancy           [16]uint64     `json:"queue_occupancy"`
	NaturalBatchWidth        [20]uint64     `json:"natural_batch_width"`
}

type Verification struct {
	Sequence                uint64
	BeginEventSequence      uint64
	CompletionEventSequence uint64
	Source                  string
	PublicKey               [32]byte
	Signature               [64]byte
	Message                 []byte
	ExactDuplicate          bool
	PublicKeyReused         bool
	ReuseDistance           uint64
	Outcome                 Outcome
	DispatchID              uint64
	JobIndex                uint32
	LaneIndex               uint32
}

type Dispatch struct {
	DispatchID         uint64
	ClaimEventSequence uint64
	ReadyEventSequence uint64
	Mode               CollectionMode
	Source             string
	QueuedItemsBefore  uint64
	QueuedItemsAfter   uint64
	SignatureLanes     uint64
	JobSignatures      []uint16
}

type Trace struct {
	Summary       Summary
	Verifications []Verification
	Dispatches    []Dispatch
}

func (t *Trace) TruncatedPrefix() bool {
	return uint64(len(t.Verifications)) < t.Summary.VerificationAttempts
}

type envelope struct {
	Type string `json:"type"`
}

type verificationJSON struct {
	Type                    string `json:"type"`
	Sequence                uint64 `json:"sequence"`
	BeginEventSequence      uint64 `json:"begin_event_sequence"`
	CompletionEventSequence uint64 `json:"completion_event_sequence"`
	Source                  string `json:"source"`
	PublicKey               string `json:"public_key"`
	Signature               string `json:"signature"`
	Message                 string `json:"message_base64"`
	ExactDuplicate          bool   `json:"exact_duplicate"`
	PublicKeyReused         bool   `json:"public_key_reused"`
	ReuseDistance           uint64 `json:"reuse_distance"`
	Outcome                 string `json:"outcome"`
	DispatchID              uint64 `json:"dispatch_id"`
	JobIndex                uint32 `json:"job_index"`
	LaneIndex               uint32 `json:"lane_index"`
}

type dispatchJSON struct {
	Type               string         `json:"type"`
	DispatchID         uint64         `json:"dispatch_id"`
	ClaimEventSequence uint64         `json:"claim_event_sequence"`
	ReadyEventSequence uint64         `json:"ready_event_sequence"`
	Mode               CollectionMode `json:"dispatch_mode"`
	Source             string         `json:"source"`
	QueuedItemsBefore  uint64         `json:"queued_items_before"`
	QueuedItemsAfter   uint64         `json:"queued_items_after"`
	SignatureLanes     uint64         `json:"signature_lanes"`
	JobSignatures      []uint16       `json:"job_signatures"`
}

// Parse accepts exactly one schema-v3 summary, followed by verification
// records and then dispatch records. Unknown fields are errors so a future
// schema revision cannot silently be benchmarked under v3 assumptions.
func Parse(r io.Reader) (*Trace, error) {
	if r == nil {
		return nil, errors.New("mithriltracev3: nil reader")
	}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	trace := new(Trace)
	line := 0
	seenSummary := false
	seenDispatch := false
	for scanner.Scan() {
		line++
		raw := bytes.TrimSpace(scanner.Bytes())
		if len(raw) == 0 {
			return nil, fmt.Errorf("mithriltracev3: line %d is empty", line)
		}
		var kind envelope
		if err := json.Unmarshal(raw, &kind); err != nil {
			return nil, fmt.Errorf("mithriltracev3: line %d envelope: %w", line, err)
		}
		switch kind.Type {
		case "summary":
			if seenSummary || line != 1 {
				return nil, fmt.Errorf("mithriltracev3: line %d has duplicate or misplaced summary", line)
			}
			if err := decodeStrict(raw, &trace.Summary); err != nil {
				return nil, fmt.Errorf("mithriltracev3: line %d summary: %w", line, err)
			}
			seenSummary = true
		case "verification":
			if !seenSummary || seenDispatch {
				return nil, fmt.Errorf("mithriltracev3: line %d has misplaced verification", line)
			}
			var encoded verificationJSON
			if err := decodeStrict(raw, &encoded); err != nil {
				return nil, fmt.Errorf("mithriltracev3: line %d verification: %w", line, err)
			}
			verification, err := decodeVerification(encoded)
			if err != nil {
				return nil, fmt.Errorf("mithriltracev3: line %d verification: %w", line, err)
			}
			trace.Verifications = append(trace.Verifications, verification)
		case "dispatch":
			if !seenSummary {
				return nil, fmt.Errorf("mithriltracev3: line %d has dispatch before summary", line)
			}
			seenDispatch = true
			var encoded dispatchJSON
			if err := decodeStrict(raw, &encoded); err != nil {
				return nil, fmt.Errorf("mithriltracev3: line %d dispatch: %w", line, err)
			}
			trace.Dispatches = append(trace.Dispatches, Dispatch{
				DispatchID:         encoded.DispatchID,
				ClaimEventSequence: encoded.ClaimEventSequence,
				ReadyEventSequence: encoded.ReadyEventSequence,
				Mode:               encoded.Mode,
				Source:             encoded.Source,
				QueuedItemsBefore:  encoded.QueuedItemsBefore,
				QueuedItemsAfter:   encoded.QueuedItemsAfter,
				SignatureLanes:     encoded.SignatureLanes,
				JobSignatures:      append([]uint16(nil), encoded.JobSignatures...),
			})
		default:
			return nil, fmt.Errorf("mithriltracev3: line %d has unknown record type %q", line, kind.Type)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("mithriltracev3: read trace: %w", err)
	}
	if !seenSummary {
		return nil, errors.New("mithriltracev3: missing summary")
	}
	if err := trace.Validate(); err != nil {
		return nil, err
	}
	return trace, nil
}

func decodeStrict(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func decodeVerification(v verificationJSON) (Verification, error) {
	var result Verification
	if err := decodeFixedHex(result.PublicKey[:], v.PublicKey); err != nil {
		return result, fmt.Errorf("public key: %w", err)
	}
	if err := decodeFixedHex(result.Signature[:], v.Signature); err != nil {
		return result, fmt.Errorf("signature: %w", err)
	}
	message, err := base64.StdEncoding.DecodeString(v.Message)
	if err != nil || base64.StdEncoding.EncodeToString(message) != v.Message {
		if err == nil {
			err = errors.New("noncanonical base64")
		}
		return result, fmt.Errorf("message: %w", err)
	}
	outcome, err := parseOutcome(v.Outcome)
	if err != nil {
		return result, err
	}
	return Verification{
		Sequence:                v.Sequence,
		BeginEventSequence:      v.BeginEventSequence,
		CompletionEventSequence: v.CompletionEventSequence,
		Source:                  v.Source,
		PublicKey:               result.PublicKey,
		Signature:               result.Signature,
		Message:                 message,
		ExactDuplicate:          v.ExactDuplicate,
		PublicKeyReused:         v.PublicKeyReused,
		ReuseDistance:           v.ReuseDistance,
		Outcome:                 outcome,
		DispatchID:              v.DispatchID,
		JobIndex:                v.JobIndex,
		LaneIndex:               v.LaneIndex,
	}, nil
}

func decodeFixedHex(out []byte, encoded string) error {
	if len(encoded) != hex.EncodedLen(len(out)) {
		return fmt.Errorf("encoded length %d, want %d", len(encoded), hex.EncodedLen(len(out)))
	}
	decoded, err := hex.DecodeString(encoded)
	if err != nil {
		return err
	}
	if hex.EncodeToString(decoded) != encoded {
		return errors.New("noncanonical lowercase hex")
	}
	copy(out, decoded)
	return nil
}

func parseOutcome(label string) (Outcome, error) {
	switch label {
	case "unknown":
		return OutcomeUnknown, nil
	case "valid":
		return OutcomeValid, nil
	case "invalid":
		return OutcomeInvalid, nil
	default:
		return OutcomeUnknown, fmt.Errorf("unknown outcome %q", label)
	}
}

func validSource(source string) bool {
	switch source {
	case "replay", "tpu", "turbine", "unknown":
		return true
	default:
		return false
	}
}

// Validate checks all invariants available in a bounded v3 export. Missing
// cross-ring records are tolerated because verification and dispatch histories
// are independently bounded; exact SIMD reconstruction is outside this tool.
func (trace *Trace) Validate() error {
	if trace == nil {
		return errors.New("mithriltracev3: nil trace")
	}
	s := trace.Summary
	if s.Type != "summary" || s.Schema != Schema {
		return fmt.Errorf("mithriltracev3: summary type/schema = %q/%q", s.Type, s.Schema)
	}
	switch s.Mode {
	case ModeDisabled, ModePassive, ModeSchedulingSimulation:
	default:
		return fmt.Errorf("mithriltracev3: invalid collection mode %q", s.Mode)
	}
	if s.Enabled && s.Mode == ModeDisabled || !s.Enabled && s.Mode != ModeDisabled {
		return fmt.Errorf("mithriltracev3: enabled=%v conflicts with mode %q", s.Enabled, s.Mode)
	}
	if s.Enabled && s.Capacity == 0 {
		return errors.New("mithriltracev3: enabled trace has zero capacity")
	}
	if s.RetainedVerifications != len(trace.Verifications) || s.RetainedDispatches != len(trace.Dispatches) {
		return fmt.Errorf("mithriltracev3: retained counts summary=%d/%d records=%d/%d", s.RetainedVerifications, s.RetainedDispatches, len(trace.Verifications), len(trace.Dispatches))
	}
	if uint64(len(trace.Verifications)) > s.VerificationAttempts {
		return errors.New("mithriltracev3: retained verifications exceed attempts")
	}
	wantRetained := s.VerificationAttempts
	if wantRetained > s.Capacity {
		wantRetained = s.Capacity
	}
	if s.Enabled && uint64(len(trace.Verifications)) != wantRetained {
		return fmt.Errorf("mithriltracev3: retained verification suffix has %d records, want %d", len(trace.Verifications), wantRetained)
	}
	events := make(map[uint64]string, 2*len(trace.Verifications)+2*len(trace.Dispatches))
	claimByID := make(map[uint64]*Dispatch, len(trace.Dispatches))
	var previousSequence uint64
	var previousBegin uint64
	for index := range trace.Verifications {
		verification := &trace.Verifications[index]
		if verification.Sequence == 0 || verification.Sequence <= previousSequence || verification.Sequence > s.VerificationAttempts {
			return fmt.Errorf("mithriltracev3: verification sequence %d is not a retained increasing attempt", verification.Sequence)
		}
		previousSequence = verification.Sequence
		wantSequence := s.VerificationAttempts - uint64(len(trace.Verifications)) + uint64(index) + 1
		if verification.Sequence != wantSequence {
			return fmt.Errorf("mithriltracev3: verification sequence %d, want contiguous suffix value %d", verification.Sequence, wantSequence)
		}
		if verification.BeginEventSequence == 0 || verification.BeginEventSequence <= previousBegin {
			return fmt.Errorf("mithriltracev3: verification %d has non-increasing begin event %d", verification.Sequence, verification.BeginEventSequence)
		}
		previousBegin = verification.BeginEventSequence
		if !validSource(verification.Source) {
			return fmt.Errorf("mithriltracev3: verification %d has invalid source %q", verification.Sequence, verification.Source)
		}
		if verification.ExactDuplicate && !verification.PublicKeyReused {
			return fmt.Errorf("mithriltracev3: verification %d is duplicate without key reuse", verification.Sequence)
		}
		if verification.PublicKeyReused {
			if verification.ReuseDistance == 0 || verification.ReuseDistance > s.Capacity {
				return fmt.Errorf("mithriltracev3: verification %d has invalid reuse distance %d", verification.Sequence, verification.ReuseDistance)
			}
		} else if verification.ReuseDistance != 0 {
			return fmt.Errorf("mithriltracev3: verification %d has distance without reuse", verification.Sequence)
		}
		if err := addEvent(events, verification.BeginEventSequence, s.ObservedEvents, fmt.Sprintf("verification %d begin", verification.Sequence)); err != nil {
			return err
		}
		if verification.CompletionEventSequence == 0 {
			if verification.Outcome != OutcomeUnknown {
				return fmt.Errorf("mithriltracev3: verification %d has outcome without completion", verification.Sequence)
			}
		} else {
			if verification.CompletionEventSequence <= verification.BeginEventSequence || verification.Outcome == OutcomeUnknown {
				return fmt.Errorf("mithriltracev3: verification %d has invalid completion/outcome", verification.Sequence)
			}
			if err := addEvent(events, verification.CompletionEventSequence, s.ObservedEvents, fmt.Sprintf("verification %d completion", verification.Sequence)); err != nil {
				return err
			}
		}
		if verification.DispatchID == 0 && (verification.JobIndex != 0 || verification.LaneIndex != 0) {
			return fmt.Errorf("mithriltracev3: uncorrelated verification %d has job/lane", verification.Sequence)
		}
	}
	var previousDispatch uint64
	for index := range trace.Dispatches {
		dispatch := &trace.Dispatches[index]
		if dispatch.DispatchID == 0 || dispatch.DispatchID <= previousDispatch {
			return fmt.Errorf("mithriltracev3: dispatch ID %d is not increasing", dispatch.DispatchID)
		}
		previousDispatch = dispatch.DispatchID
		if index > 0 && dispatch.DispatchID != trace.Dispatches[index-1].DispatchID+1 {
			return fmt.Errorf("mithriltracev3: dispatch IDs %d and %d are not a contiguous retained suffix", trace.Dispatches[index-1].DispatchID, dispatch.DispatchID)
		}
		if dispatch.Mode != s.Mode || dispatch.Mode == ModeDisabled || !validSource(dispatch.Source) {
			return fmt.Errorf("mithriltracev3: dispatch %d has invalid mode/source", dispatch.DispatchID)
		}
		if dispatch.ClaimEventSequence == 0 {
			return fmt.Errorf("mithriltracev3: dispatch %d has zero claim event", dispatch.DispatchID)
		}
		if err := addEvent(events, dispatch.ClaimEventSequence, s.ObservedEvents, fmt.Sprintf("dispatch %d claim", dispatch.DispatchID)); err != nil {
			return err
		}
		if dispatch.ReadyEventSequence == 0 {
			if dispatch.SignatureLanes != 0 || len(dispatch.JobSignatures) != 0 {
				return fmt.Errorf("mithriltracev3: unready dispatch %d has lane metadata", dispatch.DispatchID)
			}
		} else {
			if dispatch.ReadyEventSequence <= dispatch.ClaimEventSequence {
				return fmt.Errorf("mithriltracev3: dispatch %d ready precedes claim", dispatch.DispatchID)
			}
			if err := addEvent(events, dispatch.ReadyEventSequence, s.ObservedEvents, fmt.Sprintf("dispatch %d ready", dispatch.DispatchID)); err != nil {
				return err
			}
			var lanes uint64
			for _, count := range dispatch.JobSignatures {
				lanes += uint64(count)
			}
			if lanes != dispatch.SignatureLanes {
				return fmt.Errorf("mithriltracev3: dispatch %d lane sum %d != %d", dispatch.DispatchID, lanes, dispatch.SignatureLanes)
			}
			if dispatch.Mode == ModePassive && len(dispatch.JobSignatures) != 1 {
				return fmt.Errorf("mithriltracev3: passive dispatch %d has %d jobs", dispatch.DispatchID, len(dispatch.JobSignatures))
			}
		}
		claimByID[dispatch.DispatchID] = dispatch
	}
	correlated := make(map[[3]uint64]uint64)
	invalidLane := make(map[[2]uint64]uint32)
	for index := range trace.Verifications {
		verification := &trace.Verifications[index]
		if verification.DispatchID == 0 {
			continue
		}
		dispatch := claimByID[verification.DispatchID]
		if dispatch == nil {
			continue
		}
		if dispatch.ReadyEventSequence == 0 || verification.BeginEventSequence <= dispatch.ReadyEventSequence {
			return fmt.Errorf("mithriltracev3: verification %d began before dispatch %d was ready", verification.Sequence, verification.DispatchID)
		}
		if verification.Source != dispatch.Source {
			return fmt.Errorf("mithriltracev3: verification %d source %q differs from dispatch %d source %q", verification.Sequence, verification.Source, dispatch.DispatchID, dispatch.Source)
		}
		if uint64(verification.JobIndex) >= uint64(len(dispatch.JobSignatures)) || verification.LaneIndex >= uint32(dispatch.JobSignatures[verification.JobIndex]) {
			return fmt.Errorf("mithriltracev3: verification %d job/lane is outside dispatch %d", verification.Sequence, verification.DispatchID)
		}
		key := [3]uint64{verification.DispatchID, uint64(verification.JobIndex), uint64(verification.LaneIndex)}
		if prior := correlated[key]; prior != 0 {
			return fmt.Errorf("mithriltracev3: verifications %d and %d share dispatch job/lane", prior, verification.Sequence)
		}
		correlated[key] = verification.Sequence
		jobKey := [2]uint64{verification.DispatchID, uint64(verification.JobIndex)}
		if stoppedAt, ok := invalidLane[jobKey]; ok && verification.LaneIndex > stoppedAt {
			return fmt.Errorf("mithriltracev3: verification %d appears after invalid lane %d in its job", verification.Sequence, stoppedAt)
		}
		if verification.Outcome == OutcomeInvalid {
			invalidLane[jobKey] = verification.LaneIndex
		}
	}
	return nil
}

func addEvent(events map[uint64]string, event, observed uint64, label string) error {
	if event == 0 || event > observed {
		return fmt.Errorf("mithriltracev3: %s event %d exceeds observed clock %d", label, event, observed)
	}
	if prior := events[event]; prior != "" {
		return fmt.Errorf("mithriltracev3: event %d is both %s and %s", event, prior, label)
	}
	events[event] = label
	return nil
}
