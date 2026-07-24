package main

import (
	"bytes"
	stdlibed25519 "crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateOutputPathRejectsInputAndExistingEvidence(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "trace.jsonl")
	if err := os.WriteFile(input, []byte("trace"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateOutputPath(input, input); err == nil || !strings.Contains(err.Error(), "input trace") {
		t.Fatalf("same-path error = %v", err)
	}
	hardlink := filepath.Join(dir, "same-trace.jsonl")
	if err := os.Link(input, hardlink); err != nil {
		t.Fatal(err)
	}
	if err := validateOutputPath(input, hardlink); err == nil || !strings.Contains(err.Error(), "input trace") {
		t.Fatalf("hardlink error = %v", err)
	}
	existing := filepath.Join(dir, "evidence.json")
	if err := os.WriteFile(existing, []byte("prior"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateOutputPath(input, existing); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("existing-output error = %v", err)
	}
	if err := validateOutputPath(input, filepath.Join(dir, "new-evidence.json")); err != nil {
		t.Fatalf("new output rejected: %v", err)
	}
}

func TestBackendIsFixedGeneric(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run([]string{"-backend=ifma"}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "flag provided but not defined") {
		t.Fatalf("backend flag error = %v", err)
	}
}

func TestRunEmitsPinnedGenericDiagnosticArtifact(t *testing.T) {
	public, private, err := stdlibed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("tracebench-cli")
	signature := stdlibed25519.Sign(private, message)
	trace := fmt.Sprintf(
		"{\"type\":\"summary\",\"schema\":\"mithril-sigverify-v3\",\"enabled\":true,\"collection_mode\":\"passive\",\"capacity\":1,\"verification_attempts\":1,\"observed_events\":2,\"retained_verifications\":1,\"retained_dispatches\":0}\n"+
			"{\"type\":\"verification\",\"sequence\":1,\"begin_event_sequence\":1,\"completion_event_sequence\":2,\"source\":\"replay\",\"public_key\":%q,\"signature\":%q,\"message_base64\":%q,\"exact_duplicate\":false,\"public_key_reused\":false,\"reuse_distance\":0,\"outcome\":\"valid\",\"dispatch_id\":0,\"job_index\":0,\"lane_index\":0}\n",
		hex.EncodeToString(public), hex.EncodeToString(signature), base64.StdEncoding.EncodeToString(message),
	)
	input := filepath.Join(t.TempDir(), "trace.jsonl")
	if err := os.WriteFile(input, []byte(trace), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := run([]string{
		"-input", input,
		"-samples=1",
		"-sample-time=1ns",
		"-min-records=1",
		"-representative",
		"-pinned-core-attested",
		"-pretty=false",
	}, &stdout, &stderr); err != nil {
		t.Fatalf("run: %v, stderr=%s", err, stderr.String())
	}
	var result struct {
		Backend   string `json:"narya_backend"`
		InputHash string `json:"input_sha256"`
		Execution struct {
			Pinned bool `json:"pinned_core_attested"`
		} `json:"execution"`
		Production struct {
			Qualifying bool   `json:"qualifying"`
			Status     string `json:"status"`
		} `json:"production_r51_cache_gate"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("decode report: %v\n%s", err, stdout.String())
	}
	if result.Backend != "generic" || result.InputHash == "" || !result.Execution.Pinned {
		t.Fatalf("artifact identity = %+v", result)
	}
	if result.Production.Qualifying || result.Production.Status != "pending_backend_native_cache" {
		t.Fatalf("production gate = %+v", result.Production)
	}
}
