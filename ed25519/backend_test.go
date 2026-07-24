package ed25519

import "testing"

// TestBackendSelection pins the development dispatch rule: automatic
// selection stays generic even while an experimental IFMA backend is built.
// Once a backend is active it cannot be switched, only re-confirmed.
func TestBackendSelection(t *testing.T) {
	name := ActiveBackend()
	if name != "generic" {
		t.Fatalf("development auto selection = %q, want generic", name)
	}
	if err := SetBackend(name); err != nil {
		t.Fatalf("re-confirming the active backend errored: %v", err)
	}
	if err := SetBackend("stdlib"); err == nil {
		t.Fatal("switching an active backend must error")
	}
	if err := SetBackend("nope"); err == nil {
		t.Fatal("unknown backend must error")
	}
}
