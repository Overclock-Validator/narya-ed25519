package ed25519

import "testing"

// TestBackendSelection pins the dispatch rules: without the ifma
// kernel built in (or off amd64), auto selects generic; once a backend
// is active it cannot be switched, only re-confirmed.
func TestBackendSelection(t *testing.T) {
	name := ActiveBackend()
	if name != "generic" && name != "ifma" {
		t.Fatalf("auto selected %q", name)
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
