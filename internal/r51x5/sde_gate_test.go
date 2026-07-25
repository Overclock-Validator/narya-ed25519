//go:build sde_gate && amd64

package r51x5

import "testing"

// TestSDEIFMARequired turns an SDE configuration mistake into a hard failure.
// The ordinary hardware tests skip on unsupported hosts, which is appropriate
// outside the dedicated emulator job but would otherwise allow that job to go
// green without executing a single IFMA instruction.
func TestSDEIFMARequired(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Fatal("Intel SDE did not expose the AVX-512 IFMA feature set")
	}
}
