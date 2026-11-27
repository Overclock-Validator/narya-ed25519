//go:build sde_gate && amd64

package keccakmb

import "testing"

// TestSDENativeKeccakRequired prevents the emulator job from silently
// exercising only the portable path when its CPU model lacks AVX-512.
func TestSDENativeKeccakRequired(t *testing.T) {
	if !ExperimentalNativeAvailable() {
		t.Fatal("Intel SDE did not expose the AVX-512 Keccak kernel")
	}
}
