//go:build sde_gate && amd64

package sha512mb

import "testing"

// TestSDENativeSHARequired prevents the dedicated emulator job from silently
// exercising the scalar fallback when its emulated CPU model is misconfigured.
func TestSDENativeSHARequired(t *testing.T) {
	for _, width := range []int{nativeX4Width, nativeX8Width} {
		if !ExperimentalNativeAvailable(width) {
			t.Fatalf("Intel SDE did not expose the native x%d SHA-512 kernel", width)
		}
	}
}
