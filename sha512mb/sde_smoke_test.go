//go:build sde_gate && amd64

package sha512mb

import (
	"fmt"
	"testing"
)

// TestSDENativeSHASmoke keeps emulator coverage deliberately small. Intel SDE
// is orders of magnitude slower than native hardware: running the exhaustive
// native differential corpus under it exhausted the entire CI job before the
// verifier tests could start.
//
// The selected shapes still exercise both native widths, a complete group and
// a one-lane tail, the general segmented scheduler, the verifier's fixed-three-
// segment scheduler, the SHA-512 111/112-byte padding boundary (47/48 message
// bytes after the 64-byte R/A prefix), and a 1232-byte message. The exhaustive
// randomized and edge differential tests remain hardware-test gates.
func TestSDENativeSHASmoke(t *testing.T) {
	messageLengths := [...]int{0, 47, 48, 200, 1232, 1, 64}
	for _, width := range []int{nativeX4Width, nativeX8Width} {
		width := width
		t.Run(fmt.Sprintf("x%d", width), func(t *testing.T) {
			if !ExperimentalNativeAvailable(width) {
				t.Fatalf("Intel SDE did not expose the native x%d SHA-512 kernel", width)
			}

			count := width + 1
			fixed := make([][3][]byte, count)
			general := make([][][]byte, count)
			for lane := range fixed {
				fixed[lane][0] = deterministicSDEBytes(32, lane, 0)
				fixed[lane][1] = deterministicSDEBytes(32, lane, 1)
				fixed[lane][2] = deterministicSDEBytes(messageLengths[lane%len(messageLengths)], lane, 2)
				general[lane] = fixed[lane][:]
			}

			fixedOut := make([][64]byte, count)
			if !ExperimentalSum512Batch3(fixedOut, fixed, width) {
				t.Fatalf("native x%d fixed-three scheduler became unavailable", width)
			}
			checkNativeDigests3(t, fixed, fixedOut)

			generalOut := make([][64]byte, count)
			if !ExperimentalSum512Batch(generalOut, general, width) {
				t.Fatalf("native x%d general scheduler became unavailable", width)
			}
			checkNativeDigests(t, general, generalOut)
		})
	}
}

func deterministicSDEBytes(length, lane, part int) []byte {
	out := make([]byte, length)
	for i := range out {
		out[i] = byte(17*lane + 29*part + 31*i)
	}
	return out
}
