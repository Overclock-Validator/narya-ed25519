//go:build purego

package r51x5

import "testing"

func TestExperimentalIFMAUnavailableWithoutNativeKernels(t *testing.T) {
	if ExperimentalIFMAAvailable() {
		t.Fatal("purego build reported omitted IFMA kernels as executable")
	}
}
