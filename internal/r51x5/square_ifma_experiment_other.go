//go:build !amd64 || purego

package r51x5

// Keep the experiment buildable on non-amd64 test hosts. Hardware tests and
// benchmarks skip before calling this fallback.
func ifmaSquareNormalizedExperimentX4(out, x *LimbsX4) {
	ifmaMulNormalizedUncheckedX4(out, x, x)
}

func ifmaSquareNormalizedExperimentX8(out, x *LimbsX8) {
	ifmaMulNormalizedUncheckedX8(out, x, x)
}
