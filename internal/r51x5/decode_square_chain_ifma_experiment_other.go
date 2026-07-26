//go:build !amd64

package r51x5

func ifmaRepeatedSquareNormalizedExperimentX8(out, x *LimbsX8, count int) {
	state := *x
	for range count {
		ifmaMulNormalizedUncheckedX8(&state, &state, &state)
	}
	*out = state
}
