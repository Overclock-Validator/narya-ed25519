//go:build !amd64 || purego

package r51x5

func ifmaRepeatedSquareNormalizedX4(out, x *LimbsX4, count int) {
	state := *x
	for range count {
		ifmaMulNormalizedUncheckedX4(&state, &state, &state)
	}
	*out = state
}

func ifmaRepeatedSquareNormalizedX8(out, x *LimbsX8, count int) {
	state := *x
	for range count {
		ifmaMulNormalizedUncheckedX8(&state, &state, &state)
	}
	*out = state
}
