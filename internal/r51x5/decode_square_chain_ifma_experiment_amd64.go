//go:build amd64 && !purego

package r51x5

// ifmaRepeatedSquareNormalizedX4 computes count dependent squares
// while retaining the five-limb running value in YMM registers. Inputs must
// satisfy the composable u52 contract. The output is bit-identical to count
// calls to ifmaMulNormalizedUncheckedX4(state,state,state), including count=0,
// and may alias x. Count must be non-negative. The caller must enforce the
// IFMA CPU gate.
//
//go:noescape
func ifmaRepeatedSquareNormalizedX4(out, x *LimbsX4, count int)

// ifmaRepeatedSquareNormalizedX8 computes count dependent squares
// while retaining the five-limb running value in ZMM registers. Inputs must
// satisfy the composable u52 contract. The output is bit-identical to count
// calls to ifmaMulNormalizedUncheckedX8(state,state,state), including count=0,
// and may alias x. Count must be non-negative. The caller must enforce the
// IFMA CPU gate.
//
//go:noescape
func ifmaRepeatedSquareNormalizedX8(out, x *LimbsX8, count int)
