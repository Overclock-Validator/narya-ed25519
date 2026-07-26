//go:build amd64

package r51x5

// ifmaRepeatedSquareNormalizedExperimentX8 computes count dependent squares
// while retaining the five-limb running value in ZMM registers. Inputs must
// satisfy the composable u52 contract. The output is bit-identical to count
// calls to ifmaMulNormalizedUncheckedX8(state,state,state), including count=0,
// and may alias x. The caller must enforce the IFMA CPU gate.
//
//go:noescape
func ifmaRepeatedSquareNormalizedExperimentX8(out, x *LimbsX8, count int)
