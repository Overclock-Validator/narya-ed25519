//go:build amd64

package r51x5

// ifmaSquareNormalizedExperimentX4 squares four u52 radix-2^51 field
// representatives and carries the folded product back into the u52 domain.
//
// This is an unwired experiment for measuring a symmetry-aware square against
// ifmaMulNormalizedUncheckedX4(out, x, x). All five input vectors are loaded
// before the first output store, so out and x may alias.
//
//go:noescape
func ifmaSquareNormalizedExperimentX4(out, x *LimbsX4)
