//go:build amd64 && !purego

package r51x5

// ifmaMicroAoSTransposeSelectExperimentX4 loads five contiguous [X,Y,Z,T]
// rows from each selected per-key entry and performs five independent 4x4
// uint64 register transposes into IFMAPointX4.
//
// All twenty source vectors are loaded before the first output store, so out
// may exactly overlap any or all of the four source entries. The caller must
// enforce the IFMA backend CPU gate; the high YMM registers and shuffle use
// the AVX-512F/VL subset already required by that backend.
//
//go:noescape
func ifmaMicroAoSTransposeSelectExperimentX4(out *IFMAPointX4, p0, p1, p2, p3 *ifmaMicroAoSPointEntryExperiment)
