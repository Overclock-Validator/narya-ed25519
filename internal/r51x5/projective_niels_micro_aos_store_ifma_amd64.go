//go:build amd64

package r51x5

// ifmaProjectiveNielsPreSignedMicroAoSStoreTransposeX8 transposes one x8 SoA
// projective-Niels point and its precomputed negative T coordinate directly
// into entry of the eight per-key micro-AoS tables. entry must be in [0,16).
// Sources and table must not overlap.
//
//go:noescape
func ifmaProjectiveNielsPreSignedMicroAoSStoreTransposeX8(
	table *ifmaProjectiveNielsPreSignedMicroAoSTableX8,
	entry uint64,
	point *IFMAProjectiveNielsX8,
	negativeT2D *IFMAElementX8,
)
