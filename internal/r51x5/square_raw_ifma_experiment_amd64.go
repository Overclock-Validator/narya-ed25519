//go:build amd64

package r51x5

// ifmaSquareRawExperimentX4 squares four u52 radix-2^51 representatives and
// returns the exact folded u61 representation produced by
// ifmaMulRawX4(out, x, x). All inputs are loaded before any output store, so
// out may exactly alias x when their identical layouts are explicitly cast.
//
//go:noescape
func ifmaSquareRawExperimentX4(out *IFMAProductX4, x *LimbsX4)

// ifmaSquareRawExperimentX8 is the native-ZMM counterpart. It preserves the
// exact folded-u61 representation of ifmaMulRawX8(out, x, x), loads every
// input before the first store, and therefore supports exact out/x aliasing.
//
//go:noescape
func ifmaSquareRawExperimentX8(out *IFMAProductX8, x *LimbsX8)
