//go:build amd64

package r51x5

// ifmaMulRawX8 multiplies eight lanes whose limbs are below 2^52 and emits an
// exact folded IFMAProductX8 below 2^61. The caller must enforce cpufeat.IFMA
// before entry and carry-normalize the result before reusing it.
//
//go:noescape
func ifmaMulRawX8(out *IFMAProductX8, x, y *LimbsX8)

// ifmaMulRawX4 is the AVX-512VL/YMM analogue of ifmaMulRawX8.
//
//go:noescape
func ifmaMulRawX4(out *IFMAProductX4, x, y *LimbsX4)
