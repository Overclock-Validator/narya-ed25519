//go:build !amd64

package r51x5

func ifmaMulRawX8(out *IFMAProductX8, x, y *LimbsX8) {
	panic("r51x5: unreachable x8 IFMA call on non-amd64")
}

func ifmaMulRawX4(out *IFMAProductX4, x, y *LimbsX4) {
	panic("r51x5: unreachable x4 IFMA call on non-amd64")
}
