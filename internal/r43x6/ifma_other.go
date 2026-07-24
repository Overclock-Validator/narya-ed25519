//go:build !amd64

package r43x6

func ifmaMulRaw(out, x, y *Limbs) {
	panic("r43x6: unreachable IFMA call on non-amd64")
}
