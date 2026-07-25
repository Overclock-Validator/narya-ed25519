//go:build !amd64

package sha512mb

func nativeX4Available() bool { return false }
func nativeX8Available() bool { return false }

func nativeCompressX4(state *nativeStateX4, block *nativeBlockX4) {
	panic("sha512mb: AVX2 x4 compression unavailable")
}

func nativeCompressX8(state *nativeStateX8, block *nativeBlockX8) {
	panic("sha512mb: AVX-512F x8 compression unavailable")
}

func nativeCompressX8Rolling(state *nativeStateX8, block *nativeBlockX8) {
	panic("sha512mb: AVX-512F x8 rolling compression unavailable")
}
