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

func nativeTransposeCompressX8Rolling(state *nativeStateX8, ptrs *[nativeX8Width]*byte, initial uint64) {
	panic("sha512mb: AVX-512 x8 fused transpose/compression unavailable")
}

func nativeCompressVerifierFirstX8Rolling(state *nativeStateX8, rPtrs, aPtrs, messagePtrs *[nativeX8Width]*byte) {
	panic("sha512mb: AVX-512 x8 verifier-prefix compression unavailable")
}

func nativeCompressFinalX8Rolling(state *nativeStateX8, tail *nativeTailX8, tailWords, totalBits uint64) {
	panic("sha512mb: AVX-512 x8 final-block compression unavailable")
}

func nativeTransposeX8(block *nativeBlockX8, raw *[nativeX8Width][128]byte) {
	panic("sha512mb: AVX-512 x8 transpose unavailable")
}

func nativeTransposePointersX8(block *nativeBlockX8, ptrs *[nativeX8Width]*byte) {
	panic("sha512mb: AVX-512 x8 pointer transpose unavailable")
}
