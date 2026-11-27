//go:build !amd64

package keccakmb

func nativeX8Available() bool { return false }

func permuteX8Native(s *StateX8) {
	panic("keccakmb: AVX-512 x8 permutation unavailable")
}

func absorbX8Native(s *StateX8, ptrs *[Lanes]*byte, strides *[Lanes]uint64, words, blocks int) {
	panic("keccakmb: AVX-512 x8 absorb unavailable")
}

func squeezeX8Native(s *StateX8, out *[Lanes][200]byte, words, permute int) {
	panic("keccakmb: AVX-512 x8 squeeze unavailable")
}
