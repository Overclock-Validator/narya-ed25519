// Package cpufeat centralizes CPU feature detection for backend
// dispatch. Detection is runtime-only: build-level flags like GOAMD64
// are never consulted, because x86-64-v4 does not imply AVX512-IFMA.
package cpufeat

// IFMA reports whether the CPU supports the full AVX-512 subset the
// ifma backend requires (F, VL, DQ, BW, IFMA, VBMI — Ice Lake or
// Zen 4 and newer).
func IFMA() bool { return hasIFMA }
