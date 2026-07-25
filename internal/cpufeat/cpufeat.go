// Package cpufeat centralizes CPU feature detection for backend
// dispatch. Detection is runtime-only: build-level flags like GOAMD64
// are never consulted, because x86-64-v4 does not imply AVX512-IFMA.
package cpufeat

// IFMA reports whether the CPU supports the full AVX-512 subset the
// ifma backend requires (F, VL, DQ, BW, IFMA, VBMI — Ice Lake or
// Zen 4 and newer).
func IFMA() bool { return hasIFMA }

// PreferWideIFMA reports whether the measured microarchitecture should use
// one native eight-lane ZMM IFMA group instead of two four-lane YMM groups.
// It is deliberately narrower than IFMA: Zen 4 implements 512-bit arithmetic
// through two 256-bit passes, while AMD family 1Ah (Zen 5) has a native
// 512-bit datapath. Unknown IFMA CPUs retain the reviewed x4-safe default.
func PreferWideIFMA() bool { return preferWideIFMA }

func x86FamilyFromVersion(version uint32) uint32 {
	base := (version >> 8) & 0x0f
	if base == 0x0f {
		return base + ((version >> 20) & 0xff)
	}
	return base
}
