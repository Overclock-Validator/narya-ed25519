// Package cpufeat centralizes CPU feature detection for backend
// dispatch. Detection is runtime-only: build-level flags like GOAMD64
// are never consulted, because x86-64-v4 does not imply AVX512-IFMA.
package cpufeat

// IFMA reports whether the CPU supports the full AVX-512 subset the
// ifma backend requires (F, VL, DQ, BW, IFMA, VBMI — Ice Lake or
// Zen 4 and newer).
func IFMA() bool { return hasIFMA }

// PreferWideIFMA reports whether the measured microarchitecture should use
// one eight-lane ZMM IFMA group instead of two four-lane YMM groups. It is
// deliberately narrower than IFMA. Although Zen 4 implements 512-bit
// arithmetic through two 256-bit passes, the production x8 multiply and
// projective-Niels schedule is measurably faster there as well as on native-
// width Zen 5. Unknown IFMA CPUs retain the reviewed x4-safe default.
func PreferWideIFMA() bool { return preferWideIFMA }

// PreferDecodedAIFMA reports whether the measured microarchitecture should
// consume decoded-A cache entries. This is deliberately separate from SIMD
// width selection: changing an x4/x8 result must not silently change cache
// policy.
func PreferDecodedAIFMA() bool { return preferDecodedAIFMA }

// PreferWarmX8IFMA reports whether two adjacent warm x4 groups should be kept
// together as one x8 scheduling unit. It is independent of both cold width
// and decoded-A policy even when the current measured AMD set is identical.
func PreferWarmX8IFMA() bool { return preferWarmX8IFMA }

func x86FamilyFromVersion(version uint32) uint32 {
	base := (version >> 8) & 0x0f
	if base == 0x0f {
		return base + ((version >> 20) & 0xff)
	}
	return base
}
