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

// PreferRawSquareIFMA reports whether the x8 cold verifier should use the
// symmetry-aware raw-square doubling schedule. Complete-verifier measurements
// select it only on AMD family 19h (Zen 4); native-width family 1Ah (Zen 5)
// remains faster with the general-multiply schedule. This is deliberately a
// separate policy bit so a future width decision cannot silently change the
// arithmetic schedule.
func PreferRawSquareIFMA() bool { return preferRawSquareIFMA }

// PreferWideHashX4IFMA reports whether a cold x4/tail group should retain x4
// point arithmetic while hashing and reducing its challenges through the
// native x8 kernels. Complete n=4 measurements select this composition on AMD
// family 1Ah (Zen 5). Zen 4 and unknown IFMA CPUs retain the x4 hash path until
// measured independently.
func PreferWideHashX4IFMA() bool { return preferWideHashX4IFMA }

func rawSquareForAMDVersion(ifma bool, family uint32) bool {
	return ifma && family == 0x19
}

func wideHashX4ForAMDVersion(ifma bool, family uint32) bool {
	return ifma && family == 0x1a
}

func x86FamilyFromVersion(version uint32) uint32 {
	base := (version >> 8) & 0x0f
	if base == 0x0f {
		return base + ((version >> 20) & 0xff)
	}
	return base
}
