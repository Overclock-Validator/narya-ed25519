//go:build amd64

package cpufeat

import "golang.org/x/sys/cpu"

var hasIFMA = cpu.X86.HasAVX512F && cpu.X86.HasAVX512VL && cpu.X86.HasAVX512DQ &&
	cpu.X86.HasAVX512BW && cpu.X86.HasAVX512IFMA && cpu.X86.HasAVX512VBMI

var amdFamily = detectAMDFamily()

// amdPolicyHost is the measured-microarchitecture gate. forceAMDPolicy widens
// it to any IFMA-capable machine and is false in every ordinary build; see
// policyoverride_on.go for why it exists and what it does not claim.
var amdFamily19OrNewer = amdFamily >= 0x19 || forceAMDPolicy

var preferWideIFMA = hasIFMA && amdFamily19OrNewer
var preferDecodedAIFMA = hasIFMA && amdFamily19OrNewer
var preferWarmX8IFMA = hasIFMA && amdFamily19OrNewer
var preferRawSquareIFMA = rawSquareForAMDVersion(hasIFMA, amdFamily) || (hasIFMA && forceAMDPolicy)
var preferWideHashX4IFMA = wideHashX4ForAMDVersion(hasIFMA, amdFamily) || (hasIFMA && forceAMDPolicy)
var preferBatchEncodeX8IFMA = batchEncodeX8ForAMDVersion(hasIFMA, amdFamily) || (hasIFMA && forceAMDPolicy)
var preferProjectiveDoubleX8IFMA = projectiveDoubleX8ForAMDVersion(hasIFMA, amdFamily) || (hasIFMA && forceAMDPolicy)
var preferAsymmetricFixedB10X8IFMA = asymmetricFixedB10X8ForAMDVersion(hasIFMA, amdFamily) || (hasIFMA && forceAMDPolicy)
var preferNativeScalarReduceX8IFMA = nativeScalarReduceX8ForAMDVersion(hasIFMA, amdFamily) || (hasIFMA && forceAMDPolicy)
var preferPackedMul19X4IFMA = packedMul19X4ForAMDVersion(hasIFMA, amdFamily) || (hasIFMA && forceAMDPolicy)

func detectAMDFamily() uint32 {
	_, ebx, ecx, edx := cpuid(0, 0)
	const (
		auth = 0x68747541
		enti = 0x69746e65
		cAMD = 0x444d4163
	)
	if ebx != auth || edx != enti || ecx != cAMD {
		return 0
	}
	version, _, _, _ := cpuid(1, 0)
	return x86FamilyFromVersion(version)
}

//go:noescape
func cpuid(eax, ecx uint32) (a, b, c, d uint32)
