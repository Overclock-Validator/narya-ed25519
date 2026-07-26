//go:build amd64

package cpufeat

import "golang.org/x/sys/cpu"

var hasIFMA = cpu.X86.HasAVX512F && cpu.X86.HasAVX512VL && cpu.X86.HasAVX512DQ &&
	cpu.X86.HasAVX512BW && cpu.X86.HasAVX512IFMA && cpu.X86.HasAVX512VBMI

var amdFamily19OrNewer = detectAMDFamily19OrNewer()
var preferWideIFMA = hasIFMA && amdFamily19OrNewer
var preferDecodedAIFMA = hasIFMA && amdFamily19OrNewer
var preferWarmX8IFMA = hasIFMA && amdFamily19OrNewer

func detectAMDFamily19OrNewer() bool {
	_, ebx, ecx, edx := cpuid(0, 0)
	const (
		auth = 0x68747541
		enti = 0x69746e65
		cAMD = 0x444d4163
	)
	if ebx != auth || edx != enti || ecx != cAMD {
		return false
	}
	version, _, _, _ := cpuid(1, 0)
	return x86FamilyFromVersion(version) >= 0x19
}

//go:noescape
func cpuid(eax, ecx uint32) (a, b, c, d uint32)
