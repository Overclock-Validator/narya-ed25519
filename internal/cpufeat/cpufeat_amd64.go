//go:build amd64

package cpufeat

import "golang.org/x/sys/cpu"

var hasIFMA = cpu.X86.HasAVX512F && cpu.X86.HasAVX512VL && cpu.X86.HasAVX512DQ &&
	cpu.X86.HasAVX512BW && cpu.X86.HasAVX512IFMA && cpu.X86.HasAVX512VBMI
