//go:build linux && amd64

package r51x5

import (
	"runtime"
	"syscall"
	"testing"
	"unsafe"
)

// The final row of a dense affine3 entry is 24 bytes. The assembly loads it
// with a three-lane masked YMM load, whose fourth qword crosses this guard-page
// boundary. This test proves that the masked lane is fault-suppressed and that
// the selector never requires padding beyond the advertised 120-byte entry.
func TestIFMAAffine3MicroAoSTransposeMaskedLoadDoesNotOverread(t *testing.T) {
	if !microAoSSelectorExperimentCanCall() {
		t.Skip("requires AVX-512 IFMA target on amd64")
	}
	pageSize := syscall.Getpagesize()
	memory, err := syscall.Mmap(-1, 0, 2*pageSize, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE|syscall.MAP_ANON)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := syscall.Munmap(memory); err != nil {
			t.Error(err)
		}
	}()

	entrySize := int(unsafe.Sizeof(ifmaAffine3MicroAoSEntryExperiment{}))
	if entrySize != 120 {
		t.Fatalf("entry size=%d want=120", entrySize)
	}
	entry := (*ifmaAffine3MicroAoSEntryExperiment)(unsafe.Pointer(&memory[pageSize-entrySize]))
	for limb := range entry {
		for coordinate := range entry[limb] {
			entry[limb][coordinate] = uint64(1 + limb*11 + coordinate)
		}
	}
	if err := syscall.Mprotect(memory[pageSize:], syscall.PROT_NONE); err != nil {
		t.Fatal(err)
	}

	var got fixedBaseIFMACachedX4
	ifmaAffine3MicroAoSTransposeSelectExperimentX4(&got, entry, entry, entry, entry)
	for limb := 0; limb < 5; limb++ {
		for lane := 0; lane < X4Lanes; lane++ {
			if got.YPlusX.limbs[limb][lane] != entry[limb][0] ||
				got.YMinusX.limbs[limb][lane] != entry[limb][1] ||
				got.T2D.limbs[limb][lane] != entry[limb][2] {
				t.Fatalf("limb=%d lane=%d masked-load transpose mismatch", limb, lane)
			}
		}
	}
	runtime.KeepAlive(memory)
}
