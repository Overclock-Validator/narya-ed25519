//go:build amd64 && !purego

package r51x5

import "unsafe"

// ifmaProjectiveFinalProductsUncheckedX8 uses fixed byte offsets in assembly.
// Paired subtraction arrays make each expected equality a compile-time
// requirement: either direction becomes a negative array length if the Go
// layout moves. unsafe is used only for these constants; no pointer conversion
// or arithmetic reaches runtime.
var (
	_ [960 - unsafe.Sizeof(ifmaProjectivePointX8{})]byte
	_ [unsafe.Sizeof(ifmaProjectivePointX8{}) - 960]byte

	_ [320 - unsafe.Offsetof(ifmaProjectivePointX8{}.Y)]byte
	_ [unsafe.Offsetof(ifmaProjectivePointX8{}.Y) - 320]byte
	_ [640 - unsafe.Offsetof(ifmaProjectivePointX8{}.Z)]byte
	_ [unsafe.Offsetof(ifmaProjectivePointX8{}.Z) - 640]byte
)
