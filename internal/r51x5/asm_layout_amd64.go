//go:build amd64 && !purego

package r51x5

import "unsafe"

// Go assembly in this package addresses these structs by fixed byte offsets.
// Each pair of arrays below has a negative length, and so fails to compile, if
// a size or field offset moves in either direction. A failure here means the
// assembly that consumes the type must be reviewed before the constant is
// changed. Types that are plain arrays of uint64 (LimbsX8, IFMAProductX8,
// the stage-2 workspaces, scalarRadix21X8) have a layout fixed by the
// language and are not listed. ifmaProjectivePointX8 is checked in
// projective_double_x8_layout_amd64.go. unsafe is used only for these
// constants.
var (
	_ [160 - unsafe.Sizeof(IFMAElementX4{})]byte
	_ [unsafe.Sizeof(IFMAElementX4{}) - 160]byte

	_ [320 - unsafe.Sizeof(IFMAElementX8{})]byte
	_ [unsafe.Sizeof(IFMAElementX8{}) - 320]byte

	_ [640 - unsafe.Sizeof(IFMAPointX4{})]byte
	_ [unsafe.Sizeof(IFMAPointX4{}) - 640]byte
	_ [160 - unsafe.Offsetof(IFMAPointX4{}.Y)]byte
	_ [unsafe.Offsetof(IFMAPointX4{}.Y) - 160]byte
	_ [320 - unsafe.Offsetof(IFMAPointX4{}.Z)]byte
	_ [unsafe.Offsetof(IFMAPointX4{}.Z) - 320]byte
	_ [480 - unsafe.Offsetof(IFMAPointX4{}.T)]byte
	_ [unsafe.Offsetof(IFMAPointX4{}.T) - 480]byte

	_ [1280 - unsafe.Sizeof(IFMAPointX8{})]byte
	_ [unsafe.Sizeof(IFMAPointX8{}) - 1280]byte
	_ [320 - unsafe.Offsetof(IFMAPointX8{}.Y)]byte
	_ [unsafe.Offsetof(IFMAPointX8{}.Y) - 320]byte
	_ [640 - unsafe.Offsetof(IFMAPointX8{}.Z)]byte
	_ [unsafe.Offsetof(IFMAPointX8{}.Z) - 640]byte
	_ [960 - unsafe.Offsetof(IFMAPointX8{}.T)]byte
	_ [unsafe.Offsetof(IFMAPointX8{}.T) - 960]byte

	_ [1280 - unsafe.Sizeof(IFMAProjectiveNielsX8{})]byte
	_ [unsafe.Sizeof(IFMAProjectiveNielsX8{}) - 1280]byte
	_ [320 - unsafe.Offsetof(IFMAProjectiveNielsX8{}.YMinusX)]byte
	_ [unsafe.Offsetof(IFMAProjectiveNielsX8{}.YMinusX) - 320]byte
	_ [640 - unsafe.Offsetof(IFMAProjectiveNielsX8{}.Z)]byte
	_ [unsafe.Offsetof(IFMAProjectiveNielsX8{}.Z) - 640]byte
	_ [960 - unsafe.Offsetof(IFMAProjectiveNielsX8{}.T2D)]byte
	_ [unsafe.Offsetof(IFMAProjectiveNielsX8{}.T2D) - 960]byte

	_ [1280 - unsafe.Sizeof(ifmaCompletedLinearPointX8{})]byte
	_ [unsafe.Sizeof(ifmaCompletedLinearPointX8{}) - 1280]byte
	_ [320 - unsafe.Offsetof(ifmaCompletedLinearPointX8{}.YPlusX)]byte
	_ [unsafe.Offsetof(ifmaCompletedLinearPointX8{}.YPlusX) - 320]byte
	_ [640 - unsafe.Offsetof(ifmaCompletedLinearPointX8{}.Z)]byte
	_ [unsafe.Offsetof(ifmaCompletedLinearPointX8{}.Z) - 640]byte
	_ [960 - unsafe.Offsetof(ifmaCompletedLinearPointX8{}.T)]byte
	_ [unsafe.Offsetof(ifmaCompletedLinearPointX8{}.T) - 960]byte
)
