//go:build !amd64 || purego

package r51x5

func scalarReduceRadix21IFMAX8(*scalarRadix21X8) {
	panic("r51x5: native x8 scalar reduction unavailable")
}
