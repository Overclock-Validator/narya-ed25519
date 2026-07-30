//go:build !amd64 || purego

package r51x5

func ifmaCompletedProductsToLinearUncheckedX8(out *ifmaCompletedLinearPointX8, products *[4]IFMAProductX8) {
	ifmaCompletedProductsToLinearModelX8(out, products)
}
