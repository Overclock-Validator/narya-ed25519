//go:build amd64 && !purego

package r51x5

// ifmaCompletedProductsToLinearUncheckedX8 consumes four exact folded raw
// products [EF,GH,FG,EH]. It emits carried u52 [GH-EF,GH+EF,FG,EH] in the
// named output layout. GH-EF uses 535*p, the independently certified minimum
// whole-modulus bias for two raw-product terms. Input and output may not
// overlap; the caller enforces the raw-product provenance contract.
//
//go:noescape
func ifmaCompletedProductsToLinearUncheckedX8(out *ifmaCompletedLinearPointX8, products *[4]IFMAProductX8)
