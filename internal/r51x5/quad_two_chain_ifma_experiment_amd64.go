//go:build amd64 && !purego

package r51x5

// ifmaQuadTwoChainDoubleFirstOperandsUncheckedX8 applies the packed-x4 first
// operand permutation independently to the low and high 256-bit halves. q is
// u52 [X,Y,T,Z,X,Y,T,Z]; u and v must be distinct. q may alias either output
// because every input vector is loaded before the first store. The caller owns
// the IFMA gate.
//
//go:noescape
func ifmaQuadTwoChainDoubleFirstOperandsUncheckedX8(u, v, q *LimbsX8)

// ifmaQuadTwoChainDoubleFinalMultiplyUncheckedX8 applies the packed-x4 final
// linear/carry layer independently to both 256-bit halves, then consumes both
// operand pairs in one normalized x8 multiply. products must be u52
// [X^2,Y^2,Z^2,XY,X^2,Y^2,Z^2,XY]. out may alias products. The caller owns
// the IFMA gate.
//
//go:noescape
func ifmaQuadTwoChainDoubleFinalMultiplyUncheckedX8(out, products *LimbsX8)
