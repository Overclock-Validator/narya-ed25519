//go:build amd64

package r51x5

// ifmaQuadDoubleFinalOperandsUncheckedX4 transforms packed normalized
// [A=X^2, B=Y^2, C=Z^2, D=XY] coordinate lanes into the two normalized
// operands for the final packed multiplication:
//
//	left  = [E, G, E, F]
//	right = [F, H, H, G]
//
// where E=2D, G=B-A, H=-A-B, and F=B-A-2C modulo p. products must be u52.
// The pre-carry values are non-negative after adding 8p to G/H/F and remain
// below 12*2^51, so one carry/fold pass returns u52 outputs. left and right
// must be distinct; products may alias either output because all five input
// vectors are loaded before the first store. The caller owns the IFMA gate.
//
//go:noescape
func ifmaQuadDoubleFinalOperandsUncheckedX4(left, right, products *LimbsX4)
