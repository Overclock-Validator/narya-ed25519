//go:build amd64

package r43x6

// ifmaMulRaw multiplies reduced x and y and writes an equivalent unreduced
// u47 representation to out. It must only be called after cpufeat.IFMA.
//
//go:noescape
func ifmaMulRaw(out, x, y *Limbs)
