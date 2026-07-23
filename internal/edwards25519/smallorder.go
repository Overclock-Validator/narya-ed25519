// Small-order detection for verify_strict semantics. This file is part
// of narya, not the vendored upstream code.

package edwards25519

// IsSmallOrder reports whether v has order dividing the cofactor 8,
// i.e. [8]v is the identity. This is exactly ed25519-dalek's
// EdwardsPoint::is_small_order (self.mul_by_cofactor().is_identity()),
// which verify_strict uses to reject small-order A and R.
func (v *Point) IsSmallOrder() bool {
	var eightV Point
	eightV.MultByCofactor(v)
	return eightV.Equal(NewIdentityPoint()) == 1
}
