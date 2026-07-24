package edwards25519

import "github.com/Overclock-Validator/narya/internal/edwards25519/field"

// EqualAffine returns 1 if v and affine represent the same point and 0
// otherwise. affine must have Z = 1, as points returned by SetBytes do.
//
// Unlike Equal, this specialized comparison needs only two field
// multiplications. Both cross-products are required: comparing only y would
// identify P with -P, while comparing only x would identify points related by
// y -> -y.
func (v *Point) EqualAffine(affine *Point) int {
	checkInitialized(v, affine)

	var x, y field.Element
	x.Multiply(&affine.x, &v.z)
	y.Multiply(&affine.y, &v.z)

	return v.x.Equal(&x) & v.y.Equal(&y)
}
