package r51x5

import "encoding/binary"

// The coordinate-parallel orientation below has prior art in
// curve25519-dalek's AVX2 backend, curve25519-voi's Go port, and Firedancer's
// analogous AVX-512 QUAD representation. The arithmetic and packing here are
// independently implemented for Narya's radix-2^51 IFMA field layer. See
// NOTICE for source links and license details.

// quadPackedPointX4 stores one point with X, Y, T, and Z in the four IFMA
// lanes. The field multiply ABI remains lane-wise, so one call computes four
// independent coordinate products.
type quadPackedPointX4 struct {
	coordinates IFMAElementX4
}

func (p *quadPackedPointX4) setReduced(q *Point) *quadPackedPointX4 {
	var coordinates ElementX4
	coordinates.SetLane(0, &q.X)
	coordinates.SetLane(1, &q.Y)
	coordinates.SetLane(2, &q.T)
	coordinates.SetLane(3, &q.Z)
	p.coordinates.SetReduced(&coordinates)
	return p
}

func (p *quadPackedPointX4) reduced() Point {
	coordinates := p.coordinates.Reduced()
	return Point{
		X: coordinates.Lane(0),
		Y: coordinates.Lane(1),
		T: coordinates.Lane(2),
		Z: coordinates.Lane(3),
	}
}

// quadPackedCachedPointX4 is [Y-X, Y+X, 2dT, 2Z] for one cached point.
type quadPackedCachedPointX4 struct {
	coordinates IFMAElementX4
}

func (c *quadPackedCachedPointX4) setReduced(q *Point, negative bool) *quadPackedCachedPointX4 {
	var yMinusX, yPlusX, t2D, z2 Element
	yMinusX.Subtract(&q.Y, &q.X)
	yPlusX.Add(&q.Y, &q.X)
	t2D.Multiply(&q.T, &curve2D)
	z2.Add(&q.Z, &q.Z)
	if negative {
		yMinusX, yPlusX = yPlusX, yMinusX
		t2D.Negate(&t2D)
	}
	var coordinates ElementX4
	coordinates.SetLane(0, &yMinusX)
	coordinates.SetLane(1, &yPlusX)
	coordinates.SetLane(2, &t2D)
	coordinates.SetLane(3, &z2)
	c.coordinates.SetReduced(&coordinates)
	return c
}

type quadDSMOperationsX4 struct {
	hardware bool
}

// quadPointDoubleWorkspaceX4 keeps the five fully-overwritten packed
// temporaries outside the dependent doubling loop. The hardware operation
// writes every limb of every field before reading it; callers may therefore
// reuse one workspace without clearing it between doublings.
type quadPointDoubleWorkspaceX4 struct {
	u, v, products, left, right IFMAElementX4
}

// quadPointAddCachedWorkspaceX4 is the cached-add counterpart of
// quadPointDoubleWorkspaceX4. Every field is fully overwritten before use.
type quadPointAddCachedWorkspaceX4 struct {
	pointOperand, products, left, right IFMAElementX4
}

// quadNormalizeModelX4 keeps the coordinate-parallel model independent of
// the native IFMA carry/fold leaf. Besides making it a stronger oracle, this
// lets the model execute on amd64 hosts that do not expose AVX-512 IFMA.
func quadNormalizeModelX4(out *IFMAElementX4, raw *IFMAProductX4) {
	limbs, ok := normalizeIFMAProductX4(raw)
	if !ok {
		panic("r51x5: packed x4 model range invariant violated")
	}
	out.limbs = limbs
}

func (ops quadDSMOperationsX4) multiply(out, a, b *IFMAElementX4) error {
	if ops.hardware {
		return ifmaMultiplyComposableUncheckedX4(out, a, b)
	}
	return modelMultiplyComposableX4(out, a, b)
}

func (ops quadDSMOperationsX4) addCached(out, point *quadPackedPointX4, cached *quadPackedCachedPointX4) error {
	var workspace quadPointAddCachedWorkspaceX4
	return ops.addCachedWorkspace(out, point, cached, &workspace)
}

func (ops quadDSMOperationsX4) addCachedWorkspace(out, point *quadPackedPointX4, cached *quadPackedCachedPointX4, workspace *quadPointAddCachedWorkspaceX4) error {
	if ops.hardware {
		return quadPointAddCachedHardwareWorkspaceUncheckedX4(out, point, cached, workspace)
	}
	return quadPointAddCachedModelX4(out, point, cached)
}

func (ops quadDSMOperationsX4) double(out, point *quadPackedPointX4) error {
	var workspace quadPointDoubleWorkspaceX4
	return ops.doubleWorkspace(out, point, &workspace)
}

func (ops quadDSMOperationsX4) doubleWorkspace(out, point *quadPackedPointX4, workspace *quadPointDoubleWorkspaceX4) error {
	if ops.hardware {
		return quadPointDoubleHardwareWorkspaceUncheckedX4(out, point, workspace)
	}
	return quadPointDoubleModelX4(out, point)
}

func quadPackedIdentityValueX4() quadPackedPointX4 {
	var result quadPackedPointX4
	result.coordinates.limbs[0] = [X4Lanes]uint64{0, 1, 0, 1}
	return result
}

// quadDoubleFirstOperandsX4 permutes [X,Y,T,Z] into U=[X,Y,Z,X] and
// V=[X,Y,Z,Y], whose product is [X^2,Y^2,Z^2,XY].
func quadDoubleFirstOperandsX4(u, v *IFMAElementX4, q *quadPackedPointX4) {
	for limb := range q.coordinates.limbs {
		x := q.coordinates.limbs[limb][0]
		y := q.coordinates.limbs[limb][1]
		z := q.coordinates.limbs[limb][3]
		u.limbs[limb] = [X4Lanes]uint64{x, y, z, x}
		v.limbs[limb] = [X4Lanes]uint64{x, y, z, y}
	}
}

// quadDoubleFinalOperandsX4 derives the final packed multiplication operands
// from [X^2,Y^2,Z^2,XY], normalizing the linear layer once.
func quadDoubleFinalOperandsX4(left, right, products *IFMAElementX4) {
	var rawK IFMAProductX4
	for limb := range rawK {
		a := products.limbs[limb][0]
		b := products.limbs[limb][1]
		c := products.limbs[limb][2]
		d := products.limbs[limb][3]
		bias8P := 2 * ifmaSubtractionBias(limb)

		e := 2 * d
		g := b + bias8P - a
		h := bias8P - a - b
		f := b + bias8P - a - 2*c
		rawK[limb] = [X4Lanes]uint64{e, g, h, f}
	}

	var k IFMAElementX4
	quadNormalizeModelX4(&k, &rawK)
	for limb := range k.limbs {
		e := k.limbs[limb][0]
		g := k.limbs[limb][1]
		h := k.limbs[limb][2]
		f := k.limbs[limb][3]
		left.limbs[limb] = [X4Lanes]uint64{e, g, e, f}
		right.limbs[limb] = [X4Lanes]uint64{f, h, h, g}
	}
}

func quadPointDoubleHardwareUncheckedX4(out, q *quadPackedPointX4) error {
	var workspace quadPointDoubleWorkspaceX4
	return quadPointDoubleHardwareWorkspaceUncheckedX4(out, q, &workspace)
}

func quadPointDoubleHardwareWorkspaceUncheckedX4(out, q *quadPackedPointX4, workspace *quadPointDoubleWorkspaceX4) error {
	ifmaQuadDoubleFirstOperandsUncheckedX4(&workspace.u.limbs, &workspace.v.limbs, &q.coordinates.limbs)
	if err := ifmaMultiplyComposableUncheckedX4(&workspace.products, &workspace.u, &workspace.v); err != nil {
		return err
	}
	// q is no longer live after the first packed permutation, so this final
	// linear layer and multiply may write directly through out even when
	// out == q.
	ifmaQuadDoubleFinalMultiplyUncheckedX4(&out.coordinates.limbs, &workspace.products.limbs)
	return nil
}

func quadPointDoubleModelX4(out, q *quadPackedPointX4) error {
	var u, v, products, left, right IFMAElementX4
	quadDoubleFirstOperandsX4(&u, &v, q)
	if err := modelMultiplyComposableX4(&products, &u, &v); err != nil {
		return err
	}
	quadDoubleFinalOperandsX4(&left, &right, &products)
	var result IFMAElementX4
	if err := modelMultiplyComposableX4(&result, &left, &right); err != nil {
		return err
	}
	out.coordinates = result
	return nil
}

// quadCachedAddFirstOperandX4 normalizes [Y-X,Y+X,T,Z] in one packed pass.
func quadCachedAddFirstOperandX4(out *IFMAElementX4, point *quadPackedPointX4) {
	var raw IFMAProductX4
	for limb := range raw {
		x := point.coordinates.limbs[limb][0]
		y := point.coordinates.limbs[limb][1]
		t := point.coordinates.limbs[limb][2]
		z := point.coordinates.limbs[limb][3]
		raw[limb] = [X4Lanes]uint64{
			y + ifmaSubtractionBias(limb) - x,
			y + x,
			t,
			z,
		}
	}
	quadNormalizeModelX4(out, &raw)
}

// quadCachedAddFinalOperandsX4 converts [A,B,C,D] into the two packed final
// multiplication operands after one normalized linear layer.
func quadCachedAddFinalOperandsX4(left, right, products *IFMAElementX4) {
	var rawK IFMAProductX4
	for limb := range rawK {
		a := products.limbs[limb][0]
		b := products.limbs[limb][1]
		c := products.limbs[limb][2]
		d := products.limbs[limb][3]
		bias8P := 2 * ifmaSubtractionBias(limb)
		rawK[limb] = [X4Lanes]uint64{
			b + bias8P - a,
			d + c,
			b + a,
			d + bias8P - c,
		}
	}

	var k IFMAElementX4
	quadNormalizeModelX4(&k, &rawK)
	for limb := range k.limbs {
		e := k.limbs[limb][0]
		g := k.limbs[limb][1]
		h := k.limbs[limb][2]
		f := k.limbs[limb][3]
		left.limbs[limb] = [X4Lanes]uint64{e, g, e, f}
		right.limbs[limb] = [X4Lanes]uint64{f, h, h, g}
	}
}

func quadPointAddCachedHardwareUncheckedX4(out, point *quadPackedPointX4, cached *quadPackedCachedPointX4) error {
	var workspace quadPointAddCachedWorkspaceX4
	return quadPointAddCachedHardwareWorkspaceUncheckedX4(out, point, cached, &workspace)
}

func quadPointAddCachedHardwareWorkspaceUncheckedX4(out, point *quadPackedPointX4, cached *quadPackedCachedPointX4, workspace *quadPointAddCachedWorkspaceX4) error {
	ifmaQuadCachedAddFirstOperandUncheckedX4(&workspace.pointOperand.limbs, &point.coordinates.limbs)
	if err := ifmaMultiplyComposableUncheckedX4(&workspace.products, &workspace.pointOperand, &cached.coordinates); err != nil {
		return err
	}
	ifmaQuadCachedAddFinalOperandsUncheckedX4(&workspace.left.limbs, &workspace.right.limbs, &workspace.products.limbs)
	// point is no longer live after the first packed permutation, so this
	// final multiplication may write directly through out when out == point.
	return ifmaMultiplyComposableUncheckedX4(&out.coordinates, &workspace.left, &workspace.right)
}

func quadPointAddCachedModelX4(out, point *quadPackedPointX4, cached *quadPackedCachedPointX4) error {
	var pointOperand, products, left, right IFMAElementX4
	quadCachedAddFirstOperandX4(&pointOperand, point)
	if err := modelMultiplyComposableX4(&products, &pointOperand, &cached.coordinates); err != nil {
		return err
	}
	quadCachedAddFinalOperandsX4(&left, &right, &products)
	var result IFMAElementX4
	if err := modelMultiplyComposableX4(&result, &left, &right); err != nil {
		return err
	}
	out.coordinates = result
	return nil
}

var quadCachedScaleX4 = func() IFMAElementX4 {
	var one, two Element
	one.One()
	two.Add(&one, &one)
	values := [X4Lanes]Element{one, one, curve2D, two}
	var reduced ElementX4
	reduced.SetElements(&values)
	var result IFMAElementX4
	result.SetReduced(&reduced)
	return result
}()

func quadCachePackedPointX4(out *quadPackedCachedPointX4, point *quadPackedPointX4, ops quadDSMOperationsX4) error {
	var coordinates IFMAElementX4
	if ops.hardware {
		// Keep the model oracle independent of native normalization without
		// making production table construction pay for the portable carry/fold.
		// This is the same packed first-operand transform used by the hardware
		// cached-add path, and it is exact for in-place table preparation too.
		ifmaQuadCachedAddFirstOperandUncheckedX4(&coordinates.limbs, &point.coordinates.limbs)
	} else {
		quadCachedAddFirstOperandX4(&coordinates, point)
	}
	return ops.multiply(&out.coordinates, &coordinates, &quadCachedScaleX4)
}

func quadNegateCachedPointX4(out *quadPackedCachedPointX4, positive *quadPackedCachedPointX4) {
	*out = *positive
	for limb := range out.coordinates.limbs {
		out.coordinates.limbs[limb][0], out.coordinates.limbs[limb][1] =
			out.coordinates.limbs[limb][1], out.coordinates.limbs[limb][0]
	}
	conditionalNegateIFMAElementX4(&out.coordinates, 1<<2)
}

// quadNAFTable5X4 holds the eight positive odd multiples required by a
// width-5 NAF variable-base scalar multiplication.
type quadNAFTable5X4 struct {
	positive [8]quadPackedCachedPointX4
}

// quadNAFTable8X4 holds the fixed generator's 64 positive odd multiples.
type quadNAFTable8X4 struct {
	positive [64]quadPackedCachedPointX4
}

func buildQuadNAFEntriesX4(positive []quadPackedCachedPointX4, base *Point, ops quadDSMOperationsX4) error {
	if len(positive) == 0 {
		panic("r51x5: invalid quad NAF table storage")
	}
	current := new(quadPackedPointX4).setReduced(base)
	if err := quadCachePackedPointX4(&positive[0], current, ops); err != nil {
		return err
	}

	twice := *current
	var doubleWorkspace quadPointDoubleWorkspaceX4
	if err := ops.doubleWorkspace(&twice, &twice, &doubleWorkspace); err != nil {
		return err
	}
	var twiceCached quadPackedCachedPointX4
	if err := quadCachePackedPointX4(&twiceCached, &twice, ops); err != nil {
		return err
	}
	var addWorkspace quadPointAddCachedWorkspaceX4
	for entry := 1; entry < len(positive); entry++ {
		if err := ops.addCachedWorkspace(current, current, &twiceCached, &addWorkspace); err != nil {
			return err
		}
		if err := quadCachePackedPointX4(&positive[entry], current, ops); err != nil {
			return err
		}
	}
	return nil
}

func buildQuadNAFTable5X4(out *quadNAFTable5X4, base *Point, ops quadDSMOperationsX4) error {
	return buildQuadNAFEntriesX4(out.positive[:], base, ops)
}

func buildQuadNAFTable8X4(out *quadNAFTable8X4, base *Point, ops quadDSMOperationsX4) error {
	return buildQuadNAFEntriesX4(out.positive[:], base, ops)
}

func selectQuadNAFEntryX4(negative *quadPackedCachedPointX4, positive []quadPackedCachedPointX4, digit int8) *quadPackedCachedPointX4 {
	if digit == 0 || digit&1 == 0 {
		panic("r51x5: invalid quad NAF digit")
	}
	index := int(digit)
	if index < 0 {
		index = -index
	}
	index /= 2
	if index >= len(positive) {
		panic("r51x5: quad NAF digit exceeds table")
	}
	if digit < 0 {
		quadNegateCachedPointX4(negative, &positive[index])
		return negative
	}
	return &positive[index]
}

// recodeQuadCanonicalNAFX4 computes a width-w NAF from a canonical scalar.
// It is exact integer recoding and never reduces modulo the scalar order.
func recodeQuadCanonicalNAFX4(out *[256]int8, scalar *[32]byte, width uint) bool {
	*out = [256]int8{}
	if width < 2 || width > 8 {
		panic("r51x5: quad NAF width must be between 2 and 8")
	}
	if !canonicalScalarBytes(scalar) {
		return false
	}

	var words [5]uint64
	for index := 0; index < 4; index++ {
		words[index] = binary.LittleEndian.Uint64(scalar[index*8:])
	}
	radix := uint64(1 << width)
	mask := radix - 1
	for position, carry := uint(0), uint64(0); position < 256; {
		word := position / 64
		bit := position % 64
		var buffer uint64
		if bit < 64-width {
			buffer = words[word] >> bit
		} else {
			buffer = words[word]>>bit | words[word+1]<<(64-bit)
		}
		window := carry + buffer&mask
		if window&1 == 0 {
			position++
			continue
		}
		if window < radix/2 {
			carry = 0
			out[position] = int8(window)
		} else {
			carry = 1
			out[position] = int8(window) - int8(radix)
		}
		position += width
	}
	return true
}

// evaluateQuadNAFVerifyX4 computes [s]B-[k]A using exact signed-integer
// semantics. Negating k's digits, rather than replacing -k by l-k, preserves
// the cofactorless equation for mixed-order A.
func evaluateQuadNAFVerifyX4(out *quadPackedPointX4, aTable *quadNAFTable5X4, bTable *quadNAFTable8X4, s, k *[32]byte, ops quadDSMOperationsX4) (bool, error) {
	var aNAF, bNAF [256]int8
	valid := recodeQuadCanonicalNAFX4(&aNAF, k, 5)
	valid = recodeQuadCanonicalNAFX4(&bNAF, s, 8) && valid
	acc := quadPackedIdentityValueX4()
	if !valid {
		*out = acc
		return false, nil
	}

	high := 255
	for ; high >= 0 && aNAF[high] == 0 && bNAF[high] == 0; high-- {
	}
	var doubleWorkspace quadPointDoubleWorkspaceX4
	var addWorkspace quadPointAddCachedWorkspaceX4
	for bit := high; bit >= 0; bit-- {
		if err := ops.doubleWorkspace(&acc, &acc, &doubleWorkspace); err != nil {
			return false, err
		}
		if aNAF[bit] != 0 {
			var negative quadPackedCachedPointX4
			selected := selectQuadNAFEntryX4(&negative, aTable.positive[:], -aNAF[bit])
			if err := ops.addCachedWorkspace(&acc, &acc, selected, &addWorkspace); err != nil {
				return false, err
			}
		}
		if bNAF[bit] != 0 {
			var negative quadPackedCachedPointX4
			selected := selectQuadNAFEntryX4(&negative, bTable.positive[:], bNAF[bit])
			if err := ops.addCachedWorkspace(&acc, &acc, selected, &addWorkspace); err != nil {
				return false, err
			}
		}
	}
	*out = acc
	return true, nil
}
