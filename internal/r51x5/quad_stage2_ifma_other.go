//go:build !amd64

package r51x5

func ifmaQuadDoubleFirstOperandsUncheckedX4(u, v, q *LimbsX4) {
	point := quadPackedPointX4{coordinates: IFMAElementX4{limbs: *q}}
	var uElement, vElement IFMAElementX4
	quadDoubleFirstOperandsX4(&uElement, &vElement, &point)
	*u = uElement.limbs
	*v = vElement.limbs
}

func ifmaQuadCachedAddFirstOperandUncheckedX4(out, q *LimbsX4) {
	point := quadPackedPointX4{coordinates: IFMAElementX4{limbs: *q}}
	var outElement IFMAElementX4
	quadCachedAddFirstOperandX4(&outElement, &point)
	*out = outElement.limbs
}

func ifmaQuadDoubleFinalOperandsUncheckedX4(left, right, products *LimbsX4) {
	input := IFMAElementX4{limbs: *products}
	var leftElement, rightElement IFMAElementX4
	quadDoubleFinalOperandsX4(&leftElement, &rightElement, &input)
	*left = leftElement.limbs
	*right = rightElement.limbs
}

func ifmaQuadDoubleFinalMultiplyUncheckedX4(out, products *LimbsX4) {
	var left, right LimbsX4
	ifmaQuadDoubleFinalOperandsUncheckedX4(&left, &right, products)
	ifmaMulNormalizedUncheckedX4(out, &left, &right)
}

func ifmaQuadCachedAddFinalOperandsUncheckedX4(left, right, products *LimbsX4) {
	input := IFMAElementX4{limbs: *products}
	var leftElement, rightElement IFMAElementX4
	quadCachedAddFinalOperandsX4(&leftElement, &rightElement, &input)
	*left = leftElement.limbs
	*right = rightElement.limbs
}
