//go:build !amd64

package r51x5

func ifmaQuadDoubleFinalOperandsUncheckedX4(left, right, products *LimbsX4) {
	input := IFMAElementX4{limbs: *products}
	var leftElement, rightElement IFMAElementX4
	quadDoubleFinalOperandsX4(&leftElement, &rightElement, &input)
	*left = leftElement.limbs
	*right = rightElement.limbs
}

func ifmaQuadCachedAddFinalOperandsUncheckedX4(left, right, products *LimbsX4) {
	input := IFMAElementX4{limbs: *products}
	var leftElement, rightElement IFMAElementX4
	quadCachedAddFinalOperandsX4(&leftElement, &rightElement, &input)
	*left = leftElement.limbs
	*right = rightElement.limbs
}
