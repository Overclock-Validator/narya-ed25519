//go:build !amd64 || purego

package r51x5

func ifmaQuadTwoChainDoubleFirstOperandsUncheckedX8(u, v, q *LimbsX8) {
	var q4 [2]LimbsX4
	for limb := range q {
		for lane := 0; lane < X4Lanes; lane++ {
			q4[0][limb][lane] = q[limb][lane]
			q4[1][limb][lane] = q[limb][lane+X4Lanes]
		}
	}
	var u4, v4 [2]LimbsX4
	for half := range q4 {
		ifmaQuadDoubleFirstOperandsUncheckedX4(&u4[half], &v4[half], &q4[half])
	}
	for limb := range u {
		for lane := 0; lane < X4Lanes; lane++ {
			u[limb][lane] = u4[0][limb][lane]
			u[limb][lane+X4Lanes] = u4[1][limb][lane]
			v[limb][lane] = v4[0][limb][lane]
			v[limb][lane+X4Lanes] = v4[1][limb][lane]
		}
	}
}

func ifmaQuadTwoChainDoubleFinalMultiplyUncheckedX8(out, products *LimbsX8) {
	var products4, out4 [2]LimbsX4
	for limb := range products {
		for lane := 0; lane < X4Lanes; lane++ {
			products4[0][limb][lane] = products[limb][lane]
			products4[1][limb][lane] = products[limb][lane+X4Lanes]
		}
	}
	for half := range products4 {
		ifmaQuadDoubleFinalMultiplyUncheckedX4(&out4[half], &products4[half])
	}
	for limb := range out {
		for lane := 0; lane < X4Lanes; lane++ {
			out[limb][lane] = out4[0][limb][lane]
			out[limb][lane+X4Lanes] = out4[1][limb][lane]
		}
	}
}

func ifmaQuadTwoChainCachedAddFirstOperandUncheckedX8(out, q *LimbsX8) {
	var q4, out4 [2]LimbsX4
	for limb := range q {
		for lane := 0; lane < X4Lanes; lane++ {
			q4[0][limb][lane] = q[limb][lane]
			q4[1][limb][lane] = q[limb][lane+X4Lanes]
		}
	}
	for half := range q4 {
		ifmaQuadCachedAddFirstOperandUncheckedX4(&out4[half], &q4[half])
	}
	for limb := range out {
		for lane := 0; lane < X4Lanes; lane++ {
			out[limb][lane] = out4[0][limb][lane]
			out[limb][lane+X4Lanes] = out4[1][limb][lane]
		}
	}
}

func ifmaQuadTwoChainCachedAddFinalOperandsUncheckedX8(left, right, products *LimbsX8) {
	var products4, left4, right4 [2]LimbsX4
	for limb := range products {
		for lane := 0; lane < X4Lanes; lane++ {
			products4[0][limb][lane] = products[limb][lane]
			products4[1][limb][lane] = products[limb][lane+X4Lanes]
		}
	}
	for half := range products4 {
		ifmaQuadCachedAddFinalOperandsUncheckedX4(&left4[half], &right4[half], &products4[half])
	}
	for limb := range left {
		for lane := 0; lane < X4Lanes; lane++ {
			left[limb][lane] = left4[0][limb][lane]
			left[limb][lane+X4Lanes] = left4[1][limb][lane]
			right[limb][lane] = right4[0][limb][lane]
			right[limb][lane+X4Lanes] = right4[1][limb][lane]
		}
	}
}
