//go:build !amd64 || purego

package r51x5

import "math/bits"

// ifmaSquareRawExperimentX4 is the scalar non-amd64 oracle for the raw square
// experiment. Copying x before assembling the result preserves exact aliasing.
func ifmaSquareRawExperimentX4(out *IFMAProductX4, x *LimbsX4) {
	input := *x
	var result IFMAProductX4
	const mask52 = uint64(1)<<IFMAComposableLimbBits - 1
	for lane := 0; lane < X4Lanes; lane++ {
		var low, high [9]uint64
		for i := 0; i < 5; i++ {
			for j := i; j < 5; j++ {
				hi, lo := bits.Mul64(input[i][lane], input[j][lane])
				scale := uint64(1)
				if i != j {
					scale = 2
				}
				degree := i + j
				low[degree] += scale * (lo & mask52)
				high[degree] += scale * (lo>>IFMAComposableLimbBits | hi<<(64-IFMAComposableLimbBits))
			}
		}

		var coefficient [10]uint64
		for degree := range low {
			coefficient[degree] += low[degree]
			coefficient[degree+1] += 2 * high[degree]
		}
		result[0][lane] = coefficient[0] + 19*coefficient[5]
		result[1][lane] = coefficient[1] + 19*coefficient[6]
		result[2][lane] = coefficient[2] + 19*coefficient[7]
		result[3][lane] = coefficient[3] + 19*coefficient[8]
		result[4][lane] = coefficient[4] + 19*coefficient[9]
	}
	*out = result
}

// ifmaSquareRawExperimentX8 is the scalar non-amd64 oracle for the native-ZMM
// raw-square experiment. It intentionally follows the same coefficient model
// as the x4 fallback so cross-architecture tests exercise the same contract.
func ifmaSquareRawExperimentX8(out *IFMAProductX8, x *LimbsX8) {
	input := *x
	var result IFMAProductX8
	const mask52 = uint64(1)<<IFMAComposableLimbBits - 1
	for lane := 0; lane < X8Lanes; lane++ {
		var low, high [9]uint64
		for i := 0; i < 5; i++ {
			for j := i; j < 5; j++ {
				hi, lo := bits.Mul64(input[i][lane], input[j][lane])
				scale := uint64(1)
				if i != j {
					scale = 2
				}
				degree := i + j
				low[degree] += scale * (lo & mask52)
				high[degree] += scale * (lo>>IFMAComposableLimbBits | hi<<(64-IFMAComposableLimbBits))
			}
		}

		var coefficient [10]uint64
		for degree := range low {
			coefficient[degree] += low[degree]
			coefficient[degree+1] += 2 * high[degree]
		}
		result[0][lane] = coefficient[0] + 19*coefficient[5]
		result[1][lane] = coefficient[1] + 19*coefficient[6]
		result[2][lane] = coefficient[2] + 19*coefficient[7]
		result[3][lane] = coefficient[3] + 19*coefficient[8]
		result[4][lane] = coefficient[4] + 19*coefficient[9]
	}
	*out = result
}
