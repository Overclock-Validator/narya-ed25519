package r51x5

// scalarRadix21X8 is a structure-of-arrays workspace for eight independent
// 512-bit integers. Row i holds radix-2^21 coefficient i for every lane.
//
// The arithmetic schedule is the same signed ref10 reduction used by
// reduceUniformScalar. Keeping the byte parser and packer here, outside the
// native leaf, makes the native schedule directly differential-testable
// against the existing lane-serial implementation.
type scalarRadix21X8 [24][X8Lanes]int64

// reduceUniformScalarsIFMAX8 is the native implementation seam
// used by the measured Zen 5 policy. It publishes no output when native IFMA
// is unavailable. The portable scalar reducer remains the explicit oracle and
// fallback on every unmeasured CPU.
func reduceUniformScalarsIFMAX8(
	out *[X8Lanes][32]byte,
	in *[X8Lanes][64]byte,
	active uint8,
) (uint8, bool) {
	if !ExperimentalIFMAAvailable() {
		return 0, false
	}

	var limbs scalarRadix21X8
	for lane := 0; lane < X8Lanes; lane++ {
		laneMask := uint8(1 << lane)
		if active&laneMask == 0 {
			continue
		}
		for index := 0; index < 23; index++ {
			bit := index * 21
			limbs[index][lane] = (scalarLoad4(in[lane][bit>>3:]) >> uint(bit&7)) & ((1 << 21) - 1)
		}
		limbs[23][lane] = scalarLoad4(in[lane][60:]) >> 3
	}

	scalarReduceRadix21IFMAX8(&limbs)

	var result [X8Lanes][32]byte
	for lane := 0; lane < X8Lanes; lane++ {
		if active&(1<<lane) != 0 {
			storeScalarRadix21Lane(&result[lane], &limbs, lane)
		}
	}
	*out = result
	return active, true
}

func storeScalarRadix21Lane(out *[32]byte, s *scalarRadix21X8, lane int) {
	out[0] = byte(s[0][lane])
	out[1] = byte(s[0][lane] >> 8)
	out[2] = byte((s[0][lane] >> 16) | (s[1][lane] << 5))
	out[3] = byte(s[1][lane] >> 3)
	out[4] = byte(s[1][lane] >> 11)
	out[5] = byte((s[1][lane] >> 19) | (s[2][lane] << 2))
	out[6] = byte(s[2][lane] >> 6)
	out[7] = byte((s[2][lane] >> 14) | (s[3][lane] << 7))
	out[8] = byte(s[3][lane] >> 1)
	out[9] = byte(s[3][lane] >> 9)
	out[10] = byte((s[3][lane] >> 17) | (s[4][lane] << 4))
	out[11] = byte(s[4][lane] >> 4)
	out[12] = byte(s[4][lane] >> 12)
	out[13] = byte((s[4][lane] >> 20) | (s[5][lane] << 1))
	out[14] = byte(s[5][lane] >> 7)
	out[15] = byte((s[5][lane] >> 15) | (s[6][lane] << 6))
	out[16] = byte(s[6][lane] >> 2)
	out[17] = byte(s[6][lane] >> 10)
	out[18] = byte((s[6][lane] >> 18) | (s[7][lane] << 3))
	out[19] = byte(s[7][lane] >> 5)
	out[20] = byte(s[7][lane] >> 13)
	out[21] = byte(s[8][lane])
	out[22] = byte(s[8][lane] >> 8)
	out[23] = byte((s[8][lane] >> 16) | (s[9][lane] << 5))
	out[24] = byte(s[9][lane] >> 3)
	out[25] = byte(s[9][lane] >> 11)
	out[26] = byte((s[9][lane] >> 19) | (s[10][lane] << 2))
	out[27] = byte(s[10][lane] >> 6)
	out[28] = byte((s[10][lane] >> 14) | (s[11][lane] << 7))
	out[29] = byte(s[11][lane] >> 1)
	out[30] = byte(s[11][lane] >> 9)
	out[31] = byte(s[11][lane] >> 17)
}
