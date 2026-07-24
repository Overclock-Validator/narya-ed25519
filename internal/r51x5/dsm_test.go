package r51x5

import (
	"fmt"
	"math/rand"
	"testing"

	edwardsref "github.com/Overclock-Validator/narya/internal/edwards25519"
)

func TestDSMExactSignedMixedOrderMasksAndTails(t *testing.T) {
	rng := rand.New(rand.NewSource(0x51d5ba7c))
	torsion := referenceTorsionPoints(t)
	qsmRefs, qsmBases := scalarWindowQSMBasesX8(t, rng, &torsion)
	qsmCoefficients, coefficientBig := scalarWindowQSMCoefficientsX8()

	var bases8 [DSMTerms]PointX8
	var coefficients8 DSMScalarsX8
	for term := 0; term < DSMTerms; term++ {
		bases8[term] = qsmBases[term]
		coefficients8[term] = qsmCoefficients[term]
	}
	var want8 [X8Lanes]*edwardsref.Point
	for lane := 0; lane < X8Lanes; lane++ {
		term0 := exactReferenceIntegerMult(qsmRefs[0][lane], coefficientBig[0][lane])
		term1 := exactReferenceIntegerMult(qsmRefs[1][lane], coefficientBig[1][lane])
		want8[lane] = new(edwardsref.Point).Add(term0, term1)
	}

	for _, radixBits := range []uint{4, 5, 6} {
		for tail := 0; tail <= X8Lanes; tail++ {
			active := uint8((1 << tail) - 1)
			var got PointX8
			DSMX8(&got, &bases8, &coefficients8, radixBits, active)
			assertMaskedPointX8(t, fmt.Sprintf("DSM x8 radix %d tail %d", 1<<radixBits, tail), &got, &want8, active)
		}
		for disabledLane := 0; disabledLane < X8Lanes; disabledLane++ {
			active := uint8(0xff &^ (1 << disabledLane))
			var got PointX8
			DSMX8(&got, &bases8, &coefficients8, radixBits, active)
			assertMaskedPointX8(t, fmt.Sprintf("DSM x8 radix %d disabled %d", 1<<radixBits, disabledLane), &got, &want8, active)
		}
	}

	for half := 0; half < 2; half++ {
		var bases4 [DSMTerms]PointX4
		var coefficients4 DSMScalarsX4
		var want4 [X4Lanes]*edwardsref.Point
		for term := 0; term < DSMTerms; term++ {
			var points [X4Lanes]Point
			for lane := 0; lane < X4Lanes; lane++ {
				index := half*X4Lanes + lane
				points[lane] = bases8[term].Lane(index)
				coefficients4[term][lane] = coefficients8[term][index]
			}
			bases4[term].SetPoints(&points)
		}
		for lane := 0; lane < X4Lanes; lane++ {
			want4[lane] = want8[half*X4Lanes+lane]
		}
		for _, radixBits := range []uint{4, 5, 6} {
			for tail := 0; tail <= X4Lanes; tail++ {
				active := uint8((1 << tail) - 1)
				var got PointX4
				DSMX4(&got, &bases4, &coefficients4, radixBits, active)
				assertMaskedPointX4(t, fmt.Sprintf("DSM x4 half %d radix %d tail %d", half, 1<<radixBits, tail), &got, &want4, active)
			}
		}
	}
}
