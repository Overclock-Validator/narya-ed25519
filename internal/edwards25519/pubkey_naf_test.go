package edwards25519

import (
	"math/rand"
	"testing"
	"unsafe"
)

func TestPubkeyNAFTableMatchesColdDoubleScalarMult(t *testing.T) {
	rng := rand.New(rand.NewSource(0x4e41525941))
	for round := 0; round < 256; round++ {
		pointScalar := randomScalarForNAFTest(t, rng)
		a := randomScalarForNAFTest(t, rng)
		b := randomScalarForNAFTest(t, rng)

		point := (&Point{}).ScalarBaseMult(pointScalar)
		table := NewPubkeyNAFTable(point)
		want := (&Point{}).VarTimeDoubleScalarBaseMult(a, point, b)
		got := (&Point{}).VarTimeDoubleScalarBaseMultTable(a, table, b)
		if got.Equal(want) != 1 {
			t.Fatalf("round %d: compact-table DSM differs from cold DSM", round)
		}
	}
}

func TestPubkeyNAFTableSize(t *testing.T) {
	const want = 8 * 4 * 5 * 8
	if got := unsafe.Sizeof(PubkeyNAFTable{}); got != want {
		t.Fatalf("sizeof(PubkeyNAFTable) = %d, want %d", got, want)
	}
}

func TestPubkeyNAFTableEdgePointsAndScalars(t *testing.T) {
	pointEncodings := [][32]byte{
		{1}, // identity
		{},  // y=0 order-four point
		{
			0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
		}, // order-two point
	}
	zeroBytes := [32]byte{}
	oneBytes := [32]byte{1}
	minusOneBytes := [32]byte{
		0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
		0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
	}
	minusOneBytes[0]-- // canonical scalar L-1
	scalarBytes := [][32]byte{zeroBytes, oneBytes, minusOneBytes}

	for pointIndex := range pointEncodings {
		point, err := (&Point{}).SetBytes(pointEncodings[pointIndex][:])
		if err != nil {
			t.Fatalf("point %d: %v", pointIndex, err)
		}
		table := NewPubkeyNAFTable(point)
		for aIndex := range scalarBytes {
			a, err := NewScalar().SetCanonicalBytes(scalarBytes[aIndex][:])
			if err != nil {
				t.Fatalf("a scalar %d: %v", aIndex, err)
			}
			for bIndex := range scalarBytes {
				b, err := NewScalar().SetCanonicalBytes(scalarBytes[bIndex][:])
				if err != nil {
					t.Fatalf("b scalar %d: %v", bIndex, err)
				}
				want := (&Point{}).VarTimeDoubleScalarBaseMult(a, point, b)
				got := (&Point{}).VarTimeDoubleScalarBaseMultTable(a, table, b)
				if got.Equal(want) != 1 {
					t.Fatalf("point=%d a=%d b=%d: compact-table DSM differs", pointIndex, aIndex, bIndex)
				}
			}
		}
	}
}

func randomScalarForNAFTest(t *testing.T, rng *rand.Rand) *Scalar {
	t.Helper()
	var wide [64]byte
	_, _ = rng.Read(wide[:])
	s, err := NewScalar().SetUniformBytes(wide[:])
	if err != nil {
		t.Fatal(err)
	}
	return s
}
