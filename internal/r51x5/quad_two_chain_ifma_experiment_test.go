package r51x5

import (
	"math/rand"
	"testing"
)

func packQuadTwoChainX8(first, second *quadPackedPointX4) IFMAElementX8 {
	var packed IFMAElementX8
	for limb := range packed.limbs {
		for lane := 0; lane < X4Lanes; lane++ {
			packed.limbs[limb][lane] = first.coordinates.limbs[limb][lane]
			packed.limbs[limb][lane+X4Lanes] = second.coordinates.limbs[limb][lane]
		}
	}
	return packed
}

func unpackQuadTwoChainX8(packed *IFMAElementX8) [2]quadPackedPointX4 {
	var points [2]quadPackedPointX4
	for limb := range packed.limbs {
		for lane := 0; lane < X4Lanes; lane++ {
			points[0].coordinates.limbs[limb][lane] = packed.limbs[limb][lane]
			points[1].coordinates.limbs[limb][lane] = packed.limbs[limb][lane+X4Lanes]
		}
	}
	return points
}

func TestExperimentalQuadTwoChainDoubleX8MatchesTwoX4(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		return
	}

	rng := rand.New(rand.NewSource(0x5142c8a1))
	torsion := referenceTorsionPoints(t)
	for round := 0; round < 64; round++ {
		var scalarPoints [2]Point
		for half := range scalarPoints {
			ref := randomMixedReferencePoint(t, rng, torsion[(round+half)%len(torsion)])
			if _, err := scalarPoints[half].SetBytes(ref.Bytes()); err != nil {
				t.Fatalf("round %d half %d: decode fixture: %v", round, half, err)
			}
			lambda := randomNonUnitElement(t, rng)
			scalarPoints[half].X.Multiply(&scalarPoints[half].X, &lambda)
			scalarPoints[half].Y.Multiply(&scalarPoints[half].Y, &lambda)
			scalarPoints[half].T.Multiply(&scalarPoints[half].T, &lambda)
			scalarPoints[half].Z.Multiply(&scalarPoints[half].Z, &lambda)
		}

		x4 := [2]quadPackedPointX4{
			*new(quadPackedPointX4).setReduced(&scalarPoints[0]),
			*new(quadPackedPointX4).setReduced(&scalarPoints[1]),
		}
		x8 := packQuadTwoChainX8(&x4[0], &x4[1])
		var x4Workspace [2]quadPointDoubleWorkspaceX4
		var x8Workspace quadTwoChainDoubleWorkspaceX8

		chain := 1 + round%19
		for step := 0; step < chain; step++ {
			for half := range x4 {
				if err := quadPointDoubleHardwareWorkspaceUncheckedX4(&x4[half], &x4[half], &x4Workspace[half]); err != nil {
					t.Fatalf("round %d step %d half %d x4: %v", round, step, half, err)
				}
			}
			if err := quadTwoChainDoubleHardwareWorkspaceUncheckedX8(&x8, &x8, &x8Workspace); err != nil {
				t.Fatalf("round %d step %d x8: %v", round, step, err)
			}
			got := unpackQuadTwoChainX8(&x8)
			for half := range got {
				if got[half].coordinates != x4[half].coordinates {
					t.Fatalf("round %d step %d half %d: two-chain x8 differs from x4 oracle", round, step, half)
				}
				reduced := got[half].reduced()
				assertScalarPointInvariant(t, "two-chain x8", &reduced)
			}
		}
	}
}

func TestExperimentalQuadTwoChainDoubleX8ZeroAllocations(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		return
	}
	var state IFMAElementX8
	for limb := range state.limbs {
		for lane := range state.limbs[limb] {
			state.limbs[limb][lane] = uint64(1 + limb*X8Lanes + lane)
		}
	}
	var workspace quadTwoChainDoubleWorkspaceX8
	if allocs := testing.AllocsPerRun(100, func() {
		if err := quadTwoChainDoubleHardwareWorkspaceUncheckedX8(&state, &state, &workspace); err != nil {
			panic(err)
		}
	}); allocs != 0 {
		t.Fatalf("allocations=%v", allocs)
	}
}

var benchmarkQuadTwoChainX8Sink IFMAElementX8

func BenchmarkExperimentalQuadTwoChainDoubleX8(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skip("AVX-512 IFMA is unavailable")
	}

	var encoded [32]byte
	encoded[0] = 0x58
	for index := 1; index < len(encoded); index++ {
		encoded[index] = 0x66
	}
	var point Point
	if _, err := point.SetBytes(encoded[:]); err != nil {
		b.Fatal(err)
	}
	first := new(quadPackedPointX4).setReduced(&point)
	second := *first
	var secondWorkspace quadPointDoubleWorkspaceX4
	if err := quadPointDoubleHardwareWorkspaceUncheckedX4(&second, &second, &secondWorkspace); err != nil {
		b.Fatal(err)
	}

	b.Run("two-independent-packed-x4", func(b *testing.B) {
		states := [2]quadPackedPointX4{*first, second}
		var workspaces [2]quadPointDoubleWorkspaceX4
		b.ReportAllocs()
		b.ResetTimer()
		for index := 0; index < b.N; index++ {
			for half := range states {
				if err := quadPointDoubleHardwareWorkspaceUncheckedX4(&states[half], &states[half], &workspaces[half]); err != nil {
					b.Fatal(err)
				}
			}
		}
		b.ReportMetric(2, "chains/op")
		benchmarkQuadPackedPointX4Sink = states[0]
	})

	b.Run("two-chain-zmm", func(b *testing.B) {
		state := packQuadTwoChainX8(first, &second)
		var workspace quadTwoChainDoubleWorkspaceX8
		b.ReportAllocs()
		b.ResetTimer()
		for index := 0; index < b.N; index++ {
			if err := quadTwoChainDoubleHardwareWorkspaceUncheckedX8(&state, &state, &workspace); err != nil {
				b.Fatal(err)
			}
		}
		b.ReportMetric(2, "chains/op")
		benchmarkQuadTwoChainX8Sink = state
	})
}
