package r51x5

import (
	"encoding/hex"
	"math/rand"
	"testing"
)

// quadPointDoubleHardwareX4 is the minimum coordinate-parallel hardware
// prototype: two existing x4 IFMA multiplications plus one standalone packed
// normalization. Production callers gate IFMA once in the constructor and
// use the unchecked core directly.
func quadPointDoubleHardwareX4(out, q *quadPackedPointX4) error {
	if !ExperimentalIFMAAvailable() {
		return ErrIFMAUnavailable
	}
	return quadPointDoubleHardwareUncheckedX4(out, q)
}

func TestExperimentalCoordinateParallelDoubleX4(t *testing.T) {
	rng := rand.New(rand.NewSource(0x514d0b1e))
	torsion := referenceTorsionPoints(t)
	for round := 0; round < 64; round++ {
		ref := randomMixedReferencePoint(t, rng, torsion[round%len(torsion)])
		var start Point
		if _, err := start.SetBytes(ref.Bytes()); err != nil {
			t.Fatalf("round %d: decode fixture: %v", round, err)
		}

		// Exercise genuinely projective inputs rather than only the affine Z=1
		// decoder output. Scaling all four extended coordinates preserves XY=ZT.
		lambda := randomNonUnitElement(t, rng)
		start.X.Multiply(&start.X, &lambda)
		start.Y.Multiply(&start.Y, &lambda)
		start.T.Multiply(&start.T, &lambda)
		start.Z.Multiply(&start.Z, &lambda)
		assertScalarPointInvariant(t, "quad start", &start)

		points := [X4Lanes]Point{
			start,
			*NewIdentityPoint(),
			*NewIdentityPoint(),
			*NewIdentityPoint(),
		}
		var want PointX4
		want.SetPoints(&points)
		model := new(quadPackedPointX4).setReduced(&start)
		hardware := *model

		// Repeated aliasing exercises the composable output range as well as a
		// single point operation. The scalar PointX4 path is the r51 oracle.
		chain := 1 + round%19
		for step := 0; step < chain; step++ {
			want.Double(&want)
			if err := quadPointDoubleModelX4(model, model); err != nil {
				t.Fatalf("round %d step %d: model double: %v", round, step, err)
			}
			assertQuadPackedPointX4(t, "model", round, step, model, &want)

			if ExperimentalIFMAAvailable() {
				if err := quadPointDoubleHardwareX4(&hardware, &hardware); err != nil {
					t.Fatalf("round %d step %d: hardware double: %v", round, step, err)
				}
				assertQuadPackedPointX4(t, "hardware", round, step, &hardware, &want)
			}
		}
	}
}

func TestExperimentalCoordinateParallelDoubleX4TorsionEdges(t *testing.T) {
	// Identity, order two, and both order-four points stress x=0 and y=0.
	for _, index := range []int{2, 4, 0, 1} {
		encoded, err := hex.DecodeString(pointTestEncodings[index])
		if err != nil {
			t.Fatal(err)
		}
		var start Point
		if _, err := start.SetBytes(encoded); err != nil {
			t.Fatalf("fixture %d: %v", index, err)
		}

		points := [X4Lanes]Point{
			start,
			*NewIdentityPoint(),
			*NewIdentityPoint(),
			*NewIdentityPoint(),
		}
		var want PointX4
		want.SetPoints(&points)
		model := new(quadPackedPointX4).setReduced(&start)
		hardware := *model
		for step := 0; step < 8; step++ {
			want.Double(&want)
			if err := quadPointDoubleModelX4(model, model); err != nil {
				t.Fatalf("fixture %d step %d: model: %v", index, step, err)
			}
			assertQuadPackedPointX4(t, "torsion model", index, step, model, &want)
			if ExperimentalIFMAAvailable() {
				if err := quadPointDoubleHardwareX4(&hardware, &hardware); err != nil {
					t.Fatalf("fixture %d step %d: hardware: %v", index, step, err)
				}
				assertQuadPackedPointX4(t, "torsion hardware", index, step, &hardware, &want)
			}
		}
	}
}

func TestExperimentalCoordinateParallelDoubleX4IgnoresInputT(t *testing.T) {
	var encoded [32]byte
	encoded[0] = 0x58
	for i := 1; i < len(encoded); i++ {
		encoded[i] = 0x66
	}
	var start Point
	if _, err := start.SetBytes(encoded[:]); err != nil {
		t.Fatal(err)
	}

	rng := rand.New(rand.NewSource(0x514bad7))
	model := new(quadPackedPointX4).setReduced(&start)
	corruptModel := *model
	hardware := *model
	corruptHardware := *model
	for step := 0; step < 24; step++ {
		badT := randomNonUnitElement(t, rng)
		for limb := range badT.limbs {
			corruptModel.coordinates.limbs[limb][2] = badT.limbs[limb]
			corruptHardware.coordinates.limbs[limb][2] = badT.limbs[limb]
		}
		if err := quadPointDoubleModelX4(model, model); err != nil {
			t.Fatal(err)
		}
		if err := quadPointDoubleModelX4(&corruptModel, &corruptModel); err != nil {
			t.Fatal(err)
		}
		if corruptModel.coordinates != model.coordinates {
			t.Fatalf("step %d: corrupted input T changed model output", step)
		}

		if ExperimentalIFMAAvailable() {
			if err := quadPointDoubleHardwareX4(&hardware, &hardware); err != nil {
				t.Fatal(err)
			}
			if err := quadPointDoubleHardwareX4(&corruptHardware, &corruptHardware); err != nil {
				t.Fatal(err)
			}
			if corruptHardware.coordinates != hardware.coordinates {
				t.Fatalf("step %d: corrupted input T changed hardware output", step)
			}
		}
	}
}

func TestExperimentalCoordinateParallelDoubleX4RangeEnvelope(t *testing.T) {
	// The packed permutations must preserve the generic composable u52
	// contract, even at its exclusive upper bound rather than only on point
	// fixtures emitted by current formulas.
	var q quadPackedPointX4
	for limb := range q.coordinates.limbs {
		for lane := range q.coordinates.limbs[limb] {
			q.coordinates.limbs[limb][lane] = ifmaComposableLimbLimit - 1
		}
	}
	var u, v IFMAElementX4
	quadDoubleFirstOperandsX4(&u, &v, &q)
	if !isIFMAElementX4(&u) || !isIFMAElementX4(&v) {
		t.Fatal("first packed operands escaped u52")
	}

	var products IFMAElementX4
	if err := modelMultiplyComposableX4(&products, &u, &v); err != nil {
		t.Fatalf("maximum-u52 first product: %v", err)
	}
	if !isIFMAElementX4(&products) {
		t.Fatal("first packed product escaped u52")
	}

	// Independently maximize A/B/C/D before the biased E/G/H/F schedule.
	// This directly covers its unsigned-subtraction and normalizer bounds.
	for limb := range products.limbs {
		for lane := range products.limbs[limb] {
			products.limbs[limb][lane] = ifmaComposableLimbLimit - 1
		}
	}
	var left, right IFMAElementX4
	quadDoubleFinalOperandsX4(&left, &right, &products)
	if !isIFMAElementX4(&left) || !isIFMAElementX4(&right) {
		t.Fatal("final packed operands escaped u52")
	}
	var result IFMAElementX4
	if err := modelMultiplyComposableX4(&result, &left, &right); err != nil {
		t.Fatalf("maximum-u52 final product: %v", err)
	}
	if !isIFMAElementX4(&result) {
		t.Fatal("final packed product escaped u52")
	}
}

func TestIFMAQuadDoubleFirstOperandsX4MatchesPortable(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		return
	}

	inputs := make([]IFMAElementX4, 0, 1026)
	inputs = append(inputs, IFMAElementX4{})
	var maximum IFMAElementX4
	for limb := range maximum.limbs {
		for lane := range maximum.limbs[limb] {
			maximum.limbs[limb][lane] = ifmaComposableLimbLimit - 1
		}
	}
	inputs = append(inputs, maximum)
	rng := rand.New(rand.NewSource(0x514f1a57))
	for sample := 0; sample < 1024; sample++ {
		var input IFMAElementX4
		for limb := range input.limbs {
			for lane := range input.limbs[limb] {
				input.limbs[limb][lane] = rng.Uint64() & (ifmaComposableLimbLimit - 1)
			}
		}
		inputs = append(inputs, input)
	}

	for index := range inputs {
		input := inputs[index]
		point := quadPackedPointX4{coordinates: input}
		var wantU, wantV IFMAElementX4
		quadDoubleFirstOperandsX4(&wantU, &wantV, &point)

		var gotU, gotV IFMAElementX4
		ifmaQuadDoubleFirstOperandsUncheckedX4(&gotU.limbs, &gotV.limbs, &input.limbs)
		if gotU != wantU || gotV != wantV {
			t.Fatalf("input %d: native first operands differ from portable oracle", index)
		}

		aliasedU := input
		var aliasV IFMAElementX4
		ifmaQuadDoubleFirstOperandsUncheckedX4(&aliasedU.limbs, &aliasV.limbs, &aliasedU.limbs)
		if aliasedU != wantU || aliasV != wantV {
			t.Fatalf("input %d: input/U alias differs from portable oracle", index)
		}

		aliasedV := input
		var aliasU IFMAElementX4
		ifmaQuadDoubleFirstOperandsUncheckedX4(&aliasU.limbs, &aliasedV.limbs, &aliasedV.limbs)
		if aliasU != wantU || aliasedV != wantV {
			t.Fatalf("input %d: input/V alias differs from portable oracle", index)
		}
	}
}

func TestIFMAQuadDoubleFirstOperandsX4ZeroAllocations(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		return
	}
	var input, u, v IFMAElementX4
	for limb := range input.limbs {
		for lane := range input.limbs[limb] {
			input.limbs[limb][lane] = uint64(1 + limb*X4Lanes + lane)
		}
	}
	if allocs := testing.AllocsPerRun(100, func() {
		ifmaQuadDoubleFirstOperandsUncheckedX4(&u.limbs, &v.limbs, &input.limbs)
	}); allocs != 0 {
		t.Fatalf("allocations=%v", allocs)
	}
}

func TestIFMAQuadDoubleFirstMultiplyX4MatchesSplit(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		return
	}

	inputs := make([]IFMAElementX4, 0, 514)
	inputs = append(inputs, IFMAElementX4{})
	var maximum IFMAElementX4
	for limb := range maximum.limbs {
		for lane := range maximum.limbs[limb] {
			maximum.limbs[limb][lane] = ifmaComposableLimbLimit - 1
		}
	}
	inputs = append(inputs, maximum)
	rng := rand.New(rand.NewSource(0x5144464d))
	for sample := 0; sample < 512; sample++ {
		var input IFMAElementX4
		for limb := range input.limbs {
			for lane := range input.limbs[limb] {
				input.limbs[limb][lane] = rng.Uint64() & (ifmaComposableLimbLimit - 1)
			}
		}
		inputs = append(inputs, input)
	}

	for index := range inputs {
		input := inputs[index]
		var u, v, want IFMAElementX4
		ifmaQuadDoubleFirstOperandsUncheckedX4(&u.limbs, &v.limbs, &input.limbs)
		ifmaMulNormalizedUncheckedX4(&want.limbs, &u.limbs, &v.limbs)

		var got IFMAElementX4
		ifmaQuadDoubleFirstMultiplyUncheckedX4(&got.limbs, &input.limbs)
		if got != want {
			t.Fatalf("input %d: fused first multiply differs from split native oracle", index)
		}

		aliased := input
		ifmaQuadDoubleFirstMultiplyUncheckedX4(&aliased.limbs, &aliased.limbs)
		if aliased != want {
			t.Fatalf("input %d: fused input/output alias differs from split native oracle", index)
		}
	}
}

func TestIFMAQuadDoubleFirstMultiplyX4ZeroAllocations(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		return
	}
	var input, output IFMAElementX4
	for limb := range input.limbs {
		for lane := range input.limbs[limb] {
			input.limbs[limb][lane] = uint64(1 + limb*X4Lanes + lane)
		}
	}
	if allocs := testing.AllocsPerRun(100, func() {
		ifmaQuadDoubleFirstMultiplyUncheckedX4(&output.limbs, &input.limbs)
	}); allocs != 0 {
		t.Fatalf("allocations=%v", allocs)
	}
}

func TestIFMAQuadDoubleFinalOperandsX4MatchesPortable(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		return
	}

	inputs := make([]IFMAElementX4, 0, 1026)
	inputs = append(inputs, IFMAElementX4{})
	var maximum IFMAElementX4
	for limb := range maximum.limbs {
		for lane := range maximum.limbs[limb] {
			maximum.limbs[limb][lane] = ifmaComposableLimbLimit - 1
		}
	}
	inputs = append(inputs, maximum)
	rng := rand.New(rand.NewSource(0x51457a62))
	for sample := 0; sample < 1024; sample++ {
		var input IFMAElementX4
		for limb := range input.limbs {
			for lane := range input.limbs[limb] {
				input.limbs[limb][lane] = rng.Uint64() & (ifmaComposableLimbLimit - 1)
			}
		}
		inputs = append(inputs, input)
	}

	for index := range inputs {
		input := inputs[index]
		var wantLeft, wantRight IFMAElementX4
		quadDoubleFinalOperandsX4(&wantLeft, &wantRight, &input)

		var gotLeft, gotRight IFMAElementX4
		ifmaQuadDoubleFinalOperandsUncheckedX4(&gotLeft.limbs, &gotRight.limbs, &input.limbs)
		if gotLeft != wantLeft || gotRight != wantRight {
			t.Fatalf("input %d: native packed Stage 2 differs from portable oracle", index)
		}

		aliased := input
		var aliasRight IFMAElementX4
		ifmaQuadDoubleFinalOperandsUncheckedX4(&aliased.limbs, &aliasRight.limbs, &aliased.limbs)
		if aliased != wantLeft || aliasRight != wantRight {
			t.Fatalf("input %d: input/left alias differs from portable oracle", index)
		}
	}
}

func TestIFMAQuadDoubleFinalOperandsX4ZeroAllocations(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		return
	}
	var input, left, right IFMAElementX4
	for limb := range input.limbs {
		for lane := range input.limbs[limb] {
			input.limbs[limb][lane] = uint64(1 + limb*X4Lanes + lane)
		}
	}
	if allocs := testing.AllocsPerRun(100, func() {
		ifmaQuadDoubleFinalOperandsUncheckedX4(&left.limbs, &right.limbs, &input.limbs)
	}); allocs != 0 {
		t.Fatalf("allocations=%v", allocs)
	}
}

func TestIFMAQuadDoubleFinalMultiplyX4MatchesSplit(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		return
	}

	inputs := make([]IFMAElementX4, 0, 514)
	inputs = append(inputs, IFMAElementX4{})
	var maximum IFMAElementX4
	for limb := range maximum.limbs {
		for lane := range maximum.limbs[limb] {
			maximum.limbs[limb][lane] = ifmaComposableLimbLimit - 1
		}
	}
	inputs = append(inputs, maximum)
	rng := rand.New(rand.NewSource(0x514f1a63))
	for sample := 0; sample < 512; sample++ {
		var input IFMAElementX4
		for limb := range input.limbs {
			for lane := range input.limbs[limb] {
				input.limbs[limb][lane] = rng.Uint64() & (ifmaComposableLimbLimit - 1)
			}
		}
		inputs = append(inputs, input)
	}

	for index := range inputs {
		input := inputs[index]
		var left, right, want IFMAElementX4
		ifmaQuadDoubleFinalOperandsUncheckedX4(&left.limbs, &right.limbs, &input.limbs)
		ifmaMulNormalizedUncheckedX4(&want.limbs, &left.limbs, &right.limbs)

		var got IFMAElementX4
		ifmaQuadDoubleFinalMultiplyUncheckedX4(&got.limbs, &input.limbs)
		if got != want {
			t.Fatalf("input %d: fused final multiply differs from split native oracle", index)
		}

		aliased := input
		ifmaQuadDoubleFinalMultiplyUncheckedX4(&aliased.limbs, &aliased.limbs)
		if aliased != want {
			t.Fatalf("input %d: fused input/output alias differs from split native oracle", index)
		}
	}
}

func TestIFMAQuadDoubleFinalMultiplyX4ZeroAllocations(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		return
	}
	var input, output IFMAElementX4
	for limb := range input.limbs {
		for lane := range input.limbs[limb] {
			input.limbs[limb][lane] = uint64(1 + limb*X4Lanes + lane)
		}
	}
	if allocs := testing.AllocsPerRun(100, func() {
		ifmaQuadDoubleFinalMultiplyUncheckedX4(&output.limbs, &input.limbs)
	}); allocs != 0 {
		t.Fatalf("allocations=%v", allocs)
	}
}

func TestIFMAQuadCachedAddFinalMultiplyX4MatchesSplit(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		return
	}

	inputs := make([]IFMAElementX4, 0, 514)
	inputs = append(inputs, IFMAElementX4{})
	var maximum IFMAElementX4
	for limb := range maximum.limbs {
		for lane := range maximum.limbs[limb] {
			maximum.limbs[limb][lane] = ifmaComposableLimbLimit - 1
		}
	}
	inputs = append(inputs, maximum)
	rng := rand.New(rand.NewSource(0x51434144))
	for sample := 0; sample < 512; sample++ {
		var input IFMAElementX4
		for limb := range input.limbs {
			for lane := range input.limbs[limb] {
				input.limbs[limb][lane] = rng.Uint64() & (ifmaComposableLimbLimit - 1)
			}
		}
		inputs = append(inputs, input)
	}

	for index := range inputs {
		input := inputs[index]
		var left, right, want IFMAElementX4
		ifmaQuadCachedAddFinalOperandsUncheckedX4(&left.limbs, &right.limbs, &input.limbs)
		ifmaMulNormalizedUncheckedX4(&want.limbs, &left.limbs, &right.limbs)

		var got IFMAElementX4
		ifmaQuadCachedAddFinalMultiplyUncheckedX4(&got.limbs, &input.limbs)
		if got != want {
			t.Fatalf("input %d: fused cached-add final multiply differs from split native oracle", index)
		}

		aliased := input
		ifmaQuadCachedAddFinalMultiplyUncheckedX4(&aliased.limbs, &aliased.limbs)
		if aliased != want {
			t.Fatalf("input %d: fused cached-add input/output alias differs from split native oracle", index)
		}
	}
}

func TestIFMAQuadCachedAddFinalMultiplyX4ZeroAllocations(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		return
	}
	var input, output IFMAElementX4
	for limb := range input.limbs {
		for lane := range input.limbs[limb] {
			input.limbs[limb][lane] = uint64(1 + limb*X4Lanes + lane)
		}
	}
	if allocs := testing.AllocsPerRun(100, func() {
		ifmaQuadCachedAddFinalMultiplyUncheckedX4(&output.limbs, &input.limbs)
	}); allocs != 0 {
		t.Fatalf("allocations=%v", allocs)
	}
}

func TestExperimentalCoordinateParallelDoubleWorkspaceX4IgnoresPriorScratch(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		return
	}

	var encoded [32]byte
	encoded[0] = 0x58
	for index := 1; index < len(encoded); index++ {
		encoded[index] = 0x66
	}
	var point Point
	if _, err := point.SetBytes(encoded[:]); err != nil {
		t.Fatal(err)
	}

	clean := new(quadPackedPointX4).setReduced(&point)
	poisoned := *clean
	var cleanWorkspace, poisonedWorkspace quadPointDoubleWorkspaceX4
	for limb := range poisonedWorkspace.products.limbs {
		for lane := range poisonedWorkspace.products.limbs[limb] {
			value := uint64(0xa5a5_0000_0000_0000 | uint64(limb<<8|lane))
			poisonedWorkspace.products.limbs[limb][lane] = value ^ 0x1111
		}
	}

	for step := 0; step < 32; step++ {
		if err := quadPointDoubleHardwareWorkspaceUncheckedX4(clean, clean, &cleanWorkspace); err != nil {
			t.Fatalf("step %d clean: %v", step, err)
		}
		if err := quadPointDoubleHardwareWorkspaceUncheckedX4(&poisoned, &poisoned, &poisonedWorkspace); err != nil {
			t.Fatalf("step %d poisoned: %v", step, err)
		}
		if poisoned.coordinates != clean.coordinates {
			t.Fatalf("step %d: prior scratch changed the doubled point", step)
		}
	}
}

func assertQuadPackedPointX4(t *testing.T, label string, round, step int, got *quadPackedPointX4, want *PointX4) {
	t.Helper()
	gotPoint := got.reduced()
	wantPoint := want.Lane(0)
	if gotPoint.Equal(&wantPoint) != 1 {
		t.Fatalf("%s round %d step %d: packed double differs from scalar r51", label, round, step)
	}
	assertScalarPointInvariant(t, label, &gotPoint)
}

var (
	benchmarkQuadPackedPointX4Sink quadPackedPointX4
	benchmarkQuadLanePointX4Sink   IFMAPointX4
)

type quadPointDoubleSplitFirstWorkspaceX4 struct {
	u, v, products IFMAElementX4
}

func quadPointDoubleHardwareWorkspaceSplitFirstX4(
	out, q *quadPackedPointX4,
	workspace *quadPointDoubleSplitFirstWorkspaceX4,
) error {
	ifmaQuadDoubleFirstOperandsUncheckedX4(&workspace.u.limbs, &workspace.v.limbs, &q.coordinates.limbs)
	if err := ifmaMultiplyComposableUncheckedX4(&workspace.products, &workspace.u, &workspace.v); err != nil {
		return err
	}
	ifmaQuadDoubleFinalMultiplyUncheckedX4(&out.coordinates.limbs, &workspace.products.limbs)
	return nil
}

func BenchmarkExperimentalCoordinateParallelDoubleX4(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skip("AVX-512 IFMA is unavailable")
	}

	// Canonical Ed25519 basepoint encoding.
	var encoded [32]byte
	encoded[0] = 0x58
	for i := 1; i < len(encoded); i++ {
		encoded[i] = 0x66
	}
	var point Point
	if _, err := point.SetBytes(encoded[:]); err != nil {
		b.Fatal(err)
	}
	// Keep the benchmark input projective so it matches the DSM accumulator.
	var scaleBytes [32]byte
	scaleBytes[0] = 7
	var scale Element
	if _, err := scale.SetBytes(scaleBytes[:]); err != nil {
		b.Fatal(err)
	}
	point.X.Multiply(&point.X, &scale)
	point.Y.Multiply(&point.Y, &scale)
	point.T.Multiply(&point.T, &scale)
	point.Z.Multiply(&point.Z, &scale)

	b.Run("chained/quad-packed-xytz", func(b *testing.B) {
		state := new(quadPackedPointX4).setReduced(&point)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := quadPointDoubleHardwareUncheckedX4(state, state); err != nil {
				b.Fatal(err)
			}
		}
		benchmarkQuadPackedPointX4Sink = *state
	})

	b.Run("chained/quad-packed-reused-workspace", func(b *testing.B) {
		state := new(quadPackedPointX4).setReduced(&point)
		var workspace quadPointDoubleWorkspaceX4
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := quadPointDoubleHardwareWorkspaceUncheckedX4(state, state, &workspace); err != nil {
				b.Fatal(err)
			}
		}
		benchmarkQuadPackedPointX4Sink = *state
	})

	b.Run("chained/quad-packed-split-first-control", func(b *testing.B) {
		state := new(quadPackedPointX4).setReduced(&point)
		var workspace quadPointDoubleSplitFirstWorkspaceX4
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := quadPointDoubleHardwareWorkspaceSplitFirstX4(state, state, &workspace); err != nil {
				b.Fatal(err)
			}
		}
		benchmarkQuadPackedPointX4Sink = *state
	})

	b.Run("chained/current-one-active-lane", func(b *testing.B) {
		points := [X4Lanes]Point{
			point,
			*NewIdentityPoint(),
			*NewIdentityPoint(),
			*NewIdentityPoint(),
		}
		var reduced PointX4
		reduced.SetPoints(&points)
		var state IFMAPointX4
		state.SetReduced(&reduced)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := ifmaPointDoubleComposableStaticX4(&state, &state); err != nil {
				b.Fatal(err)
			}
		}
		benchmarkQuadLanePointX4Sink = state
	})
}
