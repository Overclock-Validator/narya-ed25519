package r51x5

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"runtime"
	"testing"
)

func TestBatchEncodeIFMAModelMatchesScalarEncoding(t *testing.T) {
	points, references := makeBatchEncodeRandomPoints(t, rand.New(rand.NewSource(0x51ba7c4)))

	for _, groups := range []int{1, 2, 3, 4, 8, ExperimentalIFMABatchEncodeMaxX4Groups} {
		patterns := makeBatchEncodeMaskPatterns(groups)
		for patternIndex := range patterns {
			active := patterns[patternIndex]
			t.Run(fmt.Sprintf("groups=%d/pattern=%d", groups, patternIndex), func(t *testing.T) {
				var workspace ExperimentalIFMABatchEncodeWorkspaceX4
				var got [ExperimentalIFMABatchEncodeMaxX4Groups][X4Lanes][32]byte
				if err := batchEncodeIFMAModelX4(&workspace, &got, &points, &active, groups); err != nil {
					t.Fatal(err)
				}
				assertBatchEncodeOutputs(t, &got, &references, &active, groups)
			})
		}
	}

	// Exhaust every one-group mask independently. The multi-group patterns
	// above then exercise differing masks at the same lane position.
	for mask := 0; mask < 1<<X4Lanes; mask++ {
		var active [ExperimentalIFMABatchEncodeMaxX4Groups]uint8
		active[0] = uint8(mask)
		var workspace ExperimentalIFMABatchEncodeWorkspaceX4
		var got [ExperimentalIFMABatchEncodeMaxX4Groups][X4Lanes][32]byte
		if err := batchEncodeIFMAModelX4(&workspace, &got, &points, &active, 1); err != nil {
			t.Fatalf("mask=%x: %v", mask, err)
		}
		assertBatchEncodeOutputs(t, &got, &references, &active, 1)
	}
}

func TestBatchEncodeIFMAExactScheduleCount(t *testing.T) {
	points, references := makeBatchEncodeRandomPoints(t, rand.New(rand.NewSource(0x51c0a17)))
	for _, groups := range []int{1, 2, 4, 8, ExperimentalIFMABatchEncodeMaxX4Groups} {
		var active [ExperimentalIFMABatchEncodeMaxX4Groups]uint8
		for group := 0; group < groups; group++ {
			active[group] = 0x0f
		}
		var workspace ExperimentalIFMABatchEncodeWorkspaceX4
		var got [ExperimentalIFMABatchEncodeMaxX4Groups][X4Lanes][32]byte
		ops := decode2IFMAOpsX4{}
		if err := batchEncodeIFMAX4(&workspace, &got, &points, &active, groups, &ops); err != nil {
			t.Fatal(err)
		}
		// Inversion is 254S+11M = 265 calls to the current multiply
		// primitive. Prefix/recovery costs 3*(groups-1)M and affine X/Y
		// conversion costs 2*groups M.
		wantCalls := 265 + 3*(groups-1) + 2*groups
		if ops.calls != wantCalls {
			t.Fatalf("groups=%d calls=%d want=%d", groups, ops.calls, wantCalls)
		}
		assertBatchEncodeOutputs(t, &got, &references, &active, groups)
	}
}

func TestBatchEncodeIFMASparseScheduleCount(t *testing.T) {
	points, references := makeBatchEncodeRandomPoints(t, rand.New(rand.NewSource(0x51c0a175)))
	tests := []struct {
		name   string
		groups int
		masks  []uint8
	}{
		{name: "empty", groups: 5, masks: []uint8{0, 0, 0, 0, 0}},
		{name: "one-leading-empty", groups: 5, masks: []uint8{0, 0, 0x05, 0, 0}},
		{name: "interleaved", groups: 7, masks: []uint8{0, 0x01, 0, 0x0a, 0, 0x04, 0}},
		{name: "live-first-and-gaps", groups: 7, masks: []uint8{0x08, 0, 0x03, 0, 0, 0x0c, 0}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var active [ExperimentalIFMABatchEncodeMaxX4Groups]uint8
			copy(active[:], test.masks)
			nonempty := 0
			for _, mask := range test.masks {
				if mask != 0 {
					nonempty++
				}
			}

			var workspace ExperimentalIFMABatchEncodeWorkspaceX4
			var got [ExperimentalIFMABatchEncodeMaxX4Groups][X4Lanes][32]byte
			ops := decode2IFMAOpsX4{}
			if err := batchEncodeIFMAX4(&workspace, &got, &points, &active, test.groups, &ops); err != nil {
				t.Fatal(err)
			}
			wantCalls := 0
			if nonempty != 0 {
				// One inversion, 3M for each nonempty group after the
				// first, and 2M to affine-convert each nonempty group.
				wantCalls = 265 + 3*(nonempty-1) + 2*nonempty
			}
			if ops.calls != wantCalls {
				t.Fatalf("calls=%d want=%d", ops.calls, wantCalls)
			}
			assertBatchEncodeOutputs(t, &got, &references, &active, test.groups)
		})
	}
}

func TestBatchEncodeIFMAInactiveLanesCannotContaminateActive(t *testing.T) {
	points, references := makeBatchEncodeRandomPoints(t, rand.New(rand.NewSource(0x51ac71e)))
	mutated := points
	var active [ExperimentalIFMABatchEncodeMaxX4Groups]uint8
	const groups = 8
	for group := 0; group < groups; group++ {
		active[group] = 1 << (group % X4Lanes)
		for lane := 0; lane < X4Lanes; lane++ {
			if active[group]&(1<<lane) != 0 {
				continue
			}
			for limb := 0; limb < 5; limb++ {
				// These are deliberately not curve points. They remain valid u52
				// representatives and prove that inactive Z is replaced by one
				// before the cross-group product.
				mutated[group].X.limbs[limb][lane] = uint64(0x111+group+limb+lane) << 39
				mutated[group].Y.limbs[limb][lane] = uint64(0x222+group+limb+lane) << 38
				mutated[group].Z.limbs[limb][lane] = 0
				mutated[group].T.limbs[limb][lane] = uint64(0x333+group+limb+lane) << 37
			}
		}
	}

	var originalWorkspace, mutatedWorkspace ExperimentalIFMABatchEncodeWorkspaceX4
	var original, got [ExperimentalIFMABatchEncodeMaxX4Groups][X4Lanes][32]byte
	if err := batchEncodeIFMAModelX4(&originalWorkspace, &original, &points, &active, groups); err != nil {
		t.Fatal(err)
	}
	if err := batchEncodeIFMAModelX4(&mutatedWorkspace, &got, &mutated, &active, groups); err != nil {
		t.Fatal(err)
	}
	if got != original {
		t.Fatal("inactive coordinate mutation changed batch-encode output")
	}
	assertBatchEncodeOutputs(t, &got, &references, &active, groups)
}

func TestBatchEncodeIFMAReady52AliasesMatchReducedPoints(t *testing.T) {
	points, references := makeBatchEncodeRandomPoints(t, rand.New(rand.NewSource(0x51a11a5)))
	aliased := points
	const groups = 4
	for group := 0; group < groups; group++ {
		addModulusAliasIFMAX4(t, &aliased[group].X)
		addModulusAliasIFMAX4(t, &aliased[group].Y)
		addModulusAliasIFMAX4(t, &aliased[group].Z)
		addModulusAliasIFMAX4(t, &aliased[group].T)
	}
	var active [ExperimentalIFMABatchEncodeMaxX4Groups]uint8
	active[0], active[1], active[2], active[3] = 0x0f, 0x05, 0x0a, 0x03

	var modelWorkspace ExperimentalIFMABatchEncodeWorkspaceX4
	var model [ExperimentalIFMABatchEncodeMaxX4Groups][X4Lanes][32]byte
	if err := batchEncodeIFMAModelX4(&modelWorkspace, &model, &aliased, &active, groups); err != nil {
		t.Fatal(err)
	}
	assertBatchEncodeOutputs(t, &model, &references, &active, groups)

	if ExperimentalIFMAAvailable() {
		var hardwareWorkspace ExperimentalIFMABatchEncodeWorkspaceX4
		var hardware [ExperimentalIFMABatchEncodeMaxX4Groups][X4Lanes][32]byte
		if err := hardwareWorkspace.Encode(&hardware, &aliased, &active, groups); err != nil {
			t.Fatal(err)
		}
		if hardware != model {
			t.Fatal("Ready52 alias hardware/model mismatch")
		}
	}
}

func TestBatchEncodeIFMATorsionAndSignBoundaries(t *testing.T) {
	torsion := referenceTorsionPoints(t)
	rng := rand.New(rand.NewSource(0x51e1917))
	var points [ExperimentalIFMABatchEncodeMaxX4Groups]IFMAPointX4
	var references [ExperimentalIFMABatchEncodeMaxX4Groups]PointX4
	for index := 0; index < len(torsion); index++ {
		encoded := torsion[index].Bytes()
		var point Point
		if _, err := point.SetBytes(encoded); err != nil {
			t.Fatal(err)
		}
		lambda := randomNonUnitElement(t, rng)
		point.X.Multiply(&point.X, &lambda)
		point.Y.Multiply(&point.Y, &lambda)
		point.Z.Multiply(&point.Z, &lambda)
		point.T.Multiply(&point.T, &lambda)
		group, lane := index/X4Lanes, index%X4Lanes
		references[group].SetLane(lane, &point)
	}
	for group := 0; group < 2; group++ {
		points[group].SetReduced(&references[group])
	}
	var active [ExperimentalIFMABatchEncodeMaxX4Groups]uint8
	active[0], active[1] = 0x0f, 0x0f
	var workspace ExperimentalIFMABatchEncodeWorkspaceX4
	var got [ExperimentalIFMABatchEncodeMaxX4Groups][X4Lanes][32]byte
	if err := batchEncodeIFMAModelX4(&workspace, &got, &points, &active, 2); err != nil {
		t.Fatal(err)
	}
	assertBatchEncodeOutputs(t, &got, &references, &active, 2)
}

func TestInvertIFMAX4MatchesScalarAcrossReady52Domain(t *testing.T) {
	var boundary IFMAElementX4
	var one Element
	one.One()
	for limb := range modulusLimbs {
		boundary.limbs[limb][1] = one.limbs[limb]
		boundary.limbs[limb][2] = modulusLimbs[limb]
		boundary.limbs[limb][3] = ifmaComposableLimbLimit - 1
	}
	inputs := []IFMAElementX4{boundary}
	rng := rand.New(rand.NewSource(0x511a7e))
	for round := 0; round < 16; round++ {
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
		reduced := input.Reduced()
		var want ElementX4
		want.Invert(&reduced)

		var model IFMAElementX4
		modelOps := decode2IFMAOpsX4{}
		if err := invertIFMAX4(&model, &input, &modelOps); err != nil {
			t.Fatalf("case=%d model: %v", index, err)
		}
		if modelOps.calls != 265 {
			t.Fatalf("case=%d calls=%d want=265", index, modelOps.calls)
		}
		if got := model.Reduced(); got != want {
			t.Fatalf("case=%d model inverse mismatch", index)
		}

		if ExperimentalIFMAAvailable() {
			var hardware IFMAElementX4
			hardwareOps := decode2IFMAOpsX4{hardware: true, uncheckedInputs: true}
			if err := invertIFMAX4(&hardware, &input, &hardwareOps); err != nil {
				t.Fatalf("case=%d hardware: %v", index, err)
			}
			if got := hardware.Reduced(); got != want {
				t.Fatalf("case=%d hardware inverse mismatch", index)
			}
		}
	}
}

func TestBatchEncodeIFMAAtomicFailures(t *testing.T) {
	points, _ := makeBatchEncodeRandomPoints(t, rand.New(rand.NewSource(0x51fa117)))
	var active [ExperimentalIFMABatchEncodeMaxX4Groups]uint8
	active[0], active[1] = 0x0f, 0x0f
	var sentinel [ExperimentalIFMABatchEncodeMaxX4Groups][X4Lanes][32]byte
	for group := range sentinel {
		for lane := range sentinel[group] {
			for index := range sentinel[group][lane] {
				sentinel[group][lane][index] = 0xa5
			}
		}
	}

	for _, groups := range []int{-1, 0, ExperimentalIFMABatchEncodeMaxX4Groups + 1} {
		got := sentinel
		var workspace ExperimentalIFMABatchEncodeWorkspaceX4
		if err := batchEncodeIFMAModelX4(&workspace, &got, &points, &active, groups); !errors.Is(err, errIFMABatchEncodeGroupCount) {
			t.Fatalf("groups=%d error=%v", groups, err)
		}
		if got != sentinel {
			t.Fatalf("groups=%d changed output", groups)
		}
	}

	invalidMask := active
	invalidMask[0] = 0x10
	got := sentinel
	var invalidMaskWorkspace ExperimentalIFMABatchEncodeWorkspaceX4
	if err := batchEncodeIFMAModelX4(&invalidMaskWorkspace, &got, &points, &invalidMask, 2); !errors.Is(err, errIFMABatchEncodeActiveMask) {
		t.Fatalf("invalid active mask error=%v", err)
	}
	if got != sentinel {
		t.Fatal("invalid active mask changed output")
	}

	invalid := points
	invalid[0].Z.limbs[0][0] = ifmaComposableLimbLimit
	invalidActive := active
	invalidActive[0] &^= 1 // whole-point u52 validation also covers inactive lanes
	got = sentinel
	var invalidWorkspace ExperimentalIFMABatchEncodeWorkspaceX4
	if err := batchEncodeIFMAModelX4(&invalidWorkspace, &got, &invalid, &invalidActive, 2); !errors.Is(err, errIFMAComposableInputRange) {
		t.Fatalf("invalid range error=%v", err)
	}
	if got != sentinel {
		t.Fatal("invalid input changed output")
	}

	for _, zero := range []struct {
		name  string
		limbs Limbs
	}{
		{name: "canonical", limbs: Limbs{}},
		{name: "modulus-alias", limbs: modulusLimbs},
	} {
		zeroPoints := points
		for limb := range zero.limbs {
			zeroPoints[0].Z.limbs[limb][0] = zero.limbs[limb]
		}
		var zeroActive [ExperimentalIFMABatchEncodeMaxX4Groups]uint8
		zeroActive[0] = 1
		got = sentinel
		var zeroWorkspace ExperimentalIFMABatchEncodeWorkspaceX4
		if err := batchEncodeIFMAModelX4(&zeroWorkspace, &got, &zeroPoints, &zeroActive, 1); !errors.Is(err, errIFMABatchEncodeZeroZ) {
			t.Fatalf("active zero Z %s error=%v", zero.name, err)
		}
		if got != sentinel {
			t.Fatalf("active zero Z %s changed output", zero.name)
		}
	}

	// Every arithmetic failure point must preserve the caller's output, not
	// merely a representative late failure in affine conversion.
	wantCalls := 265 + 3*(2-1) + 2*2
	for failAt := 1; failAt <= wantCalls; failAt++ {
		got = sentinel
		var failedWorkspace ExperimentalIFMABatchEncodeWorkspaceX4
		failedOps := decode2IFMAOpsX4{failAt: failAt}
		if err := batchEncodeIFMAX4(&failedWorkspace, &got, &points, &active, 2, &failedOps); !errors.Is(err, errIFMAOutputRange) {
			t.Fatalf("injected arithmetic failure call=%d error=%v", failAt, err)
		}
		if got != sentinel {
			t.Fatalf("arithmetic failure call=%d changed output", failAt)
		}
	}

	// A successful empty mask zeroes only the selected groups. The bounded API
	// does not pay a 64-point copy merely to rewrite groups the caller excluded.
	got = sentinel
	var noActive [ExperimentalIFMABatchEncodeMaxX4Groups]uint8
	var emptyWorkspace ExperimentalIFMABatchEncodeWorkspaceX4
	if err := batchEncodeIFMAModelX4(&emptyWorkspace, &got, &points, &noActive, 2); err != nil {
		t.Fatal(err)
	}
	for group := range got {
		for lane := range got[group] {
			if group < 2 {
				if got[group][lane] != ([32]byte{}) {
					t.Fatalf("empty active group=%d lane=%d was not zeroed", group, lane)
				}
			} else if got[group][lane] != sentinel[group][lane] {
				t.Fatalf("group=%d beyond selected range changed", group)
			}
		}
	}

	if !ExperimentalIFMAAvailable() {
		got = sentinel
		var unavailableWorkspace ExperimentalIFMABatchEncodeWorkspaceX4
		if err := unavailableWorkspace.Encode(&got, &points, &active, 2); !errors.Is(err, ErrIFMAUnavailable) {
			t.Fatalf("unavailable error=%v", err)
		}
		if got != sentinel {
			t.Fatal("unavailable hardware changed output")
		}
	}
}

func TestExperimentalIFMABatchEncodeX4MatchesModelAndAllocatesZero(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	points, references := makeBatchEncodeRandomPoints(t, rand.New(rand.NewSource(0x51a110c)))
	for _, groups := range []int{1, 2, 4, 8, ExperimentalIFMABatchEncodeMaxX4Groups} {
		active := makeBatchEncodeMaskPatterns(groups)[1]
		var modelWorkspace, hardwareWorkspace ExperimentalIFMABatchEncodeWorkspaceX4
		var model, hardware [ExperimentalIFMABatchEncodeMaxX4Groups][X4Lanes][32]byte
		if err := batchEncodeIFMAModelX4(&modelWorkspace, &model, &points, &active, groups); err != nil {
			t.Fatal(err)
		}
		if err := hardwareWorkspace.Encode(&hardware, &points, &active, groups); err != nil {
			t.Fatal(err)
		}
		if hardware != model {
			t.Fatalf("groups=%d hardware/model mismatch", groups)
		}
		assertBatchEncodeOutputs(t, &hardware, &references, &active, groups)
	}

	// Exercise the hardware prefix/recovery path with both leading and
	// interleaved empty groups. The regular pattern above leaves every group
	// nonempty even though it uses only one lane per group.
	const sparseGroups = 8
	var sparseActive [ExperimentalIFMABatchEncodeMaxX4Groups]uint8
	sparseActive[2], sparseActive[4], sparseActive[7] = 0x05, 0x08, 0x03
	var sparseModelWorkspace, sparseHardwareWorkspace ExperimentalIFMABatchEncodeWorkspaceX4
	var sparseModel, sparseHardware [ExperimentalIFMABatchEncodeMaxX4Groups][X4Lanes][32]byte
	if err := batchEncodeIFMAModelX4(&sparseModelWorkspace, &sparseModel, &points, &sparseActive, sparseGroups); err != nil {
		t.Fatal(err)
	}
	if err := sparseHardwareWorkspace.Encode(&sparseHardware, &points, &sparseActive, sparseGroups); err != nil {
		t.Fatal(err)
	}
	if sparseHardware != sparseModel {
		t.Fatal("sparse hardware/model mismatch")
	}
	assertBatchEncodeOutputs(t, &sparseHardware, &references, &sparseActive, sparseGroups)

	var active [ExperimentalIFMABatchEncodeMaxX4Groups]uint8
	for group := range active {
		active[group] = 0x0f
	}
	var workspace ExperimentalIFMABatchEncodeWorkspaceX4
	var out [ExperimentalIFMABatchEncodeMaxX4Groups][X4Lanes][32]byte
	if allocations := testing.AllocsPerRun(20, func() {
		if err := workspace.Encode(&out, &points, &active, ExperimentalIFMABatchEncodeMaxX4Groups); err != nil {
			panic(err)
		}
	}); allocations != 0 {
		t.Fatalf("batch encoder allocations=%.2f", allocations)
	}
}

func makeBatchEncodeMaskPatterns(groups int) [][ExperimentalIFMABatchEncodeMaxX4Groups]uint8 {
	patterns := make([][ExperimentalIFMABatchEncodeMaxX4Groups]uint8, 4)
	for group := 0; group < groups; group++ {
		patterns[0][group] = 0x0f
		patterns[1][group] = 1 << (group % X4Lanes)
		patterns[2][group] = uint8((group*7 + 3) & 0x0f)
		if group%3 != 1 {
			patterns[3][group] = uint8(0x0f >> (group % X4Lanes))
		}
	}
	return patterns
}

func addModulusAliasIFMAX4(t *testing.T, value *IFMAElementX4) {
	t.Helper()
	for limb, modulus := range modulusLimbs {
		for lane := 0; lane < X4Lanes; lane++ {
			value.limbs[limb][lane] += modulus
			if value.limbs[limb][lane] >= ifmaComposableLimbLimit {
				t.Fatalf("limb=%d lane=%d modulus alias escaped Ready52", limb, lane)
			}
		}
	}
}

func makeBatchEncodeRandomPoints(t *testing.T, rng *rand.Rand) (
	[ExperimentalIFMABatchEncodeMaxX4Groups]IFMAPointX4,
	[ExperimentalIFMABatchEncodeMaxX4Groups]PointX4,
) {
	t.Helper()
	var points [ExperimentalIFMABatchEncodeMaxX4Groups]IFMAPointX4
	var references [ExperimentalIFMABatchEncodeMaxX4Groups]PointX4
	torsion := referenceTorsionPoints(t)
	for group := range references {
		var lanes [X4Lanes]Point
		for lane := range lanes {
			ref := randomMixedReferencePoint(t, rng, torsion[(group+lane)%X8Lanes])
			if _, err := lanes[lane].SetBytes(ref.Bytes()); err != nil {
				t.Fatal(err)
			}
			lambda := randomNonUnitElement(t, rng)
			lanes[lane].X.Multiply(&lanes[lane].X, &lambda)
			lanes[lane].Y.Multiply(&lanes[lane].Y, &lambda)
			lanes[lane].Z.Multiply(&lanes[lane].Z, &lambda)
			lanes[lane].T.Multiply(&lanes[lane].T, &lambda)
			assertScalarPointInvariant(t, "batch-encode fixture", &lanes[lane])
		}
		references[group].SetPoints(&lanes)
		points[group].SetReduced(&references[group])
	}
	return points, references
}

func assertBatchEncodeOutputs(
	t *testing.T,
	got *[ExperimentalIFMABatchEncodeMaxX4Groups][X4Lanes][32]byte,
	references *[ExperimentalIFMABatchEncodeMaxX4Groups]PointX4,
	active *[ExperimentalIFMABatchEncodeMaxX4Groups]uint8,
	groups int,
) {
	t.Helper()
	for group := range got {
		var want [X4Lanes][32]byte
		if group < groups {
			want = references[group].Bytes()
		}
		for lane := 0; lane < X4Lanes; lane++ {
			live := group < groups && active[group]&(1<<lane) != 0
			if live {
				if !bytes.Equal(got[group][lane][:], want[lane][:]) {
					t.Fatalf("group=%d lane=%d got=%x want=%x", group, lane, got[group][lane], want[lane])
				}
			} else if got[group][lane] != ([32]byte{}) {
				t.Fatalf("inactive group=%d lane=%d output=%x", group, lane, got[group][lane])
			}
		}
	}
}

var benchmarkIFMABatchEncodeX4Sink [ExperimentalIFMABatchEncodeMaxX4Groups][X4Lanes][32]byte

func BenchmarkExperimentalIFMABatchEncodeX4(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	points, references := makeBatchEncodeBenchmarkPoints(b)
	var active [ExperimentalIFMABatchEncodeMaxX4Groups]uint8
	for group := range active {
		active[group] = 0x0f
	}

	for _, groups := range []int{1, 2, 4, 8, ExperimentalIFMABatchEncodeMaxX4Groups} {
		b.Run(fmt.Sprintf("impl=scalar-Bytes/groups=%d/n=%d", groups, groups*X4Lanes), func(b *testing.B) {
			b.ReportAllocs()
			var out [ExperimentalIFMABatchEncodeMaxX4Groups][X4Lanes][32]byte
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				for group := 0; group < groups; group++ {
					out[group] = references[group].Bytes()
				}
			}
			benchmarkIFMABatchEncodeX4Sink = out
		})

		b.Run(fmt.Sprintf("impl=ifma-batch/groups=%d/n=%d", groups, groups*X4Lanes), func(b *testing.B) {
			b.ReportAllocs()
			var workspace ExperimentalIFMABatchEncodeWorkspaceX4
			var out [ExperimentalIFMABatchEncodeMaxX4Groups][X4Lanes][32]byte
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				if err := workspace.Encode(&out, &points, &active, groups); err != nil {
					b.Fatal(err)
				}
			}
			benchmarkIFMABatchEncodeX4Sink = out
		})
	}
}

func makeBatchEncodeBenchmarkPoints(b *testing.B) (
	[ExperimentalIFMABatchEncodeMaxX4Groups]IFMAPointX4,
	[ExperimentalIFMABatchEncodeMaxX4Groups]PointX4,
) {
	b.Helper()
	generatorEncoding := newGeneratorEncodingForTest(b)
	var generator Point
	if _, err := generator.SetBytes(generatorEncoding[:]); err != nil {
		b.Fatal(err)
	}
	var points [ExperimentalIFMABatchEncodeMaxX4Groups]IFMAPointX4
	var references [ExperimentalIFMABatchEncodeMaxX4Groups]PointX4
	for group := range references {
		var lanes [X4Lanes]Point
		for lane := range lanes {
			lanes[lane] = generator
			var lambdaEncoding [32]byte
			lambdaEncoding[0] = byte(2 + group*X4Lanes + lane)
			var lambda Element
			if _, err := lambda.SetBytes(lambdaEncoding[:]); err != nil {
				b.Fatal(err)
			}
			lanes[lane].X.Multiply(&lanes[lane].X, &lambda)
			lanes[lane].Y.Multiply(&lanes[lane].Y, &lambda)
			lanes[lane].Z.Multiply(&lanes[lane].Z, &lambda)
			lanes[lane].T.Multiply(&lanes[lane].T, &lambda)
		}
		references[group].SetPoints(&lanes)
		points[group].SetReduced(&references[group])
	}
	return points, references
}
