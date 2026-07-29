package r51x5

import (
	"errors"
	"fmt"
	"math/rand"
	"runtime"
	"testing"
)

func makeBatchEncodeX8Fixture(t *testing.T) (
	[ExperimentalIFMABatchEncodeMaxX8Groups]IFMAPointX8,
	[ExperimentalIFMABatchEncodeMaxX4Groups]IFMAPointX4,
) {
	t.Helper()
	points4, _ := makeBatchEncodeRandomPoints(t, rand.New(rand.NewSource(0x51ba7c8)))
	var points8 [ExperimentalIFMABatchEncodeMaxX8Groups]IFMAPointX8
	for group := range points8 {
		points8[group].SetX4Halves(&points4[2*group], &points4[2*group+1])
	}
	return points8, points4
}

func splitBatchEncodeActiveX8(
	active8 *[ExperimentalIFMABatchEncodeMaxX8Groups]uint8,
	groups int,
) (active4 [ExperimentalIFMABatchEncodeMaxX4Groups]uint8) {
	for group := 0; group < groups; group++ {
		active4[2*group] = active8[group] & 0x0f
		active4[2*group+1] = active8[group] >> X4Lanes
	}
	return active4
}

func assertBatchEncodeX8MatchesX4(
	t *testing.T,
	points8 *[ExperimentalIFMABatchEncodeMaxX8Groups]IFMAPointX8,
	points4 *[ExperimentalIFMABatchEncodeMaxX4Groups]IFMAPointX4,
	active8 *[ExperimentalIFMABatchEncodeMaxX8Groups]uint8,
	groups int,
) {
	t.Helper()
	active4 := splitBatchEncodeActiveX8(active8, groups)
	var workspace8 ExperimentalIFMABatchEncodeWorkspaceX8
	var got8 [ExperimentalIFMABatchEncodeMaxX8Groups][X8Lanes][32]byte
	if err := batchEncodeIFMAModelX8(&workspace8, &got8, points8, active8, groups); err != nil {
		t.Fatal(err)
	}
	var workspace4 ExperimentalIFMABatchEncodeWorkspaceX4
	var got4 [ExperimentalIFMABatchEncodeMaxX4Groups][X4Lanes][32]byte
	if err := batchEncodeIFMAModelX4(&workspace4, &got4, points4, &active4, 2*groups); err != nil {
		t.Fatal(err)
	}
	for group := 0; group < groups; group++ {
		for lane := 0; lane < X8Lanes; lane++ {
			want := got4[2*group+lane/X4Lanes][lane%X4Lanes]
			if got8[group][lane] != want {
				t.Fatalf("group=%d lane=%d got=%x want=%x", group, lane, got8[group][lane], want)
			}
		}
	}
}

func TestBatchEncodeIFMAModelX8MatchesX4AllMasks(t *testing.T) {
	points8, points4 := makeBatchEncodeX8Fixture(t)
	for mask := 0; mask < 256; mask++ {
		var active [ExperimentalIFMABatchEncodeMaxX8Groups]uint8
		active[0] = uint8(mask)
		assertBatchEncodeX8MatchesX4(t, &points8, &points4, &active, 1)
	}
	for _, groups := range []int{2, 4, ExperimentalIFMABatchEncodeMaxX8Groups} {
		var active [ExperimentalIFMABatchEncodeMaxX8Groups]uint8
		for group := 0; group < groups; group++ {
			active[group] = uint8((group*73 + 0x35) & 0xff)
			if group%3 == 1 {
				active[group] = 0
			}
		}
		assertBatchEncodeX8MatchesX4(t, &points8, &points4, &active, groups)
	}
}

func TestBatchEncodeIFMAX8ScheduleAndInactiveIsolation(t *testing.T) {
	points8, points4 := makeBatchEncodeX8Fixture(t)
	const groups = ExperimentalIFMABatchEncodeMaxX8Groups
	var active [ExperimentalIFMABatchEncodeMaxX8Groups]uint8
	for group := range active {
		active[group] = 1 << group
	}

	var workspace ExperimentalIFMABatchEncodeWorkspaceX8
	var got [ExperimentalIFMABatchEncodeMaxX8Groups][X8Lanes][32]byte
	ops := decode2IFMAOpsX8{}
	if err := batchEncodeIFMAX8(&workspace, &got, &points8, &active, groups, &ops); err != nil {
		t.Fatal(err)
	}
	if want := 265 + 3*(groups-1) + 2*groups; ops.calls != want {
		t.Fatalf("calls=%d want=%d", ops.calls, want)
	}

	mutated := points8
	for group := range mutated {
		for lane := 0; lane < X8Lanes; lane++ {
			if active[group]&(1<<lane) != 0 {
				continue
			}
			for limb := 0; limb < 5; limb++ {
				mutated[group].X.limbs[limb][lane] = uint64(0x111+group+limb+lane) << 39
				mutated[group].Y.limbs[limb][lane] = uint64(0x222+group+limb+lane) << 38
				mutated[group].Z.limbs[limb][lane] = 0
				mutated[group].T.limbs[limb][lane] = uint64(0x333+group+limb+lane) << 37
			}
		}
	}
	var mutatedWorkspace ExperimentalIFMABatchEncodeWorkspaceX8
	var mutatedOutput [ExperimentalIFMABatchEncodeMaxX8Groups][X8Lanes][32]byte
	if err := batchEncodeIFMAModelX8(&mutatedWorkspace, &mutatedOutput, &mutated, &active, groups); err != nil {
		t.Fatal(err)
	}
	if mutatedOutput != got {
		t.Fatal("inactive x8 coordinates contaminated an active lane")
	}
	assertBatchEncodeX8MatchesX4(t, &points8, &points4, &active, groups)
}

func TestBatchEncodeIFMAX8AtomicFailures(t *testing.T) {
	points, _ := makeBatchEncodeX8Fixture(t)
	var active [ExperimentalIFMABatchEncodeMaxX8Groups]uint8
	active[0], active[1] = 0xff, 0x55
	var sentinel [ExperimentalIFMABatchEncodeMaxX8Groups][X8Lanes][32]byte
	for group := range sentinel {
		for lane := range sentinel[group] {
			for index := range sentinel[group][lane] {
				sentinel[group][lane][index] = 0xa5
			}
		}
	}

	for _, groups := range []int{-1, 0, ExperimentalIFMABatchEncodeMaxX8Groups + 1} {
		got := sentinel
		var workspace ExperimentalIFMABatchEncodeWorkspaceX8
		if err := batchEncodeIFMAModelX8(&workspace, &got, &points, &active, groups); !errors.Is(err, errIFMABatchEncodeX8GroupCount) {
			t.Fatalf("groups=%d error=%v", groups, err)
		}
		if got != sentinel {
			t.Fatalf("groups=%d changed output", groups)
		}
	}

	invalid := points
	invalid[0].Z.limbs[0][7] = ifmaComposableLimbLimit
	got := sentinel
	var invalidWorkspace ExperimentalIFMABatchEncodeWorkspaceX8
	if err := batchEncodeIFMAModelX8(&invalidWorkspace, &got, &invalid, &active, 2); !errors.Is(err, errIFMAComposableInputRange) {
		t.Fatalf("invalid range error=%v", err)
	}
	if got != sentinel {
		t.Fatal("invalid input changed output")
	}

	for _, zero := range []struct {
		name  string
		limbs [5]uint64
	}{
		{name: "canonical"},
		{name: "modulus-alias", limbs: modulusLimbs},
	} {
		zeroPoints := points
		zeroPoints[0].Z = IFMAElementX8{}
		for limb := range zero.limbs {
			zeroPoints[0].Z.limbs[limb][0] = zero.limbs[limb]
		}
		var zeroActive [ExperimentalIFMABatchEncodeMaxX8Groups]uint8
		zeroActive[0] = 1
		got = sentinel
		var zeroWorkspace ExperimentalIFMABatchEncodeWorkspaceX8
		if err := batchEncodeIFMAModelX8(&zeroWorkspace, &got, &zeroPoints, &zeroActive, 1); !errors.Is(err, errIFMABatchEncodeX8ZeroZ) {
			t.Fatalf("zero Z %s error=%v", zero.name, err)
		}
		if got != sentinel {
			t.Fatalf("zero Z %s changed output", zero.name)
		}
	}

	const calls = 265 + 3 + 4
	for failAt := 1; failAt <= calls; failAt++ {
		got = sentinel
		var failedWorkspace ExperimentalIFMABatchEncodeWorkspaceX8
		ops := decode2IFMAOpsX8{failAt: failAt}
		if err := batchEncodeIFMAX8(&failedWorkspace, &got, &points, &active, 2, &ops); !errors.Is(err, errIFMAOutputRange) {
			t.Fatalf("failure call=%d error=%v", failAt, err)
		}
		if got != sentinel {
			t.Fatalf("failure call=%d changed output", failAt)
		}
	}
}

func TestExperimentalIFMABatchEncodeX8MatchesModelAndAllocatesZero(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	points, _ := makeBatchEncodeX8Fixture(t)
	var active [ExperimentalIFMABatchEncodeMaxX8Groups]uint8
	for group := range active {
		active[group] = uint8(0x81 | 1<<(group%X8Lanes))
	}
	var modelWorkspace, hardwareWorkspace ExperimentalIFMABatchEncodeWorkspaceX8
	var model, hardware [ExperimentalIFMABatchEncodeMaxX8Groups][X8Lanes][32]byte
	if err := batchEncodeIFMAModelX8(&modelWorkspace, &model, &points, &active, len(active)); err != nil {
		t.Fatal(err)
	}
	if err := hardwareWorkspace.Encode(&hardware, &points, &active, len(active)); err != nil {
		t.Fatal(err)
	}
	if hardware != model {
		t.Fatal("x8 batch encoder hardware/model mismatch")
	}
	if allocations := testing.AllocsPerRun(20, func() {
		if err := hardwareWorkspace.Encode(&hardware, &points, &active, len(active)); err != nil {
			panic(err)
		}
	}); allocations != 0 {
		t.Fatalf("x8 batch encoder allocations=%.2f", allocations)
	}
}

var benchmarkIFMABatchEncodeX8Sink [ExperimentalIFMABatchEncodeMaxX8Groups][X8Lanes][32]byte

func BenchmarkExperimentalIFMABatchEncodeX8(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	points4, _ := makeBatchEncodeBenchmarkPoints(b)
	var points [ExperimentalIFMABatchEncodeMaxX8Groups]IFMAPointX8
	for group := range points {
		points[group].SetX4Halves(&points4[2*group], &points4[2*group+1])
	}
	var active [ExperimentalIFMABatchEncodeMaxX8Groups]uint8
	for group := range active {
		active[group] = 0xff
	}
	for _, groups := range []int{1, 2, 4, ExperimentalIFMABatchEncodeMaxX8Groups} {
		b.Run(fmt.Sprintf("groups=%d/n=%d", groups, groups*X8Lanes), func(b *testing.B) {
			var workspace ExperimentalIFMABatchEncodeWorkspaceX8
			var out [ExperimentalIFMABatchEncodeMaxX8Groups][X8Lanes][32]byte
			b.ReportAllocs()
			for range b.N {
				if err := workspace.Encode(&out, &points, &active, groups); err != nil {
					b.Fatal(err)
				}
			}
			benchmarkIFMABatchEncodeX8Sink = out
		})
	}
}
