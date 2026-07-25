package r51x5

import (
	"errors"
	"fmt"
	"math/rand"
	"runtime"
	"testing"
)

func TestCompareCompressedYFirstIFMAModelMatchesLiteralEncoding(t *testing.T) {
	points, references := makeBatchEncodeRandomPoints(t, rand.New(rand.NewSource(0x51f1a57)))

	for _, groups := range []int{1, 2, 3, 4, 8, ExperimentalIFMABatchEncodeMaxX4Groups} {
		for patternIndex, active := range makeBatchEncodeMaskPatterns(groups) {
			for _, candidateKind := range []string{"exact", "mixed"} {
				t.Run(fmt.Sprintf("groups=%d/pattern=%d/candidates=%s", groups, patternIndex, candidateKind), func(t *testing.T) {
					candidates := makeYFirstCandidates(t, &references, groups, candidateKind)
					assertYFirstMatchesLiteral(t, &points, &references, &active, &candidates, groups)
				})
			}
		}
	}
}

func TestCompareCompressedYFirstIFMALeadingEmptyAndTail(t *testing.T) {
	points, references := makeBatchEncodeRandomPoints(t, rand.New(rand.NewSource(0x51f1ead)))
	const groups = 7
	var active [ExperimentalIFMABatchEncodeMaxX4Groups]uint8
	active[2], active[4], active[6] = 0x05, 0x08, 0x03
	candidates := makeYFirstCandidates(t, &references, groups, "mixed")
	assertYFirstMatchesLiteral(t, &points, &references, &active, &candidates, groups)
}

func TestCompareCompressedYFirstIFMARNegQSignMismatch(t *testing.T) {
	points, references := makeBatchEncodeRandomPoints(t, rand.New(rand.NewSource(0x51f1519)))
	const groups = 4
	var active [ExperimentalIFMABatchEncodeMaxX4Groups]uint8
	for group := 0; group < groups; group++ {
		active[group] = 0x0f
	}
	candidates := references
	for group := 0; group < groups; group++ {
		for lane := 0; lane < X4Lanes; lane++ {
			// Negating a nonzero Edwards x-coordinate preserves y and flips
			// exactly the compressed sign bit. Even the x=0 boundary remains a
			// required rejection because sign-bit-one is not canonical there.
			candidates[group][lane][31] ^= 0x80
		}
	}

	var workspace ExperimentalIFMABatchEncodeWorkspaceX4
	var got [ExperimentalIFMABatchEncodeMaxX4Groups]uint8
	ops := decode2IFMAOpsX4{}
	if err := compareCompressedYFirstIFMAX4(&workspace, &got, &points, &active, yFirstBytes(&candidates), groups, &ops); err != nil {
		t.Fatal(err)
	}
	for group := 0; group < groups; group++ {
		if got[group] != 0 {
			t.Fatalf("group=%d sign-mismatch mask=%02x", group, got[group])
		}
	}
	// Y survives in every group, so sign-only mismatches intentionally pay
	// the inversion. This distinguishes the X-sign half from the early gate.
	wantCalls := 265 + 5*groups - 3
	if ops.calls != wantCalls {
		t.Fatalf("calls=%d want=%d", ops.calls, wantCalls)
	}
}

func TestCompareCompressedYFirstIFMAXZeroSignBoundary(t *testing.T) {
	// Torsion indexes 0 and 4 are the identity and order-two point. Both have
	// x=0, so their canonical compressed sign is zero even after projective
	// rescaling; setting bit 255 is the forbidden negative-zero alias.
	torsion := referenceTorsionPoints(t)
	rng := rand.New(rand.NewSource(0x51f1c000))
	var scalar PointX4
	var encoded [ExperimentalIFMABatchEncodeMaxX4Groups][X4Lanes][32]byte
	for lane, torsionIndex := range []int{0, 4} {
		compressed := torsion[torsionIndex].Bytes()
		copy(encoded[0][lane][:], compressed)
		if encoded[0][lane][31]&0x80 != 0 {
			t.Fatalf("torsion index=%d has noncanonical x=0 sign", torsionIndex)
		}
		var point Point
		if _, err := point.SetBytes(compressed); err != nil {
			t.Fatal(err)
		}
		lambda := randomNonUnitElement(t, rng)
		point.X.Multiply(&point.X, &lambda)
		point.Y.Multiply(&point.Y, &lambda)
		point.Z.Multiply(&point.Z, &lambda)
		point.T.Multiply(&point.T, &lambda)
		scalar.SetLane(lane, &point)
	}
	var points [ExperimentalIFMABatchEncodeMaxX4Groups]IFMAPointX4
	points[0].SetReduced(&scalar)
	var active [ExperimentalIFMABatchEncodeMaxX4Groups]uint8
	active[0] = 0x03

	var workspace ExperimentalIFMABatchEncodeWorkspaceX4
	var got [ExperimentalIFMABatchEncodeMaxX4Groups]uint8
	if err := compareCompressedYFirstIFMAModelX4(&workspace, &got, &points, &active, &encoded, 1); err != nil {
		t.Fatal(err)
	}
	if got[0] != 0x03 {
		t.Fatalf("canonical x=0 mask=%02x want=03", got[0])
	}

	encoded[0][0][31] |= 0x80
	encoded[0][1][31] |= 0x80
	if err := compareCompressedYFirstIFMAModelX4(&workspace, &got, &points, &active, &encoded, 1); err != nil {
		t.Fatal(err)
	}
	if got[0] != 0 {
		t.Fatalf("negative-zero aliases accepted mask=%02x", got[0])
	}
}

func TestCompareCompressedYFirstIFMASkipsInversionOnYMismatch(t *testing.T) {
	points, references := makeBatchEncodeRandomPoints(t, rand.New(rand.NewSource(0x51f1bad)))
	const groups = 8
	var active [ExperimentalIFMABatchEncodeMaxX4Groups]uint8
	for group := 0; group < groups; group++ {
		active[group] = 0x0f
	}
	candidates := makeYFirstCandidates(t, &references, groups, "different-y")

	var workspace ExperimentalIFMABatchEncodeWorkspaceX4
	var got [ExperimentalIFMABatchEncodeMaxX4Groups]uint8
	ops := decode2IFMAOpsX4{failAt: groups + 1}
	if err := compareCompressedYFirstIFMAX4(&workspace, &got, &points, &active, yFirstBytes(&candidates), groups, &ops); err != nil {
		t.Fatalf("comparator reached inversion after all Y lanes failed: %v", err)
	}
	if ops.calls != groups {
		t.Fatalf("multiply calls=%d want only %d projective-Y products", ops.calls, groups)
	}
	for group := 0; group < groups; group++ {
		if got[group] != 0 {
			t.Fatalf("group=%d y-mismatch mask=%02x", group, got[group])
		}
	}

	// Noncanonical low-255-bit values are rejected before even the Y product.
	for group := 0; group < groups; group++ {
		for lane := 0; lane < X4Lanes; lane++ {
			candidates[group][lane] = modulusEncodingWithSign(byte(lane & 1))
		}
	}
	ops = decode2IFMAOpsX4{failAt: 1}
	if err := compareCompressedYFirstIFMAX4(&workspace, &got, &points, &active, yFirstBytes(&candidates), groups, &ops); err != nil {
		t.Fatalf("noncanonical y reached field multiplication: %v", err)
	}
	if ops.calls != 0 {
		t.Fatalf("noncanonical y multiply calls=%d want=0", ops.calls)
	}
}

func TestCompareCompressedYFirstIFMAInvalidZFailsClosed(t *testing.T) {
	points, references := makeBatchEncodeRandomPoints(t, rand.New(rand.NewSource(0x51f1200)))
	var active [ExperimentalIFMABatchEncodeMaxX4Groups]uint8
	active[0] = 1

	// A bad Z whose lane fails the projective-Y gate returns a false verdict
	// without entering inversion. The internal invariant violation cannot turn
	// into acceptance.
	mismatch := points
	for limb := 0; limb < 5; limb++ {
		mismatch[0].Z.limbs[limb][0] = 0
		mismatch[0].Y.limbs[limb][0] = 0
	}
	mismatch[0].Y.limbs[0][0] = 1
	candidates := references
	candidates[0][0] = [32]byte{}
	var workspace ExperimentalIFMABatchEncodeWorkspaceX4
	var got [ExperimentalIFMABatchEncodeMaxX4Groups]uint8
	if err := compareCompressedYFirstIFMAModelX4(&workspace, &got, &mismatch, &active, yFirstBytes(&candidates), 1); err != nil {
		t.Fatal(err)
	}
	if got[0] != 0 {
		t.Fatalf("zero-Z y-mismatch accepted mask=%02x", got[0])
	}

	// If bad Z and Y=0 survive the Y gate, the reused inversion core detects
	// field-zero Z. The staged result is not committed on error.
	surviving := points
	for limb := 0; limb < 5; limb++ {
		surviving[0].Y.limbs[limb][0] = 0
		surviving[0].Z.limbs[limb][0] = 0
	}
	candidates[0][0] = [32]byte{}
	for group := range got {
		got[group] = 0xa5
	}
	want := got
	if err := compareCompressedYFirstIFMAModelX4(&workspace, &got, &surviving, &active, yFirstBytes(&candidates), 1); !errors.Is(err, errIFMABatchEncodeZeroZ) {
		t.Fatalf("zero-Z survivor error=%v", err)
	}
	if got != want {
		t.Fatal("zero-Z error changed output")
	}
}

func TestCompareCompressedYFirstIFMAAtomicArithmeticFailure(t *testing.T) {
	points, references := makeBatchEncodeRandomPoints(t, rand.New(rand.NewSource(0x51f1a70)))
	const groups = 2
	var active [ExperimentalIFMABatchEncodeMaxX4Groups]uint8
	active[0], active[1] = 0x0f, 0x0f
	var sentinel [ExperimentalIFMABatchEncodeMaxX4Groups]uint8
	for group := range sentinel {
		sentinel[group] = 0xa5
	}

	// Cover one failure in the projective-Y phase and one after that phase in
	// the fixed inversion chain.
	for _, failAt := range []int{1, groups + 1} {
		got := sentinel
		var workspace ExperimentalIFMABatchEncodeWorkspaceX4
		ops := decode2IFMAOpsX4{failAt: failAt}
		if err := compareCompressedYFirstIFMAX4(&workspace, &got, &points, &active, yFirstBytes(&references), groups, &ops); !errors.Is(err, errIFMAOutputRange) {
			t.Fatalf("failAt=%d error=%v", failAt, err)
		}
		if got != sentinel {
			t.Fatalf("failAt=%d changed output", failAt)
		}
	}
}

func TestExperimentalIFMACompareCompressedYFirstMatchesModelAndAllocatesZero(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	points, references := makeBatchEncodeRandomPoints(t, rand.New(rand.NewSource(0x51f1a110)))
	const groups = ExperimentalIFMABatchEncodeMaxX4Groups
	active := makeBatchEncodeMaskPatterns(groups)[2]
	candidates := makeYFirstCandidates(t, &references, groups, "mixed")

	var modelWorkspace, hardwareWorkspace ExperimentalIFMABatchEncodeWorkspaceX4
	var model, hardware [ExperimentalIFMABatchEncodeMaxX4Groups]uint8
	if err := compareCompressedYFirstIFMAModelX4(&modelWorkspace, &model, &points, &active, yFirstBytes(&candidates), groups); err != nil {
		t.Fatal(err)
	}
	if err := hardwareWorkspace.CompareCompressedYFirst(&hardware, &points, &active, yFirstBytes(&candidates), groups); err != nil {
		t.Fatal(err)
	}
	if hardware != model {
		t.Fatalf("hardware/model mismatch\nhardware=%x\nmodel=%x", hardware, model)
	}

	for group := 0; group < groups; group++ {
		active[group] = 0x0f
	}
	candidates = references
	if allocations := testing.AllocsPerRun(20, func() {
		if err := hardwareWorkspace.CompareCompressedYFirst(&hardware, &points, &active, yFirstBytes(&candidates), groups); err != nil {
			panic(err)
		}
	}); allocations != 0 {
		t.Fatalf("y-first comparator allocations=%.2f", allocations)
	}
}

func assertYFirstMatchesLiteral(
	t *testing.T,
	points *[ExperimentalIFMABatchEncodeMaxX4Groups]IFMAPointX4,
	references *batchEncodeReferenceEncodings,
	active *[ExperimentalIFMABatchEncodeMaxX4Groups]uint8,
	candidates *batchEncodeReferenceEncodings,
	groups int,
) {
	t.Helper()
	var encodeWorkspace, compareWorkspace ExperimentalIFMABatchEncodeWorkspaceX4
	var literal [ExperimentalIFMABatchEncodeMaxX4Groups][X4Lanes][32]byte
	if err := batchEncodeIFMAModelX4(&encodeWorkspace, &literal, points, active, groups); err != nil {
		t.Fatal(err)
	}
	assertBatchEncodeOutputs(t, &literal, references, active, groups)

	var got [ExperimentalIFMABatchEncodeMaxX4Groups]uint8
	for group := range got {
		got[group] = 0xa5
	}
	if err := compareCompressedYFirstIFMAModelX4(&compareWorkspace, &got, points, active, yFirstBytes(candidates), groups); err != nil {
		t.Fatal(err)
	}
	for group := range got {
		if group >= groups {
			if got[group] != 0xa5 {
				t.Fatalf("group=%d beyond selected range changed to %02x", group, got[group])
			}
			continue
		}
		var want uint8
		for lane := 0; lane < X4Lanes; lane++ {
			if active[group]&(1<<lane) != 0 && literal[group][lane] == candidates[group][lane] {
				want |= 1 << lane
			}
		}
		if got[group] != want {
			t.Fatalf("group=%d got=%02x want=%02x", group, got[group], want)
		}
	}
}

func makeYFirstCandidates(
	t testing.TB,
	references *batchEncodeReferenceEncodings,
	groups int,
	kind string,
) batchEncodeReferenceEncodings {
	t.Helper()
	out := *references
	for group := 0; group < groups; group++ {
		for lane := 0; lane < X4Lanes; lane++ {
			switch kind {
			case "exact":
			case "different-y":
				out[group][lane] = differentCanonicalYEncoding(t, references[group][lane])
			case "mixed":
				switch (group*X4Lanes + lane) & 3 {
				case 0:
				case 1:
					out[group][lane][31] ^= 0x80
				case 2:
					out[group][lane] = differentCanonicalYEncoding(t, references[group][lane])
				case 3:
					out[group][lane] = modulusEncodingWithSign(byte(lane & 1))
				}
			default:
				t.Fatalf("unknown candidate kind %q", kind)
			}
		}
	}
	return out
}

func yFirstBytes(in *batchEncodeReferenceEncodings) *[ExperimentalIFMABatchEncodeMaxX4Groups][X4Lanes][32]byte {
	return (*[ExperimentalIFMABatchEncodeMaxX4Groups][X4Lanes][32]byte)(in)
}

func differentCanonicalYEncoding(t testing.TB, encoded [32]byte) [32]byte {
	t.Helper()
	sign := encoded[31] & 0x80
	encoded[31] &= 0x7f
	var y, one, changed Element
	if _, err := y.SetCanonicalBytes(encoded[:]); err != nil {
		t.Fatal(err)
	}
	one.One()
	changed.Add(&y, &one)
	out := changed.Bytes()
	out[31] |= sign
	return out
}

func modulusEncodingWithSign(sign byte) [32]byte {
	out := [32]byte{
		0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
	}
	out[31] |= (sign & 1) << 7
	return out
}

var benchmarkIFMAYFirstMaskSink [ExperimentalIFMABatchEncodeMaxX4Groups]uint8

func BenchmarkExperimentalIFMACompareCompressedYFirstX4(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	points, scalarReferences := makeBatchEncodeBenchmarkPoints(b)
	var references batchEncodeReferenceEncodings
	for group := range scalarReferences {
		for lane := 0; lane < X4Lanes; lane++ {
			point := scalarReferences[group].Lane(lane)
			references[group][lane] = point.Bytes()
		}
	}
	for _, groups := range []int{1, 2, 4, 8, ExperimentalIFMABatchEncodeMaxX4Groups} {
		var active [ExperimentalIFMABatchEncodeMaxX4Groups]uint8
		for group := 0; group < groups; group++ {
			active[group] = 0x0f
		}
		for _, kind := range []string{"exact", "different-y"} {
			candidates := makeYFirstCandidates(b, &references, groups, kind)
			b.Run(fmt.Sprintf("candidates=%s/groups=%d/n=%d", kind, groups, groups*X4Lanes), func(b *testing.B) {
				b.ReportAllocs()
				var workspace ExperimentalIFMABatchEncodeWorkspaceX4
				var out [ExperimentalIFMABatchEncodeMaxX4Groups]uint8
				b.ResetTimer()
				for iteration := 0; iteration < b.N; iteration++ {
					if err := workspace.CompareCompressedYFirst(&out, &points, &active, yFirstBytes(&candidates), groups); err != nil {
						b.Fatal(err)
					}
				}
				benchmarkIFMAYFirstMaskSink = out
			})
		}
	}
}
