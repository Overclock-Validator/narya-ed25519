package r51x5

import (
	"errors"
	"fmt"
	"math/rand"
	"runtime"
	"sync"
	"testing"

	edwardsref "github.com/Overclock-Validator/narya-ed25519/internal/edwards25519"
)

func TestExperimentalFixedBaseCombShapeAndPayload(t *testing.T) {
	tests := []struct {
		width, rounds, positions, entries, bytes int
	}{
		{4, 64, 32, 8, 60 * 1024},
		{5, 51, 26, 16, 99_840},
		{8, 32, 16, 128, 480 * 1024},
	}
	base, _ := fixedBaseGenerator(t)
	for _, test := range tests {
		table := BuildExperimentalFixedBaseCombTable(&base, uint(test.width))
		if table.RadixBits() != uint(test.width) || table.RoundCount() != test.rounds || table.PositionCount() != test.positions || table.EntryCount() != test.entries {
			t.Fatalf("width %d shape=(%d,%d,%d,%d)", test.width, table.RadixBits(), table.RoundCount(), table.PositionCount(), table.EntryCount())
		}
		if got := table.NominalPayloadBytes(); got != test.bytes {
			t.Fatalf("width %d payload=%d want=%d", test.width, got, test.bytes)
		}
	}
}

func TestExperimentalFixedBaseCombRecodingClearsUsedRoundsOnReuse(t *testing.T) {
	var out fixedBaseDigitsX8
	for index := range out.rounds {
		out.rounds[index].Magnitude = [X8Lanes]uint8{1, 1, 1, 1, 1, 1, 1, 1}
		out.rounds[index].NonzeroMask = 0xff
		out.rounds[index].NegativeMask = 0xff
	}
	var scalars [X8Lanes][32]byte
	if valid := recodeFixedBaseScalarsX8(&out, &scalars, 0, 8); valid != 0 {
		t.Fatalf("inactive recode valid=%02x", valid)
	}
	for round := 0; round < int(out.count); round++ {
		if out.rounds[round] != (RadixRoundX8{}) {
			t.Fatalf("round %d retained stale digits", round)
		}
	}
}

func TestExperimentalFixedBaseCombPrecomputedSigns(t *testing.T) {
	base, _ := fixedBaseGenerator(t)
	for _, width := range []uint{4, 5, 8} {
		table := BuildExperimentalFixedBaseCombTable(&base, width)
		for index := range table.signedPoints {
			positive, negative := &table.signedPoints[index][0], &table.signedPoints[index][1]
			var positiveT2D, negativeT2D Element
			for limb := range modulusLimbs {
				if negative[limb][0] != positive[limb][1] || negative[limb][1] != positive[limb][0] {
					t.Fatalf("width %d entry %d limb %d signed Y coordinates mismatch", width, index, limb)
				}
				positiveT2D.limbs[limb] = positive[limb][2]
				negativeT2D.limbs[limb] = negative[limb][2]
			}
			var want Element
			want.Negate(&positiveT2D)
			if negativeT2D.Equal(&want) != 1 {
				t.Fatalf("width %d entry %d negative 2dT mismatch", width, index)
			}
		}
	}
}

func TestExperimentalFixedBaseCombX8MatchesIndependentReference(t *testing.T) {
	rng := rand.New(rand.NewSource(0xb451c08b))
	base, referenceBase := fixedBaseGenerator(t)
	var scalars [X8Lanes][32]byte
	for lane := range scalars {
		scalars[lane] = randomCanonicalFixedBaseScalar(t, rng)
	}
	// Exercise zero, L-1, and a noncanonical encoding in fixed lane positions.
	scalars[0] = [32]byte{}
	scalars[1] = scalarOrderBytes
	decrementLittleEndian(&scalars[1])
	scalars[5] = scalarOrderBytes

	masks := []uint8{0, 1, 3, 7, 0x0f, 0x1f, 0x3f, 0x7f, 0xff, 0x55, 0xaa}
	for lane := 0; lane < X8Lanes; lane++ {
		masks = append(masks, 0xff&^(1<<lane))
	}
	for _, width := range []uint{4, 5, 8} {
		for lane := range scalars {
			scalars[lane] = randomCanonicalFixedBaseScalar(t, rng)
		}
		scalars[0] = [32]byte{}
		scalars[1] = scalarOrderBytes
		decrementLittleEndian(&scalars[1])
		scalars[5] = scalarOrderBytes
		table := BuildExperimentalFixedBaseCombTable(&base, width)
		for _, active := range masks {
			var got PointX8
			usable := ExperimentalFixedBaseCombScalarMultX8(&got, table, &scalars, active)
			wantUsable := active &^ (1 << 5)
			if usable != wantUsable {
				t.Fatalf("width %d active=%02x usable=%02x want=%02x", width, active, usable, wantUsable)
			}
			assertFixedBaseX8(t, fmt.Sprintf("width=%d/active=%02x", width, active), &got, referenceBase, &scalars, usable)
		}

		for iteration := 0; iteration < 32; iteration++ {
			for lane := range scalars {
				scalars[lane] = randomCanonicalFixedBaseScalar(t, rng)
			}
			active := uint8(rng.Uint32())
			var got PointX8
			if usable := ExperimentalFixedBaseCombScalarMultX8(&got, table, &scalars, active); usable != active {
				t.Fatalf("width %d iteration=%d usable=%02x active=%02x", width, iteration, usable, active)
			}
			assertFixedBaseX8(t, fmt.Sprintf("width=%d/iteration=%d", width, iteration), &got, referenceBase, &scalars, active)
		}
	}
}

func TestExperimentalFixedBaseCombX4MatchesX8Halves(t *testing.T) {
	rng := rand.New(rand.NewSource(0xb45104a8))
	base, _ := fixedBaseGenerator(t)
	for _, width := range []uint{4, 5, 8} {
		table := BuildExperimentalFixedBaseCombTable(&base, width)
		for iteration := 0; iteration < 24; iteration++ {
			var scalars8 [X8Lanes][32]byte
			for lane := range scalars8 {
				scalars8[lane] = randomCanonicalFixedBaseScalar(t, rng)
			}
			if iteration%3 == 0 {
				scalars8[iteration%X8Lanes] = scalarOrderBytes
			}
			active8 := uint8(rng.Uint32())
			var want8 PointX8
			usable8 := ExperimentalFixedBaseCombScalarMultX8(&want8, table, &scalars8, active8)
			var joined PointX8
			var joinedUsable uint8
			for half := 0; half < 2; half++ {
				var scalars4 [X4Lanes][32]byte
				copy(scalars4[:], scalars8[half*X4Lanes:(half+1)*X4Lanes])
				active4 := (active8 >> (half * X4Lanes)) & 0x0f
				var got4 PointX4
				usable4 := ExperimentalFixedBaseCombScalarMultX4(&got4, table, &scalars4, active4)
				joinedUsable |= usable4 << (half * X4Lanes)
				for lane := 0; lane < X4Lanes; lane++ {
					point := got4.Lane(lane)
					joined.SetLane(half*X4Lanes+lane, &point)
				}
			}
			if joinedUsable != usable8 {
				t.Fatalf("width %d iteration %d x4 usable=%02x x8=%02x", width, iteration, joinedUsable, usable8)
			}
			if mask := joined.Equal(&want8); mask != 0xff {
				t.Fatalf("width %d iteration %d x4/x8 equality=%02x", width, iteration, mask)
			}
		}
	}
}

func TestExperimentalFixedBaseCombPreservesTorsionScalarSemantics(t *testing.T) {
	// y=0, sign=0 is a canonical order-four Edwards25519 point. Testing a
	// torsion base makes accidental scalar reduction or dropped comb carries
	// visible even when the generator's prime-order component would hide it.
	var encoding [32]byte
	var base Point
	if _, err := base.SetBytes(encoding[:]); err != nil {
		t.Fatal(err)
	}
	referenceBase, err := new(edwardsref.Point).SetBytes(encoding[:])
	if err != nil {
		t.Fatal(err)
	}
	var scalars [X8Lanes][32]byte
	values := []uint64{0, 1, 2, 3, 4, 5, 8, 15}
	for lane, value := range values {
		for byteIndex := 0; byteIndex < 8; byteIndex++ {
			scalars[lane][byteIndex] = byte(value >> (8 * byteIndex))
		}
	}
	for _, width := range []uint{4, 5, 8} {
		table := BuildExperimentalFixedBaseCombTable(&base, width)
		var got PointX8
		if usable := ExperimentalFixedBaseCombScalarMultX8(&got, table, &scalars, 0xff); usable != 0xff {
			t.Fatalf("width %d usable=%02x", width, usable)
		}
		assertFixedBaseX8(t, fmt.Sprintf("torsion/width=%d", width), &got, referenceBase, &scalars, 0xff)
	}
}

func TestExperimentalFixedBaseCombEvaluationAllocations(t *testing.T) {
	rng := rand.New(rand.NewSource(0xb451a110))
	base, _ := fixedBaseGenerator(t)
	var scalars8 [X8Lanes][32]byte
	for lane := range scalars8 {
		scalars8[lane] = randomCanonicalFixedBaseScalar(t, rng)
	}
	for _, width := range []uint{4, 5, 8} {
		table := BuildExperimentalFixedBaseCombTable(&base, width)
		var out8 PointX8
		if allocs := testing.AllocsPerRun(20, func() {
			ExperimentalFixedBaseCombScalarMultX8(&out8, table, &scalars8, 0xff)
		}); allocs != 0 {
			t.Fatalf("width %d x8 allocations=%v", width, allocs)
		}
		var scalars4 [X4Lanes][32]byte
		copy(scalars4[:], scalars8[:X4Lanes])
		var out4 PointX4
		if allocs := testing.AllocsPerRun(20, func() {
			ExperimentalFixedBaseCombScalarMultX4(&out4, table, &scalars4, 0x0f)
		}); allocs != 0 {
			t.Fatalf("width %d x4 allocations=%v", width, allocs)
		}
	}
}

func TestExperimentalFixedBaseCombSplitDSMMatchesSharedDoubling(t *testing.T) {
	B, A, s, k := fixedBaseCombDSMFixtures(t)
	negative := [DSMTerms]uint8{0, 0xff}
	currentBases := [DSMTerms]PointX8{B, A}
	var currentScalars FixedDSMScalarsX8
	currentScalars[0], currentScalars[1] = s, k
	var current FixedDSMWorkspaceX8
	var aOnly ExperimentalVariableBaseWorkspaceX8
	current.Prepare(&currentBases, 5)
	aOnly.Prepare(&A, 5)
	base, _ := fixedBaseGenerator(t)

	for _, width := range []uint{4, 5, 8} {
		table := BuildExperimentalFixedBaseCombTable(&base, width)
		for _, active := range []uint8{0, 1, 3, 7, 0x0f, 0x1f, 0x3f, 0x7f, 0xff, 0x55, 0xaa} {
			var want, aTerm, bTerm, got PointX8
			wantMask := current.Evaluate(&want, &currentScalars, &negative, active)
			maskA := aOnly.Evaluate(&aTerm, &k, active, active)
			maskB := ExperimentalFixedBaseCombScalarMultX8(&bTerm, table, &s, active)
			got.Add(&aTerm, &bTerm)
			if gotMask := maskA & maskB; gotMask != wantMask {
				t.Fatalf("width %d active=%02x split mask=%02x shared=%02x", width, active, gotMask, wantMask)
			}
			if equality := got.Equal(&want); equality != 0xff {
				t.Fatalf("width %d active=%02x split/shared equality=%02x", width, active, equality)
			}
		}
	}
}

func TestExperimentalFixedBaseCombTableSupportsConcurrentReads(t *testing.T) {
	rng := rand.New(rand.NewSource(0xb451c0de))
	base, _ := fixedBaseGenerator(t)
	table := BuildExperimentalFixedBaseCombTable(&base, 8)
	var scalars [X8Lanes][32]byte
	for lane := range scalars {
		scalars[lane] = randomCanonicalFixedBaseScalar(t, rng)
	}
	var want PointX8
	wantMask := ExperimentalFixedBaseCombScalarMultX8(&want, table, &scalars, 0xff)

	const workers = 16
	results := make(chan string, workers)
	var wait sync.WaitGroup
	wait.Add(workers)
	for worker := 0; worker < workers; worker++ {
		go func() {
			defer wait.Done()
			var got PointX8
			if mask := ExperimentalFixedBaseCombScalarMultX8(&got, table, &scalars, 0xff); mask != wantMask {
				results <- fmt.Sprintf("mask=%02x want=%02x", mask, wantMask)
				return
			}
			if equality := got.Equal(&want); equality != 0xff {
				results <- fmt.Sprintf("equality=%02x", equality)
			}
		}()
	}
	wait.Wait()
	close(results)
	for result := range results {
		t.Error(result)
	}
}

func TestExperimentalIFMAFixedBaseCombUnavailable(t *testing.T) {
	if ExperimentalIFMAAvailable() {
		t.Skip("requires a machine without AVX-512 IFMA")
	}
	base, _ := fixedBaseGenerator(t)
	table := BuildExperimentalFixedBaseCombTable(&base, 4)
	var scalars4 [X4Lanes][32]byte
	var out4 IFMAPointX4
	if _, err := ExperimentalIFMAFixedBaseCombScalarMultX4(&out4, table, &scalars4, 0x0f); !errors.Is(err, ErrIFMAUnavailable) {
		t.Fatalf("x4 error=%v", err)
	}
	var scalars8 [X8Lanes][32]byte
	var out8 IFMAPointX8
	if _, err := ExperimentalIFMAFixedBaseCombScalarMultX8(&out8, table, &scalars8, 0xff); !errors.Is(err, ErrIFMAUnavailable) {
		t.Fatalf("x8 error=%v", err)
	}
}

func TestExperimentalIFMAFixedBaseCombMatchesScalar(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("requires AVX-512 IFMA")
	}
	rng := rand.New(rand.NewSource(0xb4511f4a))
	base, _ := fixedBaseGenerator(t)
	var scalars [X8Lanes][32]byte
	for lane := range scalars {
		scalars[lane] = randomCanonicalFixedBaseScalar(t, rng)
	}
	scalars[5] = scalarOrderBytes
	masks := []uint8{0, 1, 3, 7, 0x0f, 0x1f, 0x3f, 0x7f, 0xff, 0x55, 0xaa}
	for lane := 0; lane < X8Lanes; lane++ {
		masks = append(masks, 0xff&^(1<<lane))
	}
	for _, width := range []uint{4, 5, 8} {
		table := BuildExperimentalFixedBaseCombTable(&base, width)
		for _, active := range masks {
			var want PointX8
			wantMask := ExperimentalFixedBaseCombScalarMultX8(&want, table, &scalars, active)
			var gotIFMA IFMAPointX8
			gotMask, err := ExperimentalIFMAFixedBaseCombScalarMultX8(&gotIFMA, table, &scalars, active)
			if err != nil {
				t.Fatal(err)
			}
			got := gotIFMA.Reduced()
			if gotMask != wantMask || got.Equal(&want) != 0xff {
				t.Fatalf("width %d active=%02x mask got=%02x want=%02x equality=%02x", width, active, gotMask, wantMask, got.Equal(&want))
			}

			var joined PointX8
			var joinedMask uint8
			for half := 0; half < 2; half++ {
				var scalars4 [X4Lanes][32]byte
				copy(scalars4[:], scalars[half*X4Lanes:(half+1)*X4Lanes])
				active4 := (active >> (half * X4Lanes)) & 0x0f
				var got4IFMA IFMAPointX4
				mask4, err := ExperimentalIFMAFixedBaseCombScalarMultX4(&got4IFMA, table, &scalars4, active4)
				if err != nil {
					t.Fatal(err)
				}
				joinedMask |= mask4 << (half * X4Lanes)
				got4 := got4IFMA.Reduced()
				for lane := 0; lane < X4Lanes; lane++ {
					point := got4.Lane(lane)
					joined.SetLane(half*X4Lanes+lane, &point)
				}
			}
			if joinedMask != wantMask || joined.Equal(&want) != 0xff {
				t.Fatalf("width %d active=%02x two-x4 mask=%02x want=%02x equality=%02x", width, active, joinedMask, wantMask, joined.Equal(&want))
			}
		}
	}
}

func TestExperimentalIFMAFixedBaseCombPreservesTorsionAndSplitDSM(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("requires AVX-512 IFMA")
	}
	var torsion Point
	if _, err := torsion.SetBytes(make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	var torsionScalars [X8Lanes][32]byte
	for lane, value := range []byte{0, 1, 2, 3, 4, 5, 8, 15} {
		torsionScalars[lane][0] = value
	}
	for _, width := range []uint{4, 5, 8} {
		table := BuildExperimentalFixedBaseCombTable(&torsion, width)
		var want PointX8
		wantMask := ExperimentalFixedBaseCombScalarMultX8(&want, table, &torsionScalars, 0xff)
		var gotIFMA IFMAPointX8
		gotMask, err := ExperimentalIFMAFixedBaseCombScalarMultX8(&gotIFMA, table, &torsionScalars, 0xff)
		if err != nil {
			t.Fatal(err)
		}
		got := gotIFMA.Reduced()
		if gotMask != wantMask || got.Equal(&want) != 0xff {
			t.Fatalf("torsion width %d masks=%02x/%02x equality=%02x", width, gotMask, wantMask, got.Equal(&want))
		}
	}

	B, A, s, k := fixedBaseCombDSMFixtures(t)
	bases := [DSMTerms]PointX8{B, A}
	var scalars FixedDSMScalarsX8
	scalars[0], scalars[1] = s, k
	negative := [DSMTerms]uint8{0, 0xff}
	var shared ExperimentalIFMAFixedDSMWorkspaceX8
	if err := shared.PrepareBoth(&bases, 5); err != nil {
		t.Fatal(err)
	}
	var variable ExperimentalIFMAVariableBaseWorkspaceX8
	if err := variable.Prepare(&A, 5); err != nil {
		t.Fatal(err)
	}
	base, _ := fixedBaseGenerator(t)
	for _, width := range []uint{4, 5, 8} {
		table := BuildExperimentalFixedBaseCombTable(&base, width)
		for _, active := range []uint8{0, 1, 3, 7, 0x0f, 0x1f, 0x3f, 0x7f, 0xff, 0x55, 0xaa} {
			var want, aTerm, bTerm, got IFMAPointX8
			wantMask, err := shared.Evaluate(&want, &scalars, &negative, active)
			if err != nil {
				t.Fatal(err)
			}
			maskA, err := variable.Evaluate(&aTerm, &k, active, active)
			if err != nil {
				t.Fatal(err)
			}
			maskB, err := ExperimentalIFMAFixedBaseCombScalarMultX8(&bTerm, table, &s, active)
			if err != nil {
				t.Fatal(err)
			}
			if err := ExperimentalIFMAPointAddComposableX8(&got, &aTerm, &bTerm); err != nil {
				t.Fatal(err)
			}
			gotReduced, wantReduced := got.Reduced(), want.Reduced()
			if gotMask := maskA & maskB; gotMask != wantMask || gotReduced.Bytes() != wantReduced.Bytes() {
				t.Fatalf("split width %d active=%02x masks=%02x/%02x", width, active, gotMask, wantMask)
			}
		}
	}
}

func TestExperimentalIFMAFixedBaseCombZeroAllocations(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("requires AVX-512 IFMA")
	}
	rng := rand.New(rand.NewSource(0xb4511fa1))
	base, _ := fixedBaseGenerator(t)
	var scalars [X8Lanes][32]byte
	for lane := range scalars {
		scalars[lane] = randomCanonicalFixedBaseScalar(t, rng)
	}
	for _, width := range []uint{4, 5, 8} {
		table := BuildExperimentalFixedBaseCombTable(&base, width)
		var out IFMAPointX8
		if allocs := testing.AllocsPerRun(20, func() {
			if _, err := ExperimentalIFMAFixedBaseCombScalarMultX8(&out, table, &scalars, 0xff); err != nil {
				panic(err)
			}
		}); allocs != 0 {
			t.Fatalf("width %d IFMA allocations=%v", width, allocs)
		}
	}
}

func TestFixedBaseIFMACachedUncheckedSelectorsMatchChecked(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("requires AVX-512 IFMA/VBMI")
	}

	rng := rand.New(rand.NewSource(0xb4515e1f))
	base, _ := fixedBaseGenerator(t)
	var scalars8 [X8Lanes][32]byte
	for lane := range scalars8 {
		scalars8[lane] = randomCanonicalFixedBaseScalar(t, rng)
	}
	var scalars4 [X4Lanes][32]byte
	copy(scalars4[:], scalars8[:X4Lanes])

	for _, width := range []uint{4, 5, 8} {
		table := BuildExperimentalFixedBaseCombTable(&base, width)
		for _, active := range []uint8{0, 1, 3, 5, 0x0f, 0x33, 0x55, 0xaa, 0xff} {
			var digits8 fixedBaseDigitsX8
			usable8 := recodeFixedBaseScalarsX8(&digits8, &scalars8, active, width)
			for position := 0; position < int(table.positions); position++ {
				for parity := 0; parity < 2; parity++ {
					round := 2*position + parity
					if round >= int(digits8.count) {
						continue
					}
					var want, got fixedBaseIFMACachedX8
					selectFixedBaseIFMACachedX8(&want, table, position, &digits8.rounds[round], usable8)
					selectFixedBaseIFMACachedUncheckedX8(&got, table, position, &digits8.rounds[round], usable8)
					if got != want {
						t.Fatalf("x8 width=%d active=%02x position=%d parity=%d", width, active, position, parity)
					}
				}
			}

			var digits4 fixedBaseDigitsX4
			usable4 := recodeFixedBaseScalarsX4(&digits4, &scalars4, active, width)
			for position := 0; position < int(table.positions); position++ {
				for parity := 0; parity < 2; parity++ {
					round := 2*position + parity
					if round >= int(digits4.count) {
						continue
					}
					var want, got fixedBaseIFMACachedX4
					selectFixedBaseIFMACachedX4(&want, table, position, &digits4.rounds[round], usable4)
					selectFixedBaseIFMACachedUncheckedX4(&got, table, position, &digits4.rounds[round], usable4)
					if got != want {
						t.Fatalf("x4 width=%d active=%02x position=%d parity=%d", width, active, position, parity)
					}
				}
			}
		}
	}
}

func addFixedBaseIFMACachedReferenceX8(out, point *IFMAPointX8, cached *fixedBaseIFMACachedX8) {
	p := *point
	var yMinusX, yPlusX, A, B, C, D, E, F, G, H IFMAElementX8
	yMinusX.Subtract(&p.Y, &p.X)
	yPlusX.Add(&p.Y, &p.X)
	_ = ifmaMultiplyComposableUncheckedX8(&A, &yMinusX, &cached.YMinusX)
	_ = ifmaMultiplyComposableUncheckedX8(&B, &yPlusX, &cached.YPlusX)
	_ = ifmaMultiplyComposableUncheckedX8(&C, &p.T, &cached.T2D)
	D.Add(&p.Z, &p.Z)
	E.Subtract(&B, &A)
	F.Subtract(&D, &C)
	G.Add(&D, &C)
	H.Add(&B, &A)
	var result IFMAPointX8
	_ = ifmaMultiplyComposableUncheckedX8(&result.X, &E, &F)
	_ = ifmaMultiplyComposableUncheckedX8(&result.Y, &G, &H)
	_ = ifmaMultiplyComposableUncheckedX8(&result.T, &E, &H)
	_ = ifmaMultiplyComposableUncheckedX8(&result.Z, &F, &G)
	*out = result
}

func addFixedBaseIFMACachedReferenceX4(out, point *IFMAPointX4, cached *fixedBaseIFMACachedX4) {
	p := *point
	var yMinusX, yPlusX, A, B, C, D, E, F, G, H IFMAElementX4
	yMinusX.Subtract(&p.Y, &p.X)
	yPlusX.Add(&p.Y, &p.X)
	_ = ifmaMultiplyComposableUncheckedX4(&A, &yMinusX, &cached.YMinusX)
	_ = ifmaMultiplyComposableUncheckedX4(&B, &yPlusX, &cached.YPlusX)
	_ = ifmaMultiplyComposableUncheckedX4(&C, &p.T, &cached.T2D)
	D.Add(&p.Z, &p.Z)
	E.Subtract(&B, &A)
	F.Subtract(&D, &C)
	G.Add(&D, &C)
	H.Add(&B, &A)
	var result IFMAPointX4
	_ = ifmaMultiplyComposableUncheckedX4(&result.X, &E, &F)
	_ = ifmaMultiplyComposableUncheckedX4(&result.Y, &G, &H)
	_ = ifmaMultiplyComposableUncheckedX4(&result.T, &E, &H)
	_ = ifmaMultiplyComposableUncheckedX4(&result.Z, &F, &G)
	*out = result
}

func TestFixedBaseIFMACachedAddWorkspaceX4MatchesReference(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	base, _ := fixedBaseGenerator(t)
	table := BuildExperimentalFixedBaseCombTable(&base, 8)
	_, points8, _, _ := fixedBaseCombDSMFixtures(t)
	var points PointX4
	for lane := 0; lane < X4Lanes; lane++ {
		point := points8.Lane(lane)
		points.SetLane(lane, &point)
	}
	var point IFMAPointX4
	point.SetReduced(&points)

	for iteration := 0; iteration < 128; iteration++ {
		var round RadixRoundX4
		round.NonzeroMask = 0x0f
		for lane := 0; lane < X4Lanes; lane++ {
			round.Magnitude[lane] = uint8(1 + (iteration+17*lane)%int(table.entries))
			if (iteration+lane)&1 != 0 {
				round.NegativeMask |= 1 << lane
			}
		}
		var cached fixedBaseIFMACachedX4
		selectFixedBaseIFMACachedX4(&cached, table, iteration%int(table.positions), &round, 0x0f)
		var want IFMAPointX4
		addFixedBaseIFMACachedReferenceX4(&want, &point, &cached)
		got := point
		var workspace fixedBaseIFMAAddScratchX4
		if err := addFixedBaseIFMACachedWorkspaceX4(&got, &got, &cached, &workspace); err != nil {
			t.Fatal(err)
		}
		gotReduced, wantReduced := got.Reduced(), want.Reduced()
		if mask := gotReduced.Equal(&wantReduced); mask != 0x0f {
			t.Fatalf("iteration=%d equality=%02x", iteration, mask)
		}
		point = got
	}
}

func TestFixedBaseIFMACachedAddWorkspaceX4ZeroAllocations(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	base, _ := fixedBaseGenerator(t)
	table := BuildExperimentalFixedBaseCombTable(&base, 8)
	_, points8, _, _ := fixedBaseCombDSMFixtures(t)
	var points PointX4
	for lane := 0; lane < X4Lanes; lane++ {
		point := points8.Lane(lane)
		points.SetLane(lane, &point)
	}
	var point IFMAPointX4
	point.SetReduced(&points)
	var round RadixRoundX4
	round.NonzeroMask = 0x0f
	for lane := range round.Magnitude {
		round.Magnitude[lane] = uint8(lane + 1)
	}
	var cached fixedBaseIFMACachedX4
	selectFixedBaseIFMACachedX4(&cached, table, 0, &round, 0x0f)
	var workspace fixedBaseIFMAAddScratchX4
	if allocs := testing.AllocsPerRun(1000, func() {
		if err := addFixedBaseIFMACachedWorkspaceX4(&point, &point, &cached, &workspace); err != nil {
			t.Fatal(err)
		}
	}); allocs != 0 {
		t.Fatalf("fixed-base x4 cached add allocations=%v", allocs)
	}
}

func TestFixedBaseIFMACachedAddWorkspaceX8MatchesReference(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	base, _ := fixedBaseGenerator(t)
	table := BuildExperimentalFixedBaseCombTable(&base, 8)
	_, points, _, _ := fixedBaseCombDSMFixtures(t)
	var point IFMAPointX8
	point.SetReduced(&points)

	for iteration := 0; iteration < 128; iteration++ {
		var round RadixRoundX8
		round.NonzeroMask = 0xff
		for lane := 0; lane < X8Lanes; lane++ {
			round.Magnitude[lane] = uint8(1 + (iteration+17*lane)%int(table.entries))
			if (iteration+lane)&1 != 0 {
				round.NegativeMask |= 1 << lane
			}
		}
		var cached fixedBaseIFMACachedX8
		selectFixedBaseIFMACachedX8(&cached, table, iteration%int(table.positions), &round, 0xff)

		var want IFMAPointX8
		addFixedBaseIFMACachedReferenceX8(&want, &point, &cached)
		got := point
		var workspace fixedBaseIFMAAddScratchX8
		for limb := range workspace.yMinusX.limbs {
			for lane := range workspace.yMinusX.limbs[limb] {
				poison := uint64((iteration+1)*(limb+3)*(lane+5)) & (ifmaComposableLimbLimit - 1)
				workspace.yMinusX.limbs[limb][lane] = poison
				workspace.yPlusX.limbs[limb][lane] = poison ^ 0x51
				for slot := range workspace.stage2 {
					workspace.stage2[slot][limb][lane] = poison ^ uint64(slot+1)
				}
			}
		}
		if err := addFixedBaseIFMACachedWorkspaceX8(&got, &got, &cached, &workspace); err != nil {
			t.Fatal(err)
		}
		gotReduced, wantReduced := got.Reduced(), want.Reduced()
		if mask := gotReduced.Equal(&wantReduced); mask != 0xff {
			t.Fatalf("iteration=%d equality=%02x", iteration, mask)
		}
		point = got
	}
}

func TestFixedBaseIFMACachedAddWorkspaceX8ZeroAllocations(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	base, _ := fixedBaseGenerator(t)
	table := BuildExperimentalFixedBaseCombTable(&base, 8)
	_, points, _, _ := fixedBaseCombDSMFixtures(t)
	var point IFMAPointX8
	point.SetReduced(&points)
	var round RadixRoundX8
	round.NonzeroMask = 0xff
	for lane := range round.Magnitude {
		round.Magnitude[lane] = uint8(lane + 1)
	}
	var cached fixedBaseIFMACachedX8
	selectFixedBaseIFMACachedX8(&cached, table, 0, &round, 0xff)
	var workspace fixedBaseIFMAAddScratchX8
	if allocs := testing.AllocsPerRun(1000, func() {
		if err := addFixedBaseIFMACachedWorkspaceX8(&point, &point, &cached, &workspace); err != nil {
			t.Fatal(err)
		}
	}); allocs != 0 {
		t.Fatalf("fixed-base cached add allocations=%v", allocs)
	}
}

func assertFixedBaseX8(t *testing.T, label string, got *PointX8, base *edwardsref.Point, scalars *[X8Lanes][32]byte, usable uint8) {
	t.Helper()
	for lane := 0; lane < X8Lanes; lane++ {
		gotLane := got.Lane(lane)
		if usable&(1<<lane) == 0 {
			if gotLane.IsIdentity() != 1 {
				t.Fatalf("%s lane %d unusable output is not identity", label, lane)
			}
			continue
		}
		scalar, err := edwardsref.NewScalar().SetCanonicalBytes(scalars[lane][:])
		if err != nil {
			t.Fatalf("%s lane %d reference scalar: %v", label, lane, err)
		}
		want := new(edwardsref.Point).ScalarMult(scalar, base)
		assertScalarPointMatchesReference(t, fmt.Sprintf("%s/lane=%d", label, lane), &gotLane, want)
	}
}

func fixedBaseGenerator(t testing.TB) (Point, *edwardsref.Point) {
	t.Helper()
	reference := edwardsref.NewGeneratorPoint()
	var base Point
	if _, err := base.SetBytes(reference.Bytes()); err != nil {
		t.Fatal(err)
	}
	return base, reference
}

func randomCanonicalFixedBaseScalar(t testing.TB, rng *rand.Rand) [32]byte {
	t.Helper()
	var wide [64]byte
	_, _ = rng.Read(wide[:])
	scalar, err := edwardsref.NewScalar().SetUniformBytes(wide[:])
	if err != nil {
		t.Fatal(err)
	}
	var encoded [32]byte
	copy(encoded[:], scalar.Bytes())
	return encoded
}

func decrementLittleEndian(value *[32]byte) {
	for index := range value {
		if value[index] != 0 {
			value[index]--
			return
		}
		value[index] = 0xff
	}
}

var (
	benchmarkFixedBaseCombPointX4     PointX4
	benchmarkFixedBaseCombPointX8     PointX8
	benchmarkFixedBaseCombIFMAPointX4 IFMAPointX4
	benchmarkFixedBaseCombIFMAPointX8 IFMAPointX8
	benchmarkFixedBaseCachedX8        fixedBaseCachedX8
	benchmarkFixedBaseIFMACachedX8    fixedBaseIFMACachedX8
	benchmarkFixedBaseCombMask        uint8
	benchmarkFixedBaseCombTable       *ExperimentalFixedBaseCombTable
)

func BenchmarkExperimentalFixedBaseCombBuild(b *testing.B) {
	base, _ := fixedBaseGenerator(b)
	for _, width := range []uint{4, 5, 8} {
		_, positions, entries := fixedBaseCombShape(width)
		payload := positions * entries * 3 * len(modulusLimbs) * 8
		b.Run(fmt.Sprintf("radix=%d", 1<<width), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				benchmarkFixedBaseCombTable = BuildExperimentalFixedBaseCombTable(&base, width)
			}
			b.ReportMetric(float64(payload), "table-bytes")
		})
	}
}

var benchmarkFixedBaseDigitsX8 fixedBaseDigitsX8

func TestFixedBaseRadix256FullRecodingMatchesGeneric(t *testing.T) {
	rng := rand.New(rand.NewSource(0xb451_256f))
	for iteration := 0; iteration < 10_000; iteration++ {
		var scalars [X8Lanes][32]byte
		for lane := range scalars {
			scalars[lane] = randomCanonicalFixedBaseScalar(t, rng)
		}
		if iteration%127 == 0 {
			scalars[iteration%X8Lanes] = scalarOrderBytes
		}
		var want, got fixedBaseDigitsX8
		want.rounds[63].NonzeroMask = 0xff
		got.rounds[63].NonzeroMask = 0xff
		wantValid := recodeFixedBaseScalarsX8(&want, &scalars, 0xff, 8)
		gotValid := recodeFixedBaseRadix256FullX8(&got, &scalars)
		if gotValid != wantValid || got != want {
			t.Fatalf("iteration %d: specialized radix-256 recoding differs from generic", iteration)
		}
	}
}

// BenchmarkExperimentalFixedBaseCombRecodingX8 isolates the fixed-base scalar
// recoder from table selection and point arithmetic. Keep all eight lanes live:
// the registered cold r51 backend uses this shape with radix 256, while the
// smaller widths remain useful comparison points for experimental combs.
func BenchmarkExperimentalFixedBaseCombRecodingX8(b *testing.B) {
	rng := rand.New(rand.NewSource(0xb4515ca1))
	var scalars [X8Lanes][32]byte
	for lane := range scalars {
		scalars[lane] = randomCanonicalFixedBaseScalar(b, rng)
	}
	for _, width := range []uint{4, 5, 8} {
		b.Run(fmt.Sprintf("radix=%d", 1<<width), func(b *testing.B) {
			b.ReportAllocs()
			var out fixedBaseDigitsX8
			for iteration := 0; iteration < b.N; iteration++ {
				recodeFixedBaseScalarsX8(&out, &scalars, 0xff, width)
			}
			benchmarkFixedBaseDigitsX8 = out
		})
	}
	b.Run("radix=256-full/generic", func(b *testing.B) {
		b.ReportAllocs()
		var out fixedBaseDigitsX8
		for iteration := 0; iteration < b.N; iteration++ {
			recodeFixedBaseScalarsX8(&out, &scalars, 0xff, 8)
		}
		benchmarkFixedBaseDigitsX8 = out
	})
	b.Run("radix=256-full/specialized", func(b *testing.B) {
		b.ReportAllocs()
		var out fixedBaseDigitsX8
		for iteration := 0; iteration < b.N; iteration++ {
			recodeFixedBaseRadix256FullX8(&out, &scalars)
		}
		benchmarkFixedBaseDigitsX8 = out
	})
}

func BenchmarkExperimentalFixedBaseCombSelectionX8(b *testing.B) {
	base, _ := fixedBaseGenerator(b)
	rng := rand.New(rand.NewSource(0xb4515e1e))
	var scalars [X8Lanes][32]byte
	for lane := range scalars {
		scalars[lane] = randomCanonicalFixedBaseScalar(b, rng)
	}
	for _, width := range []uint{4, 5, 8} {
		table := BuildExperimentalFixedBaseCombTable(&base, width)
		var digits fixedBaseDigitsX8
		recodeFixedBaseScalarsX8(&digits, &scalars, 0xff, width)
		b.Run(fmt.Sprintf("radix=%d", 1<<width), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				position := iteration % table.PositionCount()
				round := 2 * position
				selectFixedBaseCachedX8(&benchmarkFixedBaseCachedX8, table, position, &digits.rounds[round], 0xff)
			}
			b.ReportMetric(float64(table.NominalPayloadBytes()), "table-bytes")
			b.ReportMetric(float64(table.NominalPayloadBytes())/1024, "table-KiB")
		})
	}
}

func BenchmarkExperimentalFixedBaseCombIFMASelectionX8(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skip("requires AVX-512 IFMA")
	}
	base, _ := fixedBaseGenerator(b)
	rng := rand.New(rand.NewSource(0xb4515e1f))
	var scalars [X8Lanes][32]byte
	for lane := range scalars {
		scalars[lane] = randomCanonicalFixedBaseScalar(b, rng)
	}
	for _, width := range []uint{4, 5, 8} {
		table := BuildExperimentalFixedBaseCombTable(&base, width)
		var digits fixedBaseDigitsX8
		usable := recodeFixedBaseScalarsX8(&digits, &scalars, 0xff, width)
		b.Run(fmt.Sprintf("radix=%d/checked", 1<<width), func(b *testing.B) {
			var out fixedBaseIFMACachedX8
			b.ReportAllocs()
			for iteration := 0; iteration < b.N; iteration++ {
				position := iteration % table.PositionCount()
				round := 2 * position
				selectFixedBaseIFMACachedX8(&out, table, position, &digits.rounds[round], usable)
			}
			benchmarkFixedBaseIFMACachedX8 = out
		})
		b.Run(fmt.Sprintf("radix=%d/unchecked", 1<<width), func(b *testing.B) {
			var out fixedBaseIFMACachedX8
			b.ReportAllocs()
			for iteration := 0; iteration < b.N; iteration++ {
				position := iteration % table.PositionCount()
				round := 2 * position
				selectFixedBaseIFMACachedUncheckedX8(&out, table, position, &digits.rounds[round], usable)
			}
			benchmarkFixedBaseIFMACachedX8 = out
		})
	}
}

func BenchmarkExperimentalFixedBaseCombScalarMult(b *testing.B) {
	base, _ := fixedBaseGenerator(b)
	rng := rand.New(rand.NewSource(0xb451b00b))
	var scalars8 [X8Lanes][32]byte
	for lane := range scalars8 {
		scalars8[lane] = randomCanonicalFixedBaseScalar(b, rng)
	}
	var scalars4 [X4Lanes][32]byte
	copy(scalars4[:], scalars8[:X4Lanes])
	for _, width := range []uint{4, 5, 8} {
		table := BuildExperimentalFixedBaseCombTable(&base, width)
		b.Run(fmt.Sprintf("model/x4/radix=%d", 1<<width), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				ExperimentalFixedBaseCombScalarMultX4(&benchmarkFixedBaseCombPointX4, table, &scalars4, 0x0f)
			}
			b.ReportMetric(float64(table.NominalPayloadBytes()), "table-bytes")
		})
		b.Run(fmt.Sprintf("model/x8/radix=%d", 1<<width), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				ExperimentalFixedBaseCombScalarMultX8(&benchmarkFixedBaseCombPointX8, table, &scalars8, 0xff)
			}
			b.ReportMetric(float64(table.NominalPayloadBytes()), "table-bytes")
		})
		b.Run(fmt.Sprintf("ifma/x4/radix=%d", 1<<width), func(b *testing.B) {
			if !ExperimentalIFMAAvailable() {
				b.Skip("requires AVX-512 IFMA")
			}
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				if _, err := ExperimentalIFMAFixedBaseCombScalarMultX4(&benchmarkFixedBaseCombIFMAPointX4, table, &scalars4, 0x0f); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(table.NominalPayloadBytes()), "table-bytes")
		})
		b.Run(fmt.Sprintf("ifma/x8/radix=%d", 1<<width), func(b *testing.B) {
			if !ExperimentalIFMAAvailable() {
				b.Skip("requires AVX-512 IFMA")
			}
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				if _, err := ExperimentalIFMAFixedBaseCombScalarMultX8(&benchmarkFixedBaseCombIFMAPointX8, table, &scalars8, 0xff); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(table.NominalPayloadBytes()), "table-bytes")
		})
	}
}

func BenchmarkExperimentalFixedBaseCombCompleteDSMTradeoffX8(b *testing.B) {
	base, _ := fixedBaseGenerator(b)
	B, A, s, k := fixedBaseCombDSMFixtures(b)
	negative := [DSMTerms]uint8{0, 0xff}

	// The current comparison point shares one radix-32 doubling chain between
	// B and the cold arbitrary-key A term.
	currentBases := [DSMTerms]PointX8{B, A}
	var currentScalars FixedDSMScalarsX8
	currentScalars[0] = s
	currentScalars[1] = k
	var current FixedDSMWorkspaceX8
	current.Prepare(&currentBases, 5)
	b.Run("model/current-shared-doubling/radixA=32", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for iteration := 0; iteration < b.N; iteration++ {
			benchmarkFixedBaseCombMask = current.Evaluate(&benchmarkFixedBaseCombPointX8, &currentScalars, &negative, 0xff)
		}
		b.ReportMetric(float64(2*NominalFullTableBytes(X8Lanes, 4, 5)), "tables-bytes")
	})

	// The split experiment retains only A in the shared-doubling loop, then
	// adds the independently evaluated scalar-stored B comb result. This is the
	// meaningful full group-arithmetic comparison; a standalone B benchmark
	// would hide the fact that A still requires its doubling chain.
	var aOnly ExperimentalVariableBaseWorkspaceX8
	aOnly.Prepare(&A, 5)
	for _, width := range []uint{4, 5, 8} {
		table := BuildExperimentalFixedBaseCombTable(&base, width)
		b.Run(fmt.Sprintf("model/split-combB/radixA=32/radixB=%d", 1<<width), func(b *testing.B) {
			b.ReportAllocs()
			var aTerm, bTerm PointX8
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				maskA := aOnly.Evaluate(&aTerm, &k, 0xff, 0xff)
				maskB := ExperimentalFixedBaseCombScalarMultX8(&bTerm, table, &s, 0xff)
				benchmarkFixedBaseCombPointX8.Add(&aTerm, &bTerm)
				benchmarkFixedBaseCombMask = maskA & maskB
			}
			b.ReportMetric(float64(NominalFullTableBytes(X8Lanes, 4, 5)+table.NominalPayloadBytes()), "tables-bytes")
		})
	}

	if !ExperimentalIFMAAvailable() {
		return
	}
	var currentIFMA ExperimentalIFMAFixedDSMWorkspaceX8
	if err := currentIFMA.PrepareBoth(&currentBases, 5); err != nil {
		b.Fatal(err)
	}
	b.Run("ifma/current-shared-doubling/radixA=32", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for iteration := 0; iteration < b.N; iteration++ {
			mask, err := currentIFMA.Evaluate(&benchmarkFixedBaseCombIFMAPointX8, &currentScalars, &negative, 0xff)
			if err != nil {
				b.Fatal(err)
			}
			benchmarkFixedBaseCombMask = mask
		}
		b.ReportMetric(float64(2*NominalFullTableBytes(X8Lanes, 4, 5)), "tables-bytes")
	})
	var aOnlyIFMA ExperimentalIFMAVariableBaseWorkspaceX8
	if err := aOnlyIFMA.Prepare(&A, 5); err != nil {
		b.Fatal(err)
	}
	for _, width := range []uint{4, 5, 8} {
		table := BuildExperimentalFixedBaseCombTable(&base, width)
		b.Run(fmt.Sprintf("ifma/split-combB/radixA=32/radixB=%d", 1<<width), func(b *testing.B) {
			b.ReportAllocs()
			var aTerm, bTerm IFMAPointX8
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				maskA, err := aOnlyIFMA.Evaluate(&aTerm, &k, 0xff, 0xff)
				if err != nil {
					b.Fatal(err)
				}
				maskB, err := ExperimentalIFMAFixedBaseCombScalarMultX8(&bTerm, table, &s, 0xff)
				if err != nil {
					b.Fatal(err)
				}
				if err := ExperimentalIFMAPointAddComposableX8(&benchmarkFixedBaseCombIFMAPointX8, &aTerm, &bTerm); err != nil {
					b.Fatal(err)
				}
				benchmarkFixedBaseCombMask = maskA & maskB
			}
			b.ReportMetric(float64(NominalFullTableBytes(X8Lanes, 4, 5)+table.NominalPayloadBytes()), "tables-bytes")
		})
	}
}

func fixedBaseCombDSMFixtures(tb testing.TB) (PointX8, PointX8, [X8Lanes][32]byte, [X8Lanes][32]byte) {
	tb.Helper()
	rng := rand.New(rand.NewSource(0xb451d5a0))
	base := edwardsref.NewGeneratorPoint()
	var bEncodings, aEncodings [X8Lanes][32]byte
	var s, k [X8Lanes][32]byte
	for lane := 0; lane < X8Lanes; lane++ {
		copy(bEncodings[lane][:], base.Bytes())
		s[lane] = randomCanonicalFixedBaseScalar(tb, rng)
		k[lane] = randomCanonicalFixedBaseScalar(tb, rng)
		variableScalarBytes := randomCanonicalFixedBaseScalar(tb, rng)
		variableScalar, err := edwardsref.NewScalar().SetCanonicalBytes(variableScalarBytes[:])
		if err != nil {
			tb.Fatal(err)
		}
		variablePoint := new(edwardsref.Point).ScalarBaseMult(variableScalar)
		copy(aEncodings[lane][:], variablePoint.Bytes())
	}
	var B, A PointX8
	if mask := B.SetBytes(&bEncodings); mask != 0xff {
		tb.Fatalf("B mask=%02x", mask)
	}
	if mask := A.SetBytes(&aEncodings); mask != 0xff {
		tb.Fatalf("A mask=%02x", mask)
	}
	return B, A, s, k
}
