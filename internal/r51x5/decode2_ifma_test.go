package r51x5

import (
	"errors"
	"fmt"
	"math/rand"
	"testing"
)

func TestIFMADecode2ModelX8EveryTailAndLane(t *testing.T) {
	vectors := decode2IFMAEdgeEncodings(t)
	var aBytes, rBytes [X8Lanes][32]byte
	for lane := 0; lane < X8Lanes; lane++ {
		aBytes[lane] = vectors[lane]
		rBytes[lane] = vectors[lane+X8Lanes]
	}
	for active := 0; active < 1<<X8Lanes; active++ {
		checkIFMADecode2ModelX8(t, fmt.Sprintf("active=%02x", active), &aBytes, &rBytes, uint8(active))
	}
}

func TestIFMADecode2ModelX4EveryTailAndLane(t *testing.T) {
	vectors := decode2IFMAEdgeEncodings(t)
	var aBytes, rBytes [X4Lanes][32]byte
	for lane := 0; lane < X4Lanes; lane++ {
		aBytes[lane] = vectors[lane]
		rBytes[lane] = vectors[lane+X4Lanes]
	}
	for active := 0; active < 1<<X4Lanes; active++ {
		checkIFMADecode2ModelX4(t, fmt.Sprintf("active=%x", active), &aBytes, &rBytes, uint8(active))
	}
}

func TestIFMADecode2ModelPermissiveAliases(t *testing.T) {
	vectors := decode2IFMAEdgeEncodings(t)
	for start := 0; start < len(vectors); start += X8Lanes {
		var aBytes, rBytes [X8Lanes][32]byte
		for lane := 0; lane < X8Lanes; lane++ {
			aBytes[lane] = vectors[(start+lane)%len(vectors)]
			rBytes[lane] = vectors[(start+lane+1)%len(vectors)]
		}
		checkIFMADecode2ModelX8(t, fmt.Sprintf("start=%d", start), &aBytes, &rBytes, 0xff)
	}
}

func TestIFMADecode2ModelX8MatchesTwoX4AndSequentialChains(t *testing.T) {
	rng := rand.New(rand.NewSource(0x1f2d28451))
	for round := 0; round < 64; round++ {
		var aBytes, rBytes [X8Lanes][32]byte
		for lane := 0; lane < X8Lanes; lane++ {
			_, _ = rng.Read(aBytes[lane][:])
			_, _ = rng.Read(rBytes[lane][:])
		}
		active := uint8(rng.Uint32())
		var pairedA, sequentialA PointX8
		var pairedR, sequentialR AffinePointX8
		pairedAMask, pairedRMask, err := decode2NoTIFMAModelX8(&pairedA, &pairedR, &aBytes, &rBytes, active)
		if err != nil {
			t.Fatal(err)
		}
		sequentialOps := decode2IFMAOpsX8{}
		sequentialAMask, sequentialRMask, err := decode2NoTIFMAX8(&sequentialA, &sequentialR, &aBytes, &rBytes, active, &sequentialOps, false)
		if err != nil {
			t.Fatal(err)
		}
		if pairedAMask != sequentialAMask || pairedRMask != sequentialRMask || pairedA != sequentialA || pairedR != sequentialR {
			t.Fatalf("round %d: interleaved and sequential schedules differ", round)
		}
		var uncheckedModelA PointX8
		var uncheckedModelR AffinePointX8
		uncheckedModelOps := decode2IFMAOpsX8{uncheckedInputs: true}
		uncheckedModelAMask, uncheckedModelRMask, err := decode2NoTIFMAX8(&uncheckedModelA, &uncheckedModelR, &aBytes, &rBytes, active, &uncheckedModelOps, true)
		if err != nil {
			t.Fatal(err)
		}
		if pairedAMask != uncheckedModelAMask || pairedRMask != uncheckedModelRMask || pairedA != uncheckedModelA || pairedR != uncheckedModelR {
			t.Fatalf("round %d: checked and boundary-checked model schedules differ", round)
		}
		var independentA PointX8
		var independentR AffinePointX8
		independentOps := decode2IFMAOpsX8{}
		independentAMask, independentRMask, err := decode2NoTIFMAIndependentX8(&independentA, &independentR, &aBytes, &rBytes, active, &independentOps)
		if err != nil {
			t.Fatal(err)
		}
		if pairedAMask != independentAMask || pairedRMask != independentRMask || pairedA != independentA || pairedR != independentR {
			t.Fatalf("round %d: paired and independent decoders differ", round)
		}

		var joinedA PointX8
		var joinedR AffinePointX8
		var joinedAMask, joinedRMask uint8
		for half := 0; half < 2; half++ {
			var a4Bytes, r4Bytes [X4Lanes][32]byte
			for lane := 0; lane < X4Lanes; lane++ {
				a4Bytes[lane] = aBytes[half*X4Lanes+lane]
				r4Bytes[lane] = rBytes[half*X4Lanes+lane]
			}
			var a4 PointX4
			var r4 AffinePointX4
			a4Mask, r4Mask, err := decode2NoTIFMAModelX4(&a4, &r4, &a4Bytes, &r4Bytes, active>>(half*X4Lanes))
			if err != nil {
				t.Fatal(err)
			}
			joinedAMask |= a4Mask << (half * X4Lanes)
			joinedRMask |= r4Mask << (half * X4Lanes)
			for lane := 0; lane < X4Lanes; lane++ {
				point := a4.Lane(lane)
				joinedA.SetLane(half*X4Lanes+lane, &point)
				rx, ry := r4.X.Lane(lane), r4.Y.Lane(lane)
				joinedR.X.SetLane(half*X4Lanes+lane, &rx)
				joinedR.Y.SetLane(half*X4Lanes+lane, &ry)
			}
		}
		if pairedAMask != joinedAMask || pairedRMask != joinedRMask || pairedA != joinedA || pairedR != joinedR {
			t.Fatalf("round %d: x8 and two x4 schedules differ", round)
		}
	}
}

func TestIFMADecode2ErrorLeavesOutputsUnchanged(t *testing.T) {
	generator := newGeneratorEncodingForTest(t)
	var a8Bytes, r8Bytes [X8Lanes][32]byte
	for lane := 0; lane < X8Lanes; lane++ {
		a8Bytes[lane], r8Bytes[lane] = generator, generator
	}
	var validA8 PointX8
	var validR8 AffinePointX8
	countOps8 := decode2IFMAOpsX8{}
	if _, _, err := decode2NoTIFMAX8(&validA8, &validR8, &a8Bytes, &r8Bytes, 0xff, &countOps8, true); err != nil {
		t.Fatal(err)
	}
	for _, failAt := range []int{1, countOps8.calls / 2, countOps8.calls} {
		for _, unchecked := range []bool{false, true} {
			a8, r8 := validA8, validR8
			ops := decode2IFMAOpsX8{uncheckedInputs: unchecked, failAt: failAt}
			aMask, rMask, err := decode2NoTIFMAX8(&a8, &r8, &a8Bytes, &r8Bytes, 0xff, &ops, true)
			if !errors.Is(err, errIFMAOutputRange) || aMask != 0 || rMask != 0 {
				t.Fatalf("x8 unchecked=%v failure %d returned (%02x,%02x,%v)", unchecked, failAt, aMask, rMask, err)
			}
			if a8 != validA8 || r8 != validR8 {
				t.Fatalf("x8 unchecked=%v failure %d changed output", unchecked, failAt)
			}
		}
	}

	var a4Bytes, r4Bytes [X4Lanes][32]byte
	copy(a4Bytes[:], a8Bytes[:X4Lanes])
	copy(r4Bytes[:], r8Bytes[:X4Lanes])
	var validA4 PointX4
	var validR4 AffinePointX4
	countOps4 := decode2IFMAOpsX4{}
	if _, _, err := decode2NoTIFMAX4(&validA4, &validR4, &a4Bytes, &r4Bytes, 0x0f, &countOps4, true); err != nil {
		t.Fatal(err)
	}
	for _, failAt := range []int{1, countOps4.calls / 2, countOps4.calls} {
		for _, unchecked := range []bool{false, true} {
			a4, r4 := validA4, validR4
			ops := decode2IFMAOpsX4{uncheckedInputs: unchecked, failAt: failAt}
			aMask, rMask, err := decode2NoTIFMAX4(&a4, &r4, &a4Bytes, &r4Bytes, 0x0f, &ops, true)
			if !errors.Is(err, errIFMAOutputRange) || aMask != 0 || rMask != 0 {
				t.Fatalf("x4 unchecked=%v failure %d returned (%x,%x,%v)", unchecked, failAt, aMask, rMask, err)
			}
			if a4 != validA4 || r4 != validR4 {
				t.Fatalf("x4 unchecked=%v failure %d changed output", unchecked, failAt)
			}
		}
	}
}

func TestIFMADecode2UncheckedBoundaryRejectsOutOfRange(t *testing.T) {
	one4 := broadcastX4(new(Element).One())
	one8 := broadcastX8(new(Element).One())
	var good4, bad4 IFMAElementX4
	var good8, bad8 IFMAElementX8
	good4.SetReduced(&one4)
	good8.SetReduced(&one8)
	bad4, bad8 = good4, good8
	bad4.limbs[0][0] = ifmaComposableLimbLimit
	bad8.limbs[0][0] = ifmaComposableLimbLimit
	ops4 := decode2IFMAOpsX4{uncheckedInputs: true}
	ops8 := decode2IFMAOpsX8{uncheckedInputs: true}
	if err := ops4.validatePairImports(&good4, &bad4, &good4, &good4); !errors.Is(err, errIFMAComposableInputRange) {
		t.Fatalf("x4 boundary error=%v", err)
	}
	if err := ops4.validateOneImports(&bad4, &good4, &good4); !errors.Is(err, errIFMAComposableInputRange) {
		t.Fatalf("x4 one-point boundary error=%v", err)
	}
	if err := ops8.validatePairImports(&good8, &bad8, &good8, &good8); !errors.Is(err, errIFMAComposableInputRange) {
		t.Fatalf("x8 boundary error=%v", err)
	}
	if err := ops8.validateOneImports(&bad8, &good8, &good8); !errors.Is(err, errIFMAComposableInputRange) {
		t.Fatalf("x8 one-point boundary error=%v", err)
	}
}

func TestIFMADecode2UnavailableLeavesOutputsUnchanged(t *testing.T) {
	if ExperimentalIFMAAvailable() {
		t.Skip("requires a target without the complete IFMA feature set")
	}
	var a8 PointX8
	var r8 AffinePointX8
	a8.Y = broadcastX8(new(Element).One())
	r8.Y = broadcastX8(new(Element).One())
	wantA8, wantR8 := a8, r8
	var a8Bytes, r8Bytes [X8Lanes][32]byte
	aMask, rMask, err := ExperimentalIFMADecode2NoTX8(&a8, &r8, &a8Bytes, &r8Bytes, 0xff)
	if !errors.Is(err, ErrIFMAUnavailable) || aMask != 0 || rMask != 0 || a8 != wantA8 || r8 != wantR8 {
		t.Fatalf("x8 unavailable result=(%02x,%02x,%v), changed=%v", aMask, rMask, err, a8 != wantA8 || r8 != wantR8)
	}

	var a4 PointX4
	var r4 AffinePointX4
	a4.Y = broadcastX4(new(Element).One())
	r4.Y = broadcastX4(new(Element).One())
	wantA4, wantR4 := a4, r4
	var a4Bytes, r4Bytes [X4Lanes][32]byte
	aMask, rMask, err = ExperimentalIFMADecode2NoTX4(&a4, &r4, &a4Bytes, &r4Bytes, 0x0f)
	if !errors.Is(err, ErrIFMAUnavailable) || aMask != 0 || rMask != 0 || a4 != wantA4 || r4 != wantR4 {
		t.Fatalf("x4 unavailable result=(%x,%x,%v), changed=%v", aMask, rMask, err, a4 != wantA4 || r4 != wantR4)
	}
}

func TestIFMADecode2ZeroAlloc(t *testing.T) {
	generator := newGeneratorEncodingForTest(t)
	var a8Bytes, r8Bytes [X8Lanes][32]byte
	for lane := 0; lane < X8Lanes; lane++ {
		a8Bytes[lane], r8Bytes[lane] = generator, generator
	}
	var a8 PointX8
	var r8 AffinePointX8
	if allocs := testing.AllocsPerRun(20, func() {
		if _, _, err := decode2NoTIFMAModelX8(&a8, &r8, &a8Bytes, &r8Bytes, 0xff); err != nil {
			panic(err)
		}
	}); allocs != 0 {
		t.Fatalf("x8 model allocated %.2f objects", allocs)
	}
	if allocs := testing.AllocsPerRun(20, func() {
		ops := decode2IFMAOpsX8{uncheckedInputs: true}
		if _, _, err := decode2NoTIFMAX8(&a8, &r8, &a8Bytes, &r8Bytes, 0xff, &ops, true); err != nil {
			panic(err)
		}
	}); allocs != 0 {
		t.Fatalf("x8 boundary-checked model allocated %.2f objects", allocs)
	}

	var a4Bytes, r4Bytes [X4Lanes][32]byte
	copy(a4Bytes[:], a8Bytes[:X4Lanes])
	copy(r4Bytes[:], r8Bytes[:X4Lanes])
	var a4 PointX4
	var r4 AffinePointX4
	if allocs := testing.AllocsPerRun(20, func() {
		if _, _, err := decode2NoTIFMAModelX4(&a4, &r4, &a4Bytes, &r4Bytes, 0x0f); err != nil {
			panic(err)
		}
	}); allocs != 0 {
		t.Fatalf("x4 model allocated %.2f objects", allocs)
	}
	if allocs := testing.AllocsPerRun(20, func() {
		ops := decode2IFMAOpsX4{uncheckedInputs: true}
		if _, _, err := decode2NoTIFMAX4(&a4, &r4, &a4Bytes, &r4Bytes, 0x0f, &ops, true); err != nil {
			panic(err)
		}
	}); allocs != 0 {
		t.Fatalf("x4 boundary-checked model allocated %.2f objects", allocs)
	}

	if ExperimentalIFMAAvailable() {
		if allocs := testing.AllocsPerRun(20, func() {
			if _, _, err := ExperimentalIFMADecode2NoTX8(&a8, &r8, &a8Bytes, &r8Bytes, 0xff); err != nil {
				panic(err)
			}
		}); allocs != 0 {
			t.Fatalf("x8 hardware API allocated %.2f objects", allocs)
		}
		if allocs := testing.AllocsPerRun(20, func() {
			if _, _, err := ExperimentalIFMADecode2NoTX4(&a4, &r4, &a4Bytes, &r4Bytes, 0x0f); err != nil {
				panic(err)
			}
		}); allocs != 0 {
			t.Fatalf("x4 hardware API allocated %.2f objects", allocs)
		}
	}
}

func TestIFMADecode2HardwareMatchesReference(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("requires AVX-512 IFMA")
	}
	vectors := decode2IFMAEdgeEncodings(t)
	var edgeA8, edgeR8 [X8Lanes][32]byte
	for lane := 0; lane < X8Lanes; lane++ {
		edgeA8[lane] = vectors[lane]
		edgeR8[lane] = vectors[lane+X8Lanes]
	}
	for active := 0; active < 1<<X8Lanes; active++ {
		checkIFMADecode2HardwareX8(t, fmt.Sprintf("active=%02x", active), &edgeA8, &edgeR8, uint8(active))
	}
	for start := 0; start < len(vectors); start += X8Lanes {
		for lane := 0; lane < X8Lanes; lane++ {
			edgeA8[lane] = vectors[(start+lane)%len(vectors)]
			edgeR8[lane] = vectors[(start+lane+1)%len(vectors)]
		}
		checkIFMADecode2HardwareX8(t, fmt.Sprintf("alias-start=%d", start), &edgeA8, &edgeR8, 0xff)
	}
	var edgeA4, edgeR4 [X4Lanes][32]byte
	copy(edgeA4[:], edgeA8[:X4Lanes])
	copy(edgeR4[:], edgeR8[:X4Lanes])
	for active := 0; active < 1<<X4Lanes; active++ {
		var gotA, wantA PointX4
		var gotR, wantR AffinePointX4
		gotAMask, gotRMask, err := ExperimentalIFMADecode2NoTX4(&gotA, &gotR, &edgeA4, &edgeR4, uint8(active))
		if err != nil {
			t.Fatal(err)
		}
		wantAMask, wantRMask := Decode2NoTX4(&wantA, &wantR, &edgeA4, &edgeR4, uint8(active))
		if gotAMask != wantAMask || gotRMask != wantRMask || gotA != wantA || gotR != wantR {
			t.Fatalf("x4 active=%x: hardware differs from reference", active)
		}
	}

	rng := rand.New(rand.NewSource(0x51f2d2))
	for round := 0; round < 64; round++ {
		var aBytes, rBytes [X8Lanes][32]byte
		for lane := 0; lane < X8Lanes; lane++ {
			_, _ = rng.Read(aBytes[lane][:])
			_, _ = rng.Read(rBytes[lane][:])
		}
		active := uint8(rng.Uint32())
		var gotA PointX8
		var gotR AffinePointX8
		gotAMask, gotRMask, err := ExperimentalIFMADecode2NoTX8(&gotA, &gotR, &aBytes, &rBytes, active)
		if err != nil {
			t.Fatal(err)
		}
		var checkedA PointX8
		var checkedR AffinePointX8
		checkedOps := decode2IFMAOpsX8{hardware: true}
		checkedAMask, checkedRMask, err := decode2NoTIFMAX8(&checkedA, &checkedR, &aBytes, &rBytes, active, &checkedOps, true)
		if err != nil {
			t.Fatal(err)
		}
		if gotAMask != checkedAMask || gotRMask != checkedRMask || gotA != checkedA || gotR != checkedR {
			t.Fatalf("round %d: checked and boundary-checked hardware differ", round)
		}
		wantA, wantR, wantAMask, wantRMask := referenceDecode2X8(&aBytes, &rBytes, active)
		if gotAMask != wantAMask || gotRMask != wantRMask || gotA != wantA || gotR != wantR {
			t.Fatalf("round %d: hardware differs from reference", round)
		}
		for half := 0; half < 2; half++ {
			var a4Bytes, r4Bytes [X4Lanes][32]byte
			copy(a4Bytes[:], aBytes[half*X4Lanes:(half+1)*X4Lanes])
			copy(r4Bytes[:], rBytes[half*X4Lanes:(half+1)*X4Lanes])
			var gotA4 PointX4
			var gotR4 AffinePointX4
			gotA4Mask, gotR4Mask, err := ExperimentalIFMADecode2NoTX4(&gotA4, &gotR4, &a4Bytes, &r4Bytes, active>>(half*X4Lanes))
			if err != nil {
				t.Fatal(err)
			}
			var checkedA4 PointX4
			var checkedR4 AffinePointX4
			checkedOps4 := decode2IFMAOpsX4{hardware: true}
			checkedA4Mask, checkedR4Mask, err := decode2NoTIFMAX4(&checkedA4, &checkedR4, &a4Bytes, &r4Bytes, active>>(half*X4Lanes), &checkedOps4, true)
			if err != nil {
				t.Fatal(err)
			}
			if gotA4Mask != checkedA4Mask || gotR4Mask != checkedR4Mask || gotA4 != checkedA4 || gotR4 != checkedR4 {
				t.Fatalf("round %d half %d: checked and boundary-checked x4 hardware differ", round, half)
			}
			var wantA4 PointX4
			var wantR4 AffinePointX4
			wantA4Mask, wantR4Mask := Decode2NoTX4(&wantA4, &wantR4, &a4Bytes, &r4Bytes, active>>(half*X4Lanes))
			if gotA4Mask != wantA4Mask || gotR4Mask != wantR4Mask || gotA4 != wantA4 || gotR4 != wantR4 {
				t.Fatalf("round %d half %d: x4 hardware differs from reference", round, half)
			}
		}
	}
}

func checkIFMADecode2HardwareX8(t *testing.T, label string, aBytes, rBytes *[X8Lanes][32]byte, active uint8) {
	t.Helper()
	var gotA PointX8
	var gotR AffinePointX8
	gotAMask, gotRMask, err := ExperimentalIFMADecode2NoTX8(&gotA, &gotR, aBytes, rBytes, active)
	if err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	wantA, wantR, wantAMask, wantRMask := referenceDecode2X8(aBytes, rBytes, active)
	if gotAMask != wantAMask || gotRMask != wantRMask || gotA != wantA || gotR != wantR {
		t.Fatalf("%s: hardware differs from reference", label)
	}
}

func checkIFMADecode2ModelX8(t *testing.T, label string, aBytes, rBytes *[X8Lanes][32]byte, active uint8) {
	t.Helper()
	var gotA PointX8
	var gotR AffinePointX8
	gotAMask, gotRMask, err := decode2NoTIFMAModelX8(&gotA, &gotR, aBytes, rBytes, active)
	if err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	wantA, wantR, wantAMask, wantRMask := referenceDecode2X8(aBytes, rBytes, active)
	if gotAMask != wantAMask || gotRMask != wantRMask || gotA != wantA || gotR != wantR {
		t.Fatalf("%s: model differs: masks got=(%02x,%02x) want=(%02x,%02x)", label, gotAMask, gotRMask, wantAMask, wantRMask)
	}
	assertReducedDecode2X8(t, label, &gotA, &gotR)
}

func checkIFMADecode2ModelX4(t *testing.T, label string, aBytes, rBytes *[X4Lanes][32]byte, active uint8) {
	t.Helper()
	var gotA PointX4
	var gotR AffinePointX4
	gotAMask, gotRMask, err := decode2NoTIFMAModelX4(&gotA, &gotR, aBytes, rBytes, active)
	if err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	var wantA PointX4
	var wantR AffinePointX4
	wantAMask, wantRMask := Decode2NoTX4(&wantA, &wantR, aBytes, rBytes, active)
	if gotAMask != wantAMask || gotRMask != wantRMask || gotA != wantA || gotR != wantR {
		t.Fatalf("%s: model differs: masks got=(%x,%x) want=(%x,%x)", label, gotAMask, gotRMask, wantAMask, wantRMask)
	}
	if !IsReducedX4(gotA.X.limbs) || !IsReducedX4(gotA.Y.limbs) || !IsReducedX4(gotA.Z.limbs) || !IsReducedX4(gotA.T.limbs) || !IsReducedX4(gotR.X.limbs) || !IsReducedX4(gotR.Y.limbs) {
		t.Fatalf("%s: output crossed the API boundary unreduced", label)
	}
}

func referenceDecode2X8(aBytes, rBytes *[X8Lanes][32]byte, active uint8) (PointX8, AffinePointX8, uint8, uint8) {
	var a PointX8
	var r AffinePointX8
	aMask, rMask := Decode2NoTX8(&a, &r, aBytes, rBytes, active)
	return a, r, aMask, rMask
}

func assertReducedDecode2X8(t *testing.T, label string, a *PointX8, r *AffinePointX8) {
	t.Helper()
	if !IsReducedX8(a.X.limbs) || !IsReducedX8(a.Y.limbs) || !IsReducedX8(a.Z.limbs) || !IsReducedX8(a.T.limbs) || !IsReducedX8(r.X.limbs) || !IsReducedX8(r.Y.limbs) {
		t.Fatalf("%s: output crossed the API boundary unreduced", label)
	}
}

func decode2IFMAEdgeEncodings(t *testing.T) [][32]byte {
	t.Helper()
	vectors := make([][32]byte, 0, 82)
	vectors = append(vectors, newGeneratorEncodingForTest(t), deterministicInvalidPointEncoding(t))
	for value := byte(0); value <= 18; value++ {
		canonical := [32]byte{value}
		vectors = append(vectors, canonical)
		canonical[31] |= 0x80
		vectors = append(vectors, canonical)

		// 2^255 = p+19, so p+value is accepted by the permissive decoder
		// and reduces to value for precisely these nineteen low values.
		alias := [32]byte{0xed + value}
		for i := 1; i < 31; i++ {
			alias[i] = 0xff
		}
		alias[31] = 0x7f
		vectors = append(vectors, alias)
		alias[31] |= 0x80
		vectors = append(vectors, alias)
	}
	return vectors
}

var (
	benchmarkIFMADecode2A8     PointX8
	benchmarkIFMADecode2R8     AffinePointX8
	benchmarkIFMADecode2Masks8 [2]uint8
	benchmarkIFMADecode2A4     PointX4
	benchmarkIFMADecode2R4     AffinePointX4
	benchmarkIFMADecode2Masks4 [2]uint8
)

func BenchmarkExperimentalIFMADecode2NoT(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skip("requires AVX-512 IFMA")
	}
	generator := newGeneratorEncodingForTest(b)
	var a8Bytes, r8Bytes [X8Lanes][32]byte
	for lane := 0; lane < X8Lanes; lane++ {
		a8Bytes[lane], r8Bytes[lane] = generator, generator
		a8Bytes[lane][31] ^= byte(lane&1) << 7
		r8Bytes[lane][31] ^= byte((lane>>1)&1) << 7
	}

	for _, lanes := range []int{1, 4, 8} {
		active := uint8((1 << lanes) - 1)
		b.Run(fmt.Sprintf("x8/paired-interleaved/active=%d", lanes), func(b *testing.B) {
			b.ReportAllocs()
			var a PointX8
			var r AffinePointX8
			var aMask, rMask uint8
			for i := 0; i < b.N; i++ {
				ops := decode2IFMAOpsX8{hardware: true, uncheckedInputs: true}
				var err error
				aMask, rMask, err = decode2NoTIFMAX8(&a, &r, &a8Bytes, &r8Bytes, active, &ops, true)
				if err != nil {
					b.Fatal(err)
				}
			}
			benchmarkIFMADecode2A8, benchmarkIFMADecode2R8 = a, r
			benchmarkIFMADecode2Masks8 = [2]uint8{aMask, rMask}
		})
		b.Run(fmt.Sprintf("x8/paired-sequential-pow-chains/active=%d", lanes), func(b *testing.B) {
			b.ReportAllocs()
			var a PointX8
			var r AffinePointX8
			var aMask, rMask uint8
			for i := 0; i < b.N; i++ {
				ops := decode2IFMAOpsX8{hardware: true, uncheckedInputs: true}
				var err error
				aMask, rMask, err = decode2NoTIFMAX8(&a, &r, &a8Bytes, &r8Bytes, active, &ops, false)
				if err != nil {
					b.Fatal(err)
				}
			}
			benchmarkIFMADecode2A8, benchmarkIFMADecode2R8 = a, r
			benchmarkIFMADecode2Masks8 = [2]uint8{aMask, rMask}
		})
		b.Run(fmt.Sprintf("x8/two-independent-decoders/active=%d", lanes), func(b *testing.B) {
			b.ReportAllocs()
			var a PointX8
			var r AffinePointX8
			var aMask, rMask uint8
			for i := 0; i < b.N; i++ {
				ops := decode2IFMAOpsX8{hardware: true, uncheckedInputs: true}
				var err error
				aMask, rMask, err = decode2NoTIFMAIndependentX8(&a, &r, &a8Bytes, &r8Bytes, active, &ops)
				if err != nil {
					b.Fatal(err)
				}
			}
			b.Run("x8/paired-checked-every-multiply/active=8", func(b *testing.B) {
				b.ReportAllocs()
				var a PointX8
				var r AffinePointX8
				var aMask, rMask uint8
				for i := 0; i < b.N; i++ {
					ops := decode2IFMAOpsX8{hardware: true}
					var err error
					aMask, rMask, err = decode2NoTIFMAX8(&a, &r, &a8Bytes, &r8Bytes, 0xff, &ops, true)
					if err != nil {
						b.Fatal(err)
					}
				}
				benchmarkIFMADecode2A8, benchmarkIFMADecode2R8 = a, r
				benchmarkIFMADecode2Masks8 = [2]uint8{aMask, rMask}
			})
			benchmarkIFMADecode2A8, benchmarkIFMADecode2R8 = a, r
			benchmarkIFMADecode2Masks8 = [2]uint8{aMask, rMask}
		})
	}

	var a4Bytes, r4Bytes [X4Lanes][32]byte
	copy(a4Bytes[:], a8Bytes[:X4Lanes])
	copy(r4Bytes[:], r8Bytes[:X4Lanes])
	for _, interleaved := range []bool{true, false} {
		label := "paired-sequential-pow-chains"
		if interleaved {
			label = "paired-interleaved"
		}
		b.Run("x4/"+label+"/active=4", func(b *testing.B) {
			b.ReportAllocs()
			var a PointX4
			var r AffinePointX4
			var aMask, rMask uint8
			for i := 0; i < b.N; i++ {
				ops := decode2IFMAOpsX4{hardware: true, uncheckedInputs: true}
				var err error
				aMask, rMask, err = decode2NoTIFMAX4(&a, &r, &a4Bytes, &r4Bytes, 0x0f, &ops, interleaved)
				if err != nil {
					b.Fatal(err)
				}
			}
			benchmarkIFMADecode2A4, benchmarkIFMADecode2R4 = a, r
			benchmarkIFMADecode2Masks4 = [2]uint8{aMask, rMask}
		})
	}
	b.Run("x4/two-independent-decoders/active=4", func(b *testing.B) {
		b.ReportAllocs()
		var a PointX4
		var r AffinePointX4
		var aMask, rMask uint8
		for i := 0; i < b.N; i++ {
			ops := decode2IFMAOpsX4{hardware: true, uncheckedInputs: true}
			var err error
			aMask, rMask, err = decode2NoTIFMAIndependentX4(&a, &r, &a4Bytes, &r4Bytes, 0x0f, &ops)
			if err != nil {
				b.Fatal(err)
			}
		}
		benchmarkIFMADecode2A4, benchmarkIFMADecode2R4 = a, r
		benchmarkIFMADecode2Masks4 = [2]uint8{aMask, rMask}
	})
	b.Run("x4/paired-checked-every-multiply/active=4", func(b *testing.B) {
		b.ReportAllocs()
		var a PointX4
		var r AffinePointX4
		var aMask, rMask uint8
		for i := 0; i < b.N; i++ {
			ops := decode2IFMAOpsX4{hardware: true}
			var err error
			aMask, rMask, err = decode2NoTIFMAX4(&a, &r, &a4Bytes, &r4Bytes, 0x0f, &ops, true)
			if err != nil {
				b.Fatal(err)
			}
		}
		benchmarkIFMADecode2A4, benchmarkIFMADecode2R4 = a, r
		benchmarkIFMADecode2Masks4 = [2]uint8{aMask, rMask}
	})

	b.Run("two-x4/paired-interleaved/active=8", func(b *testing.B) {
		b.ReportAllocs()
		var a [2]PointX4
		var r [2]AffinePointX4
		var masks [2]uint8
		for i := 0; i < b.N; i++ {
			for half := 0; half < 2; half++ {
				var aBytes, rBytes [X4Lanes][32]byte
				copy(aBytes[:], a8Bytes[half*X4Lanes:(half+1)*X4Lanes])
				copy(rBytes[:], r8Bytes[half*X4Lanes:(half+1)*X4Lanes])
				ops := decode2IFMAOpsX4{hardware: true, uncheckedInputs: true}
				aMask, rMask, err := decode2NoTIFMAX4(&a[half], &r[half], &aBytes, &rBytes, 0x0f, &ops, true)
				if err != nil {
					b.Fatal(err)
				}
				masks[0] = aMask
				masks[1] = rMask
			}
		}
		benchmarkIFMADecode2A4, benchmarkIFMADecode2R4 = a[1], r[1]
		benchmarkIFMADecode2Masks4 = masks
	})
}
