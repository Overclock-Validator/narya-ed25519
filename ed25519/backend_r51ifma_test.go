package ed25519

import (
	"bytes"
	stded25519 "crypto/ed25519"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"testing"

	"github.com/Overclock-Validator/narya/internal/edwards25519"
	"github.com/Overclock-Validator/narya/internal/r51x5"
	"github.com/Overclock-Validator/narya/sha512mb"
)

// r51IFMABenchmarkBackend routes the forced pipeline through verifyBatch's
// production-shaped raw-slice dispatch. It makes the complete benchmark pay
// the same public length/dispatch boundary a future registered SIMD backend
// would use, without allocating batchItems only to unpack them again.
type r51IFMABenchmarkBackend struct {
	pipeline *r51IFMAPipeline
	err      error
}

func (*r51IFMABenchmarkBackend) name() string { return "forced-r51-benchmark" }

func (*r51IFMABenchmarkBackend) verify(Profile, *[32]byte, []byte, []byte, *PrecomputedKey) bool {
	panic("ed25519: forced r51 benchmark backend has no single-signature path")
}

func (*r51IFMABenchmarkBackend) verifyBatch(Profile, []batchItem) {
	panic("ed25519: forced r51 benchmark backend bypassed raw batch dispatch")
}

func (*r51IFMABenchmarkBackend) supportsPrecomp() bool { return false }

func (*r51IFMABenchmarkBackend) buildPrecomp(pub *[32]byte) (*PrecomputedKey, error) {
	return &PrecomputedKey{raw: *pub}, nil
}

func (b *r51IFMABenchmarkBackend) verifyBatchRaw(profile Profile, pubs []*[32]byte, msgs, sigs [][]byte, ok []bool) bool {
	var all bool
	all, b.err = b.pipeline.VerifyBatch(profile, pubs, msgs, sigs, ok)
	return all
}

func requireR51IFMAPipeline(t testing.TB, kind r51IFMAPipelineKind, radixBits uint) *r51IFMAPipeline {
	t.Helper()
	if !r51IFMAPipelineAvailable(kind) {
		t.Skipf("forced %s r51 IFMA pipeline unavailable on %s/%s", kind, runtime.GOOS, runtime.GOARCH)
	}
	pipeline, err := newR51IFMAPipeline(kind, radixBits)
	if err != nil {
		t.Fatalf("new forced %s radix %d pipeline: %v", kind, 1<<radixBits, err)
	}
	return pipeline
}

func requireR51IFMAEncodedQReferencePipeline(t testing.TB, kind r51IFMAPipelineKind, radixBits uint) *r51IFMAPipeline {
	t.Helper()
	if !r51IFMAPipelineAvailable(kind) {
		t.Skipf("forced %s r51 IFMA encoded-Q reference unavailable on %s/%s", kind, runtime.GOOS, runtime.GOARCH)
	}
	pipeline, err := newR51IFMAEncodedQReferencePipeline(kind, radixBits)
	if err != nil {
		t.Fatalf("new forced %s radix %d encoded-Q reference: %v", kind, 1<<radixBits, err)
	}
	return pipeline
}

func requireR51IFMACombPipeline(t testing.TB, kind r51IFMAPipelineKind, variableRadixBits, fixedRadixBits uint) *r51IFMAPipeline {
	t.Helper()
	if !r51IFMAPipelineAvailable(kind) {
		t.Skipf("forced %s r51 IFMA comb pipeline unavailable on %s/%s", kind, runtime.GOOS, runtime.GOARCH)
	}
	pipeline, err := newR51IFMACombPipeline(kind, variableRadixBits, fixedRadixBits)
	if err != nil {
		t.Fatalf("new forced %s A-radix %d B-comb %d pipeline: %v", kind, 1<<variableRadixBits, 1<<fixedRadixBits, err)
	}
	return pipeline
}

func assertR51IFMAPipelineVectors(t *testing.T, pipeline *r51IFMAPipeline, vectors []r51ReferenceVector, profile Profile) {
	t.Helper()
	pubs := make([]*[32]byte, len(vectors))
	msgs := make([][]byte, len(vectors))
	sigs := make([][]byte, len(vectors))
	got := make([]bool, len(vectors))
	wantAll := true
	want := make([]bool, len(vectors))
	for index := range vectors {
		pubs[index] = &vectors[index].pub
		msgs[index] = vectors[index].msg
		sigs[index] = vectors[index].sig
		want[index] = referenceVerifyProfile(profile, pubs[index], msgs[index], sigs[index])
		wantAll = wantAll && want[index]
	}
	gotAll, err := pipeline.VerifyBatch(profile, pubs, msgs, sigs, got)
	if err != nil {
		t.Fatalf("%s A-radix %d B=%s: %v", pipeline.kind, 1<<pipeline.radixBits, pipeline.fixedBaseLabel(), err)
	}
	if gotAll != wantAll {
		t.Fatalf("%s A-radix %d B=%s aggregate=%v want=%v", pipeline.kind, 1<<pipeline.radixBits, pipeline.fixedBaseLabel(), gotAll, wantAll)
	}
	for index := range vectors {
		if got[index] != want[index] {
			t.Fatalf("%s profile=%d %s A-radix=%d B=%s got=%v want=%v\npub=%x\nmsg=%x\nsig=%x", vectors[index].name, profile, pipeline.kind, 1<<pipeline.radixBits, pipeline.fixedBaseLabel(), got[index], want[index], vectors[index].pub, vectors[index].msg, vectors[index].sig)
		}
	}
}

func everyR51IFMAPipelineConfig(t *testing.T, run func(t *testing.T, pipeline *r51IFMAPipeline)) {
	t.Helper()
	for _, kind := range []r51IFMAPipelineKind{r51IFMAX4, r51IFMATwoX4, r51IFMAX8} {
		for _, radixBits := range []uint{4, 5, 6} {
			kind, radixBits := kind, radixBits
			t.Run(fmt.Sprintf("path=%s/radix=%d", kind, 1<<radixBits), func(t *testing.T) {
				run(t, requireR51IFMAPipeline(t, kind, radixBits))
			})
		}
	}
}

func everyR51IFMACombPipelineConfig(t *testing.T, run func(t *testing.T, pipeline *r51IFMAPipeline)) {
	t.Helper()
	for _, kind := range []r51IFMAPipelineKind{r51IFMAX4, r51IFMATwoX4, r51IFMAX8} {
		for _, fixedRadixBits := range []uint{4, 5, 8} {
			kind, fixedRadixBits := kind, fixedRadixBits
			t.Run(fmt.Sprintf("path=%s/radixA=32/fixedB=comb%d", kind, 1<<fixedRadixBits), func(t *testing.T) {
				run(t, requireR51IFMACombPipeline(t, kind, 5, fixedRadixBits))
			})
		}
	}
}

func TestR51IFMAPipelineForcedOnlyAndHardwareGated(t *testing.T) {
	productionBackend := pick("").name()
	productionHashLanes := sha512mb.Lanes()
	// The reviewed adapter is explicitly selectable, while empty/automatic
	// dispatch remains generic until the release gate changes separately.
	if len(registry) != 4 {
		t.Fatalf("backend registry has %d entries, want generic/ifma/r51/stdlib", len(registry))
	}
	for _, name := range []string{"generic", "ifma", "r51", "stdlib"} {
		if _, registered := registry[name]; !registered {
			t.Fatalf("expected production backend %q is not registered", name)
		}
	}
	if _, ok := registry["r51"].(*r51Backend); !ok {
		t.Fatalf("registered r51 backend has type %T", registry["r51"])
	}
	for _, name := range []string{"r51-ifma", "forced-r51-benchmark"} {
		if _, registered := registry[name]; registered {
			t.Fatalf("dormant r51 artifact unexpectedly registered as %q", name)
		}
	}
	for name, candidate := range registry {
		if _, registered := candidate.(*r51IFMABenchmarkBackend); registered {
			t.Fatalf("test-only r51 adapter unexpectedly registered as %q", name)
		}
	}
	for _, kind := range []r51IFMAPipelineKind{r51IFMAX4, r51IFMATwoX4, r51IFMAX8} {
		pipeline, err := newR51IFMAPipeline(kind, 4)
		if r51IFMAPipelineAvailable(kind) {
			if err != nil || pipeline == nil {
				t.Fatalf("available %s pipeline=(%p,%v)", kind, pipeline, err)
			}
		} else if err == nil || pipeline != nil {
			t.Fatalf("unavailable %s pipeline=(%p,%v), want nil,error", kind, pipeline, err)
		}
		encodedReference, encodedReferenceErr := newR51IFMAEncodedQReferencePipeline(kind, 5)
		if r51IFMAPipelineAvailable(kind) {
			if encodedReferenceErr != nil || encodedReference == nil || !encodedReference.encodedQReference {
				t.Fatalf("available %s encoded-Q reference=(%p,%v), mode=%v", kind, encodedReference, encodedReferenceErr, encodedReference != nil && encodedReference.encodedQReference)
			}
			if pipeline.encodedQReference {
				t.Fatalf("ordinary %s constructor enabled encoded-Q reference mode", kind)
			}
		} else if encodedReferenceErr == nil || encodedReference != nil {
			t.Fatalf("unavailable %s encoded-Q reference=(%p,%v), want nil,error", kind, encodedReference, encodedReferenceErr)
		}
		combPipeline, combErr := newR51IFMACombPipeline(kind, 5, 8)
		if r51IFMAPipelineAvailable(kind) {
			if combErr != nil || combPipeline == nil || combPipeline.fixedBaseComb == nil {
				t.Fatalf("available %s comb pipeline=(%p,%v)", kind, combPipeline, combErr)
			}
			second, err := newR51IFMACombPipeline(kind, 5, 8)
			if err != nil || second.fixedBaseComb != combPipeline.fixedBaseComb {
				t.Fatalf("%s pipelines do not share immutable B comb: first=%p second=%p err=%v", kind, combPipeline.fixedBaseComb, second.fixedBaseComb, err)
			}
		} else if combErr == nil || combPipeline != nil {
			t.Fatalf("unavailable %s comb pipeline=(%p,%v), want nil,error", kind, combPipeline, combErr)
		}
	}
	if got := pick("").name(); got != productionBackend || got != "generic" {
		t.Fatalf("forced experiment changed auto backend from %q to %q", productionBackend, got)
	}
	if got := sha512mb.Lanes(); got != productionHashLanes {
		t.Fatalf("forced experiment changed production SHA lanes from %d to %d", productionHashLanes, got)
	}
}

func TestR51ChallengeSegmentsPreserveOriginalNoncanonicalA(t *testing.T) {
	var noncanonicalA [32]byte
	found := false
	for alias := byte(2); alias <= 18 && !found; alias++ {
		candidate := [32]byte{0: 0xed + alias, 31: 0x7f}
		for index := 1; index < 31; index++ {
			candidate[index] = 0xff
		}
		for sign := byte(0); sign <= 1; sign++ {
			candidate[31] = 0x7f | sign<<7
			point, err := new(r51x5.Point).SetBytes(candidate[:])
			if err == nil && !smallOrderEncoding(candidate[:]) {
				encoded := point.Bytes()
				if bytes.Equal(encoded[:], candidate[:]) {
					continue
				}
				noncanonicalA = candidate
				found = true
				break
			}
		}
	}
	if !found {
		t.Fatal("failed to find a decodable noncanonical non-small-order A alias")
	}
	decoded, err := new(r51x5.Point).SetBytes(noncanonicalA[:])
	if err != nil {
		t.Fatal(err)
	}
	canonicalA := decoded.Bytes()
	var otherA [32]byte
	otherA[0] = 9
	pubs := []*[32]byte{&noncanonicalA, &otherA, &otherA}
	sigs := make([][]byte, len(pubs))
	msgs := [][]byte{[]byte("original-alias"), []byte("inactive"), []byte("second-live")}
	for index := range sigs {
		sigs[index] = make([]byte, 64)
		sigs[index][0] = byte(0x40 + index)
	}
	var segments [r51x5.X8Lanes][3][]byte
	var lanes [r51x5.X8Lanes]uint8
	if got := compactR51ChallengeSegments(&segments, &lanes, pubs, msgs, sigs, 0, len(pubs), 0x05); got != 2 {
		t.Fatalf("compacted inputs = %d, want 2", got)
	}
	if lanes[0] != 0 || lanes[1] != 2 || !bytes.Equal(segments[0][1], noncanonicalA[:]) {
		t.Fatalf("compaction lanes=%v A=%x", lanes[:2], segments[0][1])
	}
	hashSegments := func(parts [][]byte) [64]byte {
		h := sha512.New()
		for _, part := range parts {
			_, _ = h.Write(part)
		}
		var digest [64]byte
		h.Sum(digest[:0])
		return digest
	}
	originalDigest := hashSegments(segments[0][:])
	canonicalDigest := hashSegments([][]byte{sigs[0][:32], canonicalA[:], msgs[0]})
	if originalDigest == canonicalDigest {
		t.Fatal("canonicalizing A did not change the independently hashed challenge")
	}
	if allocs := testing.AllocsPerRun(20, func() {
		compactR51ChallengeSegments(&segments, &lanes, pubs, msgs, sigs, 0, len(pubs), 0x05)
	}); allocs != 0 {
		t.Fatalf("challenge compaction allocations=%v", allocs)
	}
}

func TestR51IFMACombPipelineReferenceCorporaTailsAndMixedOrder(t *testing.T) {
	vectors := append(r51CCTVVectors(t), r51WycheproofVectors(t)...)
	mixture := makeR51HonestVectors(t, 17)
	mixture[3].msg[0] ^= 0x80
	mixture[8].sig[63] |= 0xe0
	mixture[16] = makeR51MixedOrderValidVector(t)
	vectors = append(vectors, mixture...)
	everyR51IFMACombPipelineConfig(t, func(t *testing.T, pipeline *r51IFMAPipeline) {
		for _, profile := range []Profile{DalekStrict, StdlibCompat} {
			assertR51IFMAPipelineVectors(t, pipeline, vectors, profile)
			for count := 1; count <= len(mixture); count++ {
				assertR51IFMAPipelineVectors(t, pipeline, mixture[:count], profile)
			}
		}
	})
}

func TestR51IFMAPipelineCCTVAndWycheproof(t *testing.T) {
	everyR51IFMAPipelineConfig(t, func(t *testing.T, pipeline *r51IFMAPipeline) {
		for _, corpus := range []struct {
			name    string
			vectors []r51ReferenceVector
		}{
			{"cctv", r51CCTVVectors(t)},
			{"wycheproof", r51WycheproofVectors(t)},
		} {
			for _, profile := range []Profile{DalekStrict, StdlibCompat} {
				t.Run(fmt.Sprintf("%s/profile=%d", corpus.name, profile), func(t *testing.T) {
					assertR51IFMAPipelineVectors(t, pipeline, corpus.vectors, profile)
				})
			}
		}
	})
}

func TestR51IFMAPipelineFiredancerFuzzRegressions(t *testing.T) {
	vectors := repeatFiredancerFuzzRegressionVectors(t, 17)
	everyR51IFMAPipelineConfig(t, func(t *testing.T, pipeline *r51IFMAPipeline) {
		for _, profile := range []Profile{DalekStrict, StdlibCompat} {
			assertR51IFMAPipelineVectors(t, pipeline, vectors, profile)
		}
	})
	everyR51IFMACombPipelineConfig(t, func(t *testing.T, pipeline *r51IFMAPipeline) {
		for _, profile := range []Profile{DalekStrict, StdlibCompat} {
			assertR51IFMAPipelineVectors(t, pipeline, vectors, profile)
		}
	})
}

func TestR51IFMAPipelineTailsInvalidLanesAndRandomMixtures(t *testing.T) {
	vectors := makeR51HonestVectors(t, 67)
	for index := range vectors {
		switch index % 5 {
		case 1:
			vectors[index].sig[7] ^= 0x20
		case 2:
			vectors[index].msg[0] ^= 0x80
		case 3:
			vectors[index].pub[11] ^= 0x08
		case 4:
			vectors[index].sig[63] |= 0xe0
		}
	}
	honest := makeR51HonestVectors(t, 17)
	everyR51IFMAPipelineConfig(t, func(t *testing.T, pipeline *r51IFMAPipeline) {
		for _, profile := range []Profile{DalekStrict, StdlibCompat} {
			assertR51IFMAPipelineVectors(t, pipeline, vectors, profile)
			for count := 1; count <= len(honest); count++ {
				assertR51IFMAPipelineVectors(t, pipeline, honest[:count], profile)
				for invalidLane := 0; invalidLane < count; invalidLane++ {
					invalid := cloneR51Vectors(honest[:count])
					invalid[invalidLane].msg[0] ^= 0x80
					assertR51IFMAPipelineVectors(t, pipeline, invalid, profile)
				}
			}
		}
	})
}

func TestR51IFMAPipelinePermissiveAAndExactSignedMixedOrder(t *testing.T) {
	// Find a decodable y=p+n alias. Strict preparation must not add a
	// canonical-A requirement, even though this arbitrary signature is invalid.
	var noncanonicalA [32]byte
	found := false
	for alias := byte(2); alias <= 18 && !found; alias++ {
		candidate := [32]byte{0: 0xed + alias, 31: 0x7f}
		for index := 1; index < 31; index++ {
			candidate[index] = 0xff
		}
		for sign := byte(0); sign <= 1; sign++ {
			candidate[31] = 0x7f | sign<<7
			if _, err := new(r51x5.Point).SetBytes(candidate[:]); err == nil && !smallOrderEncoding(candidate[:]) {
				noncanonicalA = candidate
				found = true
				break
			}
		}
	}
	if !found {
		t.Fatal("failed to find decodable noncanonical non-small-order A")
	}
	honest := makeR51HonestVectors(t, 1)[0]
	honest.name = "noncanonical-decodable-A"
	honest.pub = noncanonicalA
	if _, valid := prepareR51Signature(DalekStrict, &honest.pub, honest.sig); !valid {
		t.Fatal("strict preparation rejected a permissible noncanonical A")
	}

	mixed := makeR51MixedOrderValidVector(t)
	if !referenceVerifyProfile(DalekStrict, &mixed.pub, mixed.msg, mixed.sig) {
		t.Fatal("mixed-order exact-signed fixture is not strict-valid")
	}
	everyR51IFMAPipelineConfig(t, func(t *testing.T, pipeline *r51IFMAPipeline) {
		assertR51IFMAPipelineVectors(t, pipeline, []r51ReferenceVector{honest, mixed}, DalekStrict)
	})
}

func TestCanonicalScalarEncodingMatchesReference(t *testing.T) {
	order := ed25519ScalarOrderEncoding
	orderMinusOne := order
	for index := range orderMinusOne {
		if orderMinusOne[index] != 0 {
			orderMinusOne[index]--
			break
		}
		orderMinusOne[index] = 0xff
	}
	orderPlusOne := order
	for index := range orderPlusOne {
		orderPlusOne[index]++
		if orderPlusOne[index] != 0 {
			break
		}
	}

	cases := [][]byte{
		nil,
		make([]byte, 31),
		make([]byte, 33),
		make([]byte, 32),
		orderMinusOne[:],
		order[:],
		orderPlusOne[:],
		append(make([]byte, 31), 0x80),
	}
	for index, encoded := range cases {
		got := canonicalScalarEncoding(encoded)
		_, err := edwards25519.NewScalar().SetCanonicalBytes(encoded)
		if want := err == nil; got != want {
			t.Fatalf("boundary %d canonical=%v, reference=%v: %x", index, got, want, encoded)
		}
	}

	for counter := 0; counter < 4096; counter++ {
		seed := []byte{byte(counter), byte(counter >> 8)}
		digest := sha512.Sum512(seed)
		encoded := digest[:32]
		got := canonicalScalarEncoding(encoded)
		_, err := edwards25519.NewScalar().SetCanonicalBytes(encoded)
		if want := err == nil; got != want {
			t.Fatalf("random %d canonical=%v, reference=%v: %x", counter, got, want, encoded)
		}
	}

	invalid := ed25519ScalarOrderEncoding[:]
	if allocs := testing.AllocsPerRun(100, func() {
		if canonicalScalarEncoding(invalid) {
			panic("group order accepted as canonical")
		}
	}); allocs != 0 {
		t.Fatalf("invalid scalar predicate allocations=%v", allocs)
	}
}

func TestR51IFMAPipelineX8MatchesTwoX4(t *testing.T) {
	if !r51IFMAPipelineAvailable(r51IFMAX8) || !r51IFMAPipelineAvailable(r51IFMATwoX4) {
		t.Skipf("both forced r51 IFMA pipeline widths are required on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	vectors := makeR51HonestVectors(t, 17)
	vectors[3].msg[0] ^= 0x80
	vectors[8].sig[63] |= 0xe0
	vectors[16] = makeR51MixedOrderValidVector(t)
	for _, radixBits := range []uint{4, 5, 6} {
		x8, err := newR51IFMAPipeline(r51IFMAX8, radixBits)
		if err != nil {
			t.Fatal(err)
		}
		twoX4, err := newR51IFMAPipeline(r51IFMATwoX4, radixBits)
		if err != nil {
			t.Fatal(err)
		}
		for _, profile := range []Profile{DalekStrict, StdlibCompat} {
			pubs := make([]*[32]byte, len(vectors))
			msgs := make([][]byte, len(vectors))
			sigs := make([][]byte, len(vectors))
			for index := range vectors {
				pubs[index], msgs[index], sigs[index] = &vectors[index].pub, vectors[index].msg, vectors[index].sig
			}
			gotX8 := make([]bool, len(vectors))
			gotTwoX4 := make([]bool, len(vectors))
			allX8, errX8 := x8.VerifyBatch(profile, pubs, msgs, sigs, gotX8)
			allTwoX4, errTwoX4 := twoX4.VerifyBatch(profile, pubs, msgs, sigs, gotTwoX4)
			if errX8 != nil || errTwoX4 != nil || allX8 != allTwoX4 {
				t.Fatalf("radix %d profile %d x8=(%v,%v) two-x4=(%v,%v)", 1<<radixBits, profile, allX8, errX8, allTwoX4, errTwoX4)
			}
			for index := range vectors {
				if gotX8[index] != gotTwoX4[index] {
					t.Fatalf("radix %d profile %d lane %d x8=%v two-x4=%v", 1<<radixBits, profile, index, gotX8[index], gotTwoX4[index])
				}
			}
		}
	}
}

func TestR51IFMAPairedGateSemanticDifferential(t *testing.T) {
	if !r51IFMAPipelineAvailable(r51IFMAX8) || !r51IFMAPipelineAvailable(r51IFMATwoX4) {
		t.Skipf("paired-decode admission comparison requires x8 and two-x4 IFMA on %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	mixture := makeR51HonestVectors(t, 64)
	for index := range mixture {
		switch index % 7 {
		case 1:
			mixture[index].msg[0] ^= 0x80
		case 2:
			mixture[index].sig[7] ^= 0x20
		case 3:
			mixture[index].sig[63] |= 0xe0
		case 4:
			mixture[index].pub[11] ^= 0x08
		}
	}
	mixture[63] = makeR51MixedOrderValidVector(t)

	corpora := []struct {
		name    string
		vectors []r51ReferenceVector
	}{
		{name: "cctv", vectors: r51CCTVVectors(t)},
		{name: "wycheproof", vectors: r51WycheproofVectors(t)},
		{name: "mixture/n=1", vectors: mixture[:1]},
		{name: "mixture/n=8", vectors: mixture[:8]},
		{name: "mixture/n=17", vectors: mixture[:17]},
		{name: "mixture/n=64", vectors: mixture},
	}

	for _, kind := range []r51IFMAPipelineKind{r51IFMATwoX4, r51IFMAX8} {
		paired := requireR51IFMAPipeline(t, kind, 5)
		encodedReference := requireR51IFMAEncodedQReferencePipeline(t, kind, 5)
		for _, profile := range []Profile{DalekStrict, StdlibCompat} {
			for _, corpus := range corpora {
				corpus := corpus
				t.Run(fmt.Sprintf("path=%s/profile=%d/%s", kind, profile, corpus.name), func(t *testing.T) {
					assertR51IFMAPairedGateVectors(t, paired, encodedReference, corpus.vectors, profile)
				})
			}
		}
	}
}

func assertR51IFMAPairedGateVectors(t *testing.T, paired, encodedReference *r51IFMAPipeline, vectors []r51ReferenceVector, profile Profile) {
	t.Helper()
	pubs := make([]*[32]byte, len(vectors))
	msgs := make([][]byte, len(vectors))
	sigs := make([][]byte, len(vectors))
	want := make([]bool, len(vectors))
	wantAll := true
	for index := range vectors {
		pubs[index], msgs[index], sigs[index] = &vectors[index].pub, vectors[index].msg, vectors[index].sig
		want[index] = referenceVerifyProfile(profile, pubs[index], msgs[index], sigs[index])
		wantAll = wantAll && want[index]
	}
	pairedOK := make([]bool, len(vectors))
	referenceOK := make([]bool, len(vectors))
	pairedAll, pairedErr := paired.VerifyBatch(profile, pubs, msgs, sigs, pairedOK)
	referenceAll, referenceErr := encodedReference.VerifyBatch(profile, pubs, msgs, sigs, referenceOK)
	if pairedErr != nil || referenceErr != nil {
		t.Fatalf("paired=%v encoded-Q=%v", pairedErr, referenceErr)
	}
	if pairedAll != wantAll || referenceAll != wantAll || pairedAll != referenceAll {
		t.Fatalf("aggregate paired=%v encoded-Q=%v want=%v", pairedAll, referenceAll, wantAll)
	}
	for index := range vectors {
		if pairedOK[index] != want[index] || referenceOK[index] != want[index] || pairedOK[index] != referenceOK[index] {
			t.Fatalf("%s lane=%d paired=%v encoded-Q=%v want=%v\npub=%x\nmsg=%x\nsig=%x", vectors[index].name, index, pairedOK[index], referenceOK[index], want[index], vectors[index].pub, vectors[index].msg, vectors[index].sig)
		}
	}
}

func TestR51IFMAPipelineKernelErrorClearsPriorGroupVerdicts(t *testing.T) {
	pipeline := requireR51IFMAPipeline(t, r51IFMAX8, 5)
	failure := errors.New("injected second-group variable-table failure")
	prepareCalls := 0
	pipeline.beforePrepareVariableX8 = func() error {
		prepareCalls++
		if prepareCalls == 2 {
			return failure
		}
		return nil
	}

	fixture := makeBatchFixture(t, r51x5.X8Lanes+1, 200)
	verdicts := make([]bool, len(fixture.pubs))
	all, err := pipeline.VerifyBatch(
		DalekStrict,
		fixture.pubs,
		fixture.msgs,
		fixture.sigs,
		verdicts,
	)
	if all || !errors.Is(err, failure) {
		t.Fatalf("verification=(%v,%v), want (false,injected failure)", all, err)
	}
	if prepareCalls != 2 {
		t.Fatalf("variable-table preparations=%d, want 2", prepareCalls)
	}
	for lane, accepted := range verdicts {
		if accepted {
			t.Fatalf("lane %d retained a partial-success verdict after kernel failure", lane)
		}
	}
}

func TestR51IFMAPipelineExactSignedMixedOrderEveryLane(t *testing.T) {
	mixed := makeR51MixedOrderValidVector(t)
	for lane := 0; lane < r51x5.X8Lanes; lane++ {
		vectors := makeR51HonestVectors(t, r51x5.X8Lanes)
		vectors[lane] = mixed
		for _, kind := range []r51IFMAPipelineKind{r51IFMAX4, r51IFMATwoX4, r51IFMAX8} {
			for _, radixBits := range []uint{5, 6} {
				t.Run(fmt.Sprintf("shared/path=%s/radix=%d/lane=%d", kind, 1<<radixBits, lane), func(t *testing.T) {
					assertR51IFMAPipelineVectors(t, requireR51IFMAPipeline(t, kind, radixBits), vectors, DalekStrict)
				})
			}
			t.Run(fmt.Sprintf("comb/path=%s/lane=%d", kind, lane), func(t *testing.T) {
				assertR51IFMAPipelineVectors(t, requireR51IFMACombPipeline(t, kind, 5, 5), vectors, DalekStrict)
			})
		}
	}
}

// makeR51MixedOrderValidVector constructs A=[a]B+T2 and R=[r]B+T2, then
// grinds an odd challenge and sets s=r+k*a. Exact integer -k therefore keeps
// the order-two component and accepts. Replacing -k with the scalar encoding
// L-k erases that component and rejects, making this a consensus discriminator.
func makeR51MixedOrderValidVector(t *testing.T) r51ReferenceVector {
	t.Helper()
	a, rScalar := scalarFromUint64(t, 5), scalarFromUint64(t, 7)
	orderTwoEncoding, err := hex.DecodeString("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
	if err != nil {
		t.Fatal(err)
	}
	torsion, err := (&edwards25519.Point{}).SetBytes(orderTwoEncoding)
	if err != nil {
		t.Fatal(err)
	}
	A := (&edwards25519.Point{}).Add((&edwards25519.Point{}).ScalarBaseMult(a), torsion)
	R := (&edwards25519.Point{}).Add((&edwards25519.Point{}).ScalarBaseMult(rScalar), torsion)
	var pub [stded25519.PublicKeySize]byte
	copy(pub[:], A.Bytes())
	var message [8]byte
	var k *edwards25519.Scalar
	for counter := uint64(0); ; counter++ {
		for byteIndex := range message {
			message[byteIndex] = byte(counter >> (8 * byteIndex))
		}
		k = strictChallenge(t, R.Bytes(), pub[:], message[:])
		if k.Bytes()[0]&1 == 1 {
			break
		}
		if counter == 1024 {
			t.Fatal("failed to grind odd mixed-order challenge")
		}
	}
	s := (&edwards25519.Scalar{}).Multiply(k, a)
	s.Add(s, rScalar)
	sigArray := assembleStrictTestSignature(R, s)
	sig := append([]byte(nil), sigArray[:]...)
	return r51ReferenceVector{name: "mixed-order-exact-minus-k", pub: pub, msg: append([]byte(nil), message[:]...), sig: sig}
}

func TestR51IFMAPipelineZeroAllocations(t *testing.T) {
	for _, kind := range []r51IFMAPipelineKind{r51IFMAX4, r51IFMATwoX4, r51IFMAX8} {
		for _, radixBits := range []uint{4, 5, 6} {
			pipeline := requireR51IFMAPipeline(t, kind, radixBits)
			for _, count := range []int{1, 4, 8, 9, 17} {
				fixture := makeBatchFixture(t, count, 200)
				for _, profile := range []Profile{DalekStrict, StdlibCompat} {
					if allocs := testing.AllocsPerRun(10, func() {
						all, err := pipeline.VerifyBatch(profile, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok)
						if err != nil || !all {
							panic(fmt.Sprintf("verify=(%v,%v)", all, err))
						}
					}); allocs != 0 {
						t.Fatalf("%s radix=%d count=%d profile=%d allocations=%v", kind, 1<<radixBits, count, profile, allocs)
					}
				}
			}
			invalid := makeBatchFixture(t, 17, 200)
			for _, lane := range []int{1, 8, 16} {
				invalid.sigs[lane] = append([]byte(nil), invalid.sigs[lane]...)
				invalid.sigs[lane][63] |= 0xe0
			}
			if allocs := testing.AllocsPerRun(10, func() {
				if _, err := pipeline.VerifyBatch(DalekStrict, invalid.pubs, invalid.msgs, invalid.sigs, invalid.ok); err != nil {
					panic(err)
				}
			}); allocs != 0 {
				t.Fatalf("%s radix=%d sparse-invalid allocations=%v", kind, 1<<radixBits, allocs)
			}
		}
	}
}

func TestR51IFMAPairedGateZeroAllocations(t *testing.T) {
	for _, kind := range []r51IFMAPipelineKind{r51IFMATwoX4, r51IFMAX8} {
		for _, encodedReference := range []bool{false, true} {
			var pipeline *r51IFMAPipeline
			if encodedReference {
				pipeline = requireR51IFMAEncodedQReferencePipeline(t, kind, 5)
			} else {
				pipeline = requireR51IFMAPipeline(t, kind, 5)
			}
			for _, count := range []int{1, 8, 64} {
				fixture := makeBatchFixture(t, count, 200)
				if allocs := testing.AllocsPerRun(10, func() {
					all, err := pipeline.VerifyBatch(DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok)
					if err != nil || !all {
						panic(fmt.Sprintf("verify=(%v,%v)", all, err))
					}
				}); allocs != 0 {
					t.Fatalf("%s encoded-reference=%v count=%d allocations=%v", kind, encodedReference, count, allocs)
				}
			}
		}
	}
}

func TestR51IFMACombPipelineZeroAllocations(t *testing.T) {
	fixture := makeBatchFixture(t, 17, 200)
	for _, kind := range []r51IFMAPipelineKind{r51IFMAX4, r51IFMATwoX4, r51IFMAX8} {
		for _, fixedRadixBits := range []uint{4, 5, 8} {
			pipeline := requireR51IFMACombPipeline(t, kind, 5, fixedRadixBits)
			for _, profile := range []Profile{DalekStrict, StdlibCompat} {
				if allocs := testing.AllocsPerRun(10, func() {
					all, err := pipeline.VerifyBatch(profile, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok)
					if err != nil || !all {
						panic(fmt.Sprintf("verify=(%v,%v)", all, err))
					}
				}); allocs != 0 {
					t.Fatalf("%s A-radix 32 B-comb %d profile=%d allocations=%v", kind, 1<<fixedRadixBits, profile, allocs)
				}
			}
			invalid := makeBatchFixture(t, 17, 200)
			for _, lane := range []int{1, 8, 16} {
				invalid.sigs[lane] = append([]byte(nil), invalid.sigs[lane]...)
				invalid.sigs[lane][63] |= 0xe0
			}
			if allocs := testing.AllocsPerRun(10, func() {
				if _, err := pipeline.VerifyBatch(DalekStrict, invalid.pubs, invalid.msgs, invalid.sigs, invalid.ok); err != nil {
					panic(err)
				}
			}); allocs != 0 {
				t.Fatalf("%s A-radix 32 B-comb %d sparse-invalid allocations=%v", kind, 1<<fixedRadixBits, allocs)
			}
		}
	}
}

// FuzzR51IFMAPipelineDifferential invokes the final forced r51 pipelines
// directly. The registered "ifma" backend is the independent r43 reference,
// so the package-level differential target cannot cover these kernels until
// production dispatch is intentionally changed.
func FuzzR51IFMAPipelineDifferential(f *testing.F) {
	if !r51IFMAPipelineAvailable(r51IFMAX8) || !r51IFMAPipelineAvailable(r51IFMATwoX4) {
		f.Skipf("forced r51 IFMA pipelines unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	seed := [stded25519.SeedSize]byte{1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31}
	privateKey := stded25519.NewKeyFromSeed(seed[:])
	publicKey := privateKey.Public().(stded25519.PublicKey)
	message := []byte("forced r51 differential fuzz seed")
	signature := stded25519.Sign(privateKey, message)
	f.Add([]byte(publicKey), message, signature, []byte{0, 0, 0})
	badSignature := append([]byte(nil), signature...)
	badSignature[0] ^= 1
	f.Add([]byte(publicKey), message, badSignature, []byte{18, 63, 0xff, 0x55})

	// Keep every non-fuzzed lane distinct and self-consistent. Each callback
	// inserts its arbitrary tuple at a control-selected position, while the
	// remaining lanes mix valid signatures, full-equation failures, and cheap
	// scalar-precheck failures. This exercises tails, multiple x4/x8 groups,
	// verdict remapping, and cross-lane contamination rather than repeatedly
	// fuzzing only lane zero of a one-item batch.
	const maxFuzzBatch = 64
	var honestPubs [maxFuzzBatch][32]byte
	var honestMsgs [maxFuzzBatch][]byte
	var honestSigs [maxFuzzBatch][]byte
	for lane := 0; lane < maxFuzzBatch; lane++ {
		laneSeed := seed
		laneSeed[0] ^= byte(lane + 1)
		laneSeed[31] ^= byte(3*lane + 1)
		laneKey := stded25519.NewKeyFromSeed(laneSeed[:])
		copy(honestPubs[lane][:], laneKey.Public().(stded25519.PublicKey))
		honestMsgs[lane] = []byte(fmt.Sprintf("forced r51 honest fuzz lane %d", lane))
		honestSigs[lane] = stded25519.Sign(laneKey, honestMsgs[lane])
	}
	fuzzCounts := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 32, 64}

	pipelines := []*r51IFMAPipeline{
		requireR51IFMAPipeline(f, r51IFMATwoX4, 4),
		requireR51IFMAPipeline(f, r51IFMAX8, 4),
		requireR51IFMAPipeline(f, r51IFMATwoX4, 5),
		requireR51IFMAPipeline(f, r51IFMAX8, 5),
		requireR51IFMAPipeline(f, r51IFMATwoX4, 6),
		requireR51IFMAPipeline(f, r51IFMAX8, 6),
	}
	f.Fuzz(func(t *testing.T, publicKey, message, signature, control []byte) {
		if len(publicKey) > 64 || len(message) > 4096 || len(signature) > 128 || len(control) > 128 {
			return
		}
		countSelector := byte(0)
		if len(control) > 0 {
			countSelector = control[0]
		}
		count := fuzzCounts[int(countSelector)%len(fuzzCounts)]
		fuzzLane := 0
		if len(control) > 1 {
			fuzzLane = int(control[1]) % count
		}

		pubStorage := make([][32]byte, count)
		pubs := make([]*[32]byte, count)
		msgs := make([][]byte, count)
		sigs := make([][]byte, count)
		want := make([]bool, count)
		for lane := 0; lane < count; lane++ {
			pubStorage[lane] = honestPubs[lane]
			pubs[lane] = &pubStorage[lane]
			msgs[lane] = honestMsgs[lane]
			sigs[lane] = honestSigs[lane]
			mode := byte(lane)
			if len(control) > 2 {
				mode ^= control[2+(lane%(len(control)-2))]
			}
			switch mode % 4 {
			case 1:
				sigs[lane] = append([]byte(nil), sigs[lane]...)
				sigs[lane][0] ^= 1
			case 2:
				sigs[lane] = append([]byte(nil), sigs[lane]...)
				sigs[lane][63] |= 0xe0
			}
		}
		copy(pubStorage[fuzzLane][:], publicKey)
		msgs[fuzzLane] = message
		sigs[fuzzLane] = signature

		wantAll := true
		for lane := range want {
			want[lane] = referenceVerifyProfile(DalekStrict, pubs[lane], msgs[lane], sigs[lane])
			wantAll = wantAll && want[lane]
		}
		ok := make([]bool, count)
		for _, pipeline := range pipelines {
			for lane := range ok {
				ok[lane] = !want[lane]
			}
			backend := &r51IFMABenchmarkBackend{pipeline: pipeline}
			all := verifyBatch(backend, DalekStrict, pubs, msgs, sigs, ok, nil)
			if backend.err != nil {
				t.Fatalf("%s radix=%d pipeline: %v", pipeline.kind, 1<<pipeline.radixBits, backend.err)
			}
			if all != wantAll {
				t.Fatalf("%s radix=%d aggregate=%v want=%v count=%d fuzzLane=%d", pipeline.kind, 1<<pipeline.radixBits, all, wantAll, count, fuzzLane)
			}
			for lane := range ok {
				if ok[lane] != want[lane] {
					t.Fatalf("%s radix=%d lane=%d got=%v want=%v count=%d fuzzLane=%d\npub=%x\nmsg=%x\nsig=%x", pipeline.kind, 1<<pipeline.radixBits, lane, ok[lane], want[lane], count, fuzzLane, pubs[lane][:], msgs[lane], sigs[lane])
				}
			}
		}
	})
}

var benchmarkR51IFMAPipelineResult bool

type r51IFMAThroughputConfiguration struct {
	kind           r51IFMAPipelineKind
	radixBits      uint
	fixedRadixBits uint
}

var r51IFMAThroughputShortlist = [...]r51IFMAThroughputConfiguration{
	{kind: r51IFMATwoX4, radixBits: 4},
	{kind: r51IFMATwoX4, radixBits: 5},
	{kind: r51IFMATwoX4, radixBits: 6},
	{kind: r51IFMATwoX4, radixBits: 5, fixedRadixBits: 4},
	{kind: r51IFMATwoX4, radixBits: 5, fixedRadixBits: 5},
	{kind: r51IFMATwoX4, radixBits: 5, fixedRadixBits: 8},
	{kind: r51IFMAX8, radixBits: 4},
	{kind: r51IFMAX8, radixBits: 5},
	{kind: r51IFMAX8, radixBits: 6},
	{kind: r51IFMAX8, radixBits: 5, fixedRadixBits: 4},
	{kind: r51IFMAX8, radixBits: 5, fixedRadixBits: 5},
	{kind: r51IFMAX8, radixBits: 5, fixedRadixBits: 8},
}

func (configuration r51IFMAThroughputConfiguration) fixedBaseLabel() string {
	if configuration.fixedRadixBits == 0 {
		return "shared"
	}
	return fmt.Sprintf("comb%d", 1<<configuration.fixedRadixBits)
}

func (configuration r51IFMAThroughputConfiguration) requirePipeline(t testing.TB) *r51IFMAPipeline {
	t.Helper()
	if configuration.fixedRadixBits == 0 {
		return requireR51IFMAPipeline(t, configuration.kind, configuration.radixBits)
	}
	return requireR51IFMACombPipeline(t, configuration.kind, configuration.radixBits, configuration.fixedRadixBits)
}

func TestR51IFMAParallelWorkerIsolation(t *testing.T) {
	if !r51IFMAPipelineAvailable(r51IFMATwoX4) || !r51IFMAPipelineAvailable(r51IFMAX8) {
		t.Skipf("forced r51 IFMA worker pipelines unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	const workerCount = 2
	fixture := makeBatchFixture(t, 64, 200)
	for _, configuration := range r51IFMAThroughputShortlist {
		configuration := configuration
		name := fmt.Sprintf("path=%s/radixA=%d/fixedB=%s", configuration.kind, 1<<configuration.radixBits, configuration.fixedBaseLabel())
		t.Run(name, func(t *testing.T) {
			pipelines := make([]*r51IFMAPipeline, workerCount)
			verdicts := make([][]bool, workerCount)
			results := make([]bool, workerCount)
			errs := make([]error, workerCount)
			for worker := range pipelines {
				pipelines[worker] = configuration.requirePipeline(t)
				verdicts[worker] = make([]bool, len(fixture.pubs))
			}

			start := make(chan struct{})
			var workers sync.WaitGroup
			workers.Add(workerCount)
			for worker := range pipelines {
				go func(worker int) {
					defer workers.Done()
					<-start
					for iteration := 0; iteration < 3; iteration++ {
						results[worker], errs[worker] = pipelines[worker].VerifyBatch(
							DalekStrict,
							fixture.pubs,
							fixture.msgs,
							fixture.sigs,
							verdicts[worker],
						)
						if errs[worker] != nil || !results[worker] {
							return
						}
					}
				}(worker)
			}
			close(start)
			workers.Wait()

			for worker := range pipelines {
				if errs[worker] != nil || !results[worker] {
					t.Fatalf("worker %d verify=(%v,%v)", worker, results[worker], errs[worker])
				}
				for lane, accepted := range verdicts[worker] {
					if !accepted {
						t.Fatalf("worker %d rejected valid lane %d", worker, lane)
					}
				}
			}
		})
	}
}

// BenchmarkR51IFMAPipelineParallel measures complete-verifier throughput at
// the caller's GOMAXPROCS setting. Each RunParallel goroutine acquires exactly
// one pipeline prepared before the timer starts: DSM/decode workspaces, the
// backend adapter, its error slot, and the verdict slice are never shared.
// The public keys, messages, signatures, and process-wide scalar B-comb table
// are read-only and intentionally shared so the benchmark exposes the table
// and cache pressure of a production-sized verifier worker pool.
//
// This remains a forced benchmark. It does not register the r51 candidate or
// alter production dispatch.
func BenchmarkR51IFMAPipelineParallel(b *testing.B) {
	type stdlibWorkerState struct {
		ok     []bool
		result bool
		used   bool
	}
	type workerState struct {
		backend r51IFMABenchmarkBackend
		ok      []bool
		result  bool
		used    bool
	}

	workerCount := runtime.GOMAXPROCS(0)
	for _, messageSize := range []int{64, 200, 1232} {
		// n=4 is the warm comb's minimum group and x8's half-empty worst case;
		// the intermediate widths locate the two-x4/x8 crossover.
		for _, count := range []int{4, 8, 16, 32, 64} {
			fixture := makeBatchFixture(b, count, messageSize)
			b.Run(fmt.Sprintf(
				"workers=%d/stage=cold-A/path=stdlib/n=%d/msg=%d",
				workerCount,
				count,
				messageSize,
			), func(b *testing.B) {
				workers := make([]stdlibWorkerState, workerCount)
				available := make(chan *stdlibWorkerState, workerCount)
				for index := range workers {
					workers[index].ok = make([]bool, count)
					available <- &workers[index]
				}

				b.ReportAllocs()
				b.SetParallelism(1)
				b.ResetTimer()
				b.RunParallel(func(pb *testing.PB) {
					worker := <-available
					for pb.Next() {
						worker.used = true
						worker.result = true
						for index := range fixture.pubs {
							worker.ok[index] = stded25519.Verify(
								fixture.pubs[index][:],
								fixture.msgs[index],
								fixture.sigs[index],
							)
							worker.result = worker.result && worker.ok[index]
						}
					}
					available <- worker
				})
				b.StopTimer()

				elapsed := b.Elapsed()
				result := true
				for range workers {
					worker := <-available
					if worker.used && !worker.result {
						b.Fatal("parallel stdlib verification rejected a valid fixture")
					}
					result = result && (!worker.used || worker.result)
				}
				benchmarkR51IFMAPipelineResult = result
				b.ReportMetric(float64(elapsed.Nanoseconds())/float64(b.N*count)/1000, "µs/sig")
				b.ReportMetric(float64(b.N*count)/elapsed.Seconds(), "sig/s")
			})
			for _, configuration := range r51IFMAThroughputShortlist {
				name := fmt.Sprintf(
					"workers=%d/stage=cold-A/path=%s/radixA=%d/fixedB=%s/n=%d/msg=%d",
					workerCount,
					configuration.kind,
					1<<configuration.radixBits,
					configuration.fixedBaseLabel(),
					count,
					messageSize,
				)
				b.Run(name, func(b *testing.B) {
					workers := make([]workerState, workerCount)
					available := make(chan *workerState, workerCount)
					for index := range workers {
						workers[index].backend.pipeline = configuration.requirePipeline(b)
						workers[index].ok = make([]bool, count)
						available <- &workers[index]
					}

					b.ReportAllocs()
					b.SetParallelism(1)
					b.ResetTimer()
					b.RunParallel(func(pb *testing.PB) {
						worker := <-available
						for pb.Next() {
							worker.used = true
							worker.result = verifyBatch(
								&worker.backend,
								DalekStrict,
								fixture.pubs,
								fixture.msgs,
								fixture.sigs,
								worker.ok,
								nil,
							)
							if worker.backend.err != nil {
								break
							}
						}
						available <- worker
					})
					b.StopTimer()

					elapsed := b.Elapsed()
					result := true
					for range workers {
						worker := <-available
						if worker.backend.err != nil {
							b.Fatal(worker.backend.err)
						}
						if worker.used && !worker.result {
							b.Fatal("forced parallel r51 verification rejected a valid fixture")
						}
						result = result && (!worker.used || worker.result)
					}
					benchmarkR51IFMAPipelineResult = result
					b.ReportMetric(float64(elapsed.Nanoseconds())/float64(b.N*count)/1000, "µs/sig")
					b.ReportMetric(float64(b.N*count)/elapsed.Seconds(), "sig/s")
				})
			}
		}
	}
}

// BenchmarkR51IFMAPairedGate is the complete admission comparator for paired
// decompression. Both rows use radix-32 cold-A DSM with the ordinary shared-B
// table and hash the same original R/A/message byte segments. Only the decode
// and final-equality boundary differs:
//
//   - decode=single-A/final=encoded-Q: one A decode and Q.Bytes()==Rbytes
//   - decode=paired-AR/final=projective: paired A/R decode and cross-products
//
// Keep this matrix small and release-shaped so the >=2% paired-decode gate is
// based on complete verification rather than a decompression microbenchmark.
func BenchmarkR51IFMAPairedGate(b *testing.B) {
	type candidate struct {
		decode string
		final  string
		new    func(testing.TB, r51IFMAPipelineKind, uint) *r51IFMAPipeline
	}
	candidates := [...]candidate{
		{decode: "single-A", final: "encoded-Q", new: requireR51IFMAEncodedQReferencePipeline},
		{decode: "paired-AR", final: "projective", new: requireR51IFMAPipeline},
	}
	for _, messageSize := range []int{64, 200, 1232} {
		for _, count := range []int{1, 8, 64} {
			fixture := makeBatchFixture(b, count, messageSize)
			for _, kind := range []r51IFMAPipelineKind{r51IFMATwoX4, r51IFMAX8} {
				for _, candidate := range candidates {
					name := fmt.Sprintf(
						"stage=cold-A/path=%s/decode=%s/final=%s/radixA=32/fixedB=shared/n=%d/msg=%d",
						kind,
						candidate.decode,
						candidate.final,
						count,
						messageSize,
					)
					b.Run(name, func(b *testing.B) {
						backend := r51IFMABenchmarkBackend{pipeline: candidate.new(b, kind, 5)}
						b.ReportAllocs()
						b.ResetTimer()
						var result bool
						for iteration := 0; iteration < b.N; iteration++ {
							result = verifyBatch(
								&backend,
								DalekStrict,
								fixture.pubs,
								fixture.msgs,
								fixture.sigs,
								fixture.ok,
								nil,
							)
							if backend.err != nil {
								break
							}
						}
						b.StopTimer()
						if backend.err != nil {
							b.Fatal(backend.err)
						}
						if !result {
							b.Fatal("forced paired-decode admission candidate rejected a valid fixture")
						}
						benchmarkR51IFMAPipelineResult = result
						elapsed := b.Elapsed()
						b.ReportMetric(float64(elapsed.Nanoseconds())/float64(b.N*count)/1000, "µs/sig")
						b.ReportMetric(float64(b.N*count)/elapsed.Seconds(), "sig/s")
					})
				}
			}
		}
	}
}

func BenchmarkR51IFMAPipeline(b *testing.B) {
	// This matrix includes every width through 17 plus the 32/64 throughput
	// points. Use -bench with path/radixA/fixedB/n/msg filters for target runs;
	// the unfiltered Cartesian product is intentionally comprehensive and is
	// not the recommended way to collect ten three-second samples.
	// stage=cold-A is the complete path: byte prechecks, paired decode, native
	// SHA, reduction, cold A-table construction, DSM, one reduction boundary,
	// and final equality. The companion internal/r51x5 benchmarks expose
	// Decode2 plus DSM's prepared-loop and cold-A-table+loop stages separately.
	counts := make([]int, 0, 19)
	for count := 1; count <= 17; count++ {
		counts = append(counts, count)
	}
	counts = append(counts, 32, 64)
	for _, messageSize := range []int{64, 176, 200, 512, 1024, 1232} {
		for _, count := range counts {
			fixture := makeBatchFixture(b, count, messageSize)
			b.Run(fmt.Sprintf("stage=cold-A/path=stdlib/n=%d/msg=%d", count, messageSize), func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()
				var result bool
				for iteration := 0; iteration < b.N; iteration++ {
					result = true
					for index := range fixture.pubs {
						fixture.ok[index] = stded25519.Verify(fixture.pubs[index][:], fixture.msgs[index], fixture.sigs[index])
						result = result && fixture.ok[index]
					}
				}
				benchmarkR51IFMAPipelineResult = result
				b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*count)/1000, "µs/sig")
			})
			b.Run(fmt.Sprintf("stage=cold-A/path=generic-strict/n=%d/msg=%d", count, messageSize), func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()
				var result bool
				for iteration := 0; iteration < b.N; iteration++ {
					result = verifyBatch(genericBackend{}, DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok, nil)
				}
				benchmarkR51IFMAPipelineResult = result
				b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*count)/1000, "µs/sig")
			})
			for _, kind := range []r51IFMAPipelineKind{r51IFMAX4, r51IFMATwoX4, r51IFMAX8} {
				for _, radixBits := range []uint{4, 5, 6} {
					name := fmt.Sprintf("stage=cold-A/path=%s/radixA=%d/fixedB=shared/n=%d/msg=%d", kind, 1<<radixBits, count, messageSize)
					b.Run(name, func(b *testing.B) {
						pipeline := requireR51IFMAPipeline(b, kind, radixBits)
						backend := &r51IFMABenchmarkBackend{pipeline: pipeline}
						b.ReportAllocs()
						b.ResetTimer() // fixed-base B preparation is outside timed work
						var result bool
						for iteration := 0; iteration < b.N; iteration++ {
							result = verifyBatch(backend, DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok, nil)
							if backend.err != nil {
								b.Fatal(backend.err)
							}
						}
						benchmarkR51IFMAPipelineResult = result
						b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*count)/1000, "µs/sig")
					})
				}
				for _, fixedRadixBits := range []uint{4, 5, 8} {
					name := fmt.Sprintf("stage=cold-A/path=%s/radixA=32/fixedB=comb%d/n=%d/msg=%d", kind, 1<<fixedRadixBits, count, messageSize)
					b.Run(name, func(b *testing.B) {
						pipeline := requireR51IFMACombPipeline(b, kind, 5, fixedRadixBits)
						backend := &r51IFMABenchmarkBackend{pipeline: pipeline}
						b.ReportAllocs()
						b.ResetTimer() // shared scalar B-comb construction is outside timed work
						var result bool
						for iteration := 0; iteration < b.N; iteration++ {
							result = verifyBatch(backend, DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok, nil)
							if backend.err != nil {
								b.Fatal(backend.err)
							}
						}
						benchmarkR51IFMAPipelineResult = result
						b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*count)/1000, "µs/sig")
					})
				}
			}
		}
	}
}

type r51InvalidArithmeticCandidate struct {
	name          string
	variableRadix uint
	fixedRadix    uint
}

var r51InvalidArithmeticCandidates = [...]r51InvalidArithmeticCandidate{
	{name: "shared", variableRadix: 4},
	{name: "shared", variableRadix: 5},
	{name: "shared", variableRadix: 6},
	{name: "comb16", variableRadix: 5, fixedRadix: 4},
	{name: "comb32", variableRadix: 5, fixedRadix: 5},
	{name: "comb256", variableRadix: 5, fixedRadix: 8},
}

func requireR51InvalidArithmeticPipeline(tb testing.TB, kind r51IFMAPipelineKind, candidate r51InvalidArithmeticCandidate) *r51IFMAPipeline {
	tb.Helper()
	if candidate.fixedRadix != 0 {
		return requireR51IFMACombPipeline(tb, kind, candidate.variableRadix, candidate.fixedRadix)
	}
	return requireR51IFMAPipeline(tb, kind, candidate.variableRadix)
}

func BenchmarkR51IFMAPipelineInvalidMix(b *testing.B) {
	type invalidCase struct {
		name string
		mark func(*batchFixture, int)
	}
	cases := []invalidCase{
		{
			name: "precheck",
			mark: func(fixture *batchFixture, lane int) {
				fixture.sigs[lane] = append([]byte(nil), fixture.sigs[lane]...)
				fixture.sigs[lane][63] |= 0xe0
			},
		},
		{
			name: "equation",
			mark: func(fixture *batchFixture, lane int) {
				fixture.msgs[lane] = append([]byte(nil), fixture.msgs[lane]...)
				fixture.msgs[lane][0] ^= 0x80
			},
		},
	}
	for _, count := range []int{8, 17} {
		for _, invalid := range cases {
			for _, quarter := range []int{0, 1, 2, 3, 4} {
				batches := makeQuarterMix(b, count, 200, quarter, invalid.mark)
				for _, kind := range []r51IFMAPipelineKind{r51IFMATwoX4, r51IFMAX8} {
					for _, candidate := range r51InvalidArithmeticCandidates {
						name := fmt.Sprintf("invalid=%s/ratio=%d/4/path=%s/radixA=%d/fixedB=%s/n=%d/msg=200", invalid.name, quarter, kind, 1<<candidate.variableRadix, candidate.name, count)
						b.Run(name, func(b *testing.B) {
							pipeline := requireR51InvalidArithmeticPipeline(b, kind, candidate)
							b.ReportAllocs()
							b.ResetTimer()
							var result bool
							for iteration := 0; iteration < b.N; iteration++ {
								for phase := range batches {
									var err error
									result, err = pipeline.VerifyBatch(DalekStrict, batches[phase].pubs, batches[phase].msgs, batches[phase].sigs, batches[phase].ok)
									if err != nil {
										b.Fatal(err)
									}
								}
							}
							benchmarkR51IFMAPipelineResult = result
							b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*count*len(batches))/1000, "µs/sig")
						})
					}
				}
			}
		}
	}
}

func BenchmarkR51IFMAPipelineInvalidLane(b *testing.B) {
	for _, count := range []int{8, 9, 16, 17} {
		for invalidLane := 0; invalidLane < count; invalidLane++ {
			fixture := makeBatchFixture(b, count, 200)
			fixture.msgs[invalidLane] = append([]byte(nil), fixture.msgs[invalidLane]...)
			fixture.msgs[invalidLane][0] ^= 0x80
			for _, kind := range []r51IFMAPipelineKind{r51IFMATwoX4, r51IFMAX8} {
				for _, candidate := range r51InvalidArithmeticCandidates {
					name := fmt.Sprintf("path=%s/radixA=%d/fixedB=%s/n=%d/invalidLane=%d/msg=200", kind, 1<<candidate.variableRadix, candidate.name, count, invalidLane)
					b.Run(name, func(b *testing.B) {
						pipeline := requireR51InvalidArithmeticPipeline(b, kind, candidate)
						b.ReportAllocs()
						b.ResetTimer()
						var result bool
						for iteration := 0; iteration < b.N; iteration++ {
							var err error
							result, err = pipeline.VerifyBatch(DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok)
							if err != nil {
								b.Fatal(err)
							}
						}
						benchmarkR51IFMAPipelineResult = result
						b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*count)/1000, "µs/sig")
					})
				}
			}
		}
	}
}
