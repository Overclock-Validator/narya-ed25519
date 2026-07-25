package r51x5

import (
	"bytes"
	stded25519 "crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"hash"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
)

// This file is the complete-path gate for the test-only heterogeneous warm-key
// comb. It intentionally depends on the lower-level experiment in
// heterogeneous_partial_comb_experiment_test.go: none of this machinery is
// reachable from a production backend or automatic dispatch.

const heterogeneousPartialCombCompleteMaxInputsExperiment = ExperimentalIFMABatchEncodeMaxX4Groups * X4Lanes

type heterogeneousPartialCombCompleteCandidateExperiment uint8

const (
	heterogeneousPartialCombCompleteRegularExperiment heterogeneousPartialCombCompleteCandidateExperiment = iota
	heterogeneousPartialCombCompleteB8Experiment
	heterogeneousPartialCombCompleteB10Experiment
)

func (candidate heterogeneousPartialCombCompleteCandidateExperiment) String() string {
	switch candidate {
	case heterogeneousPartialCombCompleteRegularExperiment:
		return "regular-prepared"
	case heterogeneousPartialCombCompleteB8Experiment:
		return "partial-A6r9-B8r3-pre-signed"
	case heterogeneousPartialCombCompleteB10Experiment:
		return "partial-A6r9-B10r5-pre-signed"
	default:
		panic("r51x5: unknown complete warm-comb candidate")
	}
}

type heterogeneousPartialCombCompleteInputExperiment struct {
	pub       [32]byte
	message   []byte
	signature []byte
}

type heterogeneousPartialCombCompleteKeyShapeExperiment uint8

const (
	heterogeneousPartialCombCompleteDistinctKeysExperiment heterogeneousPartialCombCompleteKeyShapeExperiment = iota
	heterogeneousPartialCombCompleteFourKeyCycleExperiment
	heterogeneousPartialCombCompleteSameKeyExperiment
)

func (shape heterogeneousPartialCombCompleteKeyShapeExperiment) String() string {
	switch shape {
	case heterogeneousPartialCombCompleteDistinctKeysExperiment:
		return "distinct-keys"
	case heterogeneousPartialCombCompleteFourKeyCycleExperiment:
		return "four-key-cycle"
	case heterogeneousPartialCombCompleteSameKeyExperiment:
		return "same-key"
	default:
		panic("r51x5: unknown complete warm-comb key shape")
	}
}

type heterogeneousPartialCombCompletePreparedGroupExperiment struct {
	partial heterogeneousPartialCombA6R9VectorTableGroupExperiment
	tables  [X4Lanes]*heterogeneousPartialCombTableExperiment
	regular [X4Lanes]ifmaMicroAoSPerKeyTableExperiment
}

type heterogeneousPartialCombCompletePreparedKeyExperiment struct {
	partial *heterogeneousPartialCombTableExperiment
	regular ifmaMicroAoSPerKeyTableExperiment
}

// heterogeneousPartialCombCompleteVerifierExperiment owns all mutable scratch
// used after preparation. Verify is allocation-free and non-concurrent. Its
// timing includes an exact-original-byte map lookup and per-group pointer
// assembly, but deliberately excludes cache admission, eviction, and table
// construction. The public-key bytes are retained separately from the
// decoded/precomputed point: the challenge must hash the exact caller encoding,
// including a permissible noncanonical A encoding.
type heterogeneousPartialCombCompleteVerifierExperiment struct {
	count  int
	groups int
	pubs   [heterogeneousPartialCombCompleteMaxInputsExperiment][32]byte

	prepared [ExperimentalIFMABatchEncodeMaxX4Groups]heterogeneousPartialCombCompletePreparedGroupExperiment
	regularB *asymmetricFixedBTableExperiment
	b8       *heterogeneousPartialCombPreSignedSharedTableExperiment
	b10      *heterogeneousPartialCombPreSignedSharedTableExperiment
	keys     map[[32]byte]heterogeneousPartialCombCompletePreparedKeyExperiment

	hash   hash.Hash
	digest [sha512.Size]byte
	wide   [X4Lanes][sha512.Size]byte

	encoder ExperimentalIFMABatchEncodeWorkspaceX4
	points  [ExperimentalIFMABatchEncodeMaxX4Groups]IFMAPointX4
	active  [ExperimentalIFMABatchEncodeMaxX4Groups]uint8
	encoded [ExperimentalIFMABatchEncodeMaxX4Groups][X4Lanes][32]byte
}

var heterogeneousPartialCombCompleteFixedTablesExperiment struct {
	once    sync.Once
	regular *asymmetricFixedBTableExperiment
	b8      *heterogeneousPartialCombPreSignedSharedTableExperiment
	b10     *heterogeneousPartialCombPreSignedSharedTableExperiment
}

func newHeterogeneousPartialCombCompleteVerifierExperiment(
	tb testing.TB,
	inputs []heterogeneousPartialCombCompleteInputExperiment,
) *heterogeneousPartialCombCompleteVerifierExperiment {
	tb.Helper()
	if !ExperimentalIFMAAvailable() {
		tb.Skip("requires AVX-512 IFMA target")
	}
	if len(inputs) == 0 || len(inputs) > heterogeneousPartialCombCompleteMaxInputsExperiment || len(inputs)%X4Lanes != 0 {
		tb.Fatalf("complete warm-comb preparation count=%d, want a positive multiple of %d up to %d", len(inputs), X4Lanes, heterogeneousPartialCombCompleteMaxInputsExperiment)
	}

	verifier := &heterogeneousPartialCombCompleteVerifierExperiment{
		count:  len(inputs),
		groups: len(inputs) / X4Lanes,
		hash:   sha512.New(),
		keys:   make(map[[32]byte]heterogeneousPartialCombCompletePreparedKeyExperiment, len(inputs)),
	}
	for index := range inputs {
		verifier.pubs[index] = inputs[index].pub
		if packedEncodesSmallOrderPointX4(inputs[index].pub[:]) {
			tb.Fatalf("complete warm-comb preparation input=%d is small order", index)
		}
	}

	var generatorEncoding [32]byte
	generatorEncoding[0] = 0x58
	for index := 1; index < len(generatorEncoding); index++ {
		generatorEncoding[index] = 0x66
	}
	var generator Point
	if _, err := generator.SetBytes(generatorEncoding[:]); err != nil {
		tb.Fatal(err)
	}
	heterogeneousPartialCombCompleteFixedTablesExperiment.once.Do(func() {
		heterogeneousPartialCombCompleteFixedTablesExperiment.regular = buildAsymmetricFixedBTableExperiment(&generator, 10)
		b8 := buildHeterogeneousPartialCombTableExperiment(&generator, heterogeneousPartialCombB8R3Experiment)
		b10 := buildHeterogeneousPartialCombTableExperiment(&generator, heterogeneousPartialCombB10R5Experiment)
		heterogeneousPartialCombCompleteFixedTablesExperiment.b8 = buildHeterogeneousPartialCombPreSignedSharedTableExperiment(b8)
		heterogeneousPartialCombCompleteFixedTablesExperiment.b10 = buildHeterogeneousPartialCombPreSignedSharedTableExperiment(b10)
	})
	verifier.regularB = heterogeneousPartialCombCompleteFixedTablesExperiment.regular
	verifier.b8 = heterogeneousPartialCombCompleteFixedTablesExperiment.b8
	verifier.b10 = heterogeneousPartialCombCompleteFixedTablesExperiment.b10

	var generatorLanes [X4Lanes]Point
	for lane := range generatorLanes {
		generatorLanes[lane] = generator
	}
	var generatorX4 PointX4
	generatorX4.SetPoints(&generatorLanes)

	var buildWorkspace heterogeneousPartialCombA6R9VectorBuildWorkspaceExperiment
	for group := 0; group < verifier.groups; group++ {
		var encoded [X4Lanes][32]byte
		for lane := range encoded {
			encoded[lane] = inputs[group*X4Lanes+lane].pub
		}
		var decoded PointX4
		valid, err := ExperimentalIFMADecodeX4(&decoded, &encoded, 0x0f)
		if err != nil {
			tb.Fatal(err)
		}
		if valid != 0x0f {
			tb.Fatalf("complete warm-comb preparation group=%d decode mask=%02x", group, valid)
		}

		prepared := &verifier.prepared[group]
		needsBuild := false
		for lane := 0; lane < X4Lanes; lane++ {
			if _, ok := verifier.keys[encoded[lane]]; !ok {
				needsBuild = true
				break
			}
		}
		var newPartial [X4Lanes]*heterogeneousPartialCombTableExperiment
		var newRegular [X4Lanes]ifmaMicroAoSPerKeyTableExperiment
		if needsBuild {
			if err := buildHeterogeneousPartialCombA6R9VectorGroupExperiment(&prepared.partial, &decoded, &buildWorkspace); err != nil {
				tb.Fatal(err)
			}
			newPartial = prepared.partial.tablePointers()

			var regularWorkspace ExperimentalIFMAFixedDSMWorkspaceRadix64X4
			if err := regularWorkspace.PrepareBoth(&[DSMTerms]PointX4{generatorX4, decoded}, 6); err != nil {
				tb.Fatal(err)
			}
			newRegular = importIFMAMicroAoSTablesExperimentX4(&regularWorkspace.tables[1])
		}
		for lane := 0; lane < X4Lanes; lane++ {
			key := encoded[lane]
			if cached, ok := verifier.keys[key]; ok {
				prepared.tables[lane] = cached.partial
				prepared.regular[lane] = cached.regular
				continue
			}
			prepared.tables[lane] = newPartial[lane]
			prepared.regular[lane] = newRegular[lane]
			verifier.keys[key] = heterogeneousPartialCombCompletePreparedKeyExperiment{
				partial: newPartial[lane],
				regular: newRegular[lane],
			}
		}
	}
	return verifier
}

// Verify evaluates the complete strict predicate for the prepared public keys.
// inputs must preserve the preparation order and may change only messages and
// signatures. Every verdict is cleared before work starts and remains false on
// any arithmetic error.
func (verifier *heterogeneousPartialCombCompleteVerifierExperiment) Verify(
	candidate heterogeneousPartialCombCompleteCandidateExperiment,
	inputs []heterogeneousPartialCombCompleteInputExperiment,
	ok []bool,
) (bool, error) {
	if len(inputs) != verifier.count || len(ok) != verifier.count {
		panic("r51x5: complete warm-comb slice lengths differ from preparation")
	}
	for index := range ok {
		ok[index] = false
	}
	for group := 0; group < verifier.groups; group++ {
		verifier.points[group] = IFMAPointX4{}
		verifier.active[group] = 0
		verifier.encoded[group] = [X4Lanes][32]byte{}

		var scalars FixedDSMScalarsX4
		partialTables := verifier.prepared[group].tables
		regularTables := verifier.prepared[group].regular
		var live uint8
		for lane := 0; lane < X4Lanes; lane++ {
			index := group*X4Lanes + lane
			input := &inputs[index]
			cached, hit := verifier.keys[input.pub]
			if input.pub != verifier.pubs[index] || !hit || len(input.signature) != stded25519.SignatureSize {
				continue
			}
			partialTables[lane] = cached.partial
			regularTables[lane] = cached.regular
			copy(scalars[0][lane][:], input.signature[32:])
			if !canonicalScalarBytes(&scalars[0][lane]) ||
				packedEncodesSmallOrderPointX4(input.signature[:32]) ||
				!packedCanonicalREncodingX4(input.signature[:32]) {
				continue
			}

			verifier.hash.Reset()
			_, _ = verifier.hash.Write(input.signature[:32])
			_, _ = verifier.hash.Write(input.pub[:])
			_, _ = verifier.hash.Write(input.message)
			sum := verifier.hash.Sum(verifier.digest[:0])
			if len(sum) != len(verifier.digest) {
				panic("r51x5: SHA-512 returned an invalid digest length")
			}
			verifier.wide[lane] = verifier.digest
			live |= 1 << lane
		}

		var reduced [X4Lanes][32]byte
		live &= ExperimentalReduceUniformScalarsX4(&reduced, &verifier.wide, live)
		scalars[1] = reduced
		negative := [DSMTerms]uint8{0, live}
		var usable uint8
		var err error
		switch candidate {
		case heterogeneousPartialCombCompleteRegularExperiment:
			usable, err = evaluateAsymmetricFixedBDensePreparedRadix64DSMX4(
				&verifier.points[group], &regularTables,
				verifier.regularB, &scalars, &negative, live,
			)
		case heterogeneousPartialCombCompleteB8Experiment:
			usable, err = evaluateHeterogeneousPartialCombPreSignedBDSMX4Experiment(
				&verifier.points[group], &partialTables,
				verifier.b8, &scalars, &negative, live,
			)
		case heterogeneousPartialCombCompleteB10Experiment:
			usable, err = evaluateHeterogeneousPartialCombPreSignedBDSMX4Experiment(
				&verifier.points[group], &partialTables,
				verifier.b10, &scalars, &negative, live,
			)
		default:
			panic("r51x5: unknown complete warm-comb candidate")
		}
		if err != nil {
			return false, err
		}
		verifier.active[group] = usable
	}

	if err := verifier.encoder.Encode(&verifier.encoded, &verifier.points, &verifier.active, verifier.groups); err != nil {
		return false, err
	}
	all := true
	for group := 0; group < verifier.groups; group++ {
		for lane := 0; lane < X4Lanes; lane++ {
			index := group*X4Lanes + lane
			accepted := len(inputs[index].signature) == stded25519.SignatureSize &&
				verifier.active[group]&(1<<lane) != 0 &&
				bytes.Equal(verifier.encoded[group][lane][:], inputs[index].signature[:32])
			ok[index] = accepted
			all = all && accepted
		}
	}
	return all, nil
}

func makeHeterogeneousPartialCombCompleteInputsExperiment(
	tb testing.TB,
	count, messageSize int,
	shape heterogeneousPartialCombCompleteKeyShapeExperiment,
) []heterogeneousPartialCombCompleteInputExperiment {
	tb.Helper()
	keyCount := count
	switch shape {
	case heterogeneousPartialCombCompleteDistinctKeysExperiment:
	case heterogeneousPartialCombCompleteFourKeyCycleExperiment:
		keyCount = X4Lanes
	case heterogeneousPartialCombCompleteSameKeyExperiment:
		keyCount = 1
	default:
		panic("r51x5: unknown complete warm-comb key shape")
	}
	publicKeys := make([]stded25519.PublicKey, keyCount)
	privateKeys := make([]stded25519.PrivateKey, keyCount)
	for index := 0; index < keyCount; index++ {
		public, private, err := stded25519.GenerateKey(rand.Reader)
		if err != nil {
			tb.Fatal(err)
		}
		publicKeys[index], privateKeys[index] = public, private
	}
	inputs := make([]heterogeneousPartialCombCompleteInputExperiment, count)
	for index := range inputs {
		keyIndex := index % keyCount
		copy(inputs[index].pub[:], publicKeys[keyIndex])
		inputs[index].message = make([]byte, messageSize)
		if _, err := rand.Read(inputs[index].message); err != nil {
			tb.Fatal(err)
		}
		inputs[index].signature = stded25519.Sign(privateKeys[keyIndex], inputs[index].message)
	}
	return inputs
}

func assertHeterogeneousPartialCombCompleteMatchesPackedExperiment(
	t *testing.T,
	name string,
	inputs []heterogeneousPartialCombCompleteInputExperiment,
) {
	t.Helper()
	verifier := newHeterogeneousPartialCombCompleteVerifierExperiment(t, inputs)
	want := make([]bool, len(inputs))
	packed, err := NewExperimentalPackedStrictVerifierX4()
	if err != nil {
		t.Fatal(err)
	}
	for index := range inputs {
		want[index], err = packed.Verify(&inputs[index].pub, inputs[index].message, inputs[index].signature)
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, candidate := range []heterogeneousPartialCombCompleteCandidateExperiment{
		heterogeneousPartialCombCompleteRegularExperiment,
		heterogeneousPartialCombCompleteB8Experiment,
		heterogeneousPartialCombCompleteB10Experiment,
	} {
		got := make([]bool, len(inputs))
		all, err := verifier.Verify(candidate, inputs, got)
		if err != nil {
			t.Fatalf("%s/%s: %v", name, candidate, err)
		}
		wantAll := true
		for index := range want {
			wantAll = wantAll && want[index]
			if got[index] != want[index] {
				t.Fatalf("%s/%s input=%d got=%v want=%v", name, candidate, index, got[index], want[index])
			}
		}
		if all != wantAll {
			t.Fatalf("%s/%s all=%v want=%v", name, candidate, all, wantAll)
		}
	}
}

func TestHeterogeneousPartialCombCompleteStrictDifferentialExperiment(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("requires AVX-512 IFMA target")
	}

	honest := makeHeterogeneousPartialCombCompleteInputsExperiment(
		t, X4Lanes, 200, heterogeneousPartialCombCompleteDistinctKeysExperiment,
	)
	assertHeterogeneousPartialCombCompleteMatchesPackedExperiment(t, "honest", honest)

	mutated := append([]heterogeneousPartialCombCompleteInputExperiment(nil), honest...)
	mutated[1].message = append([]byte(nil), honest[1].message...)
	mutated[1].message[len(mutated[1].message)/2] ^= 1
	mutated[2].signature = append([]byte(nil), honest[2].signature...)
	mutated[2].signature[9] ^= 0x40
	assertHeterogeneousPartialCombCompleteMatchesPackedExperiment(t, "independent-invalid-lanes", mutated)

	malformedLengths := append([]heterogeneousPartialCombCompleteInputExperiment(nil), honest...)
	for lane, length := range []int{0, 31, 32, 63} {
		malformedLengths[lane].signature = append([]byte(nil), honest[lane].signature[:length]...)
	}
	assertHeterogeneousPartialCombCompleteMatchesPackedExperiment(t, "short-signatures", malformedLengths)
	longSignature := append([]heterogeneousPartialCombCompleteInputExperiment(nil), honest...)
	longSignature[0].signature = append(append([]byte(nil), honest[0].signature...), 0)
	assertHeterogeneousPartialCombCompleteMatchesPackedExperiment(t, "long-signature", longSignature)

	mixedPub, mixedMessage, mixedSignature := quadPairedRMixedOrderValidVectorX4(t)
	mixed := make([]heterogeneousPartialCombCompleteInputExperiment, X4Lanes)
	for lane := range mixed {
		mixed[lane] = heterogeneousPartialCombCompleteInputExperiment{
			pub: mixedPub, message: mixedMessage, signature: mixedSignature,
		}
	}
	assertHeterogeneousPartialCombCompleteMatchesPackedExperiment(t, "mixed-order-valid", mixed)

	// Dalek strict deliberately permits a noncanonical decodable A. The
	// signature belongs to another key, so the equation rejects, but successful
	// preparation proves the rejection is not an accidental canonical-A gate.
	noncanonical := append([]heterogeneousPartialCombCompleteInputExperiment(nil), honest...)
	noncanonical[0].pub = quadPairedRNoncanonicalDecodablePointX4(t)
	assertHeterogeneousPartialCombCompleteMatchesPackedExperiment(t, "noncanonical-decodable-A", noncanonical)
}

func TestHeterogeneousPartialCombCompletePreparedTableReuseExperiment(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("requires AVX-512 IFMA target")
	}
	for _, test := range []struct {
		shape      heterogeneousPartialCombCompleteKeyShapeExperiment
		uniqueKeys int
	}{
		{shape: heterogeneousPartialCombCompleteFourKeyCycleExperiment, uniqueKeys: X4Lanes},
		{shape: heterogeneousPartialCombCompleteSameKeyExperiment, uniqueKeys: 1},
	} {
		inputs := makeHeterogeneousPartialCombCompleteInputsExperiment(t, 8, 200, test.shape)
		verifier := newHeterogeneousPartialCombCompleteVerifierExperiment(t, inputs)
		seenPartial := make(map[*heterogeneousPartialCombTableExperiment]struct{})
		seenRegular := make(map[*ifmaMicroAoSPointEntryExperiment]struct{})
		for group := 0; group < verifier.groups; group++ {
			for lane := 0; lane < X4Lanes; lane++ {
				seenPartial[verifier.prepared[group].tables[lane]] = struct{}{}
				regular := verifier.prepared[group].regular[lane].points
				if len(regular) == 0 {
					t.Fatalf("shape=%s group=%d lane=%d has empty regular table", test.shape, group, lane)
				}
				seenRegular[&regular[0]] = struct{}{}
			}
		}
		if len(seenPartial) != test.uniqueKeys || len(seenRegular) != test.uniqueKeys {
			t.Fatalf("shape=%s unique partial=%d regular=%d want=%d", test.shape, len(seenPartial), len(seenRegular), test.uniqueKeys)
		}
	}
}

func TestHeterogeneousPartialCombCompleteStrictZeroAllocationsExperiment(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("requires AVX-512 IFMA target")
	}
	inputs := makeHeterogeneousPartialCombCompleteInputsExperiment(
		t, X4Lanes, 200, heterogeneousPartialCombCompleteDistinctKeysExperiment,
	)
	verifier := newHeterogeneousPartialCombCompleteVerifierExperiment(t, inputs)
	var ok [X4Lanes]bool
	for _, candidate := range []heterogeneousPartialCombCompleteCandidateExperiment{
		heterogeneousPartialCombCompleteRegularExperiment,
		heterogeneousPartialCombCompleteB8Experiment,
		heterogeneousPartialCombCompleteB10Experiment,
	} {
		allocations := testing.AllocsPerRun(10, func() {
			all, err := verifier.Verify(candidate, inputs, ok[:])
			if err != nil || !all {
				panic("r51x5: complete warm-comb verifier rejected honest signatures")
			}
		})
		if allocations != 0 {
			t.Fatalf("%s allocations=%v want 0", candidate, allocations)
		}
	}
}

var heterogeneousPartialCombCompleteResultSinkExperiment bool
var heterogeneousPartialCombCompleteParallelSinkExperiment uint64

func BenchmarkHeterogeneousPartialCombCompleteStrictExperiment(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skip("requires AVX-512 IFMA target")
	}
	for _, shape := range []heterogeneousPartialCombCompleteKeyShapeExperiment{
		heterogeneousPartialCombCompleteDistinctKeysExperiment,
		heterogeneousPartialCombCompleteFourKeyCycleExperiment,
		heterogeneousPartialCombCompleteSameKeyExperiment,
	} {
		for _, messageSize := range []int{200, 1232} {
			inputs := makeHeterogeneousPartialCombCompleteInputsExperiment(
				b, heterogeneousPartialCombCompleteMaxInputsExperiment, messageSize, shape,
			)
			for _, count := range []int{4, 8, 64} {
				batch := inputs[:count]
				verifier := newHeterogeneousPartialCombCompleteVerifierExperiment(b, batch)
				ok := make([]bool, count)
				for _, candidate := range []heterogeneousPartialCombCompleteCandidateExperiment{
					heterogeneousPartialCombCompleteRegularExperiment,
					heterogeneousPartialCombCompleteB8Experiment,
					heterogeneousPartialCombCompleteB10Experiment,
				} {
					name := fmt.Sprintf("keys=%s/implementation=%s/n=%d/msg=%d", shape, candidate, count, messageSize)
					b.Run(name, func(b *testing.B) {
						b.ReportAllocs()
						b.ResetTimer()
						var all bool
						var err error
						for iteration := 0; iteration < b.N; iteration++ {
							all, err = verifier.Verify(candidate, batch, ok)
							if err != nil || !all {
								b.Fatalf("complete verify=(%v,%v)", all, err)
							}
						}
						heterogeneousPartialCombCompleteResultSinkExperiment = all
						b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*count), "ns/signature")
					})
				}
			}
		}
	}
}

// BenchmarkHeterogeneousPartialCombCompleteStrictParallelExperiment models a
// process-wide immutable warm-key cache under production worker pressure. The
// prepared A tables, exact-key map, and fixed B table are shared; each parallel
// worker owns its hash state, scalar scratch, points, and batch encoder.
func BenchmarkHeterogeneousPartialCombCompleteStrictParallelExperiment(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skip("requires AVX-512 IFMA target")
	}
	const count = heterogeneousPartialCombCompleteMaxInputsExperiment
	for _, shape := range []heterogeneousPartialCombCompleteKeyShapeExperiment{
		heterogeneousPartialCombCompleteDistinctKeysExperiment,
		heterogeneousPartialCombCompleteFourKeyCycleExperiment,
		heterogeneousPartialCombCompleteSameKeyExperiment,
	} {
		inputs := makeHeterogeneousPartialCombCompleteInputsExperiment(b, count, 200, shape)
		prepared := newHeterogeneousPartialCombCompleteVerifierExperiment(b, inputs)
		for _, candidate := range []heterogeneousPartialCombCompleteCandidateExperiment{
			heterogeneousPartialCombCompleteB8Experiment,
			heterogeneousPartialCombCompleteB10Experiment,
		} {
			name := fmt.Sprintf("keys=%s/implementation=%s/n=%d/msg=200", shape, candidate, count)
			b.Run(name, func(b *testing.B) {
				workerCount := runtime.GOMAXPROCS(0)
				workers := make([]heterogeneousPartialCombCompleteVerifierExperiment, workerCount)
				verdicts := make([][]bool, workerCount)
				for index := range workers {
					workers[index] = *prepared
					workers[index].hash = sha512.New()
					workers[index].digest = [sha512.Size]byte{}
					workers[index].wide = [X4Lanes][sha512.Size]byte{}
					workers[index].encoder = ExperimentalIFMABatchEncodeWorkspaceX4{}
					workers[index].points = [ExperimentalIFMABatchEncodeMaxX4Groups]IFMAPointX4{}
					workers[index].active = [ExperimentalIFMABatchEncodeMaxX4Groups]uint8{}
					workers[index].encoded = [ExperimentalIFMABatchEncodeMaxX4Groups][X4Lanes][32]byte{}
					verdicts[index] = make([]bool, count)
				}

				var sequence uint64
				b.ReportAllocs()
				b.SetParallelism(1)
				b.ResetTimer()
				b.RunParallel(func(pb *testing.PB) {
					index := int(atomic.AddUint64(&sequence, 1) - 1)
					if index >= len(workers) {
						panic("r51x5: benchmark created more workers than GOMAXPROCS")
					}
					worker := &workers[index]
					ok := verdicts[index]
					var all bool
					for pb.Next() {
						var err error
						all, err = worker.Verify(candidate, inputs, ok)
						if err != nil || !all {
							panic("r51x5: parallel complete warm-comb verifier rejected honest signatures")
						}
					}
					if all {
						atomic.AddUint64(&heterogeneousPartialCombCompleteParallelSinkExperiment, 1)
					}
				})
				b.StopTimer()
				b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*count), "ns/signature")
				b.ReportMetric(float64(b.N*count)/b.Elapsed().Seconds(), "sig/s")
				b.ReportMetric(float64(workerCount), "workers")
			})
		}
	}
}
