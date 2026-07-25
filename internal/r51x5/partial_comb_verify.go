// Complete strict verifier over the heterogeneous warm-key partial comb.
//
// Promoted from heterogeneous_partial_comb_complete_verify_experiment_test.go.
// Unlike the other lifts this one is not verbatim: the constructor took a
// testing.TB and reported failure through tb.Skip/tb.Fatalf, so it has been
// reshaped to return an error. Behaviour is otherwise unchanged, and the test
// file keeps a thin testing.TB wrapper so existing callers are untouched.

package r51x5

import (
	"bytes"
	stded25519 "crypto/ed25519"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"sync"
)

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

// errPartialCombUnavailable reports that this host cannot run the warm comb.
// Callers treat it as "fall back to the cold path", not as a fault.
var errPartialCombUnavailable = errors.New("r51x5: warm partial comb requires AVX-512 IFMA")

func newHeterogeneousPartialCombCompleteVerifier(
	inputs []heterogeneousPartialCombCompleteInputExperiment,
) (*heterogeneousPartialCombCompleteVerifierExperiment, error) {
	if !ExperimentalIFMAAvailable() {
		return nil, errPartialCombUnavailable
	}
	if len(inputs) == 0 || len(inputs) > heterogeneousPartialCombCompleteMaxInputsExperiment || len(inputs)%X4Lanes != 0 {
		return nil, fmt.Errorf("r51x5: complete warm-comb preparation count=%d, want a positive multiple of %d up to %d", len(inputs), X4Lanes, heterogeneousPartialCombCompleteMaxInputsExperiment)
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
			return nil, fmt.Errorf("r51x5: complete warm-comb preparation input=%d is small order", index)
		}
	}

	var generatorEncoding [32]byte
	generatorEncoding[0] = 0x58
	for index := 1; index < len(generatorEncoding); index++ {
		generatorEncoding[index] = 0x66
	}
	var generator Point
	if _, err := generator.SetBytes(generatorEncoding[:]); err != nil {
		return nil, err
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
			return nil, err
		}
		if valid != 0x0f {
			return nil, fmt.Errorf("r51x5: complete warm-comb preparation group=%d decode mask=%02x", group, valid)
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
				return nil, err
			}
			newPartial = prepared.partial.tablePointers()

			var regularWorkspace ExperimentalIFMAFixedDSMWorkspaceRadix64X4
			if err := regularWorkspace.PrepareBoth(&[DSMTerms]PointX4{generatorX4, decoded}, 6); err != nil {
				return nil, err
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
	return verifier, nil
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
