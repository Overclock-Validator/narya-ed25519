package r51x5

import (
	"bytes"
	stded25519 "crypto/ed25519"
	"crypto/sha512"
	"fmt"
	"hash"
	"math/rand"
	"testing"

	"github.com/Overclock-Validator/narya-ed25519/internal/heea8l"
)

// experimentalQuadTwoChainHEEAWorkspaceX8 evaluates the exact transformed
// equation
//
//	[lambda0]B + [lambda1]([2^128]B) - [tau]R - [epsilon*rho]A
//
// as two independent coordinate-parallel chains in one ZMM register. The low
// half accumulates the B and R terms; the high half accumulates the B128 and A
// terms. Each bit therefore needs one native-ZMM doubling, at most one packed
// fixed-base add, and at most one packed variable-base add.
//
// This is deliberately test-only. It measures the singleton-only HEEA avenue
// without making it reachable from a public backend.
type experimentalQuadTwoChainHEEAWorkspaceX8 struct {
	ops  quadDSMOperationsX4
	b    Point
	b128 Point

	bTable    quadNAFTable8X4
	b128Table quadNAFTable8X4
	rTable    quadNAFTable5X4
	aTable    quadNAFTable5X4

	digits [QSMTerms][256]int8

	doubleWorkspace  quadTwoChainDoubleWorkspaceX8
	addWorkspace     quadTwoChainCachedAddWorkspaceX8
	combineWorkspace quadPointAddCachedWorkspaceX4
	negative         [QSMTerms]quadPackedCachedPointX4

	tableCurrent      IFMAElementX8
	tableTwice        IFMAElementX8
	tableCached       IFMAElementX8
	tableTwiceCached  IFMAElementX8
	tableCacheOperand IFMAElementX8
}

var experimentalQuadTwoChainCachedScaleX8 = func() IFMAElementX8 {
	var scale IFMAElementX8
	for limb := range scale.limbs {
		for lane := 0; lane < X4Lanes; lane++ {
			scale.limbs[limb][lane] = quadCachedScaleX4.limbs[limb][lane]
			scale.limbs[limb][lane+X4Lanes] = quadCachedScaleX4.limbs[limb][lane]
		}
	}
	return scale
}()

func newExperimentalQuadTwoChainHEEAWorkspaceX8() (*experimentalQuadTwoChainHEEAWorkspaceX8, error) {
	if !ExperimentalIFMAAvailable() {
		return nil, ErrIFMAUnavailable
	}
	workspace := &experimentalQuadTwoChainHEEAWorkspaceX8{
		ops: quadDSMOperationsX4{hardware: true},
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
	var b128Packed PointX4
	b128Packed.SetIdentity().SetLane(0, &generator)
	for doubling := 0; doubling < heeaBaseSplitBit; doubling++ {
		b128Packed.Double(&b128Packed)
	}
	b128 := b128Packed.Lane(0)
	workspace.b = generator
	workspace.b128 = b128
	if err := buildQuadNAFTable8X4(&workspace.bTable, &generator, workspace.ops); err != nil {
		return nil, err
	}
	if err := buildQuadNAFTable8X4(&workspace.b128Table, &b128, workspace.ops); err != nil {
		return nil, err
	}
	return workspace, nil
}

func (workspace *experimentalQuadTwoChainHEEAWorkspaceX8) prepareVariableBases(r, a *Point) error {
	var packedR, packedA quadPackedPointX4
	packedR.setReduced(r)
	packedA.setReduced(a)
	workspace.tableCurrent = packQuadTwoChainPointsX8(&packedR, &packedA)
	if err := workspace.storeVariableTableEntry(0, &workspace.tableCurrent); err != nil {
		return err
	}

	workspace.tableTwice = workspace.tableCurrent
	if err := quadTwoChainDoubleHardwareWorkspaceUncheckedX8(
		&workspace.tableTwice, &workspace.tableTwice, &workspace.doubleWorkspace,
	); err != nil {
		return err
	}
	if err := workspace.cacheTwoChainPoint(&workspace.tableTwiceCached, &workspace.tableTwice); err != nil {
		return err
	}

	for entry := 1; entry < len(workspace.rTable.positive); entry++ {
		if err := quadTwoChainCachedAddHardwareWorkspaceUncheckedX8(
			&workspace.tableCurrent,
			&workspace.tableCurrent,
			&workspace.tableTwiceCached,
			&workspace.addWorkspace,
		); err != nil {
			return err
		}
		if err := workspace.storeVariableTableEntry(entry, &workspace.tableCurrent); err != nil {
			return err
		}
	}
	return nil
}

func (workspace *experimentalQuadTwoChainHEEAWorkspaceX8) cacheTwoChainPoint(out, point *IFMAElementX8) error {
	ifmaQuadTwoChainCachedAddFirstOperandUncheckedX8(&workspace.tableCacheOperand.limbs, &point.limbs)
	return ifmaMultiplyComposableUncheckedX8(out, &workspace.tableCacheOperand, &experimentalQuadTwoChainCachedScaleX8)
}

func (workspace *experimentalQuadTwoChainHEEAWorkspaceX8) storeVariableTableEntry(entry int, point *IFMAElementX8) error {
	if err := workspace.cacheTwoChainPoint(&workspace.tableCached, point); err != nil {
		return err
	}
	for limb := range workspace.tableCached.limbs {
		for lane := 0; lane < X4Lanes; lane++ {
			workspace.rTable.positive[entry].coordinates.limbs[limb][lane] =
				workspace.tableCached.limbs[limb][lane]
			workspace.aTable.positive[entry].coordinates.limbs[limb][lane] =
				workspace.tableCached.limbs[limb][lane+X4Lanes]
		}
	}
	return nil
}

func recodeQuadSignedNAFX4(out *[256]int8, scalar *[32]byte, negative bool, width uint) bool {
	if !recodeQuadCanonicalNAFX4(out, scalar, width) {
		return false
	}
	if negative {
		for index := range out {
			out[index] = -out[index]
		}
	}
	return true
}

func (workspace *experimentalQuadTwoChainHEEAWorkspaceX8) evaluate(
	out *quadPackedPointX4,
	coefficients *ExperimentalHEEABaseSplitCoefficientsX4,
) (bool, error) {
	identity := quadPackedIdentityValueX4()
	if coefficients == nil || coefficients.ValidMask()&1 == 0 {
		*out = identity
		return false, nil
	}

	valid := recodeQuadSignedNAFX4(
		&workspace.digits[0], &coefficients.scalars[0][0],
		coefficients.negativeMasks[0]&1 != 0, 8,
	)
	valid = recodeQuadSignedNAFX4(
		&workspace.digits[1], &coefficients.scalars[1][0],
		coefficients.negativeMasks[1]&1 != 0, 8,
	) && valid
	valid = recodeQuadSignedNAFX4(
		&workspace.digits[2], &coefficients.scalars[2][0],
		coefficients.negativeMasks[2]&1 != 0, 5,
	) && valid
	valid = recodeQuadSignedNAFX4(
		&workspace.digits[3], &coefficients.scalars[3][0],
		coefficients.negativeMasks[3]&1 != 0, 5,
	) && valid
	if !valid {
		*out = identity
		return false, nil
	}

	packed := packQuadTwoChainPointsX8(&identity, &identity)
	high := 255
	for ; high >= 0; high-- {
		if workspace.digits[0][high] != 0 || workspace.digits[1][high] != 0 ||
			workspace.digits[2][high] != 0 || workspace.digits[3][high] != 0 {
			break
		}
	}

	cachedIdentity := quadPackedCachedIdentityValueX4()
	for bit := high; bit >= 0; bit-- {
		if err := quadTwoChainDoubleHardwareWorkspaceUncheckedX8(
			&packed, &packed, &workspace.doubleWorkspace,
		); err != nil {
			return false, err
		}

		fixed0, fixed1 := workspace.digits[0][bit], workspace.digits[1][bit]
		if fixed0 != 0 || fixed1 != 0 {
			selected0, selected1 := &cachedIdentity, &cachedIdentity
			if fixed0 != 0 {
				selected0 = selectQuadNAFEntryX4(
					&workspace.negative[0], workspace.bTable.positive[:], fixed0,
				)
			}
			if fixed1 != 0 {
				selected1 = selectQuadNAFEntryX4(
					&workspace.negative[1], workspace.b128Table.positive[:], fixed1,
				)
			}
			cached := packQuadTwoChainCachedX8(selected0, selected1)
			if err := quadTwoChainCachedAddHardwareWorkspaceUncheckedX8(
				&packed, &packed, &cached, &workspace.addWorkspace,
			); err != nil {
				return false, err
			}
		}

		variable0, variable1 := workspace.digits[2][bit], workspace.digits[3][bit]
		if variable0 != 0 || variable1 != 0 {
			selected0, selected1 := &cachedIdentity, &cachedIdentity
			if variable0 != 0 {
				selected0 = selectQuadNAFEntryX4(
					&workspace.negative[2], workspace.rTable.positive[:], variable0,
				)
			}
			if variable1 != 0 {
				selected1 = selectQuadNAFEntryX4(
					&workspace.negative[3], workspace.aTable.positive[:], variable1,
				)
			}
			cached := packQuadTwoChainCachedX8(selected0, selected1)
			if err := quadTwoChainCachedAddHardwareWorkspaceUncheckedX8(
				&packed, &packed, &cached, &workspace.addWorkspace,
			); err != nil {
				return false, err
			}
		}
	}

	terms := unpackQuadTwoChainPointsX8(&packed)
	var highCached quadPackedCachedPointX4
	if err := quadCachePackedPointX4(&highCached, &terms[1], workspace.ops); err != nil {
		return false, err
	}
	if err := quadPointAddCachedHardwareWorkspaceUncheckedX4(
		out, &terms[0], &highCached, &workspace.combineWorkspace,
	); err != nil {
		return false, err
	}
	return true, nil
}

type experimentalPackedHEEAStrictVerifierX8 struct {
	width     heea8l.WidthLimit
	workspace *experimentalQuadTwoChainHEEAWorkspaceX8
	hash      hash.Hash
	digest    [sha512.Size]byte
}

func newExperimentalPackedHEEAStrictVerifierX8(width heea8l.WidthLimit) (*experimentalPackedHEEAStrictVerifierX8, error) {
	if width != heea8l.Width128 && width != heea8l.Width132 && width != heea8l.Width136 {
		return nil, fmt.Errorf("r51x5: invalid singleton HEEA width %d", width)
	}
	workspace, err := newExperimentalQuadTwoChainHEEAWorkspaceX8()
	if err != nil {
		return nil, err
	}
	return &experimentalPackedHEEAStrictVerifierX8{
		width:     width,
		workspace: workspace,
		hash:      sha512.New(),
	}, nil
}

func admittedExperimentalHEEACandidate(selection heea8l.FixedSelection, width heea8l.WidthLimit) bool {
	return selection.UseCandidate && selection.Fallback == heea8l.NoFallback &&
		selection.Candidate.BitLen() <= int(width) &&
		(selection.Candidate.Epsilon == -1 || selection.Candidate.Epsilon == 1) &&
		selection.Candidate.Tau.Sign() != 0 && selection.Candidate.Tau.Limbs[0]&1 == 1 &&
		selection.Candidate.UnitMultiplier()
}

func experimentalHEEACoefficient(in heea8l.SignedCoefficient) ExperimentalHEEASignedCoefficient {
	return ExperimentalHEEASignedCoefficient{
		Magnitude: in.BytesLE(),
		Negative:  in.Negative,
	}
}

// verify evaluates the complete DalekStrict predicate. usedHEEA is false only
// when exact selector/coefficient admission falls back to the existing packed
// singleton DSM using the already-decoded A and already-reduced challenge.
func (verifier *experimentalPackedHEEAStrictVerifierX8) verify(
	pub *[32]byte,
	message, signature []byte,
) (accepted, usedHEEA bool, err error) {
	if verifier == nil || verifier.workspace == nil || verifier.hash == nil {
		return false, false, errExperimentalPackedStrictVerifierUninitialized
	}

	var s [32]byte
	if !packedStrictBytePrechecksX4(pub, signature, &s) {
		return false, false, nil
	}

	var encoded [X4Lanes][32]byte
	encoded[0] = *pub
	copy(encoded[1][:], signature[:32])
	var decoded PointX4
	valid, err := ExperimentalIFMADecodeX4(&decoded, &encoded, 0b0011)
	if err != nil {
		return false, false, err
	}
	if valid&0b0011 != 0b0011 {
		return false, false, nil
	}

	verifier.hash.Reset()
	_, _ = verifier.hash.Write(signature[:32])
	_, _ = verifier.hash.Write(pub[:])
	_, _ = verifier.hash.Write(message)
	sum := verifier.hash.Sum(verifier.digest[:0])
	if len(sum) != len(verifier.digest) {
		panic("r51x5: SHA-512 returned an invalid digest length")
	}
	var wide [X4Lanes][sha512.Size]byte
	wide[0] = verifier.digest
	var reduced [X4Lanes][32]byte
	if ExperimentalReduceUniformScalarsX4(&reduced, &wide, 1)&1 == 0 {
		return false, false, nil
	}

	a := decoded.Lane(0)
	selection := heea8l.SelectLehmer(reduced[0], verifier.width)
	if !admittedExperimentalHEEACandidate(selection, verifier.width) {
		if err := buildQuadNAFTable5X4(&verifier.workspace.aTable, &a, verifier.workspace.ops); err != nil {
			return false, false, err
		}
		var q quadPackedPointX4
		usable, err := evaluateQuadNAFVerifyX4(
			&q, &verifier.workspace.aTable, &verifier.workspace.bTable,
			&s, &reduced[0], verifier.workspace.ops,
		)
		if err != nil || !usable {
			return false, false, err
		}
		accepted, err := quadPackedEqualDecodedAffineLaneX4(&q, &decoded, 1, verifier.workspace.ops)
		return accepted, false, err
	}

	r := decoded.Lane(1)
	if err := verifier.workspace.prepareVariableBases(&r, &a); err != nil {
		return false, false, err
	}

	var scalars [X4Lanes][32]byte
	var tau, rho [X4Lanes]ExperimentalHEEASignedCoefficient
	var epsilon [X4Lanes]int8
	scalars[0] = s
	tau[0] = experimentalHEEACoefficient(selection.Candidate.Tau)
	rho[0] = experimentalHEEACoefficient(selection.Candidate.Rho)
	epsilon[0] = selection.Candidate.Epsilon
	var coefficients ExperimentalHEEABaseSplitCoefficientsX4
	usable, fallback := ExperimentalPrepareHEEABaseSplitCoefficientsX4(
		&coefficients, &scalars, &tau, &rho, &epsilon, 1,
	)
	if usable != 1 || fallback != 0 {
		// Defensive selector-to-evaluator disagreement uses the exact ordinary
		// path; it is never admitted with truncated or reduced coefficients.
		if err := buildQuadNAFTable5X4(&verifier.workspace.aTable, &a, verifier.workspace.ops); err != nil {
			return false, false, err
		}
		var q quadPackedPointX4
		ordinaryUsable, err := evaluateQuadNAFVerifyX4(
			&q, &verifier.workspace.aTable, &verifier.workspace.bTable,
			&s, &reduced[0], verifier.workspace.ops,
		)
		if err != nil || !ordinaryUsable {
			return false, false, err
		}
		accepted, err := quadPackedEqualDecodedAffineLaneX4(&q, &decoded, 1, verifier.workspace.ops)
		return accepted, false, err
	}

	var transformed quadPackedPointX4
	usableHEEA, err := verifier.workspace.evaluate(&transformed, &coefficients)
	if err != nil || !usableHEEA {
		return false, true, err
	}
	point := transformed.reduced()
	return point.IsIdentity() != 0, true, nil
}

func experimentalChallengeScalarX4(pub *[32]byte, message, signature []byte) ([32]byte, bool) {
	var reduced [X4Lanes][32]byte
	if pub == nil || len(signature) != stded25519.SignatureSize {
		return reduced[0], false
	}
	digest := sha512.New()
	_, _ = digest.Write(signature[:32])
	_, _ = digest.Write(pub[:])
	_, _ = digest.Write(message)
	wideDigest := digest.Sum(nil)
	var wide [X4Lanes][sha512.Size]byte
	copy(wide[0][:], wideDigest)
	valid := ExperimentalReduceUniformScalarsX4(&reduced, &wide, 1)
	return reduced[0], valid&1 != 0
}

func TestExperimentalPackedHEEAStrictVerifierX8Differential(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("AVX-512 IFMA is unavailable")
	}
	baseline, err := NewExperimentalPackedStrictVerifierX4()
	if err != nil {
		t.Fatal(err)
	}
	candidates := make([]*experimentalPackedHEEAStrictVerifierX8, 0, 3)
	for _, width := range []heea8l.WidthLimit{heea8l.Width128, heea8l.Width132, heea8l.Width136} {
		candidate, err := newExperimentalPackedHEEAStrictVerifierX8(width)
		if err != nil {
			t.Fatalf("W%d: %v", width, err)
		}
		candidates = append(candidates, candidate)
	}

	seed := bytes.Repeat([]byte{0x51}, stded25519.SeedSize)
	private := stded25519.NewKeyFromSeed(seed)
	publicBytes := private.Public().(stded25519.PublicKey)
	var public [32]byte
	copy(public[:], publicBytes)

	for index := 0; index < 256; index++ {
		message := make([]byte, 64+(index%5)*233)
		for offset := range message {
			message[offset] = byte(index*17 + offset*29)
		}
		signature := stded25519.Sign(private, message)
		want, err := baseline.Verify(&public, message, signature)
		if err != nil || !want {
			t.Fatalf("valid case %d baseline=(%v,%v)", index, want, err)
		}
		for _, candidate := range candidates {
			got, _, err := candidate.verify(&public, message, signature)
			if err != nil || got != want {
				t.Fatalf("valid case %d W%d=(%v,%v), want %v", index, candidate.width, got, err, want)
			}
		}

		badMessage := append([]byte(nil), message...)
		if len(badMessage) == 0 {
			badMessage = []byte{1}
		} else {
			badMessage[len(badMessage)/2] ^= 0x80
		}
		want, err = baseline.Verify(&public, badMessage, signature)
		if err != nil || want {
			t.Fatalf("invalid case %d baseline=(%v,%v)", index, want, err)
		}
		for _, candidate := range candidates {
			got, _, err := candidate.verify(&public, badMessage, signature)
			if err != nil || got != want {
				t.Fatalf("invalid case %d W%d=(%v,%v), want %v", index, candidate.width, got, err, want)
			}
		}
	}
}

func TestExperimentalQuadTwoChainHEEANAFX8MixedOrderDifferential(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("AVX-512 IFMA is unavailable")
	}
	workspace, err := newExperimentalQuadTwoChainHEEAWorkspaceX8()
	if err != nil {
		t.Fatal(err)
	}
	fixture := newQuadDSMFixtureX4(t)
	r := fixture.a
	var a Point
	fixedBasePointAdd(&a, &fixture.a, &fixture.b)
	if err := workspace.prepareVariableBases(&r, &a); err != nil {
		t.Fatal(err)
	}
	var sequentialR, sequentialA quadNAFTable5X4
	if err := buildQuadNAFTable5X4(&sequentialR, &r, workspace.ops); err != nil {
		t.Fatal(err)
	}
	if err := buildQuadNAFTable5X4(&sequentialA, &a, workspace.ops); err != nil {
		t.Fatal(err)
	}
	if workspace.rTable != sequentialR || workspace.aTable != sequentialA {
		t.Fatal("paired R/A table build differs from sequential x4 tables")
	}

	var b4, b1284, r4, a4 PointX4
	b4.SetIdentity().SetLane(0, &workspace.b)
	b1284.SetIdentity().SetLane(0, &workspace.b128)
	r4.SetIdentity().SetLane(0, &r)
	a4.SetIdentity().SetLane(0, &a)

	rng := rand.New(rand.NewSource(0x484545415a4d4d))
	for sample := 0; sample < 256; sample++ {
		var k, s [32]byte
		_, _ = rng.Read(k[:])
		_, _ = rng.Read(s[:])
		k[31] &= 0x0f
		s[31] &= 0x0f
		selection := heea8l.SelectLehmer(k, heea8l.Width136)
		if !admittedExperimentalHEEACandidate(selection, heea8l.Width136) {
			t.Fatalf("sample %d: W136 selector fallback", sample)
		}

		var scalars [X4Lanes][32]byte
		var tauFixed, rhoFixed [X4Lanes]ExperimentalHEEASignedCoefficient
		var epsilon [X4Lanes]int8
		scalars[0] = s
		tauFixed[0] = experimentalHEEACoefficient(selection.Candidate.Tau)
		rhoFixed[0] = experimentalHEEACoefficient(selection.Candidate.Rho)
		epsilon[0] = selection.Candidate.Epsilon
		var coefficients ExperimentalHEEABaseSplitCoefficientsX4
		usable, fallback := ExperimentalPrepareHEEABaseSplitCoefficientsX4(
			&coefficients, &scalars, &tauFixed, &rhoFixed, &epsilon, 1,
		)
		if usable != 1 || fallback != 0 {
			t.Fatalf("sample %d: coefficient masks usable=%x fallback=%x", sample, usable, fallback)
		}

		var got quadPackedPointX4
		if valid, err := workspace.evaluate(&got, &coefficients); err != nil || !valid {
			t.Fatalf("sample %d: two-chain=(%v,%v)", sample, valid, err)
		}

		tauBytes := selection.Candidate.Tau.BytesLE()
		rhoBytes := selection.Candidate.Rho.BytesLE()
		var sSigned, tauSigned, rhoSigned [X4Lanes]SignedMagnitude
		sSigned[0] = NewSignedMagnitude(s[:], false)
		tauSigned[0] = NewSignedMagnitude(tauBytes[:], selection.Candidate.Tau.Negative)
		rhoSigned[0] = NewSignedMagnitude(rhoBytes[:], selection.Candidate.Rho.Negative)
		var want PointX4
		if referenceUsable := ExperimentalHEEABaseSplitEquationX4(
			&want, &b4, &b1284, &r4, &a4,
			&sSigned, &tauSigned, &rhoSigned, &epsilon, 5, 1,
		); referenceUsable != 1 {
			t.Fatalf("sample %d: scalar reference rejected", sample)
		}
		gotPoint := got.reduced()
		wantPoint := want.Lane(0)
		if gotPoint.Equal(&wantPoint) != 1 {
			t.Fatalf("sample %d: two-chain HEEA differs from exact four-term reference", sample)
		}
	}
}

func TestExperimentalPackedHEEAStrictVerifierX8FallbackAndAllocations(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("AVX-512 IFMA is unavailable")
	}
	verifier, err := newExperimentalPackedHEEAStrictVerifierX8(heea8l.Width128)
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := NewExperimentalPackedStrictVerifierX4()
	if err != nil {
		t.Fatal(err)
	}
	private := stded25519.NewKeyFromSeed(bytes.Repeat([]byte{0xa8}, stded25519.SeedSize))
	publicBytes := private.Public().(stded25519.PublicKey)
	var public [32]byte
	copy(public[:], publicBytes)

	var admittedMessage, admittedSignature, fallbackMessage, fallbackSignature []byte
	for counter := 0; counter < 4096 && (admittedSignature == nil || fallbackSignature == nil); counter++ {
		message := []byte(fmt.Sprintf("narya-singleton-heea-%d", counter))
		signature := stded25519.Sign(private, message)
		challenge, ok := experimentalChallengeScalarX4(&public, message, signature)
		if !ok {
			t.Fatal("challenge reduction failed")
		}
		selection := heea8l.SelectLehmer(challenge, heea8l.Width128)
		if admittedExperimentalHEEACandidate(selection, heea8l.Width128) {
			if admittedSignature == nil {
				admittedMessage = message
				admittedSignature = signature
			}
		} else if fallbackSignature == nil {
			fallbackMessage = message
			fallbackSignature = signature
		}
	}
	if admittedSignature == nil || fallbackSignature == nil {
		t.Fatalf("failed to find admitted=%v fallback=%v fixture", admittedSignature != nil, fallbackSignature != nil)
	}

	for _, test := range []struct {
		name      string
		message   []byte
		signature []byte
		usedHEEA  bool
	}{
		{name: "admitted", message: admittedMessage, signature: admittedSignature, usedHEEA: true},
		{name: "fallback", message: fallbackMessage, signature: fallbackSignature, usedHEEA: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			want, err := baseline.Verify(&public, test.message, test.signature)
			if err != nil || !want {
				t.Fatalf("baseline=(%v,%v)", want, err)
			}
			got, usedHEEA, err := verifier.verify(&public, test.message, test.signature)
			if err != nil || got != want || usedHEEA != test.usedHEEA {
				t.Fatalf("candidate=(accepted=%v HEEA=%v err=%v), want (%v,%v,nil)", got, usedHEEA, err, want, test.usedHEEA)
			}
			if allocs := testing.AllocsPerRun(100, func() {
				accepted, _, err := verifier.verify(&public, test.message, test.signature)
				if err != nil || !accepted {
					panic("r51x5: singleton HEEA allocation fixture rejected")
				}
			}); allocs != 0 {
				t.Fatalf("allocations=%v want 0", allocs)
			}
		})
	}
}

func BenchmarkExperimentalPackedHEEAStrictVerifierX8(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skip("AVX-512 IFMA is unavailable")
	}
	private := stded25519.NewKeyFromSeed(bytes.Repeat([]byte{0xb8}, stded25519.SeedSize))
	publicBytes := private.Public().(stded25519.PublicKey)
	var public [32]byte
	copy(public[:], publicBytes)

	message := make([]byte, 1232)
	var signature []byte
	for counter := 0; counter < 4096; counter++ {
		for index := range message {
			message[index] = byte(counter*13 + index*31)
		}
		candidateSignature := stded25519.Sign(private, message)
		challenge, ok := experimentalChallengeScalarX4(&public, message, candidateSignature)
		if !ok {
			b.Fatal("challenge reduction failed")
		}
		if admittedExperimentalHEEACandidate(heea8l.SelectLehmer(challenge, heea8l.Width128), heea8l.Width128) {
			signature = candidateSignature
			break
		}
	}
	if signature == nil {
		b.Fatal("failed to find W128-admitted benchmark fixture")
	}

	type corpusEntry struct {
		message   []byte
		signature []byte
	}
	corpus := make([]corpusEntry, 256)
	for entry := range corpus {
		entryMessage := make([]byte, 1232)
		for index := range entryMessage {
			entryMessage[index] = byte(entry*47 + index*19)
		}
		corpus[entry] = corpusEntry{
			message:   entryMessage,
			signature: stded25519.Sign(private, entryMessage),
		}
	}

	baseline, err := NewExperimentalPackedStrictVerifierX4()
	if err != nil {
		b.Fatal(err)
	}
	b.Run("path=ordinary-packed-x4", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for iteration := 0; iteration < b.N; iteration++ {
			accepted, err := baseline.Verify(&public, message, signature)
			if err != nil || !accepted {
				b.Fatalf("ordinary=(%v,%v)", accepted, err)
			}
		}
	})
	b.Run("mix=corpus-256/path=ordinary-packed-x4", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for iteration := 0; iteration < b.N; iteration++ {
			entry := &corpus[iteration%len(corpus)]
			accepted, err := baseline.Verify(&public, entry.message, entry.signature)
			if err != nil || !accepted {
				b.Fatalf("ordinary=(%v,%v)", accepted, err)
			}
		}
	})

	for _, width := range []heea8l.WidthLimit{heea8l.Width128, heea8l.Width132, heea8l.Width136} {
		verifier, err := newExperimentalPackedHEEAStrictVerifierX8(width)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(fmt.Sprintf("path=heea-two-chain-zmm/W%d", width), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				accepted, usedHEEA, err := verifier.verify(&public, message, signature)
				if err != nil || !accepted || !usedHEEA {
					b.Fatalf("HEEA=(accepted=%v used=%v err=%v)", accepted, usedHEEA, err)
				}
			}
		})

		admitted := 0
		for entry := range corpus {
			challenge, ok := experimentalChallengeScalarX4(
				&public, corpus[entry].message, corpus[entry].signature,
			)
			if !ok {
				b.Fatal("corpus challenge reduction failed")
			}
			if admittedExperimentalHEEACandidate(heea8l.SelectLehmer(challenge, width), width) {
				admitted++
			}
		}
		b.Run(fmt.Sprintf("mix=corpus-256/path=heea-two-chain-zmm/W%d", width), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			b.ReportMetric(100*float64(admitted)/float64(len(corpus)), "HEEA-admit%")
			for iteration := 0; iteration < b.N; iteration++ {
				entry := &corpus[iteration%len(corpus)]
				accepted, _, err := verifier.verify(&public, entry.message, entry.signature)
				if err != nil || !accepted {
					b.Fatalf("HEEA corpus=(accepted=%v err=%v)", accepted, err)
				}
			}
		})
	}
}
