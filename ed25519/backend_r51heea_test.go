package ed25519

import (
	stded25519 "crypto/ed25519"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/bits"
	"runtime"
	"testing"

	"github.com/Overclock-Validator/narya-ed25519/internal/edwards25519"
	"github.com/Overclock-Validator/narya-ed25519/internal/heea8l"
	"github.com/Overclock-Validator/narya-ed25519/internal/r51x5"
	"github.com/Overclock-Validator/narya-ed25519/sha512mb"
)

// r51HEEAPipeline is a forced, test-only complete DalekStrict experiment.
// It is deliberately unreachable from backend registration and automatic
// dispatch. Each group performs strict byte preparation, paired A/R decode,
// native segmented SHA-512 and fixed scalar reduction, allocation-free HEEA
// selection modulo 8L, cold R/A table construction, the exact transformed
// equation, and an identity test. Selector or lane-admission misses explicitly
// execute an ordinary radix-32 r51 DSM of the same x8/two-x4 shape, reusing
// the decoded points and reduced challenges. Kernel errors remain surfaced by
// this forced harness and clear every verdict; production policy would need a
// separately implemented and tested fail-safe backend fallback.
//
// All workspaces are mutable, so a pipeline is deliberately not safe for
// concurrent use.
type r51HEEAPipeline struct {
	kind       r51IFMAPipelineKind
	width      heea8l.WidthLimit
	radixBits  uint
	x8         r51IFMAHEEAWorkspaceX8
	x4         [2]r51IFMAHEEAWorkspaceX4
	ordinaryX8 r51IFMAFixedDSMWorkspaceX8
	ordinaryX4 [2]r51IFMAFixedDSMWorkspaceX4
}

// r51IFMAHEEAWorkspaceX4 keeps the selected generic workspace instantiation
// behind concrete calls. Invoking these methods through an interface makes
// each point, coefficient, and output scratch argument escape once per group.
type r51IFMAHEEAWorkspaceX4 struct {
	radixBits uint8
	radix16   *r51x5.ExperimentalIFMAHEEABaseSplitWorkspaceRadix16X4
	radix32   *r51x5.ExperimentalIFMAHEEABaseSplitWorkspaceX4
	radix64   *r51x5.ExperimentalIFMAHEEABaseSplitWorkspaceRadix64X4
}

// r51IFMAHEEAWorkspaceX8 is the eight-lane counterpart.
type r51IFMAHEEAWorkspaceX8 struct {
	radixBits uint8
	radix16   *r51x5.ExperimentalIFMAHEEABaseSplitWorkspaceRadix16X8
	radix32   *r51x5.ExperimentalIFMAHEEABaseSplitWorkspaceX8
	radix64   *r51x5.ExperimentalIFMAHEEABaseSplitWorkspaceRadix64X8
}

func (workspace *r51IFMAHEEAWorkspaceX4) PrepareFixedBase(base *r51x5.PointX4, radixBits uint) error {
	switch workspace.radixBits {
	case 4:
		return workspace.radix16.PrepareFixedBase(base, radixBits)
	case 5:
		return workspace.radix32.PrepareFixedBase(base, radixBits)
	case 6:
		return workspace.radix64.PrepareFixedBase(base, radixBits)
	default:
		panic("ed25519: uninitialized forced r51 HEEA x4 workspace")
	}
}

func (workspace *r51IFMAHEEAWorkspaceX4) PrepareVariableBasesAffineR(R *r51x5.AffinePointX4, A *r51x5.PointX4, decodedValid uint8) error {
	switch workspace.radixBits {
	case 4:
		return workspace.radix16.PrepareVariableBasesAffineR(R, A, decodedValid)
	case 5:
		return workspace.radix32.PrepareVariableBasesAffineR(R, A, decodedValid)
	case 6:
		return workspace.radix64.PrepareVariableBasesAffineR(R, A, decodedValid)
	default:
		panic("ed25519: uninitialized forced r51 HEEA x4 workspace")
	}
}

func (workspace *r51IFMAHEEAWorkspaceX4) Evaluate(out *r51x5.IFMAPointX4, coefficients *r51x5.ExperimentalHEEABaseSplitCoefficientsX4, active uint8) (uint8, uint8, error) {
	switch workspace.radixBits {
	case 4:
		return workspace.radix16.Evaluate(out, coefficients, active)
	case 5:
		return workspace.radix32.Evaluate(out, coefficients, active)
	case 6:
		return workspace.radix64.Evaluate(out, coefficients, active)
	default:
		panic("ed25519: uninitialized forced r51 HEEA x4 workspace")
	}
}

func (workspace *r51IFMAHEEAWorkspaceX8) PrepareFixedBase(base *r51x5.PointX8, radixBits uint) error {
	switch workspace.radixBits {
	case 4:
		return workspace.radix16.PrepareFixedBase(base, radixBits)
	case 5:
		return workspace.radix32.PrepareFixedBase(base, radixBits)
	case 6:
		return workspace.radix64.PrepareFixedBase(base, radixBits)
	default:
		panic("ed25519: uninitialized forced r51 HEEA x8 workspace")
	}
}

func (workspace *r51IFMAHEEAWorkspaceX8) PrepareVariableBasesAffineR(R *r51x5.AffinePointX8, A *r51x5.PointX8, decodedValid uint8) error {
	switch workspace.radixBits {
	case 4:
		return workspace.radix16.PrepareVariableBasesAffineR(R, A, decodedValid)
	case 5:
		return workspace.radix32.PrepareVariableBasesAffineR(R, A, decodedValid)
	case 6:
		return workspace.radix64.PrepareVariableBasesAffineR(R, A, decodedValid)
	default:
		panic("ed25519: uninitialized forced r51 HEEA x8 workspace")
	}
}

func (workspace *r51IFMAHEEAWorkspaceX8) Evaluate(out *r51x5.IFMAPointX8, coefficients *r51x5.ExperimentalHEEABaseSplitCoefficientsX8, active uint8) (uint8, uint8, error) {
	switch workspace.radixBits {
	case 4:
		return workspace.radix16.Evaluate(out, coefficients, active)
	case 5:
		return workspace.radix32.Evaluate(out, coefficients, active)
	case 6:
		return workspace.radix64.Evaluate(out, coefficients, active)
	default:
		panic("ed25519: uninitialized forced r51 HEEA x8 workspace")
	}
}

const r51HEEAOrdinaryFallbackRadixBits = 5

type r51HEEABenchmarkBackend struct {
	pipeline *r51HEEAPipeline
	stats    r51HEEAFallbackStats
	err      error
}

func (*r51HEEABenchmarkBackend) name() string { return "forced-r51-heea-benchmark" }

func (*r51HEEABenchmarkBackend) verify(Profile, *[32]byte, []byte, []byte, *PrecomputedKey) bool {
	panic("ed25519: forced r51 HEEA benchmark backend has no single-signature path")
}

func (*r51HEEABenchmarkBackend) verifyBatch(Profile, []batchItem) {
	panic("ed25519: forced r51 HEEA benchmark backend bypassed raw batch dispatch")
}

func (*r51HEEABenchmarkBackend) supportsPrecomp() bool { return false }

func (*r51HEEABenchmarkBackend) buildPrecomp(pub *[32]byte) (*PrecomputedKey, error) {
	return &PrecomputedKey{raw: *pub}, nil
}

func (b *r51HEEABenchmarkBackend) verifyBatchRaw(profile Profile, pubs []*[32]byte, msgs, sigs [][]byte, ok []bool) bool {
	if profile != DalekStrict {
		b.stats = r51HEEAFallbackStats{}
		b.err = fmt.Errorf("ed25519: forced r51 HEEA benchmark requires strict profile")
		return false
	}
	var all bool
	all, b.stats, b.err = b.pipeline.VerifyBatch(pubs, msgs, sigs, ok)
	return all
}

type r51HEEAFallbackStats struct {
	Selector    uint64
	Preparation uint64
	Evaluation  uint64
	Ordinary    uint64
}

func (stats *r51HEEAFallbackStats) add(other r51HEEAFallbackStats) {
	stats.Selector += other.Selector
	stats.Preparation += other.Preparation
	stats.Evaluation += other.Evaluation
	stats.Ordinary += other.Ordinary
}

func (stats r51HEEAFallbackStats) sourceTotal() uint64 {
	return stats.Selector + stats.Preparation + stats.Evaluation
}

func validateR51HEEAFallbackMasks(live, usable uint8, handoff r51HEEASelectorMasks, evaluationFallback uint8) error {
	selectorOrPreparation := handoff.SelectorFallback | handoff.PreparationFallback
	combined := selectorOrPreparation | evaluationFallback
	want := live &^ usable
	if handoff.SelectorFallback&handoff.PreparationFallback != 0 || selectorOrPreparation&evaluationFallback != 0 || combined != want {
		return fmt.Errorf("ed25519: forced r51 HEEA fallback masks are not an exact partition: live=%02x usable=%02x selector=%02x preparation=%02x evaluation=%02x", live, usable, handoff.SelectorFallback, handoff.PreparationFallback, evaluationFallback)
	}
	return nil
}

func validR51HEEAWidth(width heea8l.WidthLimit) bool {
	return width == heea8l.Width128 || width == heea8l.Width132 || width == heea8l.Width136
}

func newR51HEEAPipeline(kind r51IFMAPipelineKind, width heea8l.WidthLimit, radixBits uint) (*r51HEEAPipeline, error) {
	if kind != r51IFMATwoX4 && kind != r51IFMAX8 {
		return nil, fmt.Errorf("ed25519: invalid forced r51 HEEA pipeline %d", kind)
	}
	if !validR51HEEAWidth(width) {
		return nil, fmt.Errorf("ed25519: invalid forced r51 HEEA width %d", width)
	}
	if radixBits != 4 && radixBits != 5 {
		return nil, fmt.Errorf("ed25519: invalid forced r51 HEEA radix %d", 1<<radixBits)
	}
	if !r51IFMAPipelineAvailable(kind) {
		if !r51x5.ExperimentalIFMAAvailable() {
			return nil, r51x5.ErrIFMAUnavailable
		}
		return nil, fmt.Errorf("ed25519: forced %s SHA-512 kernel unavailable", kind)
	}

	generatorEncoding := edwards25519.NewGeneratorPoint().Bytes()
	var generator r51x5.Point
	if _, err := generator.SetBytes(generatorEncoding); err != nil {
		return nil, fmt.Errorf("ed25519: r51 HEEA generator decode: %w", err)
	}
	pipeline := &r51HEEAPipeline{kind: kind, width: width, radixBits: radixBits}
	if kind == r51IFMAX8 {
		var lanes [r51x5.X8Lanes]r51x5.Point
		for lane := range lanes {
			lanes[lane] = generator
		}
		var base r51x5.PointX8
		base.SetPoints(&lanes)
		pipeline.x8 = newR51IFMAHEEAWorkspaceX8(radixBits)
		if err := pipeline.x8.PrepareFixedBase(&base, radixBits); err != nil {
			return nil, err
		}
		pipeline.ordinaryX8 = newR51IFMAFixedDSMWorkspaceX8(r51HEEAOrdinaryFallbackRadixBits)
		if err := pipeline.ordinaryX8.PrepareFixedBase(&base, r51HEEAOrdinaryFallbackRadixBits); err != nil {
			return nil, err
		}
		return pipeline, nil
	}

	var lanes [r51x5.X4Lanes]r51x5.Point
	for lane := range lanes {
		lanes[lane] = generator
	}
	var base r51x5.PointX4
	base.SetPoints(&lanes)
	for half := range pipeline.x4 {
		pipeline.x4[half] = newR51IFMAHEEAWorkspaceX4(radixBits)
		if err := pipeline.x4[half].PrepareFixedBase(&base, radixBits); err != nil {
			return nil, err
		}
		pipeline.ordinaryX4[half] = newR51IFMAFixedDSMWorkspaceX4(r51HEEAOrdinaryFallbackRadixBits)
		if err := pipeline.ordinaryX4[half].PrepareFixedBase(&base, r51HEEAOrdinaryFallbackRadixBits); err != nil {
			return nil, err
		}
	}
	return pipeline, nil
}

func newR51IFMAHEEAWorkspaceX4(radixBits uint) r51IFMAHEEAWorkspaceX4 {
	workspace := r51IFMAHEEAWorkspaceX4{radixBits: uint8(radixBits)}
	switch radixBits {
	case 4:
		workspace.radix16 = new(r51x5.ExperimentalIFMAHEEABaseSplitWorkspaceRadix16X4)
	case 5:
		workspace.radix32 = new(r51x5.ExperimentalIFMAHEEABaseSplitWorkspaceX4)
	case 6:
		workspace.radix64 = new(r51x5.ExperimentalIFMAHEEABaseSplitWorkspaceRadix64X4)
	default:
		panic("ed25519: unsupported forced r51 HEEA radix")
	}
	return workspace
}

func newR51IFMAHEEAWorkspaceX8(radixBits uint) r51IFMAHEEAWorkspaceX8 {
	workspace := r51IFMAHEEAWorkspaceX8{radixBits: uint8(radixBits)}
	switch radixBits {
	case 4:
		workspace.radix16 = new(r51x5.ExperimentalIFMAHEEABaseSplitWorkspaceRadix16X8)
	case 5:
		workspace.radix32 = new(r51x5.ExperimentalIFMAHEEABaseSplitWorkspaceX8)
	case 6:
		workspace.radix64 = new(r51x5.ExperimentalIFMAHEEABaseSplitWorkspaceRadix64X8)
	default:
		panic("ed25519: unsupported forced r51 HEEA radix")
	}
	return workspace
}

// r51HEEASelectorCandidate is the only selector-to-QSM handoff. Callers
// cannot supply a diagnostic WidthExceeded candidate: selection is performed
// internally from the canonical challenge and admission requires both
// UseCandidate and NoFallback at the configured width.
type r51HEEASelectorCandidate struct {
	tau     r51x5.ExperimentalHEEASignedCoefficient
	rho     r51x5.ExperimentalHEEASignedCoefficient
	epsilon int8
}

func selectR51HEEACandidate(k [32]byte, width heea8l.WidthLimit) (r51HEEASelectorCandidate, bool, heea8l.FallbackReason) {
	selection := heea8l.SelectShiftSubtract(k, width)
	if !selection.UseCandidate || selection.Fallback != heea8l.NoFallback ||
		!validR51HEEAWidth(width) || selection.Candidate.BitLen() > int(width) ||
		(selection.Candidate.Epsilon != -1 && selection.Candidate.Epsilon != 1) ||
		selection.Candidate.Tau.Sign() == 0 || selection.Candidate.Tau.Limbs[0]&1 == 0 ||
		!selection.Candidate.UnitMultiplier() {
		fallback := selection.Fallback
		if fallback == heea8l.NoFallback {
			// An admitted non-unit tau would violate the selector's
			// injectivity contract. Treat a defensive invariant failure as
			// an ordinary fallback, never as an admitted equation.
			fallback = heea8l.FallbackWidthExceeded
		}
		return r51HEEASelectorCandidate{}, false, fallback
	}
	return r51HEEASelectorCandidate{
		tau: r51x5.ExperimentalHEEASignedCoefficient{
			Magnitude: selection.Candidate.Tau.BytesLE(),
			Negative:  selection.Candidate.Tau.Negative,
		},
		rho: r51x5.ExperimentalHEEASignedCoefficient{
			Magnitude: selection.Candidate.Rho.BytesLE(),
			Negative:  selection.Candidate.Rho.Negative,
		},
		epsilon: selection.Candidate.Epsilon,
	}, true, heea8l.NoFallback
}

type r51HEEASelectorMasks struct {
	SelectorCandidate   uint8
	Prepared            uint8
	SelectorFallback    uint8
	PreparationFallback uint8
}

// prepareR51HEEACoefficientsX8 keeps selector admission and coefficient
// preparation atomic. In particular, it passes only admitted selector lanes
// to coefficient preparation; an odd diagnostic candidate returned alongside
// WidthExceeded can never enter the transformed equation.
func prepareR51HEEACoefficientsX8(out *r51x5.ExperimentalHEEABaseSplitCoefficientsX8, s, k *[r51x5.X8Lanes][32]byte, width heea8l.WidthLimit, active uint8) r51HEEASelectorMasks {
	var tau, rho [r51x5.X8Lanes]r51x5.ExperimentalHEEASignedCoefficient
	var epsilon [r51x5.X8Lanes]int8
	selectorCandidate := active
	for lane := 0; lane < r51x5.X8Lanes; lane++ {
		laneMask := uint8(1 << lane)
		if active&laneMask == 0 {
			continue
		}
		candidate, use, _ := selectR51HEEACandidate(k[lane], width)
		if !use {
			selectorCandidate &^= laneMask
			continue
		}
		tau[lane], rho[lane], epsilon[lane] = candidate.tau, candidate.rho, candidate.epsilon
	}
	prepared, preparationFallback := r51x5.ExperimentalPrepareHEEABaseSplitCoefficientsX8(
		out, s, &tau, &rho, &epsilon, selectorCandidate,
	)
	return r51HEEASelectorMasks{
		SelectorCandidate:   selectorCandidate,
		Prepared:            prepared,
		SelectorFallback:    active &^ selectorCandidate,
		PreparationFallback: preparationFallback,
	}
}

func (pipeline *r51HEEAPipeline) VerifyBatch(pubs []*[32]byte, msgs, sigs [][]byte, ok []bool) (bool, r51HEEAFallbackStats, error) {
	if len(pubs) != len(msgs) || len(msgs) != len(sigs) || len(sigs) != len(ok) {
		panic("ed25519: forced r51 HEEA batch slice lengths differ")
	}
	for index := range ok {
		ok[index] = false
	}

	var stats r51HEEAFallbackStats
	for offset := 0; offset < len(pubs); offset += r51x5.X8Lanes {
		count := minR51(len(pubs)-offset, r51x5.X8Lanes)
		var groupStats r51HEEAFallbackStats
		var err error
		if pipeline.kind == r51IFMAX8 {
			groupStats, err = pipeline.verifyGroupX8(pubs, msgs, sigs, ok, offset, count)
		} else {
			groupStats, err = pipeline.verifyGroupTwoX4(pubs, msgs, sigs, ok, offset, count)
		}
		stats.add(groupStats)
		if err != nil {
			// A forced research backend must not expose a mixture of stale,
			// completed, and failed-group verdicts. No generic fallback is
			// hidden here: callers receive the error and a fail-closed mask.
			for index := range ok {
				ok[index] = false
			}
			return false, stats, err
		}
	}

	all := true
	for _, verdict := range ok {
		all = all && verdict
	}
	return all, stats, nil
}

func (pipeline *r51HEEAPipeline) verifyGroupX8(pubs []*[32]byte, msgs, sigs [][]byte, ok []bool, offset, count int) (r51HEEAFallbackStats, error) {
	var stats r51HEEAFallbackStats
	var aBytes, rBytes [r51x5.X8Lanes][32]byte
	var s [r51x5.X8Lanes][32]byte
	var candidates uint8
	for lane := 0; lane < count; lane++ {
		index := offset + lane
		coefficient, valid := prepareR51Signature(DalekStrict, pubs[index], sigs[index])
		if !valid {
			continue
		}
		aBytes[lane] = *pubs[index]
		copy(rBytes[lane][:], sigs[index][:32])
		s[lane] = coefficient
		candidates |= 1 << lane
	}

	var A r51x5.PointX8
	var R r51x5.AffinePointX8
	aValid, rValid, err := r51x5.ExperimentalIFMADecode2NoTX8(&A, &R, &aBytes, &rBytes, candidates)
	if err != nil {
		return stats, err
	}
	live := candidates & aValid & rValid
	if live == 0 {
		return stats, nil
	}

	var k [r51x5.X8Lanes][32]byte
	live, err = reduceR51NativeChallengesX8(&k, pubs, msgs, sigs, offset, count, live, sha512mb.ExperimentalWidthX8)
	if err != nil || live == 0 {
		return stats, err
	}

	var coefficients r51x5.ExperimentalHEEABaseSplitCoefficientsX8
	handoff := prepareR51HEEACoefficientsX8(&coefficients, &s, &k, pipeline.width, live)
	stats.Selector = uint64(bits.OnesCount8(handoff.SelectorFallback))
	stats.Preparation = uint64(bits.OnesCount8(handoff.PreparationFallback))

	var accepted, usable, evaluationFallback uint8
	if handoff.Prepared != 0 {
		// Retain the fully prepared selector mask in the workspace as an
		// independent gate; every selector/preparation fallback lane is
		// identity-filled before table construction.
		if err := pipeline.x8.PrepareVariableBasesAffineR(&R, &A, handoff.Prepared); err != nil {
			return stats, err
		}
		var looseQ r51x5.IFMAPointX8
		usable, evaluationFallback, err = pipeline.x8.Evaluate(&looseQ, &coefficients, handoff.Prepared)
		if err != nil {
			return stats, err
		}
		stats.Evaluation = uint64(bits.OnesCount8(evaluationFallback))
		Q := looseQ.Reduced()
		accepted = Q.IsIdentity() & usable
	}

	fallback := live &^ usable
	if err := validateR51HEEAFallbackMasks(live, usable, handoff, evaluationFallback); err != nil {
		return stats, err
	}
	stats.Ordinary = uint64(bits.OnesCount8(fallback))
	ordinaryAccepted, err := pipeline.verifyOrdinaryFallbackX8(&A, &R, &s, &k, fallback)
	if err != nil {
		return stats, err
	}
	accepted |= ordinaryAccepted
	for lane := 0; lane < count; lane++ {
		ok[offset+lane] = accepted&(1<<lane) != 0
	}
	return stats, nil
}

// verifyOrdinaryFallbackX8 evaluates [s]B-[k]A=R for exactly fallback. The
// inputs have already passed strict byte preparation, paired decode, and
// challenge reduction, so this path neither decodes nor hashes a second time.
// A lost lane is an internal invariant failure, not an invalid signature; it
// is surfaced as an error rather than silently converted into rejection.
func (pipeline *r51HEEAPipeline) verifyOrdinaryFallbackX8(A *r51x5.PointX8, R *r51x5.AffinePointX8, s, k *[r51x5.X8Lanes][32]byte, fallback uint8) (uint8, error) {
	if fallback == 0 {
		return 0, nil
	}
	if err := pipeline.ordinaryX8.PrepareVariableBase(A); err != nil {
		return 0, err
	}
	var coefficients r51x5.FixedDSMScalarsX8
	for lane := 0; lane < r51x5.X8Lanes; lane++ {
		if fallback&(1<<lane) == 0 {
			continue
		}
		coefficients[0][lane] = s[lane]
		coefficients[1][lane] = k[lane]
	}
	negative := [r51x5.DSMTerms]uint8{0, fallback}
	var looseQ r51x5.IFMAPointX8
	usable, err := pipeline.ordinaryX8.Evaluate(&looseQ, &coefficients, &negative, fallback)
	if err != nil {
		return 0, err
	}
	if usable != fallback {
		return 0, fmt.Errorf("ed25519: forced r51 HEEA ordinary x8 fallback lost lanes: active=%02x usable=%02x", fallback, usable)
	}
	Q := looseQ.Reduced()
	return Q.EqualCompactAffine(R) & usable, nil
}

func (pipeline *r51HEEAPipeline) verifyGroupTwoX4(pubs []*[32]byte, msgs, sigs [][]byte, ok []bool, offset, count int) (r51HEEAFallbackStats, error) {
	var stats r51HEEAFallbackStats
	var aBytes, rBytes [2][r51x5.X4Lanes][32]byte
	var s [r51x5.X8Lanes][32]byte
	var candidates uint8
	for lane := 0; lane < count; lane++ {
		index := offset + lane
		coefficient, valid := prepareR51Signature(DalekStrict, pubs[index], sigs[index])
		if !valid {
			continue
		}
		half, local := lane/r51x5.X4Lanes, lane%r51x5.X4Lanes
		aBytes[half][local] = *pubs[index]
		copy(rBytes[half][local][:], sigs[index][:32])
		s[lane] = coefficient
		candidates |= 1 << lane
	}

	var A [2]r51x5.PointX4
	var R [2]r51x5.AffinePointX4
	var live uint8
	for half := 0; half < 2; half++ {
		active := uint8(candidates>>(half*r51x5.X4Lanes)) & 0x0f
		if active == 0 {
			continue
		}
		aValid, rValid, err := r51x5.ExperimentalIFMADecode2NoTX4(&A[half], &R[half], &aBytes[half], &rBytes[half], active)
		if err != nil {
			return stats, err
		}
		live |= (active & aValid & rValid) << (half * r51x5.X4Lanes)
	}
	if live == 0 {
		return stats, nil
	}

	var k [r51x5.X8Lanes][32]byte
	var err error
	live, err = reduceR51NativeChallengesX8(&k, pubs, msgs, sigs, offset, count, live, sha512mb.ExperimentalWidthX4)
	if err != nil || live == 0 {
		return stats, err
	}

	var coefficients8 r51x5.ExperimentalHEEABaseSplitCoefficientsX8
	handoff := prepareR51HEEACoefficientsX8(&coefficients8, &s, &k, pipeline.width, live)
	stats.Selector = uint64(bits.OnesCount8(handoff.SelectorFallback))
	stats.Preparation = uint64(bits.OnesCount8(handoff.PreparationFallback))
	var coefficients4 [2]r51x5.ExperimentalHEEABaseSplitCoefficientsX4
	r51x5.ExperimentalSplitHEEABaseSplitCoefficientsX8(&coefficients4, &coefficients8)

	var accepted, usable, evaluationFallback uint8
	for half := 0; half < 2; half++ {
		prepared := uint8(handoff.Prepared>>(half*r51x5.X4Lanes)) & 0x0f
		if prepared == 0 {
			continue
		}
		if err := pipeline.x4[half].PrepareVariableBasesAffineR(&R[half], &A[half], prepared); err != nil {
			return stats, err
		}
		var looseQ r51x5.IFMAPointX4
		usableHalf, fallbackHalf, err := pipeline.x4[half].Evaluate(&looseQ, &coefficients4[half], prepared)
		if err != nil {
			return stats, err
		}
		stats.Evaluation += uint64(bits.OnesCount8(fallbackHalf))
		evaluationFallback |= fallbackHalf << (half * r51x5.X4Lanes)
		Q := looseQ.Reduced()
		accepted |= (Q.IsIdentity() & usableHalf) << (half * r51x5.X4Lanes)
		usable |= usableHalf << (half * r51x5.X4Lanes)
	}

	fallback := live &^ usable
	if err := validateR51HEEAFallbackMasks(live, usable, handoff, evaluationFallback); err != nil {
		return stats, err
	}
	stats.Ordinary = uint64(bits.OnesCount8(fallback))
	ordinaryAccepted, err := pipeline.verifyOrdinaryFallbackTwoX4(&A, &R, &s, &k, fallback)
	if err != nil {
		return stats, err
	}
	accepted |= ordinaryAccepted
	for lane := 0; lane < count; lane++ {
		ok[offset+lane] = accepted&(1<<lane) != 0
	}
	return stats, nil
}

// verifyOrdinaryFallbackTwoX4 is the two independent YMM-group counterpart of
// verifyOrdinaryFallbackX8. Bit positions are remapped explicitly between the
// aggregate eight-lane mask and each local four-lane verdict.
func (pipeline *r51HEEAPipeline) verifyOrdinaryFallbackTwoX4(A *[2]r51x5.PointX4, R *[2]r51x5.AffinePointX4, s, k *[r51x5.X8Lanes][32]byte, fallback uint8) (uint8, error) {
	var accepted uint8
	for half := 0; half < 2; half++ {
		shift := half * r51x5.X4Lanes
		active := uint8(fallback>>shift) & 0x0f
		if active == 0 {
			continue
		}
		if err := pipeline.ordinaryX4[half].PrepareVariableBase(&A[half]); err != nil {
			return 0, err
		}
		var coefficients r51x5.FixedDSMScalarsX4
		for local := 0; local < r51x5.X4Lanes; local++ {
			if active&(1<<local) == 0 {
				continue
			}
			lane := shift + local
			coefficients[0][local] = s[lane]
			coefficients[1][local] = k[lane]
		}
		negative := [r51x5.DSMTerms]uint8{0, active}
		var looseQ r51x5.IFMAPointX4
		usable, err := pipeline.ordinaryX4[half].Evaluate(&looseQ, &coefficients, &negative, active)
		if err != nil {
			return 0, err
		}
		if usable != active {
			return 0, fmt.Errorf("ed25519: forced r51 HEEA ordinary x4 fallback lost lanes: half=%d active=%02x usable=%02x", half, active, usable)
		}
		Q := looseQ.Reduced()
		accepted |= (Q.EqualCompactAffine(&R[half]) & usable) << shift
	}
	return accepted, nil
}

func requireR51HEEAPipeline(t testing.TB, kind r51IFMAPipelineKind, width heea8l.WidthLimit, radixBits uint) *r51HEEAPipeline {
	t.Helper()
	if !r51IFMAPipelineAvailable(kind) {
		t.Skipf("forced %s r51 HEEA pipeline unavailable on %s/%s", kind, runtime.GOOS, runtime.GOARCH)
	}
	pipeline, err := newR51HEEAPipeline(kind, width, radixBits)
	if err != nil {
		t.Fatalf("new forced %s HEEA W%d radix %d pipeline: %v", kind, width, 1<<radixBits, err)
	}
	return pipeline
}

// verifyR51HEEAScalarModel is the non-IFMA semantic integration oracle. It
// executes the same strict preparation, hashes the original bytes, invokes
// the same atomic selector handoff, and evaluates the transformed equation
// with the independently tested scalar r51 base-split QSM. Selector misses
// intentionally use the generic strict reference as a semantic oracle; only
// the timed hardware experiment uses the ordinary r51 DSM fallback.
func verifyR51HEEAScalarModel(pub *[32]byte, message, sig []byte, width heea8l.WidthLimit, radixBits uint) (accepted, fellBack bool) {
	sBytes, valid := prepareR51Signature(DalekStrict, pub, sig)
	if !valid {
		return false, false
	}
	var A, R r51x5.Point
	if _, err := A.SetBytes(pub[:]); err != nil {
		return false, false
	}
	if _, err := R.SetBytes(sig[:32]); err != nil {
		return false, false
	}

	hash := sha512.New()
	_, _ = hash.Write(sig[:32])
	_, _ = hash.Write(pub[:])
	_, _ = hash.Write(message)
	var digest [sha512.Size]byte
	hash.Sum(digest[:0])
	kScalar, err := edwards25519.NewScalar().SetUniformBytes(digest[:])
	if err != nil {
		return false, false
	}
	var kBytes [32]byte
	copy(kBytes[:], kScalar.Bytes())
	candidate, use, _ := selectR51HEEACandidate(kBytes, width)
	if !use {
		return referenceVerifyProfile(DalekStrict, pub, message, sig), true
	}

	generatorEncoding := edwards25519.NewGeneratorPoint().Bytes()
	var B r51x5.Point
	if _, err := B.SetBytes(generatorEncoding); err != nil {
		panic(fmt.Sprintf("ed25519: scalar HEEA generator decode: %v", err))
	}
	var bLanes, rLanes, aLanes [r51x5.X8Lanes]r51x5.Point
	for lane := range bLanes {
		bLanes[lane] = B
		rLanes[lane] = R
		aLanes[lane] = A
	}
	var BX8, B128X8, RX8, AX8 r51x5.PointX8
	BX8.SetPoints(&bLanes)
	RX8.SetPoints(&rLanes)
	AX8.SetPoints(&aLanes)
	r51x5.ExperimentalHEEABaseSplitB128X8(&B128X8, &BX8)

	var s, tau, rho [r51x5.X8Lanes]r51x5.SignedMagnitude
	var epsilon [r51x5.X8Lanes]int8
	s[0] = r51x5.NewSignedMagnitude(sBytes[:], false)
	tau[0] = r51x5.NewSignedMagnitude(candidate.tau.Magnitude[:], candidate.tau.Negative)
	rho[0] = r51x5.NewSignedMagnitude(candidate.rho.Magnitude[:], candidate.rho.Negative)
	epsilon[0] = candidate.epsilon
	var Q r51x5.PointX8
	usable := r51x5.ExperimentalHEEABaseSplitEquationX8(
		&Q, &BX8, &B128X8, &RX8, &AX8, &s, &tau, &rho, &epsilon, radixBits, 1,
	)
	if usable != 1 {
		return referenceVerifyProfile(DalekStrict, pub, message, sig), true
	}
	return Q.IsIdentity()&1 != 0, false
}

func r51HEEAReferenceBatch(vectors []r51ReferenceVector) (pubs []*[32]byte, msgs, sigs [][]byte, ok []bool) {
	pubs = make([]*[32]byte, len(vectors))
	msgs = make([][]byte, len(vectors))
	sigs = make([][]byte, len(vectors))
	ok = make([]bool, len(vectors))
	for index := range vectors {
		pubs[index] = &vectors[index].pub
		msgs[index] = vectors[index].msg
		sigs[index] = vectors[index].sig
	}
	return pubs, msgs, sigs, ok
}

func assertR51HEEAPipelineVectors(t *testing.T, pipeline *r51HEEAPipeline, vectors []r51ReferenceVector) r51HEEAFallbackStats {
	t.Helper()
	pubs, msgs, sigs, got := r51HEEAReferenceBatch(vectors)
	want := make([]bool, len(vectors))
	wantAll := true
	for index := range vectors {
		want[index] = referenceVerifyProfile(DalekStrict, pubs[index], msgs[index], sigs[index])
		model, _ := verifyR51HEEAScalarModel(pubs[index], msgs[index], sigs[index], pipeline.width, pipeline.radixBits)
		if model != want[index] {
			t.Fatalf("%s scalar HEEA model W%d radix=%d got=%v want=%v", vectors[index].name, pipeline.width, 1<<pipeline.radixBits, model, want[index])
		}
		wantAll = wantAll && want[index]
	}
	gotAll, stats, err := pipeline.VerifyBatch(pubs, msgs, sigs, got)
	if err != nil {
		t.Fatalf("%s W%d radix=%d: %v", pipeline.kind, pipeline.width, 1<<pipeline.radixBits, err)
	}
	if stats.Ordinary != stats.sourceTotal() {
		t.Fatalf("%s W%d radix=%d fallback accounting=%+v: ordinary must equal disjoint selector+preparation+evaluation sources", pipeline.kind, pipeline.width, 1<<pipeline.radixBits, stats)
	}
	if gotAll != wantAll {
		t.Fatalf("%s W%d radix=%d aggregate=%v want=%v stats=%+v", pipeline.kind, pipeline.width, 1<<pipeline.radixBits, gotAll, wantAll, stats)
	}
	for index := range vectors {
		if got[index] != want[index] {
			t.Fatalf("%s %s W%d radix=%d got=%v want=%v stats=%+v\npub=%x\nmsg=%x\nsig=%x", vectors[index].name, pipeline.kind, pipeline.width, 1<<pipeline.radixBits, got[index], want[index], stats, vectors[index].pub, vectors[index].msg, vectors[index].sig)
		}
	}
	return stats
}

func makeR51HEEASelectorVector(tb testing.TB, width heea8l.WidthLimit, admitted bool) r51ReferenceVector {
	return makeR51HEEASelectorVectorSized(tb, width, admitted, 24)
}

func makeR51HEEASelectorVectorSized(tb testing.TB, width heea8l.WidthLimit, admitted bool, messageSize int) r51ReferenceVector {
	tb.Helper()
	if messageSize < 8 {
		tb.Fatalf("HEEA selector fixture message size %d is smaller than the counter", messageSize)
	}
	var seed [stded25519.SeedSize]byte
	copy(seed[:], []byte("narya-r51-heea-selector-fixture"))
	privateKey := stded25519.NewKeyFromSeed(seed[:])
	publicKey := privateKey.Public().(stded25519.PublicKey)
	var pub [stded25519.PublicKeySize]byte
	copy(pub[:], publicKey)
	for counter := uint64(0); counter < 1<<16; counter++ {
		message := make([]byte, messageSize)
		copy(message, []byte("HEEA selector fixture"))
		binary.LittleEndian.PutUint64(message[len(message)-8:], counter)
		sig := stded25519.Sign(privateKey, message)
		hash := sha512.New()
		_, _ = hash.Write(sig[:32])
		_, _ = hash.Write(pub[:])
		_, _ = hash.Write(message)
		var digest [sha512.Size]byte
		hash.Sum(digest[:0])
		k, err := edwards25519.NewScalar().SetUniformBytes(digest[:])
		if err != nil {
			tb.Fatal(err)
		}
		var kBytes [32]byte
		copy(kBytes[:], k.Bytes())
		_, use, _ := selectR51HEEACandidate(kBytes, width)
		if use == admitted {
			return r51ReferenceVector{
				name: fmt.Sprintf("selector-admitted=%v-W%d-msg=%d", admitted, width, messageSize),
				pub:  pub,
				msg:  message,
				sig:  sig,
			}
		}
	}
	tb.Fatalf("failed to find HEEA selector admitted=%v fixture at W%d with message size %d", admitted, width, messageSize)
	return r51ReferenceVector{}
}

func makeR51HEEANoncanonicalAInvalidVector(t *testing.T) r51ReferenceVector {
	t.Helper()
	vector := makeR51HonestVectors(t, 1)[0]
	for alias := byte(2); alias <= 18; alias++ {
		candidate := [32]byte{0: 0xed + alias, 31: 0x7f}
		for index := 1; index < 31; index++ {
			candidate[index] = 0xff
		}
		for sign := byte(0); sign <= 1; sign++ {
			candidate[31] = 0x7f | sign<<7
			if _, err := new(r51x5.Point).SetBytes(candidate[:]); err == nil && !smallOrderEncoding(candidate[:]) {
				vector.name = "noncanonical-decodable-A-invalid-equation"
				vector.pub = candidate
				return vector
			}
		}
	}
	t.Fatal("failed to find decodable noncanonical non-small-order A")
	return r51ReferenceVector{}
}

func TestR51HEEASelectorHandoffAtomicMasks(t *testing.T) {
	admittedVector := makeR51HEEASelectorVector(t, heea8l.Width128, true)
	fallbackVector := makeR51HEEASelectorVector(t, heea8l.Width128, false)
	challenge := func(vector r51ReferenceVector) [32]byte {
		hash := sha512.New()
		_, _ = hash.Write(vector.sig[:32])
		_, _ = hash.Write(vector.pub[:])
		_, _ = hash.Write(vector.msg)
		var digest [sha512.Size]byte
		hash.Sum(digest[:0])
		k, err := edwards25519.NewScalar().SetUniformBytes(digest[:])
		if err != nil {
			t.Fatal(err)
		}
		var result [32]byte
		copy(result[:], k.Bytes())
		return result
	}
	admittedK, fallbackK := challenge(admittedVector), challenge(fallbackVector)
	var s, k [r51x5.X8Lanes][32]byte
	for lane := 0; lane < r51x5.X8Lanes; lane++ {
		s[lane][0] = 1
		if lane&1 == 0 {
			k[lane] = admittedK
		} else {
			k[lane] = fallbackK
		}
	}
	var coefficients r51x5.ExperimentalHEEABaseSplitCoefficientsX8
	masks := prepareR51HEEACoefficientsX8(&coefficients, &s, &k, heea8l.Width128, 0xff)
	if masks.SelectorCandidate != 0x55 || masks.Prepared != 0x55 || masks.SelectorFallback != 0xaa || masks.PreparationFallback != 0 {
		t.Fatalf("atomic handoff masks=%+v, want candidate/prepared=0x55 selector-fallback=0xaa", masks)
	}
	if coefficients.ValidMask() != masks.Prepared {
		t.Fatalf("coefficient valid mask=%02x prepared=%02x", coefficients.ValidMask(), masks.Prepared)
	}

	masks = prepareR51HEEACoefficientsX8(&coefficients, &s, &k, heea8l.WidthLimit(129), 0xff)
	if masks.SelectorCandidate != 0 || masks.Prepared != 0 || masks.SelectorFallback != 0xff || masks.PreparationFallback != 0 {
		t.Fatalf("invalid-width handoff masks=%+v", masks)
	}
}

func TestR51HEEAFallbackMasksFormExactDisjointPartition(t *testing.T) {
	live := uint8(0xff)
	handoff := r51HEEASelectorMasks{
		SelectorCandidate:   0xfe,
		Prepared:            0xde,
		SelectorFallback:    0x01,
		PreparationFallback: 0x20,
	}
	evaluationFallback := uint8(0x84)
	usable := live &^ (handoff.SelectorFallback | handoff.PreparationFallback | evaluationFallback)
	if err := validateR51HEEAFallbackMasks(live, usable, handoff, evaluationFallback); err != nil {
		t.Fatal(err)
	}
	stats := r51HEEAFallbackStats{
		Selector:    uint64(bits.OnesCount8(handoff.SelectorFallback)),
		Preparation: uint64(bits.OnesCount8(handoff.PreparationFallback)),
		Evaluation:  uint64(bits.OnesCount8(evaluationFallback)),
		Ordinary:    uint64(bits.OnesCount8(live &^ usable)),
	}
	if stats.sourceTotal() != stats.Ordinary {
		t.Fatalf("fallback accounting=%+v", stats)
	}

	overlapped := handoff
	overlapped.PreparationFallback |= handoff.SelectorFallback
	if err := validateR51HEEAFallbackMasks(live, usable, overlapped, evaluationFallback); err == nil {
		t.Fatal("overlapping selector/preparation fallback masks were accepted")
	}
	if err := validateR51HEEAFallbackMasks(live, usable|0x80, handoff, evaluationFallback); err == nil {
		t.Fatal("fallback source without an ordinary lane was accepted")
	}
}

func TestR51HEEAScalarEndToEndDifferentialWithoutIFMA(t *testing.T) {
	vectors := makeR51HonestVectors(t, 8)
	invalidEquation := cloneR51Vectors(vectors[:1])[0]
	invalidEquation.name = "invalid-equation"
	invalidEquation.msg[0] ^= 0x80
	admitted := makeR51HEEASelectorVector(t, heea8l.Width128, true)
	fallback := makeR51HEEASelectorVector(t, heea8l.Width128, false)
	invalidFallback := cloneR51Vectors([]r51ReferenceVector{fallback})[0]
	invalidFallback.name = "invalid-equation-selector-fallback-W128"
	invalidFallback.sig[32] ^= 1 // k excludes S, so selector outcome is unchanged.
	if referenceVerifyProfile(DalekStrict, &invalidFallback.pub, invalidFallback.msg, invalidFallback.sig) {
		t.Fatal("mutated selector-fallback signature remained valid")
	}
	vectors = append(vectors, invalidEquation, makeR51MixedOrderValidVector(t), makeR51HEEANoncanonicalAInvalidVector(t), admitted, fallback, invalidFallback)
	for _, width := range []heea8l.WidthLimit{heea8l.Width128, heea8l.Width132, heea8l.Width136} {
		for _, radixBits := range []uint{4, 5} {
			for index := range vectors {
				got, fellBack := verifyR51HEEAScalarModel(&vectors[index].pub, vectors[index].msg, vectors[index].sig, width, radixBits)
				want := referenceVerifyProfile(DalekStrict, &vectors[index].pub, vectors[index].msg, vectors[index].sig)
				if got != want {
					t.Fatalf("%s W%d radix=%d scalar transformed=%v want=%v", vectors[index].name, width, 1<<radixBits, got, want)
				}
				if width == heea8l.Width128 && (vectors[index].name == fallback.name || vectors[index].name == invalidFallback.name) && !fellBack {
					t.Fatalf("%s did not execute ordinary W128 fallback", vectors[index].name)
				}
				if width == heea8l.Width128 && vectors[index].name == admitted.name && fellBack {
					t.Fatalf("%s unexpectedly executed ordinary W128 fallback", vectors[index].name)
				}
			}
		}
	}
}

// TestR51HEEAEvenMultiplierErasesOrderTwoError is the deterministic
// consensus-divergence witness for a selector that admits an even Tau. Let
// A=[a]B and R=[r]B+T2, where T2 has order two, and choose s=r+k*a. The strict
// error point is -T2, so strict verification rejects. Multiplying the entire
// equation by Tau=2 erases that error and accepts. No challenge grinding is
// involved because s is constructed after hashing the original A/R bytes.
func TestR51HEEAEvenMultiplierErasesOrderTwoError(t *testing.T) {
	a := scalarFromUint64(t, 5)
	r := scalarFromUint64(t, 7)
	two := scalarFromUint64(t, 2)
	torsionEncoding, err := hex.DecodeString("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
	if err != nil {
		t.Fatal(err)
	}
	torsion, err := new(edwards25519.Point).SetBytes(torsionEncoding)
	if err != nil {
		t.Fatal(err)
	}
	A := new(edwards25519.Point).ScalarBaseMult(a)
	R := new(edwards25519.Point).Add(new(edwards25519.Point).ScalarBaseMult(r), torsion)
	var pub [stded25519.PublicKeySize]byte
	copy(pub[:], A.Bytes())
	message := []byte("deterministic even-tau torsion discriminator")
	k := strictChallenge(t, R.Bytes(), pub[:], message)
	s := new(edwards25519.Scalar).Multiply(k, a)
	s.Add(s, r)
	sigArray := assembleStrictTestSignature(R, s)
	if referenceVerifyProfile(DalekStrict, &pub, message, sigArray[:]) {
		t.Fatal("strict verifier accepted the order-two error witness")
	}

	tauS := new(edwards25519.Scalar).Multiply(two, s)
	rho := new(edwards25519.Scalar).Multiply(two, k)
	left := new(edwards25519.Point).ScalarBaseMult(tauS)
	right := new(edwards25519.Point).Add(
		new(edwards25519.Point).ScalarMult(two, R),
		new(edwards25519.Point).ScalarMult(rho, A),
	)
	if left.Equal(right) != 1 {
		t.Fatal("even transformed equation did not erase the order-two error")
	}
}

func TestR51HEEAPipelineForcedOnlyAndHardwareGated(t *testing.T) {
	productionBackend := pick("").name()
	productionHashLanes := sha512mb.Lanes()
	for _, kind := range []r51IFMAPipelineKind{r51IFMATwoX4, r51IFMAX8} {
		pipeline, err := newR51HEEAPipeline(kind, heea8l.Width132, 5)
		if r51IFMAPipelineAvailable(kind) {
			if err != nil || pipeline == nil {
				t.Fatalf("available %s HEEA pipeline=(%p,%v)", kind, pipeline, err)
			}
		} else if err == nil || pipeline != nil {
			t.Fatalf("unavailable %s HEEA pipeline=(%p,%v), want nil,error", kind, pipeline, err)
		}
	}
	if pipeline, err := newR51HEEAPipeline(r51IFMAX8, heea8l.WidthLimit(129), 5); err == nil || pipeline != nil {
		t.Fatalf("invalid width pipeline=(%p,%v), want nil,error", pipeline, err)
	}
	if pipeline, err := newR51HEEAPipeline(r51IFMAX4, heea8l.Width132, 5); err == nil || pipeline != nil {
		t.Fatalf("unsupported x4 pipeline=(%p,%v), want nil,error", pipeline, err)
	}
	if got := pick("").name(); got != productionBackend || got != "generic" {
		t.Fatalf("forced HEEA experiment changed auto backend from %q to %q", productionBackend, got)
	}
	if got := sha512mb.Lanes(); got != productionHashLanes {
		t.Fatalf("forced HEEA experiment changed production SHA lanes from %d to %d", productionHashLanes, got)
	}
}

func TestR51HEEAOrdinaryFallbackSurfacesUnusableScalarInvariant(t *testing.T) {
	generatorEncoding := edwards25519.NewGeneratorPoint().Bytes()
	var generator r51x5.Point
	if _, err := generator.SetBytes(generatorEncoding); err != nil {
		t.Fatal(err)
	}

	var points8 [r51x5.X8Lanes]r51x5.Point
	for lane := range points8 {
		points8[lane] = generator
	}
	var A8 r51x5.PointX8
	A8.SetPoints(&points8)
	R8 := r51x5.AffinePointX8{X: A8.X, Y: A8.Y}

	var A4 [2]r51x5.PointX4
	var R4 [2]r51x5.AffinePointX4
	for half := range A4 {
		var points4 [r51x5.X4Lanes]r51x5.Point
		for lane := range points4 {
			points4[lane] = generator
		}
		A4[half].SetPoints(&points4)
		R4[half] = r51x5.AffinePointX4{X: A4[half].X, Y: A4[half].Y}
	}

	for _, kind := range []r51IFMAPipelineKind{r51IFMATwoX4, r51IFMAX8} {
		pipeline := requireR51HEEAPipeline(t, kind, heea8l.Width132, 5)
		for _, lane := range []int{0, 7} {
			var s, k [r51x5.X8Lanes][32]byte
			for byteIndex := range k[lane] {
				k[lane][byteIndex] = 0xff // deliberately noncanonical
			}
			active := uint8(1 << lane)
			var err error
			if kind == r51IFMAX8 {
				_, err = pipeline.verifyOrdinaryFallbackX8(&A8, &R8, &s, &k, active)
			} else {
				_, err = pipeline.verifyOrdinaryFallbackTwoX4(&A4, &R4, &s, &k, active)
			}
			if err == nil {
				t.Fatalf("%s lane=%d silently converted an ordinary-DSM invariant failure into a verdict", kind, lane)
			}
		}
	}
}

func TestR51HEEAPipelineReferenceCorporaTailsInvalidLanesAndMixedOrder(t *testing.T) {
	base := append(r51CCTVVectors(t), r51WycheproofVectors(t)...)
	honest := makeR51HonestVectors(t, 17)
	mixture := cloneR51Vectors(honest)
	mixture[3].msg[0] ^= 0x80
	mixture[8].sig[63] |= 0xe0
	mixture[16] = makeR51MixedOrderValidVector(t)
	base = append(base, mixture...)
	base = append(base, makeR51HEEANoncanonicalAInvalidVector(t))
	for _, kind := range []r51IFMAPipelineKind{r51IFMATwoX4, r51IFMAX8} {
		for _, width := range []heea8l.WidthLimit{heea8l.Width128, heea8l.Width132, heea8l.Width136} {
			for _, radixBits := range []uint{4, 5} {
				pipeline := requireR51HEEAPipeline(t, kind, width, radixBits)
				t.Run(fmt.Sprintf("path=%s/W%d/radix=%d/corpora", kind, width, 1<<radixBits), func(t *testing.T) {
					assertR51HEEAPipelineVectors(t, pipeline, base)
				})
				for count := 1; count <= len(honest); count++ {
					t.Run(fmt.Sprintf("path=%s/W%d/radix=%d/tail=%d", kind, width, 1<<radixBits, count), func(t *testing.T) {
						assertR51HEEAPipelineVectors(t, pipeline, honest[:count])
					})
				}
				for invalidLane := range honest {
					invalid := cloneR51Vectors(honest)
					invalid[invalidLane].msg[0] ^= 0x40
					t.Run(fmt.Sprintf("path=%s/W%d/radix=%d/invalid-lane=%d", kind, width, 1<<radixBits, invalidLane), func(t *testing.T) {
						assertR51HEEAPipelineVectors(t, pipeline, invalid)
					})
				}
			}
		}
	}
}

func TestR51HEEAPipelineExactMixedOrderEveryLane(t *testing.T) {
	mixed := makeR51MixedOrderValidVector(t)
	for _, kind := range []r51IFMAPipelineKind{r51IFMATwoX4, r51IFMAX8} {
		for _, width := range []heea8l.WidthLimit{heea8l.Width128, heea8l.Width132, heea8l.Width136} {
			for _, radixBits := range []uint{4, 5} {
				pipeline := requireR51HEEAPipeline(t, kind, width, radixBits)
				for lane := 0; lane < r51x5.X8Lanes; lane++ {
					vectors := makeR51HonestVectors(t, r51x5.X8Lanes)
					vectors[lane] = mixed
					t.Run(fmt.Sprintf("path=%s/W%d/radix=%d/lane=%d", kind, width, 1<<radixBits, lane), func(t *testing.T) {
						assertR51HEEAPipelineVectors(t, pipeline, vectors)
					})
				}
			}
		}
	}
}

func TestR51HEEAPipelineSelectorFallbackEveryLane(t *testing.T) {
	admitted := makeR51HEEASelectorVector(t, heea8l.Width128, true)
	fallback := makeR51HEEASelectorVector(t, heea8l.Width128, false)
	invalidFallback := cloneR51Vectors([]r51ReferenceVector{fallback})[0]
	invalidFallback.name = "invalid-equation-selector-fallback-W128"
	invalidFallback.sig[32] ^= 1 // challenge and selector outcome do not hash S.
	if referenceVerifyProfile(DalekStrict, &invalidFallback.pub, invalidFallback.msg, invalidFallback.sig) {
		t.Fatal("mutated selector-fallback signature remained valid")
	}
	for _, kind := range []r51IFMAPipelineKind{r51IFMATwoX4, r51IFMAX8} {
		for _, radixBits := range []uint{4, 5} {
			pipeline := requireR51HEEAPipeline(t, kind, heea8l.Width128, radixBits)
			for _, fallbackCase := range []r51ReferenceVector{fallback, invalidFallback} {
				for lane := 0; lane < r51x5.X8Lanes; lane++ {
					vectors := make([]r51ReferenceVector, r51x5.X8Lanes)
					for index := range vectors {
						vectors[index] = admitted
					}
					vectors[lane] = fallbackCase
					t.Run(fmt.Sprintf("path=%s/radix=%d/case=%s/lane=%d", kind, 1<<radixBits, fallbackCase.name, lane), func(t *testing.T) {
						stats := assertR51HEEAPipelineVectors(t, pipeline, vectors)
						if stats.Selector != 1 || stats.Preparation != 0 || stats.Evaluation != 0 || stats.Ordinary != 1 {
							t.Fatalf("fallback stats=%+v, want one selector/ordinary fallback", stats)
						}
					})
				}
			}
		}
	}
}

func TestR51HEEAReleaseWidthSelectorFixtures(t *testing.T) {
	for _, messageSize := range []int{64, 200, 1232} {
		for _, admitted := range []bool{false, true} {
			vector := makeR51HEEASelectorVectorSized(t, heea8l.Width132, admitted, messageSize)
			hash := sha512.New()
			_, _ = hash.Write(vector.sig[:32])
			_, _ = hash.Write(vector.pub[:])
			_, _ = hash.Write(vector.msg)
			var digest [sha512.Size]byte
			hash.Sum(digest[:0])
			challenge, err := edwards25519.NewScalar().SetUniformBytes(digest[:])
			if err != nil {
				t.Fatal(err)
			}
			var challengeBytes [32]byte
			copy(challengeBytes[:], challenge.Bytes())
			_, use, _ := selectR51HEEACandidate(challengeBytes, heea8l.Width132)
			if use != admitted {
				t.Fatalf("msg=%d selector admission=%v, want %v", messageSize, use, admitted)
			}
		}
	}
}

func TestR51HEEAPipelineZeroAllocationsOnAdmittedPath(t *testing.T) {
	vector := makeR51HEEASelectorVector(t, heea8l.Width136, true)
	vectors := make([]r51ReferenceVector, 17)
	for index := range vectors {
		vectors[index] = vector
	}
	pubs, msgs, sigs, ok := r51HEEAReferenceBatch(vectors)
	for _, kind := range []r51IFMAPipelineKind{r51IFMATwoX4, r51IFMAX8} {
		for _, radixBits := range []uint{4, 5} {
			pipeline := requireR51HEEAPipeline(t, kind, heea8l.Width136, radixBits)
			if allocs := testing.AllocsPerRun(10, func() {
				all, stats, err := pipeline.VerifyBatch(pubs, msgs, sigs, ok)
				if err != nil || !all || stats != (r51HEEAFallbackStats{}) {
					panic(fmt.Sprintf("verify=(%v,%+v,%v)", all, stats, err))
				}
			}); allocs != 0 {
				t.Fatalf("%s radix=%d allocations=%v", kind, 1<<radixBits, allocs)
			}
		}
	}
}

func TestR51HEEAPipelineZeroAllocationsOnOrdinaryFallback(t *testing.T) {
	validFallback := makeR51HEEASelectorVector(t, heea8l.Width128, false)
	invalidFallback := cloneR51Vectors([]r51ReferenceVector{validFallback})[0]
	invalidFallback.name = "invalid-equation-selector-fallback-W128"
	invalidFallback.sig[32] ^= 1 // challenge and selector outcome do not hash S.
	for _, kind := range []r51IFMAPipelineKind{r51IFMATwoX4, r51IFMAX8} {
		for _, radixBits := range []uint{4, 5} {
			pipeline := requireR51HEEAPipeline(t, kind, heea8l.Width128, radixBits)
			for _, test := range []struct {
				name string
				base r51ReferenceVector
				all  bool
			}{
				{"valid", validFallback, true},
				{"invalid", invalidFallback, false},
			} {
				vectors := make([]r51ReferenceVector, 17)
				for index := range vectors {
					vectors[index] = test.base
				}
				pubs, msgs, sigs, ok := r51HEEAReferenceBatch(vectors)
				t.Run(fmt.Sprintf("path=%s/radix=%d/%s", kind, 1<<radixBits, test.name), func(t *testing.T) {
					if allocs := testing.AllocsPerRun(10, func() {
						all, stats, err := pipeline.VerifyBatch(pubs, msgs, sigs, ok)
						if err != nil || all != test.all || stats.Selector != uint64(len(vectors)) || stats.Ordinary != uint64(len(vectors)) || stats.sourceTotal() != stats.Ordinary {
							panic(fmt.Sprintf("verify=(%v,%+v,%v)", all, stats, err))
						}
						for _, verdict := range ok {
							if verdict != test.all {
								panic(fmt.Sprintf("verdict=%v want=%v", verdict, test.all))
							}
						}
					}); allocs != 0 {
						t.Fatalf("allocations=%v", allocs)
					}
				})
			}
		}
	}
}

var benchmarkR51HEEAPipelineStats r51HEEAFallbackStats

func BenchmarkR51HEEACompletePipeline(b *testing.B) {
	for _, messageSize := range []int{64, 200, 1232} {
		for _, count := range []int{8, 17, 64} {
			fixture := makeBatchFixture(b, count, messageSize)
			for _, kind := range []r51IFMAPipelineKind{r51IFMATwoX4, r51IFMAX8} {
				b.Run(fmt.Sprintf("stage=cold-AR/mode=ordinary/path=%s/radix=32/n=%d/msg=%d", kind, count, messageSize), func(b *testing.B) {
					pipeline := requireR51IFMAPipeline(b, kind, 5)
					backend := &r51IFMABenchmarkBackend{pipeline: pipeline}
					b.ReportAllocs()
					b.ResetTimer()
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
				for _, width := range []heea8l.WidthLimit{heea8l.Width128, heea8l.Width132, heea8l.Width136} {
					for _, radixBits := range []uint{4, 5} {
						name := fmt.Sprintf("stage=cold-AR/mode=heea/path=%s/W%d/radix=%d/n=%d/msg=%d", kind, width, 1<<radixBits, count, messageSize)
						b.Run(name, func(b *testing.B) {
							pipeline := requireR51HEEAPipeline(b, kind, width, radixBits)
							backend := &r51HEEABenchmarkBackend{pipeline: pipeline}
							b.ReportAllocs()
							b.ResetTimer()
							var result bool
							var total r51HEEAFallbackStats
							for iteration := 0; iteration < b.N; iteration++ {
								result = verifyBatch(backend, DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok, nil)
								if backend.err != nil {
									b.Fatal(backend.err)
								}
								total.add(backend.stats)
							}
							benchmarkR51IFMAPipelineResult = result
							benchmarkR51HEEAPipelineStats = total
							if total.Ordinary != total.sourceTotal() {
								b.Fatalf("fallback accounting=%+v", total)
							}
							denominator := float64(b.N * count)
							b.ReportMetric(float64(total.Selector)/denominator, "selector-fallback/sig")
							b.ReportMetric(float64(total.Preparation)/denominator, "preparation-fallback/sig")
							b.ReportMetric(float64(total.Evaluation)/denominator, "evaluation-fallback/sig")
							b.ReportMetric(float64(total.Ordinary)/denominator, "ordinary-fallback/sig")
							b.ReportMetric(float64(b.Elapsed().Nanoseconds())/denominator/1000, "µs/sig")
						})
					}
				}
			}
		}
	}
}

// BenchmarkR51HEEACompletePipelineParallel measures the reviewed W132,
// radix-32 HEEA candidate under the same production-worker shape as
// BenchmarkR51IFMAPipelineParallel. Every RunParallel goroutine leases one
// worker state containing its own mutable HEEA and ordinary-fallback
// workspaces, backend adapter, fallback counters, and verdict slice. Only the
// immutable input fixture is shared.
//
// This remains a forced benchmark. It does not register the HEEA pipeline or
// alter production dispatch.
func BenchmarkR51HEEACompletePipelineParallel(b *testing.B) {
	type workerState struct {
		backend r51HEEABenchmarkBackend
		ok      []bool
		total   r51HEEAFallbackStats
		result  bool
		used    bool
	}

	workerCount := runtime.GOMAXPROCS(0)
	for _, messageSize := range []int{64, 200, 1232} {
		for _, count := range []int{8, 64} {
			fixture := makeBatchFixture(b, count, messageSize)
			for _, kind := range []r51IFMAPipelineKind{r51IFMATwoX4, r51IFMAX8} {
				name := fmt.Sprintf(
					"workers=%d/stage=cold-AR/mode=heea/path=%s/W132/radix=32/n=%d/msg=%d",
					workerCount,
					kind,
					count,
					messageSize,
				)
				b.Run(name, func(b *testing.B) {
					workers := make([]workerState, workerCount)
					available := make(chan *workerState, workerCount)
					for index := range workers {
						workers[index].backend.pipeline = requireR51HEEAPipeline(
							b, kind, heea8l.Width132, 5,
						)
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
							worker.total.add(worker.backend.stats)
							if worker.backend.err != nil {
								break
							}
						}
						available <- worker
					})
					b.StopTimer()

					elapsed := b.Elapsed()
					result := true
					var total r51HEEAFallbackStats
					for range workers {
						worker := <-available
						if worker.backend.err != nil {
							b.Fatal(worker.backend.err)
						}
						if worker.used && !worker.result {
							b.Fatal("forced parallel r51 HEEA verification rejected a valid fixture")
						}
						if worker.total.Ordinary != worker.total.sourceTotal() {
							b.Fatalf("worker fallback accounting=%+v", worker.total)
						}
						total.add(worker.total)
						result = result && (!worker.used || worker.result)
					}
					benchmarkR51IFMAPipelineResult = result
					benchmarkR51HEEAPipelineStats = total
					denominator := float64(b.N * count)
					b.ReportMetric(float64(total.Selector)/denominator, "selector-fallback/sig")
					b.ReportMetric(float64(total.Preparation)/denominator, "preparation-fallback/sig")
					b.ReportMetric(float64(total.Evaluation)/denominator, "evaluation-fallback/sig")
					b.ReportMetric(float64(total.Ordinary)/denominator, "ordinary-fallback/sig")
					b.ReportMetric(float64(elapsed.Nanoseconds())/denominator/1000, "µs/sig")
					b.ReportMetric(denominator/elapsed.Seconds(), "sig/s")
				})
			}
		}
	}
}

func BenchmarkR51HEEACompletePipelineFallback(b *testing.B) {
	for _, messageSize := range []int{64, 200, 1232} {
		admitted := makeR51HEEASelectorVectorSized(b, heea8l.Width132, true, messageSize)
		fallback := makeR51HEEASelectorVectorSized(b, heea8l.Width132, false, messageSize)
		const count = r51x5.X8Lanes
		for _, kind := range []r51IFMAPipelineKind{r51IFMATwoX4, r51IFMAX8} {
			for pattern := 0; pattern <= r51x5.X8Lanes; pattern++ {
				patternName := "all"
				fallbackCount := count
				if pattern < r51x5.X8Lanes {
					patternName = fmt.Sprintf("lane-%d", pattern)
					fallbackCount = count / r51x5.X8Lanes
				}
				vectors := make([]r51ReferenceVector, count)
				for index := range vectors {
					vectors[index] = admitted
					if pattern == r51x5.X8Lanes || index%r51x5.X8Lanes == pattern {
						vectors[index] = fallback
					}
				}
				pubs, msgs, sigs, ok := r51HEEAReferenceBatch(vectors)
				name := fmt.Sprintf(
					"path=%s/W132/radix=32/n=%d/msg=%d/pattern=%s",
					kind, count, messageSize, patternName,
				)
				b.Run(name, func(b *testing.B) {
					pipeline := requireR51HEEAPipeline(b, kind, heea8l.Width132, 5)
					backend := &r51HEEABenchmarkBackend{pipeline: pipeline}
					b.ReportAllocs()
					b.ResetTimer()
					var total r51HEEAFallbackStats
					for iteration := 0; iteration < b.N; iteration++ {
						all := verifyBatch(backend, DalekStrict, pubs, msgs, sigs, ok, nil)
						if backend.err != nil || !all {
							b.Fatalf("verify=(%v,%+v,%v)", all, backend.stats, backend.err)
						}
						if backend.stats.Selector != uint64(fallbackCount) ||
							backend.stats.Preparation != 0 || backend.stats.Evaluation != 0 ||
							backend.stats.Ordinary != uint64(fallbackCount) {
							b.Fatalf("fallback stats=%+v, want %d selector/ordinary fallbacks", backend.stats, fallbackCount)
						}
						total.add(backend.stats)
					}
					benchmarkR51HEEAPipelineStats = total
					if total.Ordinary != total.sourceTotal() {
						b.Fatalf("fallback accounting=%+v", total)
					}
					denominator := float64(b.N * count)
					b.ReportMetric(float64(total.Selector)/denominator, "selector-fallback/sig")
					b.ReportMetric(float64(total.Preparation)/denominator, "preparation-fallback/sig")
					b.ReportMetric(float64(total.Evaluation)/denominator, "evaluation-fallback/sig")
					b.ReportMetric(float64(total.Ordinary)/denominator, "ordinary-fallback/sig")
					b.ReportMetric(float64(b.Elapsed().Nanoseconds())/denominator/1000, "µs/sig")
				})
			}
		}
	}
}
