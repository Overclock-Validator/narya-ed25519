package ed25519

import (
	"bytes"
	"fmt"
	"sync"

	"github.com/Overclock-Validator/narya-ed25519/internal/edwards25519"
	"github.com/Overclock-Validator/narya-ed25519/internal/r51x5"
	"github.com/Overclock-Validator/narya-ed25519/internal/sigprep"
	"github.com/Overclock-Validator/narya-ed25519/sha512mb"
)

// This file contains the complete ordinary r51 verifier core. The explicitly
// selected r51 backend owns and pools instances through backend_r51.go;
// automatic selection remains generic until the release gate changes in a
// separate reviewed commit.

// r51IFMAPipelineKind names three genuinely different forced experiments. The
// two-x4 path executes two YMM decode/DSM groups and the x4 SHA kernel; it is
// not an x8 kernel with a different label.
type r51IFMAPipelineKind uint8

const (
	r51IFMAX4 r51IFMAPipelineKind = iota
	r51IFMATwoX4
	r51IFMAX8
)

func (kind r51IFMAPipelineKind) String() string {
	switch kind {
	case r51IFMAX4:
		return "x4"
	case r51IFMATwoX4:
		return "two-x4"
	case r51IFMAX8:
		return "x8"
	default:
		return fmt.Sprintf("unknown-%d", kind)
	}
}

func (kind r51IFMAPipelineKind) shaWidth() int {
	if kind != r51IFMAX8 {
		return sha512mb.ExperimentalWidthX4
	}
	return sha512mb.ExperimentalWidthX8
}

// r51IFMAPipeline is the private complete-verifier core. Its mutable DSM
// workspaces make each instance deliberately non-concurrent. The r51 backend
// therefore checks one instance out of its worker pool per call. Fixed-base B
// tables are prepared once per worker; each verification group pays only for
// cold A table generation plus evaluation.
type r51IFMAPipeline struct {
	kind              r51IFMAPipelineKind
	radixBits         uint
	encodedQReference bool
	fixedBaseComb     *r51x5.ExperimentalFixedBaseCombTable
	x8                r51IFMAFixedDSMWorkspaceX8
	x4                [2]r51IFMAFixedDSMWorkspaceX4
	variableX8        *r51x5.ExperimentalIFMAProjectiveNielsPreSignedMicroAoSVariableBaseWorkspaceX8
	variableX4        [2]*r51x5.ExperimentalIFMAVariableBaseWorkspaceX4

	// beforePrepareVariableX8 is an error-injection seam used only by the
	// fail-closed group test. It deliberately takes no point argument: passing
	// hot-path scratch through a function value would make that scratch escape.
	beforePrepareVariableX8 func() error
}

// r51IFMAFixedDSMWorkspaceX4 keeps the selected generic instantiation behind
// concrete calls. Invoking these methods through an interface makes every
// point and scalar scratch argument escape once per verification group.
type r51IFMAFixedDSMWorkspaceX4 struct {
	radixBits uint8
	radix16   *r51x5.ExperimentalIFMAFixedDSMWorkspaceRadix16X4
	radix32   *r51x5.ExperimentalIFMAFixedDSMWorkspaceX4
	radix64   *r51x5.ExperimentalIFMAFixedDSMWorkspaceRadix64X4
}

// r51IFMAFixedDSMWorkspaceX8 is the eight-lane counterpart.
type r51IFMAFixedDSMWorkspaceX8 struct {
	radixBits uint8
	radix16   *r51x5.ExperimentalIFMAFixedDSMWorkspaceRadix16X8
	radix32   *r51x5.ExperimentalIFMAFixedDSMWorkspaceX8
	radix64   *r51x5.ExperimentalIFMAFixedDSMWorkspaceRadix64X8
}

func (workspace *r51IFMAFixedDSMWorkspaceX4) PrepareFixedBase(base *r51x5.PointX4, radixBits uint) error {
	switch workspace.radixBits {
	case 4:
		return workspace.radix16.PrepareFixedBase(base, radixBits)
	case 5:
		return workspace.radix32.PrepareFixedBase(base, radixBits)
	case 6:
		return workspace.radix64.PrepareFixedBase(base, radixBits)
	default:
		panic("ed25519: uninitialized forced r51 IFMA x4 workspace")
	}
}

func (workspace *r51IFMAFixedDSMWorkspaceX4) PrepareVariableBase(base *r51x5.PointX4) error {
	switch workspace.radixBits {
	case 4:
		return workspace.radix16.PrepareVariableBase(base)
	case 5:
		return workspace.radix32.PrepareVariableBase(base)
	case 6:
		return workspace.radix64.PrepareVariableBase(base)
	default:
		panic("ed25519: uninitialized forced r51 IFMA x4 workspace")
	}
}

func (workspace *r51IFMAFixedDSMWorkspaceX4) Evaluate(out *r51x5.IFMAPointX4, scalars *r51x5.FixedDSMScalarsX4, negative *[r51x5.DSMTerms]uint8, active uint8) (uint8, error) {
	switch workspace.radixBits {
	case 4:
		return workspace.radix16.Evaluate(out, scalars, negative, active)
	case 5:
		return workspace.radix32.Evaluate(out, scalars, negative, active)
	case 6:
		return workspace.radix64.Evaluate(out, scalars, negative, active)
	default:
		panic("ed25519: uninitialized forced r51 IFMA x4 workspace")
	}
}

func (workspace *r51IFMAFixedDSMWorkspaceX8) PrepareFixedBase(base *r51x5.PointX8, radixBits uint) error {
	switch workspace.radixBits {
	case 4:
		return workspace.radix16.PrepareFixedBase(base, radixBits)
	case 5:
		return workspace.radix32.PrepareFixedBase(base, radixBits)
	case 6:
		return workspace.radix64.PrepareFixedBase(base, radixBits)
	default:
		panic("ed25519: uninitialized forced r51 IFMA x8 workspace")
	}
}

func (workspace *r51IFMAFixedDSMWorkspaceX8) PrepareVariableBase(base *r51x5.PointX8) error {
	switch workspace.radixBits {
	case 4:
		return workspace.radix16.PrepareVariableBase(base)
	case 5:
		return workspace.radix32.PrepareVariableBase(base)
	case 6:
		return workspace.radix64.PrepareVariableBase(base)
	default:
		panic("ed25519: uninitialized forced r51 IFMA x8 workspace")
	}
}

func (workspace *r51IFMAFixedDSMWorkspaceX8) Evaluate(out *r51x5.IFMAPointX8, scalars *r51x5.FixedDSMScalarsX8, negative *[r51x5.DSMTerms]uint8, active uint8) (uint8, error) {
	switch workspace.radixBits {
	case 4:
		return workspace.radix16.Evaluate(out, scalars, negative, active)
	case 5:
		return workspace.radix32.Evaluate(out, scalars, negative, active)
	case 6:
		return workspace.radix64.Evaluate(out, scalars, negative, active)
	default:
		panic("ed25519: uninitialized forced r51 IFMA x8 workspace")
	}
}

var r51SharedCombTables [3]struct {
	once  sync.Once
	table *r51x5.ExperimentalFixedBaseCombTable
}

func r51IFMAPipelineAvailable(kind r51IFMAPipelineKind) bool {
	return r51x5.ExperimentalIFMAAvailable() && sha512mb.ExperimentalNativeAvailable(kind.shaWidth())
}

func newR51IFMAPipeline(kind r51IFMAPipelineKind, radixBits uint) (*r51IFMAPipeline, error) {
	if kind != r51IFMAX4 && kind != r51IFMATwoX4 && kind != r51IFMAX8 {
		return nil, fmt.Errorf("ed25519: invalid forced r51 IFMA pipeline %d", kind)
	}
	if radixBits != 4 && radixBits != 5 && radixBits != 6 {
		return nil, fmt.Errorf("ed25519: invalid forced r51 IFMA radix %d", 1<<radixBits)
	}
	if !r51x5.ExperimentalIFMAAvailable() {
		return nil, r51x5.ErrIFMAUnavailable
	}
	if !sha512mb.ExperimentalNativeAvailable(kind.shaWidth()) {
		return nil, fmt.Errorf("ed25519: forced %s SHA-512 kernel unavailable", kind)
	}

	generatorEncoding := edwards25519.NewGeneratorPoint().Bytes()
	var generator r51x5.Point
	if _, err := generator.SetBytes(generatorEncoding); err != nil {
		return nil, fmt.Errorf("ed25519: r51 generator decode: %w", err)
	}

	pipeline := &r51IFMAPipeline{kind: kind, radixBits: radixBits}
	if kind == r51IFMAX8 {
		var lanes [r51x5.X8Lanes]r51x5.Point
		for lane := range lanes {
			lanes[lane] = generator
		}
		var base r51x5.PointX8
		base.SetPoints(&lanes)
		pipeline.x8 = newR51IFMAFixedDSMWorkspaceX8(radixBits)
		if err := pipeline.x8.PrepareFixedBase(&base, radixBits); err != nil {
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
	halves := 1
	if kind == r51IFMATwoX4 {
		halves = 2
	}
	for half := 0; half < halves; half++ {
		pipeline.x4[half] = newR51IFMAFixedDSMWorkspaceX4(radixBits)
		if err := pipeline.x4[half].PrepareFixedBase(&base, radixBits); err != nil {
			return nil, err
		}
	}
	return pipeline, nil
}

// newR51IFMAEncodedQReferencePipeline constructs the complete admission
// control for paired decompression: it decodes A alone, computes the identical
// DSM equation, and canonical-encodes Q for the final byte comparison. The
// ordinary constructor keeps paired A/R decode plus strict projective
// equality. Neither constructor registers a backend.
func newR51IFMAEncodedQReferencePipeline(kind r51IFMAPipelineKind, radixBits uint) (*r51IFMAPipeline, error) {
	pipeline, err := newR51IFMAPipeline(kind, radixBits)
	if err != nil {
		return nil, err
	}
	pipeline.encodedQReference = true
	return pipeline, nil
}

func newR51IFMAFixedDSMWorkspaceX4(radixBits uint) r51IFMAFixedDSMWorkspaceX4 {
	workspace := r51IFMAFixedDSMWorkspaceX4{radixBits: uint8(radixBits)}
	switch radixBits {
	case 4:
		workspace.radix16 = new(r51x5.ExperimentalIFMAFixedDSMWorkspaceRadix16X4)
	case 5:
		workspace.radix32 = new(r51x5.ExperimentalIFMAFixedDSMWorkspaceX4)
	case 6:
		workspace.radix64 = new(r51x5.ExperimentalIFMAFixedDSMWorkspaceRadix64X4)
	default:
		panic("ed25519: unsupported forced r51 IFMA radix")
	}
	return workspace
}

func newR51IFMAFixedDSMWorkspaceX8(radixBits uint) r51IFMAFixedDSMWorkspaceX8 {
	workspace := r51IFMAFixedDSMWorkspaceX8{radixBits: uint8(radixBits)}
	switch radixBits {
	case 4:
		workspace.radix16 = new(r51x5.ExperimentalIFMAFixedDSMWorkspaceRadix16X8)
	case 5:
		workspace.radix32 = new(r51x5.ExperimentalIFMAFixedDSMWorkspaceX8)
	case 6:
		workspace.radix64 = new(r51x5.ExperimentalIFMAFixedDSMWorkspaceRadix64X8)
	default:
		panic("ed25519: unsupported forced r51 IFMA radix")
	}
	return workspace
}

// newR51IFMACombPipeline builds the complete-path wider-B experiment. The
// scalar-stored B table is shared by every lane, while exactly one SoA table
// per x4/x8 group is retained and rebuilt for the cold arbitrary key A.
func newR51IFMACombPipeline(kind r51IFMAPipelineKind, variableRadixBits, fixedRadixBits uint) (*r51IFMAPipeline, error) {
	if kind != r51IFMAX4 && kind != r51IFMATwoX4 && kind != r51IFMAX8 {
		return nil, fmt.Errorf("ed25519: invalid forced r51 IFMA pipeline %d", kind)
	}
	if variableRadixBits != 5 {
		return nil, fmt.Errorf("ed25519: invalid forced r51 IFMA variable radix %d", 1<<variableRadixBits)
	}
	if fixedRadixBits != 4 && fixedRadixBits != 5 && fixedRadixBits != 8 {
		return nil, fmt.Errorf("ed25519: invalid forced r51 IFMA fixed radix %d", 1<<fixedRadixBits)
	}
	if !r51x5.ExperimentalIFMAAvailable() {
		return nil, r51x5.ErrIFMAUnavailable
	}
	if !sha512mb.ExperimentalNativeAvailable(kind.shaWidth()) {
		return nil, fmt.Errorf("ed25519: forced %s SHA-512 kernel unavailable", kind)
	}

	pipeline := &r51IFMAPipeline{
		kind:          kind,
		radixBits:     variableRadixBits,
		fixedBaseComb: sharedR51FixedBaseComb(fixedRadixBits),
	}
	if kind == r51IFMAX8 {
		pipeline.variableX8 = new(r51x5.ExperimentalIFMAProjectiveNielsPreSignedMicroAoSVariableBaseWorkspaceX8)
	} else {
		halves := 1
		if kind == r51IFMATwoX4 {
			halves = 2
		}
		for half := 0; half < halves; half++ {
			pipeline.variableX4[half] = new(r51x5.ExperimentalIFMAVariableBaseWorkspaceX4)
		}
	}
	return pipeline, nil
}

func sharedR51FixedBaseComb(radixBits uint) *r51x5.ExperimentalFixedBaseCombTable {
	var index int
	switch radixBits {
	case 4:
		index = 0
	case 5:
		index = 1
	case 8:
		index = 2
	default:
		panic("ed25519: unsupported forced r51 fixed-base comb radix")
	}
	entry := &r51SharedCombTables[index]
	entry.once.Do(func() {
		generatorEncoding := edwards25519.NewGeneratorPoint().Bytes()
		var generator r51x5.Point
		if _, err := generator.SetBytes(generatorEncoding); err != nil {
			panic(fmt.Sprintf("ed25519: r51 generator decode: %v", err))
		}
		entry.table = r51x5.BuildExperimentalFixedBaseCombTable(&generator, radixBits)
	})
	return entry.table
}

func (pipeline *r51IFMAPipeline) fixedBaseLabel() string {
	if pipeline.fixedBaseComb == nil {
		return "shared"
	}
	return fmt.Sprintf("comb%d", 1<<pipeline.fixedBaseComb.RadixBits())
}

func (pipeline *r51IFMAPipeline) VerifyBatch(profile Profile, pubs []*[32]byte, msgs, sigs [][]byte, ok []bool) (bool, error) {
	if len(pubs) != len(msgs) || len(msgs) != len(sigs) || len(sigs) != len(ok) {
		panic("ed25519: forced r51 IFMA batch slice lengths differ")
	}
	if profile != DalekStrict && profile != StdlibCompat {
		panic("ed25519: unsupported forced r51 IFMA profile")
	}
	for index := range ok {
		ok[index] = false
	}

	groupWidth := r51x5.X8Lanes
	if pipeline.kind == r51IFMAX4 {
		groupWidth = r51x5.X4Lanes
	}
	for offset := 0; offset < len(pubs); offset += groupWidth {
		count := len(pubs) - offset
		if count > groupWidth {
			count = groupWidth
		}
		var err error
		if pipeline.kind == r51IFMAX8 {
			err = pipeline.verifyGroupX8(profile, pubs, msgs, sigs, ok, offset, count)
		} else {
			err = pipeline.verifyGroupTwoX4(profile, pubs, msgs, sigs, ok, offset, count)
		}
		if err != nil {
			// A kernel failure is a batch failure, not a partial verdict. In
			// particular, do not expose accepted lanes from groups completed
			// before a later group failed.
			for index := range ok {
				ok[index] = false
			}
			return false, err
		}
	}

	all := true
	for _, verdict := range ok {
		all = all && verdict
	}
	return all, nil
}

func (pipeline *r51IFMAPipeline) verifyGroupX8(profile Profile, pubs []*[32]byte, msgs, sigs [][]byte, ok []bool, offset, count int) error {
	var aBytes [r51x5.X8Lanes][32]byte
	var s [r51x5.X8Lanes][32]byte
	var candidates uint8
	for lane := 0; lane < count; lane++ {
		index := offset + lane
		coefficient, valid := prepareR51Signature(profile, pubs[index], sigs[index])
		if !valid {
			continue
		}
		aBytes[lane] = *pubs[index]
		s[lane] = coefficient
		candidates |= 1 << lane
	}
	if candidates == 0 {
		return nil
	}
	if pipeline.encodedQReference {
		return pipeline.verifyGroupEncodedQX8(profile, pubs, msgs, sigs, ok, offset, count, &aBytes, &s, candidates)
	}
	return pipeline.verifyGroupPairedX8(profile, pubs, msgs, sigs, ok, offset, count, &aBytes, &s, candidates)
}

func (pipeline *r51IFMAPipeline) verifyGroupEncodedQX8(profile Profile, pubs []*[32]byte, msgs, sigs [][]byte, ok []bool, offset, count int, aBytes *[r51x5.X8Lanes][32]byte, s *[r51x5.X8Lanes][32]byte, candidates uint8) error {
	var A r51x5.PointX8
	aValid, err := r51x5.ExperimentalIFMADecodeX8(&A, aBytes, candidates)
	if err != nil {
		return err
	}
	live := candidates & aValid
	if live == 0 {
		return nil
	}
	return pipeline.evaluateGroupX8(profile, pubs, msgs, sigs, ok, offset, count, &A, nil, s, live)
}

func (pipeline *r51IFMAPipeline) verifyGroupPairedX8(profile Profile, pubs []*[32]byte, msgs, sigs [][]byte, ok []bool, offset, count int, aBytes *[r51x5.X8Lanes][32]byte, s *[r51x5.X8Lanes][32]byte, candidates uint8) error {
	var rBytes [r51x5.X8Lanes][32]byte
	for lane := 0; lane < count; lane++ {
		if candidates&(1<<lane) != 0 {
			copy(rBytes[lane][:], sigs[offset+lane][:32])
		}
	}
	var A r51x5.PointX8
	var R r51x5.AffinePointX8
	aValid, rValid, err := r51x5.ExperimentalIFMADecode2NoTX8(&A, &R, aBytes, &rBytes, candidates)
	if err != nil {
		return err
	}
	live := candidates & aValid & rValid
	if live == 0 {
		return nil
	}
	return pipeline.evaluateGroupX8(profile, pubs, msgs, sigs, ok, offset, count, &A, &R, s, live)
}

func (pipeline *r51IFMAPipeline) evaluateGroupX8(profile Profile, pubs []*[32]byte, msgs, sigs [][]byte, ok []bool, offset, count int, A *r51x5.PointX8, R *r51x5.AffinePointX8, s *[r51x5.X8Lanes][32]byte, live uint8) error {
	var k [r51x5.X8Lanes][32]byte
	var err error
	live, err = reduceR51NativeChallengesX8(&k, pubs, msgs, sigs, offset, count, live, sha512mb.ExperimentalWidthX8)
	if err != nil || live == 0 {
		return err
	}

	var looseQ r51x5.IFMAPointX8
	var usable uint8
	if pipeline.fixedBaseComb == nil {
		if pipeline.beforePrepareVariableX8 != nil {
			if err := pipeline.beforePrepareVariableX8(); err != nil {
				return err
			}
		}
		if err := pipeline.x8.PrepareVariableBase(A); err != nil {
			return err
		}
		var coefficients r51x5.FixedDSMScalarsX8
		for lane := 0; lane < count; lane++ {
			if live&(1<<lane) == 0 {
				continue
			}
			coefficients[0][lane] = (*s)[lane]
			coefficients[1][lane] = k[lane]
		}
		negative := [r51x5.DSMTerms]uint8{0, live}
		var err error
		usable, err = pipeline.x8.Evaluate(&looseQ, &coefficients, &negative, live)
		if err != nil {
			return err
		}
	} else {
		if err := pipeline.variableX8.Prepare(A, pipeline.radixBits); err != nil {
			return err
		}
		var aTerm, bTerm r51x5.IFMAPointX8
		usableA, err := pipeline.variableX8.Evaluate(&aTerm, &k, live, live)
		if err != nil {
			return err
		}
		usableB, err := r51x5.ExperimentalIFMAFixedBaseCombScalarMultX8(&bTerm, pipeline.fixedBaseComb, s, live)
		if err != nil {
			return err
		}
		if err := r51x5.ExperimentalIFMAPointAddComposableX8(&looseQ, &aTerm, &bTerm); err != nil {
			return err
		}
		usable = usableA & usableB
	}
	live &= usable
	Q := looseQ.Reduced()
	var accepted uint8
	if R == nil {
		accepted = r51EncodedFinalMaskX8(&Q, sigs, offset, count, live)
	} else {
		accepted = r51FinalMaskX8(profile, &Q, R, sigs, offset, count, live)
	}
	for lane := 0; lane < count; lane++ {
		ok[offset+lane] = accepted&(1<<lane) != 0
	}
	return nil
}

func (pipeline *r51IFMAPipeline) verifyGroupTwoX4(profile Profile, pubs []*[32]byte, msgs, sigs [][]byte, ok []bool, offset, count int) error {
	var aBytes [2][r51x5.X4Lanes][32]byte
	var s [r51x5.X8Lanes][32]byte
	var candidates uint8
	for lane := 0; lane < count; lane++ {
		index := offset + lane
		coefficient, valid := prepareR51Signature(profile, pubs[index], sigs[index])
		if !valid {
			continue
		}
		half, local := lane/r51x5.X4Lanes, lane%r51x5.X4Lanes
		aBytes[half][local] = *pubs[index]
		s[lane] = coefficient
		candidates |= 1 << lane
	}
	if candidates == 0 {
		return nil
	}
	if pipeline.encodedQReference {
		return pipeline.verifyGroupEncodedQTwoX4(profile, pubs, msgs, sigs, ok, offset, count, &aBytes, &s, candidates)
	}
	return pipeline.verifyGroupPairedTwoX4(profile, pubs, msgs, sigs, ok, offset, count, &aBytes, &s, candidates)
}

func (pipeline *r51IFMAPipeline) verifyGroupEncodedQTwoX4(profile Profile, pubs []*[32]byte, msgs, sigs [][]byte, ok []bool, offset, count int, aBytes *[2][r51x5.X4Lanes][32]byte, s *[r51x5.X8Lanes][32]byte, candidates uint8) error {
	var A [2]r51x5.PointX4
	var live uint8
	for half := 0; half < 2; half++ {
		active := uint8(candidates >> (half * r51x5.X4Lanes))
		if active == 0 {
			continue
		}
		aValid, err := r51x5.ExperimentalIFMADecodeX4(&A[half], &(*aBytes)[half], active)
		if err != nil {
			return err
		}
		live |= (active & aValid) << (half * r51x5.X4Lanes)
	}
	if live == 0 {
		return nil
	}
	return pipeline.evaluateGroupTwoX4(profile, pubs, msgs, sigs, ok, offset, count, &A, nil, s, live)
}

func (pipeline *r51IFMAPipeline) verifyGroupPairedTwoX4(profile Profile, pubs []*[32]byte, msgs, sigs [][]byte, ok []bool, offset, count int, aBytes *[2][r51x5.X4Lanes][32]byte, s *[r51x5.X8Lanes][32]byte, candidates uint8) error {
	var rBytes [2][r51x5.X4Lanes][32]byte
	for lane := 0; lane < count; lane++ {
		if candidates&(1<<lane) == 0 {
			continue
		}
		half, local := lane/r51x5.X4Lanes, lane%r51x5.X4Lanes
		copy(rBytes[half][local][:], sigs[offset+lane][:32])
	}
	var A [2]r51x5.PointX4
	var R [2]r51x5.AffinePointX4
	var live uint8
	for half := 0; half < 2; half++ {
		active := uint8(candidates >> (half * r51x5.X4Lanes))
		if active == 0 {
			continue
		}
		aValid, rValid, err := r51x5.ExperimentalIFMADecode2NoTX4(&A[half], &R[half], &(*aBytes)[half], &rBytes[half], active)
		if err != nil {
			return err
		}
		live |= (active & aValid & rValid) << (half * r51x5.X4Lanes)
	}
	if live == 0 {
		return nil
	}
	return pipeline.evaluateGroupTwoX4(profile, pubs, msgs, sigs, ok, offset, count, &A, &R, s, live)
}

func (pipeline *r51IFMAPipeline) evaluateGroupTwoX4(profile Profile, pubs []*[32]byte, msgs, sigs [][]byte, ok []bool, offset, count int, A *[2]r51x5.PointX4, R *[2]r51x5.AffinePointX4, s *[r51x5.X8Lanes][32]byte, live uint8) error {
	var k [r51x5.X8Lanes][32]byte
	var err error
	live, err = reduceR51NativeChallengesX8(&k, pubs, msgs, sigs, offset, count, live, sha512mb.ExperimentalWidthX4)
	if err != nil || live == 0 {
		return err
	}

	var accepted uint8
	for half := 0; half < 2; half++ {
		active := uint8(live >> (half * r51x5.X4Lanes))
		if active == 0 {
			continue
		}
		var s4, k4 [r51x5.X4Lanes][32]byte
		for local := 0; local < r51x5.X4Lanes; local++ {
			lane := half*r51x5.X4Lanes + local
			if active&(1<<local) == 0 {
				continue
			}
			s4[local] = (*s)[lane]
			k4[local] = k[lane]
		}
		var looseQ r51x5.IFMAPointX4
		var usable uint8
		if pipeline.fixedBaseComb == nil {
			if err := pipeline.x4[half].PrepareVariableBase(&A[half]); err != nil {
				return err
			}
			var coefficients r51x5.FixedDSMScalarsX4
			coefficients[0], coefficients[1] = s4, k4
			negative := [r51x5.DSMTerms]uint8{0, active}
			var err error
			usable, err = pipeline.x4[half].Evaluate(&looseQ, &coefficients, &negative, active)
			if err != nil {
				return err
			}
		} else {
			if err := pipeline.variableX4[half].Prepare(&A[half], pipeline.radixBits); err != nil {
				return err
			}
			var aTerm, bTerm r51x5.IFMAPointX4
			usableA, err := pipeline.variableX4[half].Evaluate(&aTerm, &k4, active, active)
			if err != nil {
				return err
			}
			usableB, err := r51x5.ExperimentalIFMAFixedBaseCombScalarMultX4(&bTerm, pipeline.fixedBaseComb, &s4, active)
			if err != nil {
				return err
			}
			if err := r51x5.ExperimentalIFMAPointAddComposableX4(&looseQ, &aTerm, &bTerm); err != nil {
				return err
			}
			usable = usableA & usableB
		}
		Q := looseQ.Reduced()
		finalOffset := offset + half*r51x5.X4Lanes
		finalCount := minR51(count-half*r51x5.X4Lanes, r51x5.X4Lanes)
		var acceptedHalf uint8
		if R == nil {
			acceptedHalf = r51EncodedFinalMaskX4(&Q, sigs, finalOffset, finalCount, active&usable)
		} else {
			acceptedHalf = r51FinalMaskX4(profile, &Q, &(*R)[half], sigs, finalOffset, finalCount, active&usable)
		}
		accepted |= acceptedHalf << (half * r51x5.X4Lanes)
	}
	for lane := 0; lane < count; lane++ {
		ok[offset+lane] = accepted&(1<<lane) != 0
	}
	return nil
}

// prepareR51Signature applies the shared byte-level gates and returns the
// signature's S half. It is the r51 spelling of sigprep.Parse, kept because the
// native pipelines want only the scalar and do their own vectorized hashing and
// reduction rather than the per-item Reduce that sigprep.Prepare would run.
func prepareR51Signature(profile Profile, pub *[32]byte, sig []byte) ([32]byte, bool) {
	prepared, ok := sigprep.Parse(profile.rules(), pub, sig)
	if !ok {
		return [32]byte{}, false
	}
	return prepared.S, true
}

// ed25519ScalarOrderEncoding is the little-endian encoding of the prime
// subgroup order l.
var ed25519ScalarOrderEncoding = sigprep.ScalarOrderEncoding

func canonicalScalarEncoding(s []byte) bool { return sigprep.CanonicalScalarEncoding(s) }

func reduceR51NativeChallengesX8(out *[r51x5.X8Lanes][32]byte, pubs []*[32]byte, msgs, sigs [][]byte, offset, count int, live uint8, width int) (uint8, error) {
	// Keep the original R and A byte strings as independent segments. Neither
	// point decoder nor canonical-R gate may rewrite the challenge input.
	var segments [r51x5.X8Lanes][3][]byte
	var lanes [r51x5.X8Lanes]uint8
	inputCount := compactR51ChallengeSegments(&segments, &lanes, pubs, msgs, sigs, offset, count, live)
	var digests [r51x5.X8Lanes][64]byte
	if !sha512mb.ExperimentalSum512Batch3(digests[:inputCount], segments[:inputCount], width) {
		return 0, fmt.Errorf("ed25519: forced x%d SHA-512 kernel unavailable", width)
	}
	var reducedDigests [r51x5.X8Lanes][32]byte
	compactMask := uint8((uint16(1) << uint(inputCount)) - 1)
	switch width {
	case sha512mb.ExperimentalWidthX8:
		r51x5.ExperimentalReduceUniformScalarsX8(&reducedDigests, &digests, compactMask)
	case sha512mb.ExperimentalWidthX4:
		// Keep the two-x4 comparison honest: hashing and reduction both use
		// two four-lane groups rather than silently borrowing the x8 path.
		for half := 0; half < (inputCount+r51x5.X4Lanes-1)/r51x5.X4Lanes; half++ {
			var digestHalf [r51x5.X4Lanes][64]byte
			var reducedHalf [r51x5.X4Lanes][32]byte
			for lane := 0; lane < r51x5.X4Lanes; lane++ {
				compactLane := half*r51x5.X4Lanes + lane
				if compactLane < inputCount {
					digestHalf[lane] = digests[compactLane]
				}
			}
			active := uint8(compactMask >> (half * r51x5.X4Lanes))
			if active == 0 {
				continue
			}
			r51x5.ExperimentalReduceUniformScalarsX4(&reducedHalf, &digestHalf, active)
			for lane := 0; lane < r51x5.X4Lanes; lane++ {
				compactLane := half*r51x5.X4Lanes + lane
				if compactLane < inputCount {
					reducedDigests[compactLane] = reducedHalf[lane]
				}
			}
		}
	default:
		return 0, fmt.Errorf("ed25519: unsupported forced scalar-reduction width %d", width)
	}
	for digestIndex := 0; digestIndex < inputCount; digestIndex++ {
		lane := lanes[digestIndex]
		out[lane] = reducedDigests[digestIndex]
	}
	return live, nil
}

func compactR51ChallengeSegments(segments *[r51x5.X8Lanes][3][]byte, lanes *[r51x5.X8Lanes]uint8, pubs []*[32]byte, msgs, sigs [][]byte, offset, count int, live uint8) int {
	inputCount := 0
	for lane := 0; lane < count; lane++ {
		if live&(1<<lane) == 0 {
			continue
		}
		index := offset + lane
		segments[inputCount] = [3][]byte{sigs[index][:32], pubs[index][:], msgs[index]}
		lanes[inputCount] = uint8(lane)
		inputCount++
	}
	return inputCount
}

func r51FinalMaskX8(profile Profile, q *r51x5.PointX8, r *r51x5.AffinePointX8, sigs [][]byte, offset, count int, live uint8) uint8 {
	if profile == DalekStrict {
		return q.EqualCompactAffine(r) & live
	}
	return r51EncodedFinalMaskX8(q, sigs, offset, count, live)
}

func r51EncodedFinalMaskX8(q *r51x5.PointX8, sigs [][]byte, offset, count int, live uint8) uint8 {
	encoded := q.Bytes()
	var accepted uint8
	for lane := 0; lane < count; lane++ {
		if live&(1<<lane) != 0 && bytes.Equal(encoded[lane][:], sigs[offset+lane][:32]) {
			accepted |= 1 << lane
		}
	}
	return accepted
}

func r51FinalMaskX4(profile Profile, q *r51x5.PointX4, r *r51x5.AffinePointX4, sigs [][]byte, offset, count int, live uint8) uint8 {
	if profile == DalekStrict {
		return q.EqualCompactAffine(r) & live
	}
	return r51EncodedFinalMaskX4(q, sigs, offset, count, live)
}

func r51EncodedFinalMaskX4(q *r51x5.PointX4, sigs [][]byte, offset, count int, live uint8) uint8 {
	encoded := q.Bytes()
	var accepted uint8
	for lane := 0; lane < count; lane++ {
		if live&(1<<lane) != 0 && bytes.Equal(encoded[lane][:], sigs[offset+lane][:32]) {
			accepted |= 1 << lane
		}
	}
	return accepted
}

func minR51(a, b int) int {
	if a < b {
		return a
	}
	return b
}
