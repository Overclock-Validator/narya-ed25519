package ed25519

import (
	"bytes"
	"fmt"

	"github.com/Overclock-Validator/narya/internal/r51x5"
	"github.com/Overclock-Validator/narya/sha512mb"
)

// r51IFMABatchQPipeline is the complete two-x4 r51 path selected by the forced
// r51 backend. It decodes A only, retains ready DSM outputs, and canonical-
// encodes up to 64 Q points with one cross-group x4 inversion. The registered
// core uses a radix-32 A table and one process-shared radix-256 B comb; the
// earlier radix-64 two-term DSM remains a differential and benchmark reference.
//
// The ordinary r51IFMAPipeline remains the paired A/R-decode baseline, and
// newR51IFMAEncodedQReferencePipeline remains the literal per-group encoding
// oracle. Automatic backend selection does not reach this type.
type r51IFMABatchQPipeline struct {
	core      *r51IFMAPipeline
	finalizer r51IFMABatchQFinalizer

	encoder r51x5.ExperimentalIFMABatchEncodeWorkspaceX4
	points  [r51x5.ExperimentalIFMABatchEncodeMaxX4Groups]r51x5.IFMAPointX4
	active  [r51x5.ExperimentalIFMABatchEncodeMaxX4Groups]uint8
	encoded [r51x5.ExperimentalIFMABatchEncodeMaxX4Groups][r51x5.X4Lanes][32]byte
	final   [r51x5.ExperimentalIFMABatchEncodeMaxX4Groups]uint8

	// decodedA* is fixed scratch for cold A preparation and the private decoded-
	// point measurement seam. Misses are packed across the entire <=64-signature
	// encoder chunk so every x4 decode group is full except the tail, then
	// scattered back to the original signature lanes before hashing and DSM.
	decodedAPoints    [r51x5.ExperimentalIFMABatchEncodeMaxX4Groups]r51x5.PointX4
	decodedAScalars   [r51BatchQMaxChunk][32]byte
	decodedAMissBytes [r51x5.X4Lanes][32]byte
	decodedAMissLanes [r51x5.X4Lanes]uint8

	// beforeBatchEncode is an error-injection seam for the fail-closed test.
	// It takes no hot-path scratch so the fixed arrays above stay non-escaping.
	beforeBatchEncode func() error
}

// r51DecodedAEntry is the smallest benchmark representation of a reusable
// decoded public key. raw is load-bearing: Ed25519 hashes the caller's original
// public-key bytes, and the permissive decoder can map more than one byte
// string to the same point. A lookup hit is therefore usable only for the exact
// raw encoding that produced point.
//
// This remains private to the r51 implementation. It is not a cache policy
// and carries no admission, eviction, synchronization, or profile state.
type r51DecodedAEntry struct {
	raw   [32]byte
	point r51x5.Point
}

const r51BatchQMaxChunk = r51x5.ExperimentalIFMABatchEncodeMaxX4Groups * r51x5.X4Lanes

type r51IFMABatchQFinalizer uint8

const (
	r51IFMABatchQFinalizerLiteral r51IFMABatchQFinalizer = iota
	r51IFMABatchQFinalizerYFirst
)

func newR51IFMABatchQPipeline() (*r51IFMABatchQPipeline, error) {
	return newR51IFMABatchQPipelineWithFinalizer(r51IFMABatchQFinalizerLiteral)
}

func newR51IFMABatchQPipelineWithFinalizer(finalizer r51IFMABatchQFinalizer) (*r51IFMABatchQPipeline, error) {
	return newR51IFMABatchQCombPipelineWithFinalizer(finalizer)
}

// newR51IFMABatchQSharedPipelineWithFinalizer retains the former registered
// radix-64 shared two-term DSM for differential tests and complete-path A/Bs.
func newR51IFMABatchQSharedPipelineWithFinalizer(finalizer r51IFMABatchQFinalizer) (*r51IFMABatchQPipeline, error) {
	core, err := newR51IFMAPipeline(r51IFMATwoX4, 6)
	if err != nil {
		return nil, err
	}
	return newR51IFMABatchQPipelineWithCore(finalizer, core)
}

// newR51IFMABatchQCombPipelineWithFinalizer is the cold two-x4 candidate that
// keeps A on a radix-32 variable-base table and evaluates B with the shared
// radix-256 comb before using the same cross-group batch-Q finalizer. It is a
// complete-verifier core. It became the registered forced-r51 batch core after
// passing the Zen 4 and Zen 5 exact-path, allocation, and performance gates.
func newR51IFMABatchQCombPipelineWithFinalizer(finalizer r51IFMABatchQFinalizer) (*r51IFMABatchQPipeline, error) {
	core, err := newR51IFMACombPipeline(r51IFMATwoX4, 5, 8)
	if err != nil {
		return nil, err
	}
	return newR51IFMABatchQPipelineWithCore(finalizer, core)
}

func newR51IFMABatchQPipelineWithCore(finalizer r51IFMABatchQFinalizer, core *r51IFMAPipeline) (*r51IFMABatchQPipeline, error) {
	if finalizer != r51IFMABatchQFinalizerLiteral && finalizer != r51IFMABatchQFinalizerYFirst {
		return nil, fmt.Errorf("ed25519: unsupported r51 batch-Q finalizer %d", finalizer)
	}
	if core == nil || core.kind != r51IFMATwoX4 {
		return nil, fmt.Errorf("ed25519: batch-Q requires a two-x4 r51 core")
	}
	return &r51IFMABatchQPipeline{core: core, finalizer: finalizer}, nil
}

// VerifyBatch evaluates the exact ordinary Ed25519 equation. DalekStrict's
// byte prechecks retain its canonical-R and small-order policy; StdlibCompat
// skips those policy checks and still uses the literal Encode(Q)==Rbytes
// predicate. Both profiles hash the caller's original R and A byte strings.
//
// The mutable core and batch-encode scratch make an instance non-concurrent,
// matching r51IFMAPipeline. A kernel error clears every verdict, including
// verdicts committed by an earlier 64-signature chunk.
func (pipeline *r51IFMABatchQPipeline) VerifyBatch(profile Profile, pubs []*[32]byte, msgs, sigs [][]byte, ok []bool) (bool, error) {
	return pipeline.verifyBatchWithDecodedAMode(profile, pubs, msgs, sigs, ok, nil, true)
}

// verifyBatchWithDecodedA is a private measurement seam for a pre-resolved
// decoded-point tier. decoded must align one-for-one with the raw inputs. Nil
// and raw-key-mismatched entries are cold misses. Every strict byte precheck
// and every challenge hash still consumes the original caller bytes; a hit
// bypasses only A decompression. Decode misses are compacted within each
// encoder chunk and scattered back before the equation is evaluated.
func (pipeline *r51IFMABatchQPipeline) verifyBatchWithDecodedA(profile Profile, pubs []*[32]byte, msgs, sigs [][]byte, ok []bool, decoded []*r51DecodedAEntry) (bool, error) {
	return pipeline.verifyBatchWithDecodedAMode(profile, pubs, msgs, sigs, ok, decoded, true)
}

// verifyBatchWithDecodedAUncompacted retains the original per-x4 miss layout
// as a benchmark reference. It is deliberately not the candidate warm path.
func (pipeline *r51IFMABatchQPipeline) verifyBatchWithDecodedAUncompacted(profile Profile, pubs []*[32]byte, msgs, sigs [][]byte, ok []bool, decoded []*r51DecodedAEntry) (bool, error) {
	return pipeline.verifyBatchWithDecodedAMode(profile, pubs, msgs, sigs, ok, decoded, false)
}

func (pipeline *r51IFMABatchQPipeline) verifyBatchWithDecodedAMode(profile Profile, pubs []*[32]byte, msgs, sigs [][]byte, ok []bool, decoded []*r51DecodedAEntry, compactMisses bool) (bool, error) {
	if len(pubs) != len(msgs) || len(msgs) != len(sigs) || len(sigs) != len(ok) {
		panic("ed25519: forced r51 IFMA batch-Q slice lengths differ")
	}
	if decoded != nil && len(decoded) != len(pubs) {
		panic("ed25519: forced r51 IFMA decoded-A slice length differs")
	}
	if profile != DalekStrict && profile != StdlibCompat {
		panic("ed25519: unsupported forced r51 IFMA batch-Q profile")
	}
	for index := range ok {
		ok[index] = false
	}

	for offset := 0; offset < len(pubs); offset += r51BatchQMaxChunk {
		count := minR51(len(pubs)-offset, r51BatchQMaxChunk)
		if err := pipeline.verifyChunk(profile, pubs, msgs, sigs, ok, decoded, compactMisses, offset, count); err != nil {
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

func (pipeline *r51IFMABatchQPipeline) verifyChunk(profile Profile, pubs []*[32]byte, msgs, sigs [][]byte, ok []bool, decoded []*r51DecodedAEntry, compactMisses bool, offset, count int) error {
	groups := (count + r51x5.X4Lanes - 1) / r51x5.X4Lanes
	for group := 0; group < groups; group++ {
		pipeline.points[group] = r51x5.IFMAPointX4{}
		pipeline.active[group] = 0
		pipeline.encoded[group] = [r51x5.X4Lanes][32]byte{}
		pipeline.final[group] = 0
	}

	if compactMisses {
		live, err := pipeline.prepareDecodedAChunk(profile, pubs, sigs, decoded, offset, count)
		if err != nil {
			return err
		}
		for relative := 0; relative < count; relative += r51x5.X8Lanes {
			groupCount := minR51(count-relative, r51x5.X8Lanes)
			if err := pipeline.evaluatePreparedTwoX4Group(
				pubs,
				msgs,
				sigs,
				offset,
				relative,
				groupCount,
				live,
				relative/r51x5.X4Lanes,
			); err != nil {
				return err
			}
		}
	} else {
		for relative := 0; relative < count; relative += r51x5.X8Lanes {
			groupCount := minR51(count-relative, r51x5.X8Lanes)
			var err error
			if decoded == nil {
				err = pipeline.evaluateTwoX4Group(
					profile,
					pubs,
					msgs,
					sigs,
					offset+relative,
					groupCount,
					relative/r51x5.X4Lanes,
				)
			} else {
				err = pipeline.evaluateTwoX4GroupWithDecodedAUncompacted(
					profile,
					pubs,
					msgs,
					sigs,
					decoded,
					offset+relative,
					groupCount,
					relative/r51x5.X4Lanes,
				)
			}
			if err != nil {
				return err
			}
		}
	}

	if pipeline.beforeBatchEncode != nil {
		if err := pipeline.beforeBatchEncode(); err != nil {
			return err
		}
	}
	switch pipeline.finalizer {
	case r51IFMABatchQFinalizerLiteral:
		if err := pipeline.encoder.Encode(&pipeline.encoded, &pipeline.points, &pipeline.active, groups); err != nil {
			return err
		}
		for group := 0; group < groups; group++ {
			mask := pipeline.active[group] & 0x0f
			for lane := 0; lane < r51x5.X4Lanes; lane++ {
				relative := group*r51x5.X4Lanes + lane
				if relative >= count || mask&(1<<lane) == 0 {
					continue
				}
				index := offset + relative
				ok[index] = bytes.Equal(pipeline.encoded[group][lane][:], sigs[index][:32])
			}
		}
		return nil

	case r51IFMABatchQFinalizerYFirst:
		// The literal path's output buffer has exactly the required compressed-
		// R shape, so the dormant alternative reuses it as input staging. An
		// active equation lane has already passed the 64-byte signature check.
		for group := 0; group < groups; group++ {
			mask := pipeline.active[group] & 0x0f
			for lane := 0; lane < r51x5.X4Lanes; lane++ {
				if mask&(1<<lane) == 0 {
					continue
				}
				relative := group*r51x5.X4Lanes + lane
				index := offset + relative
				copy(pipeline.encoded[group][lane][:], sigs[index][:32])
			}
		}
		if err := pipeline.encoder.CompareCompressedYFirst(&pipeline.final, &pipeline.points, &pipeline.active, &pipeline.encoded, groups); err != nil {
			return err
		}
		for group := 0; group < groups; group++ {
			mask := pipeline.final[group] & 0x0f
			for lane := 0; lane < r51x5.X4Lanes; lane++ {
				relative := group*r51x5.X4Lanes + lane
				if relative >= count {
					continue
				}
				ok[offset+relative] = mask&(1<<lane) != 0
			}
		}
		return nil
	default:
		panic("ed25519: unreachable r51 batch-Q finalizer")
	}
}

func (pipeline *r51IFMABatchQPipeline) evaluateTwoX4Group(profile Profile, pubs []*[32]byte, msgs, sigs [][]byte, offset, count, outputGroup int) error {
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

	var A [2]r51x5.PointX4
	var live uint8
	for half := 0; half < 2; half++ {
		active := uint8(candidates>>(half*r51x5.X4Lanes)) & 0x0f
		if active == 0 {
			continue
		}
		aValid, err := r51x5.ExperimentalIFMADecodeX4(&A[half], &aBytes[half], active)
		if err != nil {
			return err
		}
		live |= (active & aValid) << (half * r51x5.X4Lanes)
	}
	if live == 0 {
		return nil
	}

	var k [r51x5.X8Lanes][32]byte
	var err error
	live, err = reduceR51NativeChallengesX8(&k, pubs, msgs, sigs, offset, count, live, sha512mb.ExperimentalWidthX4)
	if err != nil || live == 0 {
		return err
	}

	for half := 0; half < 2; half++ {
		active := uint8(live>>(half*r51x5.X4Lanes)) & 0x0f
		if active == 0 {
			continue
		}
		var s4, k4 [r51x5.X4Lanes][32]byte
		for local := 0; local < r51x5.X4Lanes; local++ {
			if active&(1<<local) == 0 {
				continue
			}
			lane := half*r51x5.X4Lanes + local
			s4[local], k4[local] = s[lane], k[lane]
		}

		group := outputGroup + half
		usable, err := pipeline.evaluateX4(&pipeline.points[group], &A[half], &s4, &k4, active, half)
		if err != nil {
			return err
		}
		pipeline.active[group] = active & usable
	}
	return nil
}

// prepareDecodedAChunk applies the profile/S precheck once, installs optional
// exact-key point hits directly in their original SoA lanes, and packs all
// decode misses across the encoder chunk into full x4 calls. With decoded=nil
// this is the ordinary cold path: phase compaction still fills every decode
// group except the tail. Only A decompression changes order; every later phase
// remains in original signature order.
func (pipeline *r51IFMABatchQPipeline) prepareDecodedAChunk(
	profile Profile,
	pubs []*[32]byte,
	sigs [][]byte,
	decoded []*r51DecodedAEntry,
	offset, count int,
) (uint64, error) {
	groups := (count + r51x5.X4Lanes - 1) / r51x5.X4Lanes
	for group := 0; group < groups; group++ {
		pipeline.decodedAPoints[group].SetIdentity()
	}

	var live uint64
	missCount := 0
	for relative := 0; relative < count; relative++ {
		index := offset + relative
		coefficient, valid := prepareR51Signature(profile, pubs[index], sigs[index])
		if !valid {
			continue
		}
		pipeline.decodedAScalars[relative] = coefficient

		if decoded != nil {
			entry := decoded[index]
			if entry != nil && entry.raw == *pubs[index] {
				pipeline.decodedAPoints[relative/r51x5.X4Lanes].SetLane(relative%r51x5.X4Lanes, &entry.point)
				live |= uint64(1) << relative
				continue
			}
		}

		pipeline.decodedAMissBytes[missCount] = *pubs[index]
		pipeline.decodedAMissLanes[missCount] = uint8(relative)
		missCount++
		if missCount == r51x5.X4Lanes {
			decodedLive, err := pipeline.decodePreparedAMisses(missCount)
			if err != nil {
				return 0, err
			}
			live |= decodedLive
			missCount = 0
		}
	}
	if missCount != 0 {
		decodedLive, err := pipeline.decodePreparedAMisses(missCount)
		if err != nil {
			return 0, err
		}
		live |= decodedLive
	}
	return live, nil
}

func (pipeline *r51IFMABatchQPipeline) decodePreparedAMisses(count int) (uint64, error) {
	active := uint8((uint16(1) << count) - 1)
	var points r51x5.PointX4
	valid, err := r51x5.ExperimentalIFMADecodeX4(&points, &pipeline.decodedAMissBytes, active)
	if err != nil {
		return 0, err
	}
	var live uint64
	for packed := 0; packed < count; packed++ {
		if valid&(1<<packed) == 0 {
			continue
		}
		relative := int(pipeline.decodedAMissLanes[packed])
		point := points.Lane(packed)
		pipeline.decodedAPoints[relative/r51x5.X4Lanes].SetLane(relative%r51x5.X4Lanes, &point)
		live |= uint64(1) << relative
	}
	return live, nil
}

func (pipeline *r51IFMABatchQPipeline) evaluatePreparedTwoX4Group(
	pubs []*[32]byte,
	msgs, sigs [][]byte,
	chunkOffset, relative, count int,
	chunkLive uint64,
	outputGroup int,
) error {
	live := uint8(chunkLive >> relative)
	if count < r51x5.X8Lanes {
		live &= uint8((uint16(1) << count) - 1)
	}
	if live == 0 {
		return nil
	}

	var k [r51x5.X8Lanes][32]byte
	var err error
	live, err = reduceR51NativeChallengesX8(&k, pubs, msgs, sigs, chunkOffset+relative, count, live, sha512mb.ExperimentalWidthX4)
	if err != nil || live == 0 {
		return err
	}

	for half := 0; half < 2; half++ {
		active := uint8(live>>(half*r51x5.X4Lanes)) & 0x0f
		if active == 0 {
			continue
		}
		var s4, k4 [r51x5.X4Lanes][32]byte
		for local := 0; local < r51x5.X4Lanes; local++ {
			if active&(1<<local) == 0 {
				continue
			}
			lane := half*r51x5.X4Lanes + local
			s4[local] = pipeline.decodedAScalars[relative+lane]
			k4[local] = k[lane]
		}

		group := outputGroup + half
		A := &pipeline.decodedAPoints[group]
		usable, err := pipeline.evaluateX4(&pipeline.points[group], A, &s4, &k4, active, half)
		if err != nil {
			return err
		}
		pipeline.active[group] = active & usable
	}
	return nil
}

// evaluateTwoX4GroupWithDecodedAUncompacted retains the original per-x4
// decode schedule as a benchmark control. The candidate path above compacts
// misses across the full encoder chunk.
func (pipeline *r51IFMABatchQPipeline) evaluateTwoX4GroupWithDecodedAUncompacted(
	profile Profile,
	pubs []*[32]byte,
	msgs, sigs [][]byte,
	decoded []*r51DecodedAEntry,
	offset, count, outputGroup int,
) error {
	var aBytes [2][r51x5.X4Lanes][32]byte
	var A [2]r51x5.PointX4
	A[0].SetIdentity()
	A[1].SetIdentity()
	var s [r51x5.X8Lanes][32]byte
	var candidates, hits uint8
	for lane := 0; lane < count; lane++ {
		index := offset + lane
		coefficient, valid := prepareR51Signature(profile, pubs[index], sigs[index])
		if !valid {
			continue
		}
		half, local := lane/r51x5.X4Lanes, lane%r51x5.X4Lanes
		entry := decoded[index]
		if entry != nil && entry.raw == *pubs[index] {
			A[half].SetLane(local, &entry.point)
			hits |= 1 << lane
		} else {
			aBytes[half][local] = *pubs[index]
		}
		s[lane] = coefficient
		candidates |= 1 << lane
	}
	if candidates == 0 {
		return nil
	}

	var live uint8
	for half := 0; half < 2; half++ {
		active := uint8(candidates>>(half*r51x5.X4Lanes)) & 0x0f
		if active == 0 {
			continue
		}
		hitMask := uint8(hits>>(half*r51x5.X4Lanes)) & 0x0f
		missMask := active &^ hitMask
		validMask := hitMask
		if missMask != 0 {
			var cold r51x5.PointX4
			aValid, err := r51x5.ExperimentalIFMADecodeX4(&cold, &aBytes[half], missMask)
			if err != nil {
				return err
			}
			for local := 0; local < r51x5.X4Lanes; local++ {
				if aValid&(1<<local) == 0 {
					continue
				}
				point := cold.Lane(local)
				A[half].SetLane(local, &point)
			}
			validMask |= aValid
		}
		live |= (active & validMask) << (half * r51x5.X4Lanes)
	}
	if live == 0 {
		return nil
	}

	var k [r51x5.X8Lanes][32]byte
	var err error
	live, err = reduceR51NativeChallengesX8(&k, pubs, msgs, sigs, offset, count, live, sha512mb.ExperimentalWidthX4)
	if err != nil || live == 0 {
		return err
	}

	for half := 0; half < 2; half++ {
		active := uint8(live>>(half*r51x5.X4Lanes)) & 0x0f
		if active == 0 {
			continue
		}
		var s4, k4 [r51x5.X4Lanes][32]byte
		for local := 0; local < r51x5.X4Lanes; local++ {
			if active&(1<<local) == 0 {
				continue
			}
			lane := half*r51x5.X4Lanes + local
			s4[local], k4[local] = s[lane], k[lane]
		}

		group := outputGroup + half
		usable, err := pipeline.evaluateX4(&pipeline.points[group], &A[half], &s4, &k4, active, half)
		if err != nil {
			return err
		}
		pipeline.active[group] = active & usable
	}
	return nil
}

// evaluateX4 computes [s]B-[k]A into the batch-Q point representation. The
// registered radix-64 core uses the existing shared two-term DSM workspace;
// the cold-comb candidate uses a radix-32 A table plus the shared B comb.
// Keeping the branch outside internal/r51x5 preserves one finalizer and one
// verdict mapping for differential tests of both arithmetic shapes.
func (pipeline *r51IFMABatchQPipeline) evaluateX4(
	out *r51x5.IFMAPointX4,
	A *r51x5.PointX4,
	s, k *[r51x5.X4Lanes][32]byte,
	active uint8,
	half int,
) (uint8, error) {
	if pipeline.core.fixedBaseComb == nil {
		if err := pipeline.core.x4[half].PrepareVariableBase(A); err != nil {
			return 0, err
		}
		var coefficients r51x5.FixedDSMScalarsX4
		coefficients[0], coefficients[1] = *s, *k
		negative := [r51x5.DSMTerms]uint8{0, active}
		return pipeline.core.x4[half].Evaluate(out, &coefficients, &negative, active)
	}

	variable := pipeline.core.variableX4[half]
	if variable == nil {
		panic("ed25519: uninitialized forced r51 IFMA x4 comb workspace")
	}
	if err := variable.Prepare(A, pipeline.core.radixBits); err != nil {
		return 0, err
	}
	var aTerm, bTerm r51x5.IFMAPointX4
	usableA, err := variable.Evaluate(&aTerm, k, active, active)
	if err != nil {
		return 0, err
	}
	usableB, err := r51x5.ExperimentalIFMAFixedBaseCombScalarMultX4(&bTerm, pipeline.core.fixedBaseComb, s, active)
	if err != nil {
		return 0, err
	}
	var combined r51x5.IFMAPointX4
	if err := r51x5.ExperimentalIFMAPointAddComposableX4(&combined, &aTerm, &bTerm); err != nil {
		return 0, err
	}
	*out = combined
	return usableA & usableB, nil
}

func (pipeline *r51IFMABatchQPipeline) String() string {
	finalizer := "batch-Q"
	if pipeline.finalizer == r51IFMABatchQFinalizerYFirst {
		finalizer = "y-first"
	}
	return fmt.Sprintf("%s/radix=%d/fixed=%s/%s", pipeline.core.kind, 1<<pipeline.core.radixBits, pipeline.core.fixedBaseLabel(), finalizer)
}
