package ed25519

import (
	"bytes"
	"fmt"

	"github.com/Overclock-Validator/narya/internal/r51x5"
	"github.com/Overclock-Validator/narya/sha512mb"
)

// r51IFMABatchQPipeline is a dormant complete-verifier experiment for the
// two-x4, radix-64 r51 path. It decodes A only, retains ready DSM outputs, and
// canonical-encodes up to 64 Q points with one cross-group x4 inversion.
//
// The ordinary r51IFMAPipeline remains the paired A/R-decode baseline, and
// newR51IFMAEncodedQReferencePipeline remains the literal per-group encoding
// oracle. Nothing in production backend registration or selection reaches
// this type.
type r51IFMABatchQPipeline struct {
	core *r51IFMAPipeline

	encoder r51x5.ExperimentalIFMABatchEncodeWorkspaceX4
	points  [r51x5.ExperimentalIFMABatchEncodeMaxX4Groups]r51x5.IFMAPointX4
	active  [r51x5.ExperimentalIFMABatchEncodeMaxX4Groups]uint8
	encoded [r51x5.ExperimentalIFMABatchEncodeMaxX4Groups][r51x5.X4Lanes][32]byte

	// beforeBatchEncode is an error-injection seam for the fail-closed test.
	// It takes no hot-path scratch so the fixed arrays above stay non-escaping.
	beforeBatchEncode func() error
}

func newR51IFMABatchQPipeline() (*r51IFMABatchQPipeline, error) {
	core, err := newR51IFMAPipeline(r51IFMATwoX4, 6)
	if err != nil {
		return nil, err
	}
	return &r51IFMABatchQPipeline{core: core}, nil
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
	if len(pubs) != len(msgs) || len(msgs) != len(sigs) || len(sigs) != len(ok) {
		panic("ed25519: forced r51 IFMA batch-Q slice lengths differ")
	}
	if profile != DalekStrict && profile != StdlibCompat {
		panic("ed25519: unsupported forced r51 IFMA batch-Q profile")
	}
	for index := range ok {
		ok[index] = false
	}

	const maxChunk = r51x5.ExperimentalIFMABatchEncodeMaxX4Groups * r51x5.X4Lanes
	for offset := 0; offset < len(pubs); offset += maxChunk {
		count := minR51(len(pubs)-offset, maxChunk)
		if err := pipeline.verifyChunk(profile, pubs, msgs, sigs, ok, offset, count); err != nil {
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

func (pipeline *r51IFMABatchQPipeline) verifyChunk(profile Profile, pubs []*[32]byte, msgs, sigs [][]byte, ok []bool, offset, count int) error {
	groups := (count + r51x5.X4Lanes - 1) / r51x5.X4Lanes
	for group := 0; group < groups; group++ {
		pipeline.points[group] = r51x5.IFMAPointX4{}
		pipeline.active[group] = 0
		pipeline.encoded[group] = [r51x5.X4Lanes][32]byte{}
	}

	for relative := 0; relative < count; relative += r51x5.X8Lanes {
		groupCount := minR51(count-relative, r51x5.X8Lanes)
		if err := pipeline.evaluateTwoX4Group(
			profile,
			pubs,
			msgs,
			sigs,
			offset+relative,
			groupCount,
			relative/r51x5.X4Lanes,
		); err != nil {
			return err
		}
	}

	if pipeline.beforeBatchEncode != nil {
		if err := pipeline.beforeBatchEncode(); err != nil {
			return err
		}
	}
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

		if err := pipeline.core.x4[half].PrepareVariableBase(&A[half]); err != nil {
			return err
		}
		var coefficients r51x5.FixedDSMScalarsX4
		coefficients[0], coefficients[1] = s4, k4
		negative := [r51x5.DSMTerms]uint8{0, active}
		group := outputGroup + half
		usable, err := pipeline.core.x4[half].Evaluate(&pipeline.points[group], &coefficients, &negative, active)
		if err != nil {
			return err
		}
		pipeline.active[group] = active & usable
	}
	return nil
}

func (pipeline *r51IFMABatchQPipeline) String() string {
	return fmt.Sprintf("%s/radix=%d/batch-Q", pipeline.core.kind, 1<<pipeline.core.radixBits)
}
