package r51x5

import (
	"bytes"
	sted25519 "crypto/ed25519"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
)

// WarmCombKeyA6R9 is one immutable per-key A6/r9 table. Its fields stay
// private so callers cannot manufacture a table whose compressed-key binding
// disagrees with its points. A Cache may share a key across verifier workers.
//
// WarmCombKeyA6R9PayloadBytes is the affine-cached coordinate payload. The
// complete object also retains the original 32 public-key bytes.
type WarmCombKeyA6R9 struct {
	raw     [32]byte
	storage [heterogeneousPartialCombA6R9VectorPointCountExperiment]ifmaAffine3MicroAoSEntryExperiment
}

const (
	WarmCombKeyA6R9PayloadBytes = heterogeneousPartialCombA6R9VectorPointCountExperiment * 5 * 3 * 8
	WarmCombKeyA6R9Bytes        = WarmCombKeyA6R9PayloadBytes + 32
)

// WarmCombBuildWorkspaceX4 owns the large mutable construction scratch and a
// staged four-key result. It is reusable but not concurrent. Build commits to
// caller-owned keys only after decoding, range checks, all point operations,
// the shared inversion, and affine conversion have succeeded.
type WarmCombBuildWorkspaceX4 struct {
	build  heterogeneousPartialCombA6R9VectorBuildWorkspaceExperiment
	staged heterogeneousPartialCombA6R9VectorTableGroupExperiment
}

// BuildWarmCombKeysA6R9X4 builds exactly four independent per-key tables.
// Permissively decodable noncanonical A encodings remain allowed, while every
// accepted small-order encoding is rejected. out entries must be non-nil and
// pairwise distinct. On error, none of them is modified.
func (w *WarmCombBuildWorkspaceX4) BuildWarmCombKeysA6R9X4(
	out *[X4Lanes]*WarmCombKeyA6R9,
	encoded *[X4Lanes][32]byte,
) error {
	for lane := 0; lane < X4Lanes; lane++ {
		if out[lane] == nil {
			return fmt.Errorf("r51x5: nil warm-comb output lane %d", lane)
		}
		for previous := 0; previous < lane; previous++ {
			if out[lane] == out[previous] {
				return fmt.Errorf("r51x5: aliased warm-comb output lanes %d and %d", previous, lane)
			}
		}
		if packedEncodesSmallOrderPointX4(encoded[lane][:]) {
			return fmt.Errorf("r51x5: warm-comb public key lane %d is small order", lane)
		}
	}

	var decoded PointX4
	valid, err := ExperimentalIFMADecodeX4(&decoded, encoded, 0x0f)
	if err != nil {
		return err
	}
	if valid != 0x0f {
		return fmt.Errorf("r51x5: warm-comb public-key decode mask=%02x", valid)
	}
	if err := buildHeterogeneousPartialCombA6R9VectorGroupExperiment(&w.staged, &decoded, &w.build); err != nil {
		return err
	}

	for lane := 0; lane < X4Lanes; lane++ {
		out[lane].raw = encoded[lane]
		out[lane].storage = w.staged.storage[lane]
	}
	return nil
}

func (k *WarmCombKeyA6R9) table() heterogeneousPartialCombTableExperiment {
	return heterogeneousPartialCombTableExperiment{
		points: k.storage[:],
		spec:   heterogeneousPartialCombA6R9Experiment,
	}
}

// ErrWarmCombUnavailable means this host cannot execute the IFMA warm-comb
// path. It is a dispatch result, not an internal arithmetic fault.
var ErrWarmCombUnavailable = errors.New("r51x5: warm partial comb requires AVX-512 IFMA")

// WarmCombStrictVerifierX4 owns mutable scratch for one homogeneous group of
// four cached keys. It is reusable but not concurrent. The keys and shared B
// table are immutable, so independent verifier instances may consume the same
// cache entries concurrently.
type WarmCombStrictVerifierX4 struct {
	b10 *heterogeneousPartialCombPreSignedSharedTableExperiment

	hash   hash.Hash
	digest [sha512.Size]byte
	wide   [X4Lanes][sha512.Size]byte

	encoder ExperimentalIFMABatchEncodeWorkspaceX4
	points  [ExperimentalIFMABatchEncodeMaxX4Groups]IFMAPointX4
	active  [ExperimentalIFMABatchEncodeMaxX4Groups]uint8
	encoded [ExperimentalIFMABatchEncodeMaxX4Groups][X4Lanes][32]byte
}

// NewWarmCombStrictVerifierX4 prepares the process-wide fixed-B table and one
// reusable worker. It does not build any per-key A tables.
func NewWarmCombStrictVerifierX4() (*WarmCombStrictVerifierX4, error) {
	if !ExperimentalIFMAAvailable() {
		return nil, ErrWarmCombUnavailable
	}
	initializeWarmCombFixedTables()
	if heterogeneousPartialCombCompleteFixedTablesExperiment.b10 == nil {
		return nil, errors.New("r51x5: nil warm-comb fixed-B table")
	}
	return &WarmCombStrictVerifierX4{
		b10:  heterogeneousPartialCombCompleteFixedTablesExperiment.b10,
		hash: sha512.New(),
	}, nil
}

func initializeWarmCombFixedTables() {
	heterogeneousPartialCombCompleteFixedTablesExperiment.once.Do(func() {
		var generatorEncoding [32]byte
		generatorEncoding[0] = 0x58
		for index := 1; index < len(generatorEncoding); index++ {
			generatorEncoding[index] = 0x66
		}
		var generator Point
		if _, err := generator.SetBytes(generatorEncoding[:]); err != nil {
			panic(fmt.Sprintf("r51x5: decode Ed25519 generator: %v", err))
		}
		heterogeneousPartialCombCompleteFixedTablesExperiment.regular = buildAsymmetricFixedBTableExperiment(&generator, 10)
		b8 := buildHeterogeneousPartialCombTableExperiment(&generator, heterogeneousPartialCombB8R3Experiment)
		b10 := buildHeterogeneousPartialCombTableExperiment(&generator, heterogeneousPartialCombB10R5Experiment)
		heterogeneousPartialCombCompleteFixedTablesExperiment.b8 = buildHeterogeneousPartialCombPreSignedSharedTableExperiment(b8)
		heterogeneousPartialCombCompleteFixedTablesExperiment.b10 = buildHeterogeneousPartialCombPreSignedSharedTableExperiment(b10)
	})
}

// Verify evaluates four independent DalekStrict equations with the B10 fixed
// table. It hashes the caller's original R and A bytes. A key is usable only
// when its private raw binding matches the supplied public key. Every verdict
// is cleared before work starts and remains false on error.
func (v *WarmCombStrictVerifierX4) Verify(
	keys *[X4Lanes]*WarmCombKeyA6R9,
	pubs *[X4Lanes][32]byte,
	messages *[X4Lanes][]byte,
	signatures *[X4Lanes][]byte,
	ok *[X4Lanes]bool,
) (bool, error) {
	return v.VerifyBatch(keys[:], pubs[:], messages[:], signatures[:], ok[:])
}

// VerifyBatch evaluates up to ExperimentalIFMABatchEncodeMaxX4Groups warm x4
// groups and batch-encodes every computed Q with one inversion. Inputs remain
// in caller order and the length must be a positive multiple of X4Lanes.
// Every verdict is cleared before work starts and remains false on error.
func (v *WarmCombStrictVerifierX4) VerifyBatch(
	keys []*WarmCombKeyA6R9,
	pubs [][32]byte,
	messages, signatures [][]byte,
	ok []bool,
) (bool, error) {
	count := len(keys)
	if count == 0 || count%X4Lanes != 0 || count > ExperimentalIFMABatchEncodeMaxX4Groups*X4Lanes ||
		len(pubs) != count || len(messages) != count || len(signatures) != count || len(ok) != count {
		return false, fmt.Errorf("r51x5: warm-comb batch width=%d", count)
	}
	for index := range ok {
		ok[index] = false
	}

	groups := count / X4Lanes
	for group := 0; group < groups; group++ {
		v.points[group] = IFMAPointX4{}
		v.active[group] = 0
		v.encoded[group] = [X4Lanes][32]byte{}

		var tableValues [X4Lanes]heterogeneousPartialCombTableExperiment
		var tables [X4Lanes]*heterogeneousPartialCombTableExperiment
		var scalars FixedDSMScalarsX4
		var live uint8
		for lane := 0; lane < X4Lanes; lane++ {
			index := group*X4Lanes + lane
			key := keys[index]
			if key == nil || key.raw != pubs[index] {
				continue
			}
			signature := signatures[index]
			if len(signature) != sted25519.SignatureSize {
				continue
			}
			copy(scalars[0][lane][:], signature[32:])
			if !canonicalScalarBytes(&scalars[0][lane]) ||
				packedEncodesSmallOrderPointX4(signature[:32]) ||
				!packedCanonicalREncodingX4(signature[:32]) {
				continue
			}

			tableValues[lane] = key.table()
			tables[lane] = &tableValues[lane]
			v.hash.Reset()
			_, _ = v.hash.Write(signature[:32])
			_, _ = v.hash.Write(pubs[index][:])
			_, _ = v.hash.Write(messages[index])
			sum := v.hash.Sum(v.digest[:0])
			if len(sum) != len(v.digest) {
				panic("r51x5: SHA-512 returned an invalid digest length")
			}
			v.wide[lane] = v.digest
			live |= 1 << lane
		}

		var reduced [X4Lanes][32]byte
		live &= ExperimentalReduceUniformScalarsX4(&reduced, &v.wide, live)
		scalars[1] = reduced
		negative := [DSMTerms]uint8{0, live}
		usable, err := evaluateHeterogeneousPartialCombPreSignedBDSMX4Experiment(
			&v.points[group], &tables, v.b10, &scalars, &negative, live,
		)
		if err != nil {
			return false, err
		}
		v.active[group] = usable
	}

	if err := v.encoder.Encode(&v.encoded, &v.points, &v.active, groups); err != nil {
		return false, err
	}
	all := true
	for group := 0; group < groups; group++ {
		for lane := 0; lane < X4Lanes; lane++ {
			index := group*X4Lanes + lane
			accepted := len(signatures[index]) == sted25519.SignatureSize &&
				v.active[group]&(1<<lane) != 0 &&
				bytes.Equal(v.encoded[group][lane][:], signatures[index][:32])
			ok[index] = accepted
			all = all && accepted
		}
	}
	return all, nil
}
