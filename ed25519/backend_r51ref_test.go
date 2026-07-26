package ed25519

import (
	"bytes"
	stded25519 "crypto/ed25519"
	"encoding/hex"
	"fmt"
	"math/rand"
	"testing"

	"github.com/Overclock-Validator/narya-ed25519/internal/edwards25519"
	"github.com/Overclock-Validator/narya-ed25519/internal/r51x5"
	"github.com/Overclock-Validator/narya-ed25519/sha512mb"
)

// verifyR51BatchReference is the complete, forced r51x5 verification
// scaffold. It is deliberately test-only: Decode2NoT, field operations, DSM,
// and final equality currently execute through reduced scalar lane oracles.
// No backend registration or automatic dispatch can reach this function.
//
// It nevertheless owns the intended complete predicate boundary: strict byte
// prechecks, canonical S, a segmented hash over the original R/A/message
// bytes, canonical reduction of k, paired A/R decoding, exact signed-integer
// [S]B-[k]A, lane masks/tails, and profile-specific final equality.
// Ordinary-scalar recoding and the DSM workspace use caller-owned fixed
// arrays, so the complete harness is allocation-free. This remains a
// correctness scaffold rather than a throughput backend because its point
// arithmetic and hashing still execute through scalar lane/reference paths.
func verifyR51BatchReference(profile Profile, pubs []*[32]byte, msgs, sigs [][]byte, ok []bool, width int, radixBits uint) bool {
	if len(pubs) != len(msgs) || len(msgs) != len(sigs) || len(sigs) != len(ok) {
		panic("ed25519: r51 reference batch slice lengths differ")
	}
	if profile != DalekStrict && profile != StdlibCompat {
		panic("ed25519: unsupported r51 reference profile")
	}
	if width != r51x5.X4Lanes && width != r51x5.X8Lanes {
		panic("ed25519: r51 reference width must be four or eight")
	}
	if radixBits != 4 && radixBits != 5 {
		panic("ed25519: r51 reference radix must be 16 or 32")
	}
	for i := range ok {
		ok[i] = false
	}

	generatorEncoding := edwards25519.NewGeneratorPoint().Bytes()
	var generator r51x5.Point
	if _, err := generator.SetBytes(generatorEncoding); err != nil {
		panic("ed25519: r51 generator failed to decode")
	}

	for offset := 0; offset < len(pubs); offset += width {
		count := len(pubs) - offset
		if count > width {
			count = width
		}
		if width == r51x5.X8Lanes {
			verifyR51GroupX8(profile, pubs, msgs, sigs, ok, offset, count, radixBits, &generator)
		} else {
			verifyR51GroupX4(profile, pubs, msgs, sigs, ok, offset, count, radixBits, &generator)
		}
	}

	all := true
	for _, verdict := range ok {
		all = all && verdict
	}
	return all
}

func verifyR51GroupX8(profile Profile, pubs []*[32]byte, msgs, sigs [][]byte, ok []bool, offset, count int, radixBits uint, generator *r51x5.Point) {
	var aBytes, rBytes [r51x5.X8Lanes][32]byte
	var s [r51x5.X8Lanes][32]byte
	var candidates uint8
	for lane := 0; lane < count; lane++ {
		index := offset + lane
		coefficient, valid := prepareR51Signature(profile, pubs[index], sigs[index])
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
	aValid, rValid := r51x5.Decode2NoTX8(&A, &R, &aBytes, &rBytes, candidates)
	live := candidates & aValid & rValid
	if live == 0 {
		return
	}

	var k [r51x5.X8Lanes][32]byte
	live &= reduceR51ChallengesX8(&k, pubs, msgs, sigs, offset, count, live)
	if live == 0 {
		return
	}

	var generatorLanes [r51x5.X8Lanes]r51x5.Point
	for lane := range generatorLanes {
		generatorLanes[lane] = *generator
	}
	var B r51x5.PointX8
	B.SetPoints(&generatorLanes)
	bases := [r51x5.DSMTerms]r51x5.PointX8{B, A}
	var coefficients r51x5.FixedDSMScalarsX8
	for lane := 0; lane < count; lane++ {
		if live&(1<<lane) == 0 {
			continue
		}
		coefficients[0][lane] = s[lane]
		coefficients[1][lane] = k[lane]
	}
	var Q r51x5.PointX8
	var workspace r51x5.FixedDSMWorkspaceX8
	workspace.Prepare(&bases, radixBits)
	negative := [r51x5.DSMTerms]uint8{0, live}
	live &= workspace.Evaluate(&Q, &coefficients, &negative, live)

	var accepted uint8
	if profile == DalekStrict {
		accepted = Q.EqualCompactAffine(&R) & live
	} else {
		encodedQ := Q.Bytes()
		for lane := 0; lane < count; lane++ {
			if live&(1<<lane) != 0 && bytes.Equal(encodedQ[lane][:], sigs[offset+lane][:32]) {
				accepted |= 1 << lane
			}
		}
	}
	for lane := 0; lane < count; lane++ {
		ok[offset+lane] = accepted&(1<<lane) != 0
	}
}

func verifyR51GroupX4(profile Profile, pubs []*[32]byte, msgs, sigs [][]byte, ok []bool, offset, count int, radixBits uint, generator *r51x5.Point) {
	var aBytes, rBytes [r51x5.X4Lanes][32]byte
	var s [r51x5.X4Lanes][32]byte
	var candidates uint8
	for lane := 0; lane < count; lane++ {
		index := offset + lane
		coefficient, valid := prepareR51Signature(profile, pubs[index], sigs[index])
		if !valid {
			continue
		}
		aBytes[lane] = *pubs[index]
		copy(rBytes[lane][:], sigs[index][:32])
		s[lane] = coefficient
		candidates |= 1 << lane
	}

	var A r51x5.PointX4
	var R r51x5.AffinePointX4
	aValid, rValid := r51x5.Decode2NoTX4(&A, &R, &aBytes, &rBytes, candidates)
	live := candidates & aValid & rValid
	if live == 0 {
		return
	}

	var k [r51x5.X4Lanes][32]byte
	live &= reduceR51ChallengesX4(&k, pubs, msgs, sigs, offset, count, live)
	if live == 0 {
		return
	}

	var generatorLanes [r51x5.X4Lanes]r51x5.Point
	for lane := range generatorLanes {
		generatorLanes[lane] = *generator
	}
	var B r51x5.PointX4
	B.SetPoints(&generatorLanes)
	bases := [r51x5.DSMTerms]r51x5.PointX4{B, A}
	var coefficients r51x5.FixedDSMScalarsX4
	for lane := 0; lane < count; lane++ {
		if live&(1<<lane) == 0 {
			continue
		}
		coefficients[0][lane] = s[lane]
		coefficients[1][lane] = k[lane]
	}
	var Q r51x5.PointX4
	var workspace r51x5.FixedDSMWorkspaceX4
	workspace.Prepare(&bases, radixBits)
	negative := [r51x5.DSMTerms]uint8{0, live}
	live &= workspace.Evaluate(&Q, &coefficients, &negative, live)

	var accepted uint8
	if profile == DalekStrict {
		accepted = Q.EqualCompactAffine(&R) & live
	} else {
		encodedQ := Q.Bytes()
		for lane := 0; lane < count; lane++ {
			if live&(1<<lane) != 0 && bytes.Equal(encodedQ[lane][:], sigs[offset+lane][:32]) {
				accepted |= 1 << lane
			}
		}
	}
	for lane := 0; lane < count; lane++ {
		ok[offset+lane] = accepted&(1<<lane) != 0
	}
}

func reduceR51ChallengesX8(out *[r51x5.X8Lanes][32]byte, pubs []*[32]byte, msgs, sigs [][]byte, offset, count int, live uint8) uint8 {
	var segments [r51x5.X8Lanes][3][]byte
	var inputs [r51x5.X8Lanes][][]byte
	var lanes [r51x5.X8Lanes]int
	inputCount := 0
	for lane := 0; lane < count; lane++ {
		if live&(1<<lane) == 0 {
			continue
		}
		index := offset + lane
		segments[inputCount] = [3][]byte{sigs[index][:32], pubs[index][:], msgs[index]}
		inputs[inputCount] = segments[inputCount][:]
		lanes[inputCount] = lane
		inputCount++
	}
	var digests [r51x5.X8Lanes][64]byte
	sha512mb.Sum512Batch(digests[:inputCount], inputs[:inputCount])
	for digestIndex := 0; digestIndex < inputCount; digestIndex++ {
		lane := lanes[digestIndex]
		reduced, err := edwards25519.NewScalar().SetUniformBytes(digests[digestIndex][:])
		if err != nil {
			live &^= 1 << lane
			continue
		}
		copy(out[lane][:], reduced.Bytes())
	}
	return live
}

func reduceR51ChallengesX4(out *[r51x5.X4Lanes][32]byte, pubs []*[32]byte, msgs, sigs [][]byte, offset, count int, live uint8) uint8 {
	var segments [r51x5.X4Lanes][3][]byte
	var inputs [r51x5.X4Lanes][][]byte
	var lanes [r51x5.X4Lanes]int
	inputCount := 0
	for lane := 0; lane < count; lane++ {
		if live&(1<<lane) == 0 {
			continue
		}
		index := offset + lane
		segments[inputCount] = [3][]byte{sigs[index][:32], pubs[index][:], msgs[index]}
		inputs[inputCount] = segments[inputCount][:]
		lanes[inputCount] = lane
		inputCount++
	}
	var digests [r51x5.X4Lanes][64]byte
	sha512mb.Sum512Batch(digests[:inputCount], inputs[:inputCount])
	for digestIndex := 0; digestIndex < inputCount; digestIndex++ {
		lane := lanes[digestIndex]
		reduced, err := edwards25519.NewScalar().SetUniformBytes(digests[digestIndex][:])
		if err != nil {
			live &^= 1 << lane
			continue
		}
		copy(out[lane][:], reduced.Bytes())
	}
	return live
}

type r51ReferenceVector struct {
	name string
	pub  [32]byte
	msg  []byte
	sig  []byte
}

func TestR51ReferenceVerifierMatchesCCTVAndWycheproof(t *testing.T) {
	corpora := []struct {
		name    string
		vectors []r51ReferenceVector
	}{
		{"cctv", r51CCTVVectors(t)},
		{"wycheproof", r51WycheproofVectors(t)},
	}
	configs := []struct {
		name    string
		profile Profile
	}{
		{"strict", DalekStrict},
		{"compat", StdlibCompat},
	}
	for _, corpus := range corpora {
		for _, config := range configs {
			t.Run(corpus.name+"/"+config.name, func(t *testing.T) {
				assertR51ReferenceVectors(t, corpus.vectors, config.profile, r51x5.X8Lanes, 4)
			})
		}
	}
}

func TestR51ReferenceVerifierWidthsRadicesMasksAndTails(t *testing.T) {
	vectors := makeR51HonestVectors(t, 17)
	invalidPoint := findR51InvalidEncoding(t)
	for _, profile := range []Profile{DalekStrict, StdlibCompat} {
		for _, width := range []int{r51x5.X4Lanes, r51x5.X8Lanes} {
			for _, radixBits := range []uint{4, 5} {
				label := fmt.Sprintf("profile=%d/width=%d/radix=%d", profile, width, 1<<radixBits)
				t.Run(label, func(t *testing.T) {
					// Exercise every natural group fill and every multi-group tail
					// through the 8/9 and 16/17 boundaries.
					for count := 0; count <= len(vectors); count++ {
						assertR51ReferenceVectors(t, vectors[:count], profile, width, radixBits)
					}
					for invalidLane := 0; invalidLane < width; invalidLane++ {
						invalidS := cloneR51Vectors(vectors[:width])
						invalidS[invalidLane].sig[63] |= 0xe0
						assertR51ReferenceVectors(t, invalidS, profile, width, radixBits)

						invalidA := cloneR51Vectors(vectors[:width])
						invalidA[invalidLane].pub = invalidPoint
						assertR51ReferenceVectors(t, invalidA, profile, width, radixBits)

						invalidR := cloneR51Vectors(vectors[:width])
						copy(invalidR[invalidLane].sig[:32], invalidPoint[:])
						assertR51ReferenceVectors(t, invalidR, profile, width, radixBits)
					}
				})
			}
		}
	}
}

func TestR51ReferenceVerifierMapsFullEquationFailureAtEveryBatchPosition(t *testing.T) {
	vectors := makeR51HonestVectors(t, 17)
	for _, width := range []int{r51x5.X4Lanes, r51x5.X8Lanes} {
		for _, radixBits := range []uint{4, 5} {
			for invalidLane := range vectors {
				candidate := cloneR51Vectors(vectors)
				candidate[invalidLane].msg[0] ^= 0x80
				assertR51ReferenceVectors(t, candidate, DalekStrict, width, radixBits)
			}
		}
	}
}

func TestR51ReferenceVerifierRandomValidInvalidMixtures(t *testing.T) {
	vectors := makeR51HonestVectors(t, 67)
	for i := range vectors {
		switch i % 5 {
		case 1:
			vectors[i].sig[7] ^= 0x20
		case 2:
			vectors[i].msg[0] ^= 0x80
		case 3:
			vectors[i].pub[11] ^= 0x08
		case 4:
			vectors[i].sig[63] |= 0xe0
		}
	}
	for _, profile := range []Profile{DalekStrict, StdlibCompat} {
		for _, width := range []int{r51x5.X4Lanes, r51x5.X8Lanes} {
			for _, radixBits := range []uint{4, 5} {
				assertR51ReferenceVectors(t, vectors, profile, width, radixBits)
			}
		}
	}
}

func TestR51ReferenceStrictPreparationKeepsPermissiveA(t *testing.T) {
	var noncanonicalA [32]byte
	found := false
	for alias := byte(2); alias <= 18 && !found; alias++ {
		candidate := [32]byte{0: 0xed + alias, 31: 0x7f}
		for i := 1; i < 31; i++ {
			candidate[i] = 0xff
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
		t.Fatal("failed to find a decodable noncanonical non-small-order A alias")
	}

	honest := makeR51HonestVectors(t, 1)[0]
	if _, valid := prepareR51Signature(DalekStrict, &noncanonicalA, honest.sig); !valid {
		t.Fatal("strict r51 preparation added a forbidden canonical-A rejection")
	}
}

func assertR51ReferenceVectors(t *testing.T, vectors []r51ReferenceVector, profile Profile, width int, radixBits uint) {
	t.Helper()
	pubs := make([]*[32]byte, len(vectors))
	msgs := make([][]byte, len(vectors))
	sigs := make([][]byte, len(vectors))
	got := make([]bool, len(vectors))
	want := make([]bool, len(vectors))
	allWant := true
	for i := range vectors {
		pubs[i] = &vectors[i].pub
		msgs[i] = vectors[i].msg
		sigs[i] = vectors[i].sig
		want[i] = referenceVerifyProfile(profile, &vectors[i].pub, vectors[i].msg, vectors[i].sig)
		allWant = allWant && want[i]
	}
	if allGot := verifyR51BatchReference(profile, pubs, msgs, sigs, got, width, radixBits); allGot != allWant {
		t.Fatalf("width=%d radix=%d aggregate=%v want=%v", width, 1<<radixBits, allGot, allWant)
	}
	for i := range vectors {
		if got[i] != want[i] {
			t.Fatalf("%s profile=%d width=%d radix=%d got=%v want=%v\npub=%x\nmsg=%x\nsig=%x", vectors[i].name, profile, width, 1<<radixBits, got[i], want[i], vectors[i].pub, vectors[i].msg, vectors[i].sig)
		}
	}
}

func r51CCTVVectors(t *testing.T) []r51ReferenceVector {
	t.Helper()
	result := make([]r51ReferenceVector, len(cctvVectors))
	for i, vector := range cctvVectors {
		result[i] = decodeR51Vector(t, fmt.Sprintf("cctv/%d", vector.tcID), vector.pub, vector.msg, vector.sig)
	}
	return result
}

func r51WycheproofVectors(t *testing.T) []r51ReferenceVector {
	t.Helper()
	result := make([]r51ReferenceVector, len(wycheproofVectors))
	for i, vector := range wycheproofVectors {
		result[i] = decodeR51Vector(t, fmt.Sprintf("wycheproof/%d", vector.tcID), vector.pub, vector.msg, vector.sig)
	}
	return result
}

func decodeR51Vector(t *testing.T, name, publicKey, message, signature string) r51ReferenceVector {
	t.Helper()
	pubBytes, err := hex.DecodeString(publicKey)
	if err != nil || len(pubBytes) != stded25519.PublicKeySize {
		t.Fatalf("%s: malformed public key fixture", name)
	}
	msg, err := hex.DecodeString(message)
	if err != nil {
		t.Fatalf("%s: malformed message fixture", name)
	}
	sig, err := hex.DecodeString(signature)
	if err != nil {
		t.Fatalf("%s: malformed signature fixture", name)
	}
	var pub [32]byte
	copy(pub[:], pubBytes)
	return r51ReferenceVector{name: name, pub: pub, msg: msg, sig: sig}
}

func makeR51HonestVectors(t testing.TB, count int) []r51ReferenceVector {
	t.Helper()
	rng := rand.New(rand.NewSource(0x5151ba7c))
	result := make([]r51ReferenceVector, count)
	for i := range result {
		publicKey, privateKey, err := stded25519.GenerateKey(rng)
		if err != nil {
			t.Fatal(err)
		}
		message := make([]byte, 1+(i*73)%1232)
		if _, err := rng.Read(message); err != nil {
			t.Fatal(err)
		}
		copy(result[i].pub[:], publicKey)
		result[i].name = fmt.Sprintf("honest/%d", i)
		result[i].msg = message
		result[i].sig = stded25519.Sign(privateKey, message)
	}
	return result
}

func cloneR51Vectors(in []r51ReferenceVector) []r51ReferenceVector {
	out := make([]r51ReferenceVector, len(in))
	for i := range in {
		out[i] = in[i]
		out[i].msg = append([]byte(nil), in[i].msg...)
		out[i].sig = append([]byte(nil), in[i].sig...)
	}
	return out
}

func findR51InvalidEncoding(t *testing.T) [32]byte {
	t.Helper()
	rng := rand.New(rand.NewSource(0x51dec0de))
	for attempts := 0; attempts < 1024; attempts++ {
		var candidate [32]byte
		_, _ = rng.Read(candidate[:])
		if _, err := new(r51x5.Point).SetBytes(candidate[:]); err != nil {
			return candidate
		}
	}
	t.Fatal("failed to find a deterministic invalid r51 point encoding")
	return [32]byte{}
}

var benchmarkR51ReferenceBatchResult bool

func BenchmarkR51ReferenceBatch(b *testing.B) {
	for _, messageSize := range []int{64, 200, 1232} {
		fixture := makeBatchFixture(b, 8, messageSize)
		for _, width := range []int{r51x5.X4Lanes, r51x5.X8Lanes} {
			for _, radixBits := range []uint{4, 5} {
				name := fmt.Sprintf("profile=strict/width=x%d/radix=%d/n=8/msg=%d", width, 1<<radixBits, messageSize)
				b.Run(name, func(b *testing.B) {
					b.ReportAllocs()
					var result bool
					for i := 0; i < b.N; i++ {
						result = verifyR51BatchReference(DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok, width, radixBits)
					}
					benchmarkR51ReferenceBatchResult = result
					b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*len(fixture.pubs))/1000, "µs/sig")
				})
			}
		}
	}
}
