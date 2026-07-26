//go:build oasis_compare

package ed25519

import (
	"bytes"
	stded25519 "crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"testing"

	oasised25519 "github.com/oasisprotocol/curve25519-voi/primitives/ed25519"
)

// oasisDalekStrictOptions is the exact curve25519-voi spelling of Narya's
// DalekStrict predicate. The zero-valued small-order and noncanonical-R flags
// deliberately reject those cases; A remains permissively decoded, and the
// final equation is cofactorless with a canonical byte comparison for R.
//
// Do not replace this with a curve25519-voi preset. VerifyOptionsDefault is
// cofactored, VerifyOptionsStdLib allows small-order points, and aggregate
// batch verification cannot implement a cofactorless predicate.
var oasisDalekStrictOptions = &oasised25519.Options{
	Verify: &oasised25519.VerifyOptions{
		AllowNonCanonicalA: true,
		CofactorlessVerify: true,
	},
}

// oasisCofactoredStrictBenchmarkOptions differs from DalekStrict only in the
// verification equation. It retains the same public-key/signature admission
// policy, but deliberately selects curve25519-voi's cofactored ABGLSV-Pornin
// path. It is benchmark-only: its verdict is not a Narya consensus oracle.
var oasisCofactoredStrictBenchmarkOptions = &oasised25519.Options{
	Verify: &oasised25519.VerifyOptions{
		AllowNonCanonicalA: true,
	},
}

func oasisVerifyDalekStrict(pub *[stded25519.PublicKeySize]byte, message, sig []byte) bool {
	return oasised25519.VerifyWithOptions(pub[:], message, sig, oasisDalekStrictOptions)
}

func assertOasisMatchesNaryaStrict(t *testing.T, label string, pub *[stded25519.PublicKeySize]byte, message, sig []byte) {
	t.Helper()

	want := referenceVerifyProfile(DalekStrict, pub, message, sig)
	narya := VerifyStrict(pub[:], message, sig)
	oasis := oasisVerifyDalekStrict(pub, message, sig)
	if narya != want || oasis != want {
		t.Fatalf("%s: narya=%v oasis=%v oracle=%v\npub=%x\nmsg=%x\nsig=%x", label, narya, oasis, want, pub[:], message, sig)
	}

	// ExpandedPublicKey must preserve the same acceptance predicate. Invalid
	// point encodings cannot be expanded and have already been compared via
	// the ordinary Oasis path above.
	expanded, err := oasised25519.NewExpandedPublicKey(pub[:])
	if err == nil {
		if got := oasised25519.VerifyExpandedWithOptions(expanded, message, sig, oasisDalekStrictOptions); got != want {
			t.Fatalf("%s: oasis-expanded=%v oracle=%v\npub=%x\nmsg=%x\nsig=%x", label, got, want, pub[:], message, sig)
		}
	}
}

func decodeOasisComparisonVector(t *testing.T, label, pubHex, msgHex, sigHex string) ([32]byte, []byte, []byte) {
	t.Helper()
	pubBytes, err := hex.DecodeString(pubHex)
	if err != nil || len(pubBytes) != stded25519.PublicKeySize {
		t.Fatalf("%s: invalid public key fixture", label)
	}
	message, err := hex.DecodeString(msgHex)
	if err != nil {
		t.Fatalf("%s: invalid message fixture: %v", label, err)
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil || len(sig) != stded25519.SignatureSize {
		t.Fatalf("%s: invalid signature fixture", label)
	}
	var pub [stded25519.PublicKeySize]byte
	copy(pub[:], pubBytes)
	return pub, message, sig
}

func TestOasisDalekStrictReferenceCorpora(t *testing.T) {
	t.Run("CCTV", func(t *testing.T) {
		for _, vector := range cctvVectors {
			label := fmt.Sprintf("CCTV/tc=%d", vector.tcID)
			pub, message, sig := decodeOasisComparisonVector(t, label, vector.pub, vector.msg, vector.sig)
			assertOasisMatchesNaryaStrict(t, label, &pub, message, sig)
		}
	})

	t.Run("Wycheproof", func(t *testing.T) {
		for _, vector := range wycheproofVectors {
			label := fmt.Sprintf("Wycheproof/tc=%d", vector.tcID)
			pub, message, sig := decodeOasisComparisonVector(t, label, vector.pub, vector.msg, vector.sig)
			assertOasisMatchesNaryaStrict(t, label, &pub, message, sig)
		}
	})
}

func TestOasisDalekStrictEdgeAndMixedOrderFixtures(t *testing.T) {
	var seed [stded25519.SeedSize]byte
	for i := range seed {
		seed[i] = byte(7*i + 3)
	}
	privateKey := stded25519.NewKeyFromSeed(seed[:])
	var honestPub [stded25519.PublicKeySize]byte
	copy(honestPub[:], privateKey.Public().(stded25519.PublicKey))
	message := []byte("oasis DalekStrict edge comparison")
	honestSig := stded25519.Sign(privateKey, message)
	rng := rand.New(rand.NewSource(0x0a515))

	checkEncodedPoint := func(label string, encoded []byte) {
		t.Helper()
		if len(encoded) != stded25519.PublicKeySize {
			t.Fatalf("%s: point has %d bytes", label, len(encoded))
		}

		var edgePub [stded25519.PublicKeySize]byte
		copy(edgePub[:], encoded)
		assertOasisMatchesNaryaStrict(t, label+"/A-honest-sig", &edgePub, message, honestSig)

		randomSig := make([]byte, stded25519.SignatureSize)
		_, _ = rng.Read(randomSig)
		randomSig[63] &= 0x1f
		assertOasisMatchesNaryaStrict(t, label+"/A-random-sig", &edgePub, message, randomSig)

		edgeR := append([]byte(nil), honestSig...)
		copy(edgeR[:32], encoded)
		assertOasisMatchesNaryaStrict(t, label+"/R", &honestPub, message, edgeR)
	}

	for i, encodedHex := range edgePoints {
		encoded, err := hex.DecodeString(encodedHex)
		if err != nil {
			t.Fatal(err)
		}
		checkEncodedPoint(fmt.Sprintf("edgePoints/%d", i), encoded)
	}
	for i, encodedHex := range sevenSmallOrderLow255 {
		encoded, err := hex.DecodeString(encodedHex)
		if err != nil {
			t.Fatal(err)
		}
		for sign := byte(0); sign <= 1; sign++ {
			candidate := append([]byte(nil), encoded...)
			candidate[31] = candidate[31]&0x7f | sign<<7
			checkEncodedPoint(fmt.Sprintf("small-order/%d/sign=%d", i, sign), candidate)
		}
	}

	assertOasisMatchesNaryaStrict(t, "signature-length/63", &honestPub, message, honestSig[:63])
	assertOasisMatchesNaryaStrict(t, "signature-length/65", &honestPub, message, append(append([]byte(nil), honestSig...), 0))

	nonCanonicalS := append([]byte(nil), honestSig...)
	copy(nonCanonicalS[32:], []byte{
		0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
		0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
	})
	assertOasisMatchesNaryaStrict(t, "noncanonical-S/order", &honestPub, message, nonCanonicalS)

	// This existing fixture is deliberately valid with mixed-order A and R.
	// It catches implementations that accidentally replace exact signed -k
	// with the scalar residue L-k and erase the torsion component.
	mixed := makeR51MixedOrderValidVector(t)
	assertOasisMatchesNaryaStrict(t, mixed.name, &mixed.pub, mixed.msg, mixed.sig)
	badMixed := append([]byte(nil), mixed.sig...)
	badMixed[17] ^= 0x20
	assertOasisMatchesNaryaStrict(t, mixed.name+"/mutated", &mixed.pub, mixed.msg, badMixed)
}

func TestOasisDalekStrictDeterministicRandomDifferential(t *testing.T) {
	rng := rand.New(rand.NewSource(0x0a515c0de))
	for round := 0; round < 512; round++ {
		var seed [stded25519.SeedSize]byte
		_, _ = rng.Read(seed[:])
		privateKey := stded25519.NewKeyFromSeed(seed[:])
		var pub [stded25519.PublicKeySize]byte
		copy(pub[:], privateKey.Public().(stded25519.PublicKey))
		message := make([]byte, rng.Intn(1233))
		_, _ = rng.Read(message)
		sig := stded25519.Sign(privateKey, message)

		assertOasisMatchesNaryaStrict(t, fmt.Sprintf("round=%d/honest", round), &pub, message, sig)

		mutatedSig := append([]byte(nil), sig...)
		mutatedSig[rng.Intn(len(mutatedSig))] ^= 1 << uint(rng.Intn(8))
		assertOasisMatchesNaryaStrict(t, fmt.Sprintf("round=%d/signature-bit", round), &pub, message, mutatedSig)

		if len(message) != 0 {
			mutatedMessage := append([]byte(nil), message...)
			mutatedMessage[rng.Intn(len(mutatedMessage))] ^= 1 << uint(rng.Intn(8))
			assertOasisMatchesNaryaStrict(t, fmt.Sprintf("round=%d/message-bit", round), &pub, mutatedMessage, sig)
		}

		mutatedPub := pub
		mutatedPub[rng.Intn(len(mutatedPub))] ^= 1 << uint(rng.Intn(8))
		assertOasisMatchesNaryaStrict(t, fmt.Sprintf("round=%d/public-key-bit", round), &mutatedPub, message, sig)

		garbageSig := make([]byte, stded25519.SignatureSize)
		_, _ = rng.Read(garbageSig)
		assertOasisMatchesNaryaStrict(t, fmt.Sprintf("round=%d/garbage-signature", round), &pub, message, garbageSig)
	}
}

func TestOasisAggregateBatchCannotImplementDalekStrict(t *testing.T) {
	fixture := makeFixture(t, 200)
	if !oasisVerifyDalekStrict(&fixture.pub, fixture.msg, fixture.sig) {
		t.Fatal("ordinary Oasis strict verifier rejected the honest control")
	}

	// curve25519-voi's aggregate BatchVerifier uses a cofactored random-linear
	// combination. It deliberately returns false when any entry requests
	// CofactorlessVerify, even if every signature is valid. It therefore is
	// not a Narya VerifyBatchStrict competitor and must not appear in strict
	// performance comparisons.
	var batch oasised25519.BatchVerifier
	batch.AddWithOptions(fixture.pub[:], fixture.msg, fixture.sig, oasisDalekStrictOptions)
	if batch.VerifyBatchOnly(bytes.NewReader(make([]byte, 64))) {
		t.Fatal("Oasis aggregate batch unexpectedly accepted a cofactorless entry")
	}
}

// oasisR51X4TailVerifier is a test-only dispatcher for the batch-width shape
// that the ordinary x8 experiment handles poorly: every complete group of
// four uses the real r51 x4 radix-64 pipeline, while only the 1--3 item tail
// uses curve25519-voi's consensus-equivalent serial verifier. The r51
// pipeline is mutable and non-concurrent, so one dispatcher belongs to one
// worker just like the underlying experimental pipeline.
type oasisR51X4TailVerifier struct {
	pipeline *r51IFMAPipeline

	// expanded is nil for the cold Oasis tail. A non-nil slice is aligned
	// with the input batch and must be prepared before a timed region.
	expanded []*oasised25519.ExpandedPublicKey

	// failAfterPrefix is an error-injection seam for the wrapper's fail-closed
	// contract. It is never set by a benchmark candidate.
	failAfterPrefix error
}

func prepareOasisExpandedPublicKeys(pubs []*[32]byte) []*oasised25519.ExpandedPublicKey {
	expanded := make([]*oasised25519.ExpandedPublicKey, len(pubs))
	for index, pub := range pubs {
		if pub == nil {
			continue
		}
		candidate, err := oasised25519.NewExpandedPublicKey(pub[:])
		if err == nil {
			expanded[index] = candidate
		}
	}
	return expanded
}

func clearOasisR51X4TailVerdicts(ok []bool) {
	for index := range ok {
		ok[index] = false
	}
}

func (verifier *oasisR51X4TailVerifier) VerifyBatch(pubs []*[32]byte, msgs, sigs [][]byte, ok []bool) (bool, error) {
	if len(pubs) != len(msgs) || len(msgs) != len(sigs) || len(sigs) != len(ok) {
		panic("ed25519: Oasis/r51 x4-tail batch slice lengths differ")
	}
	if verifier.expanded != nil && len(verifier.expanded) != len(pubs) {
		panic("ed25519: Oasis/r51 x4-tail expanded-key slice length differs")
	}

	// Initialize the whole output, including the serial tail, before exposing
	// any r51 verdict. Any later kernel error clears the whole slice again.
	clearOasisR51X4TailVerdicts(ok)
	prefix := len(pubs) - len(pubs)%4
	all := true
	if prefix != 0 {
		if verifier.pipeline == nil {
			return false, errors.New("ed25519: missing r51 x4-tail pipeline")
		}
		prefixAll, err := verifier.pipeline.VerifyBatch(
			DalekStrict,
			pubs[:prefix],
			msgs[:prefix],
			sigs[:prefix],
			ok[:prefix],
		)
		if err != nil {
			clearOasisR51X4TailVerdicts(ok)
			return false, err
		}
		all = prefixAll
		if verifier.failAfterPrefix != nil {
			clearOasisR51X4TailVerdicts(ok)
			return false, verifier.failAfterPrefix
		}
	}

	for index := prefix; index < len(pubs); index++ {
		accepted := false
		if pubs[index] != nil {
			if verifier.expanded == nil {
				accepted = oasised25519.VerifyWithOptions(
					pubs[index][:],
					msgs[index],
					sigs[index],
					oasisDalekStrictOptions,
				)
			} else if verifier.expanded[index] != nil {
				accepted = oasised25519.VerifyExpandedWithOptions(
					verifier.expanded[index],
					msgs[index],
					sigs[index],
					oasisDalekStrictOptions,
				)
			}
		}
		ok[index] = accepted
		all = all && accepted
	}
	return all, nil
}

type oasisR51X4TailFixture struct {
	pubs []*[32]byte
	msgs [][]byte
	sigs [][]byte
	ok   []bool
}

func makeOasisR51X4TailFixture(vectors []r51ReferenceVector) oasisR51X4TailFixture {
	fixture := oasisR51X4TailFixture{
		pubs: make([]*[32]byte, len(vectors)),
		msgs: make([][]byte, len(vectors)),
		sigs: make([][]byte, len(vectors)),
		ok:   make([]bool, len(vectors)),
	}
	for index := range vectors {
		fixture.pubs[index] = &vectors[index].pub
		fixture.msgs[index] = vectors[index].msg
		fixture.sigs[index] = vectors[index].sig
	}
	return fixture
}

func assertOasisR51X4TailFixture(t *testing.T, label string, verifier *oasisR51X4TailVerifier, fixture *oasisR51X4TailFixture) {
	t.Helper()
	wantAll := true
	want := make([]bool, len(fixture.pubs))
	for index := range want {
		want[index] = referenceVerifyProfile(DalekStrict, fixture.pubs[index], fixture.msgs[index], fixture.sigs[index])
		wantAll = wantAll && want[index]
		fixture.ok[index] = !want[index]
	}

	gotAll, err := verifier.VerifyBatch(fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok)
	if err != nil {
		t.Fatalf("%s: verify: %v", label, err)
	}
	if gotAll != wantAll {
		t.Fatalf("%s: aggregate=%v want=%v", label, gotAll, wantAll)
	}
	for index := range want {
		if fixture.ok[index] != want[index] {
			t.Fatalf("%s: lane=%d got=%v want=%v", label, index, fixture.ok[index], want[index])
		}
	}
}

func TestOasisR51X4TailDifferentialEveryInvalidLane(t *testing.T) {
	if !r51IFMAPipelineAvailable(r51IFMAX4) {
		t.Skip("real r51 x4 pipeline unavailable")
	}
	pipeline := requireR51IFMAPipeline(t, r51IFMAX4, 6)

	for count := 1; count <= 17; count++ {
		vectors := makeR51HonestVectors(t, count)
		honest := makeOasisR51X4TailFixture(vectors)
		cold := oasisR51X4TailVerifier{pipeline: pipeline}
		expanded := oasisR51X4TailVerifier{
			pipeline: pipeline,
			expanded: prepareOasisExpandedPublicKeys(honest.pubs),
		}
		assertOasisR51X4TailFixture(t, fmt.Sprintf("count=%d/mode=cold/honest", count), &cold, &honest)
		assertOasisR51X4TailFixture(t, fmt.Sprintf("count=%d/mode=expanded/honest", count), &expanded, &honest)

		for invalidLane := 0; invalidLane < count; invalidLane++ {
			invalidVectors := cloneR51Vectors(vectors)
			// This is a full-equation failure, rather than a cheap scalar or
			// strict-profile precheck, so every SIMD and tail position must
			// carry its independently computed verdict through final equality.
			invalidVectors[invalidLane].sig[0] ^= 1
			invalid := makeOasisR51X4TailFixture(invalidVectors)
			cold.expanded = nil
			expanded.expanded = prepareOasisExpandedPublicKeys(invalid.pubs)
			assertOasisR51X4TailFixture(t, fmt.Sprintf("count=%d/mode=cold/invalid-lane=%d", count, invalidLane), &cold, &invalid)
			assertOasisR51X4TailFixture(t, fmt.Sprintf("count=%d/mode=expanded/invalid-lane=%d", count, invalidLane), &expanded, &invalid)
		}
	}
}

func TestOasisR51X4TailKernelErrorFailsClosed(t *testing.T) {
	if !r51IFMAPipelineAvailable(r51IFMAX4) {
		t.Skip("real r51 x4 pipeline unavailable")
	}
	vectors := makeR51HonestVectors(t, 5)
	fixture := makeOasisR51X4TailFixture(vectors)
	for index := range fixture.ok {
		fixture.ok[index] = true
	}
	wantErr := errors.New("injected error after completed prefix")
	verifier := oasisR51X4TailVerifier{
		pipeline:        requireR51IFMAPipeline(t, r51IFMAX4, 6),
		failAfterPrefix: wantErr,
	}
	all, err := verifier.VerifyBatch(fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok)
	if all || !errors.Is(err, wantErr) {
		t.Fatalf("verify=(%v,%v), want (false,%v)", all, err, wantErr)
	}
	for index, accepted := range fixture.ok {
		if accepted {
			t.Fatalf("kernel error exposed accepted lane %d", index)
		}
	}
}

func TestOasisR51X4TailZeroAllocations(t *testing.T) {
	if !r51IFMAPipelineAvailable(r51IFMAX4) {
		t.Skip("real r51 x4 pipeline unavailable")
	}
	pipeline := requireR51IFMAPipeline(t, r51IFMAX4, 6)
	for _, count := range []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 17} {
		fixture := makeBatchFixture(t, count, 200)
		candidates := [...]struct {
			name     string
			expanded []*oasised25519.ExpandedPublicKey
		}{
			{name: "cold"},
			{name: "expanded", expanded: prepareOasisExpandedPublicKeys(fixture.pubs)},
		}
		for _, candidate := range candidates {
			verifier := oasisR51X4TailVerifier{pipeline: pipeline, expanded: candidate.expanded}
			if allocations := testing.AllocsPerRun(10, func() {
				all, err := verifier.VerifyBatch(fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok)
				if err != nil || !all {
					panic(fmt.Sprintf("verify=(%v,%v)", all, err))
				}
			}); allocations != 0 {
				t.Fatalf("mode=%s count=%d allocations=%v", candidate.name, count, allocations)
			}
		}
	}
}

var oasisComparisonResult bool

// BenchmarkOasisVerify compares only consensus-equivalent single-signature
// paths over the same message-size fixture used by BenchmarkVerify. The Oasis
// aggregate BatchVerifier is intentionally absent: its randomized cofactored
// equation is incompatible with DalekStrict's cofactorless predicate.
func BenchmarkOasisVerify(b *testing.B) {
	for _, messageSize := range []int{1232} {
		fixture := makeFixture(b, messageSize)
		expanded, err := oasised25519.NewExpandedPublicKey(fixture.pub[:])
		if err != nil {
			b.Fatal(err)
		}

		b.Run(fmt.Sprintf("impl=narya-strict/msg=%d", messageSize), func(b *testing.B) {
			b.ReportAllocs()
			var ok bool
			for i := 0; i < b.N; i++ {
				ok = VerifyStrict(fixture.pub[:], fixture.msg, fixture.sig)
			}
			if !ok {
				b.Fatal("verification failed")
			}
			oasisComparisonResult = ok
		})

		b.Run(fmt.Sprintf("impl=oasis-strict-cold/msg=%d", messageSize), func(b *testing.B) {
			b.ReportAllocs()
			var ok bool
			for i := 0; i < b.N; i++ {
				ok = oasised25519.VerifyWithOptions(fixture.pub[:], fixture.msg, fixture.sig, oasisDalekStrictOptions)
			}
			if !ok {
				b.Fatal("verification failed")
			}
			oasisComparisonResult = ok
		})

		b.Run(fmt.Sprintf("impl=oasis-strict-expanded/msg=%d", messageSize), func(b *testing.B) {
			b.ReportAllocs()
			var ok bool
			for i := 0; i < b.N; i++ {
				ok = oasised25519.VerifyExpandedWithOptions(expanded, fixture.msg, fixture.sig, oasisDalekStrictOptions)
			}
			if !ok {
				b.Fatal("verification failed")
			}
			oasisComparisonResult = ok
		})

		// These two rows quantify Voi's ABGLSV-Pornin speedup on honest
		// signatures. Their cofactored equation is not DalekStrict and must
		// never be used as an acceptance-predicate comparison.
		b.Run(fmt.Sprintf("impl=oasis-cofactored-pornin-cold/msg=%d", messageSize), func(b *testing.B) {
			b.ReportAllocs()
			var ok bool
			for i := 0; i < b.N; i++ {
				ok = oasised25519.VerifyWithOptions(fixture.pub[:], fixture.msg, fixture.sig, oasisCofactoredStrictBenchmarkOptions)
			}
			if !ok {
				b.Fatal("cofactored verification failed")
			}
			oasisComparisonResult = ok
		})

		b.Run(fmt.Sprintf("impl=oasis-cofactored-pornin-expanded/msg=%d", messageSize), func(b *testing.B) {
			b.ReportAllocs()
			var ok bool
			for i := 0; i < b.N; i++ {
				ok = oasised25519.VerifyExpandedWithOptions(expanded, fixture.msg, fixture.sig, oasisCofactoredStrictBenchmarkOptions)
			}
			if !ok {
				b.Fatal("cofactored expanded verification failed")
			}
			oasisComparisonResult = ok
		})
	}
}

func BenchmarkOasisExpandedPublicKeyBuild(b *testing.B) {
	fixture := makeFixture(b, 64)
	b.ReportAllocs()
	var expanded *oasised25519.ExpandedPublicKey
	var err error
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		expanded, err = oasised25519.NewExpandedPublicKey(fixture.pub[:])
	}
	if err != nil || expanded == nil {
		b.Fatalf("NewExpandedPublicKey: %v", err)
	}
}

// BenchmarkOasisR51X4Tail measures a real x4/radix-64 prefix with a serial
// 1--3 lane Oasis tail. The expanded mode prepares every public key before
// the timer starts; only the tail consumes those tables. The complete groups
// remain cold arbitrary-key r51 work in both modes.
func BenchmarkOasisR51X4Tail(b *testing.B) {
	if !r51IFMAPipelineAvailable(r51IFMAX4) {
		b.Skip("real r51 x4 pipeline unavailable")
	}
	counts := make([]int, 0, 19)
	for count := 1; count <= 17; count++ {
		counts = append(counts, count)
	}
	counts = append(counts, 32, 64)
	pipeline := requireR51IFMAPipeline(b, r51IFMAX4, 6)

	for _, messageSize := range []int{64, 200, 1232} {
		for _, count := range counts {
			fixture := makeBatchFixture(b, count, messageSize)
			expanded := prepareOasisExpandedPublicKeys(fixture.pubs)
			candidates := [...]struct {
				name     string
				expanded []*oasised25519.ExpandedPublicKey
			}{
				{name: "cold"},
				{name: "expanded", expanded: expanded},
			}

			for _, candidate := range candidates {
				b.Run(fmt.Sprintf("mode=%s/n=%d/msg=%d", candidate.name, count, messageSize), func(b *testing.B) {
					verifier := oasisR51X4TailVerifier{pipeline: pipeline, expanded: candidate.expanded}
					b.ReportAllocs()
					b.ResetTimer()
					var result bool
					var err error
					for iteration := 0; iteration < b.N; iteration++ {
						result, err = verifier.VerifyBatch(fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok)
						if err != nil {
							break
						}
					}
					b.StopTimer()
					if err != nil {
						b.Fatal(err)
					}
					if !result {
						b.Fatal("hybrid verifier rejected a valid fixture")
					}
					oasisComparisonResult = result
					elapsed := b.Elapsed()
					b.ReportMetric(float64(elapsed.Nanoseconds())/float64(b.N*count)/1000, "µs/sig")
					b.ReportMetric(float64(b.N*count)/elapsed.Seconds(), "sig/s")
				})
			}
		}
	}
}
