package r51x5

import (
	"bytes"
	stded25519 "crypto/ed25519"
	"crypto/rand"
	"testing"
)

// BenchmarkExperimentalCoordinateParallelPairedRPhaseBreakdownX4 decomposes
// the exact packed singleton experiment committed in
// quad_paired_r_projective_experiment_test.go. Every sub-benchmark establishes
// its inputs before ResetTimer and measures only the named phase. The rows are
// useful for attribution, but their independently sampled medians must not be
// added to predict the complete verifier: phase boundaries change register
// residency, cache state, call overhead, and overlap with adjacent work.
//
// The existing complete benchmark is algorithmically cold for A on every
// iteration: verifyPairedRProjective always decodes A and builds a fresh NAF
// table. It is intentionally microarchitecturally hot because it repeats the
// same public data, code, fixed-B table, and workspaces. This file does not add
// a synthetic cache-eviction arm. Timing an eviction sweep would measure the
// polluter, while stopping the timer around a many-megabyte sweep would make
// benchmark wall time and CPU-frequency state depend on unreported work. A
// trace-driven distinct-key benchmark is the appropriate cold-cache gate.
func BenchmarkExperimentalCoordinateParallelPairedRPhaseBreakdownX4(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skip("AVX-512 IFMA is unavailable")
	}
	fixtures := newQuadPairedRPhaseFixturesX4(b)
	fixture := &fixtures[1] // 200-byte message for message-independent phases.
	verifier, err := newQuadStrictVerifierX4()
	if err != nil {
		b.Fatal(err)
	}

	b.Run("strict-byte-prechecks", func(b *testing.B) {
		var s [32]byte
		var valid bool
		b.ReportAllocs()
		b.ResetTimer()
		for iteration := 0; iteration < b.N; iteration++ {
			valid = quadPairedRStrictBytePrechecksX4(&fixture.pub, fixture.signature, &s)
			if !valid {
				b.Fatal("strict byte prechecks rejected honest fixture")
			}
		}
		b.StopTimer()
		benchmarkQuadPairedRPhaseScalarSinkX4 = s
		benchmarkQuadPairedRPhaseBoolSinkX4 = valid
	})

	var encoded [X4Lanes][32]byte
	encoded[0] = fixture.pub
	copy(encoded[1][:], fixture.signature[:32])
	for _, decode := range []struct {
		name   string
		active uint8
	}{
		{"A-only", 0b0001},
		{"paired-A-R", 0b0011},
	} {
		b.Run("decode/"+decode.name, func(b *testing.B) {
			var point PointX4
			var mask uint8
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				mask, err = ExperimentalIFMADecodeX4(&point, &encoded, decode.active)
				if err != nil || mask&decode.active != decode.active {
					b.Fatalf("decode mask=%x err=%v", mask, err)
				}
			}
			b.StopTimer()
			benchmarkQuadPairedRPhasePointSinkX4 = point
			benchmarkQuadPairedRPhaseMaskSinkX4 = mask
		})
	}

	var decoded PointX4
	if mask, decodeErr := ExperimentalIFMADecodeX4(&decoded, &encoded, 0b0011); decodeErr != nil || mask&0b0011 != 0b0011 {
		b.Fatalf("prepare paired decode mask=%x err=%v", mask, decodeErr)
	}
	a := decoded.Lane(0)
	b.Run("cold-A-NAF-table-build", func(b *testing.B) {
		// The key bytes remain CPU-cache hot, but the complete arithmetic table
		// construction is repeated. No memoized/precomputed A state is reused.
		var table quadNAFTable5X4
		b.ReportAllocs()
		b.ResetTimer()
		for iteration := 0; iteration < b.N; iteration++ {
			if err := buildQuadNAFTable5X4(&table, &a, verifier.ops); err != nil {
				b.Fatal(err)
			}
		}
		b.StopTimer()
		benchmarkQuadPairedRPhaseTableSinkX4 = table
	})

	for index := range fixtures {
		hashFixture := &fixtures[index]
		b.Run("SHA512-plus-scalar-reduction/msg="+quadMessageSizeLabelX4(len(hashFixture.message)), func(b *testing.B) {
			var wide [X4Lanes][64]byte
			var reduced [X4Lanes][32]byte
			var mask uint8
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				verifier.hash.Reset()
				_, _ = verifier.hash.Write(hashFixture.signature[:32])
				_, _ = verifier.hash.Write(hashFixture.pub[:])
				_, _ = verifier.hash.Write(hashFixture.message)
				sum := verifier.hash.Sum(verifier.digest[:0])
				if len(sum) != len(verifier.digest) {
					b.Fatal("SHA-512 returned an invalid digest length")
				}
				wide[0] = verifier.digest
				mask = ExperimentalReduceUniformScalarsX4(&reduced, &wide, 1)
				if mask&1 == 0 {
					b.Fatal("challenge reduction failed")
				}
			}
			b.StopTimer()
			benchmarkQuadPairedRPhaseScalarSinkX4 = reduced[0]
			benchmarkQuadPairedRPhaseMaskSinkX4 = mask
		})
	}

	var aTable quadNAFTable5X4
	if err := buildQuadNAFTable5X4(&aTable, &a, verifier.ops); err != nil {
		b.Fatal(err)
	}
	var s [32]byte
	copy(s[:], fixture.signature[32:])
	var wide [X4Lanes][64]byte
	verifier.hash.Reset()
	_, _ = verifier.hash.Write(fixture.signature[:32])
	_, _ = verifier.hash.Write(fixture.pub[:])
	_, _ = verifier.hash.Write(fixture.message)
	verifier.hash.Sum(verifier.digest[:0])
	wide[0] = verifier.digest
	var reduced [X4Lanes][32]byte
	if ExperimentalReduceUniformScalarsX4(&reduced, &wide, 1)&1 == 0 {
		b.Fatal("prepare challenge reduction failed")
	}

	b.Run("prepared-NAF-DSM", func(b *testing.B) {
		var q quadPackedPointX4
		var usable bool
		b.ReportAllocs()
		b.ResetTimer()
		for iteration := 0; iteration < b.N; iteration++ {
			usable, err = evaluateQuadNAFVerifyX4(&q, &aTable, verifier.bTable, &s, &reduced[0], verifier.ops)
			if err != nil || !usable {
				b.Fatalf("prepared DSM=(%v,%v)", usable, err)
			}
		}
		b.StopTimer()
		benchmarkQuadPairedRPhasePackedPointSinkX4 = q
		benchmarkQuadPairedRPhaseBoolSinkX4 = usable
	})

	var q quadPackedPointX4
	if usable, dsmErr := evaluateQuadNAFVerifyX4(&q, &aTable, verifier.bTable, &s, &reduced[0], verifier.ops); dsmErr != nil || !usable {
		b.Fatalf("prepare DSM=(%v,%v)", usable, dsmErr)
	}
	b.Run("finalizer/encoded-Q", func(b *testing.B) {
		var accepted bool
		b.ReportAllocs()
		b.ResetTimer()
		for iteration := 0; iteration < b.N; iteration++ {
			quadPackedPointAsLaneZeroX4(&verifier.encodePoints[0], &q)
			verifier.encodeActive[0] = 1
			if err := verifier.encoder.Encode(&verifier.encoded, &verifier.encodePoints, &verifier.encodeActive, 1); err != nil {
				b.Fatal(err)
			}
			accepted = bytes.Equal(verifier.encoded[0][0][:], fixture.signature[:32])
		}
		b.StopTimer()
		if !accepted {
			b.Fatal("encoded-Q finalizer rejected prepared Q")
		}
		benchmarkQuadPairedRPhaseBoolSinkX4 = accepted
	})

	b.Run("finalizer/projective-R", func(b *testing.B) {
		var accepted bool
		b.ReportAllocs()
		b.ResetTimer()
		for iteration := 0; iteration < b.N; iteration++ {
			accepted, err = quadPackedEqualDecodedAffineLaneX4(&q, &decoded, 1, verifier.ops)
			if err != nil {
				b.Fatal(err)
			}
		}
		b.StopTimer()
		if !accepted {
			b.Fatal("projective-R finalizer rejected prepared Q")
		}
		benchmarkQuadPairedRPhaseBoolSinkX4 = accepted
	})
}

func newQuadPairedRPhaseFixturesX4(tb testing.TB) [3]quadStrictFixtureX4 {
	tb.Helper()
	publicKey, privateKey, err := stded25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	var fixtures [3]quadStrictFixtureX4
	for index, size := range [...]int{64, 200, 1232} {
		fixtures[index].message = make([]byte, size)
		for offset := range fixtures[index].message {
			fixtures[index].message[offset] = byte(offset*131 + index*17)
		}
		copy(fixtures[index].pub[:], publicKey)
		fixtures[index].signature = stded25519.Sign(privateKey, fixtures[index].message)
	}
	return fixtures
}

var (
	benchmarkQuadPairedRPhaseBoolSinkX4        bool
	benchmarkQuadPairedRPhaseMaskSinkX4        uint8
	benchmarkQuadPairedRPhaseScalarSinkX4      [32]byte
	benchmarkQuadPairedRPhasePointSinkX4       PointX4
	benchmarkQuadPairedRPhasePackedPointSinkX4 quadPackedPointX4
	benchmarkQuadPairedRPhaseTableSinkX4       quadNAFTable5X4
)

func TestExperimentalCoordinateParallelPairedRPhaseFixtureX4(t *testing.T) {
	fixtures := newQuadPairedRPhaseFixturesX4(t)
	for index := range fixtures {
		if !stded25519.Verify(fixtures[index].pub[:], fixtures[index].message, fixtures[index].signature) {
			t.Fatalf("fixture %d is not a valid Ed25519 signature", index)
		}
		if got := len(fixtures[index].message); got != [...]int{64, 200, 1232}[index] {
			t.Fatalf("fixture %d message=%d", index, got)
		}
	}
	if fixtures[0].pub != fixtures[2].pub {
		t.Fatal("phase fixtures do not share one public key")
	}
}
