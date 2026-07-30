package r51x5

import (
	"fmt"
	"testing"
)

func TestExperimentalPackedStrictVerifierPairX8MatchesSingletons(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("AVX-512 IFMA is unavailable")
	}
	verifier, err := NewExperimentalPackedStrictVerifierX4()
	if err != nil {
		t.Fatal(err)
	}
	for _, messageSize := range []int{0, 64, 200, 1232, 4096} {
		fixtures := [2]quadStrictFixtureX4{
			newQuadStrictFixtureX4(t, messageSize),
			newQuadStrictFixtureX4(t, messageSize),
		}
		pubs := [2]*[32]byte{&fixtures[0].pub, &fixtures[1].pub}
		messages := [2][]byte{fixtures[0].message, fixtures[1].message}
		signatures := [2][]byte{fixtures[0].signature, fixtures[1].signature}

		var got [2]bool
		if err := verifier.VerifyPair(pubs, messages, signatures, &got); err != nil {
			t.Fatalf("message=%d pair: %v", messageSize, err)
		}
		if got != [2]bool{true, true} {
			t.Fatalf("message=%d valid pair=%v", messageSize, got)
		}

		for broken := 0; broken < 2; broken++ {
			badMessages := messages
			badMessages[broken] = append([]byte(nil), messages[broken]...)
			if len(badMessages[broken]) == 0 {
				badMessages[broken] = []byte{1}
			} else {
				badMessages[broken][len(badMessages[broken])/2] ^= 1
			}
			if err := verifier.VerifyPair(pubs, badMessages, signatures, &got); err != nil {
				t.Fatalf("message=%d broken=%d pair: %v", messageSize, broken, err)
			}
			want := [2]bool{true, true}
			want[broken] = false
			if got != want {
				t.Fatalf("message=%d broken=%d pair=%v want=%v", messageSize, broken, got, want)
			}
		}

		shortSignatures := signatures
		shortSignatures[0] = shortSignatures[0][:63]
		if err := verifier.VerifyPair(pubs, messages, shortSignatures, &got); err != nil {
			t.Fatalf("message=%d short pair: %v", messageSize, err)
		}
		if got != [2]bool{false, true} {
			t.Fatalf("message=%d short pair=%v", messageSize, got)
		}
	}
}

func TestExperimentalPackedStrictVerifierPairX8ZeroAllocations(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("AVX-512 IFMA is unavailable")
	}
	verifier, err := NewExperimentalPackedStrictVerifierX4()
	if err != nil {
		t.Fatal(err)
	}
	fixtures := [2]quadStrictFixtureX4{
		newQuadStrictFixtureX4(t, 1232),
		newQuadStrictFixtureX4(t, 1232),
	}
	pubs := [2]*[32]byte{&fixtures[0].pub, &fixtures[1].pub}
	messages := [2][]byte{fixtures[0].message, fixtures[1].message}
	signatures := [2][]byte{fixtures[0].signature, fixtures[1].signature}
	var verdicts [2]bool
	if allocations := testing.AllocsPerRun(20, func() {
		if err := verifier.VerifyPair(pubs, messages, signatures, &verdicts); err != nil || verdicts != [2]bool{true, true} {
			panic("r51x5: paired packed verifier rejected honest signatures")
		}
	}); allocations != 0 {
		t.Fatalf("allocations=%v want 0", allocations)
	}
}

var benchmarkPackedStrictPairVerdicts [2]bool

func BenchmarkExperimentalPackedStrictVerifierPairX8(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skip("AVX-512 IFMA is unavailable")
	}
	for _, messageSize := range []int{200, 1232, 4096} {
		fixtures := [2]quadStrictFixtureX4{
			newQuadStrictFixtureX4(b, messageSize),
			newQuadStrictFixtureX4(b, messageSize),
		}
		pubs := [2]*[32]byte{&fixtures[0].pub, &fixtures[1].pub}
		messages := [2][]byte{fixtures[0].message, fixtures[1].message}
		signatures := [2][]byte{fixtures[0].signature, fixtures[1].signature}
		verifier, err := NewExperimentalPackedStrictVerifierX4()
		if err != nil {
			b.Fatal(err)
		}

		b.Run(fmt.Sprintf("message=%d/paired-zmm", messageSize), func(b *testing.B) {
			var verdicts [2]bool
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if err := verifier.VerifyPair(pubs, messages, signatures, &verdicts); err != nil || verdicts != [2]bool{true, true} {
					b.Fatal("paired packed verify failed")
				}
			}
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*2)/1000, "us/signature")
			benchmarkPackedStrictPairVerdicts = verdicts
		})
		b.Run(fmt.Sprintf("message=%d/two-singletons", messageSize), func(b *testing.B) {
			var verdicts [2]bool
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				for lane := range verdicts {
					verdicts[lane], err = verifier.Verify(pubs[lane], messages[lane], signatures[lane])
					if err != nil || !verdicts[lane] {
						b.Fatal("packed singleton verify failed")
					}
				}
			}
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*2)/1000, "us/signature")
			benchmarkPackedStrictPairVerdicts = verdicts
		})
	}
}
