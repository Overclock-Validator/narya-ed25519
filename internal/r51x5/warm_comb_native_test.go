package r51x5

import (
	"fmt"
	"testing"
	"unsafe"
)

func prepareWarmCombNativeFixture(t *testing.T) (
	*[X4Lanes]WarmCombKeyA6R9,
	*[X4Lanes][32]byte,
	*[X4Lanes][]byte,
	*[X4Lanes][]byte,
	*WarmCombStrictVerifierX4,
) {
	t.Helper()
	inputs := makeHeterogeneousPartialCombCompleteInputsExperiment(
		t, X4Lanes, 1232, heterogeneousPartialCombCompleteDistinctKeysExperiment,
	)
	pubs := new([X4Lanes][32]byte)
	messages := new([X4Lanes][]byte)
	signatures := new([X4Lanes][]byte)
	keys := new([X4Lanes]WarmCombKeyA6R9)
	var keyPointers [X4Lanes]*WarmCombKeyA6R9
	for lane := 0; lane < X4Lanes; lane++ {
		pubs[lane] = inputs[lane].pub
		messages[lane] = inputs[lane].message
		signatures[lane] = inputs[lane].signature
		keyPointers[lane] = &keys[lane]
	}
	var workspace WarmCombBuildWorkspaceX4
	if err := workspace.BuildWarmCombKeysA6R9X4(&keyPointers, pubs); err != nil {
		t.Fatal(err)
	}
	verifier, err := NewWarmCombStrictVerifierX4()
	if err != nil {
		t.Fatal(err)
	}
	return keys, pubs, messages, signatures, verifier
}

func TestWarmCombNativeKeySizeAndStrictDifferential(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("requires AVX-512 IFMA target")
	}
	if got, want := unsafe.Sizeof(WarmCombKeyA6R9{}), uintptr(WarmCombKeyA6R9Bytes); got != want {
		t.Fatalf("WarmCombKeyA6R9 bytes=%d want=%d", got, want)
	}
	keys, pubs, messages, signatures, verifier := prepareWarmCombNativeFixture(t)
	var keyPointers [X4Lanes]*WarmCombKeyA6R9
	for lane := range keyPointers {
		keyPointers[lane] = &keys[lane]
	}
	var got [X4Lanes]bool
	all, err := verifier.Verify(&keyPointers, pubs, messages, signatures, &got)
	if err != nil {
		t.Fatal(err)
	}
	if !all {
		t.Fatalf("honest warm-comb verdicts=%v", got)
	}

	packed, err := NewExperimentalPackedStrictVerifierX4()
	if err != nil {
		t.Fatal(err)
	}
	mutated := *signatures
	mutated[2] = append([]byte(nil), mutated[2]...)
	mutated[2][17] ^= 0x80
	all, err = verifier.Verify(&keyPointers, pubs, messages, &mutated, &got)
	if err != nil {
		t.Fatal(err)
	}
	if all {
		t.Fatal("warm-comb verifier accepted an independently invalid lane")
	}
	for lane := 0; lane < X4Lanes; lane++ {
		want, err := packed.Verify(&pubs[lane], messages[lane], mutated[lane])
		if err != nil {
			t.Fatal(err)
		}
		if got[lane] != want {
			t.Fatalf("lane=%d got=%v want=%v", lane, got[lane], want)
		}
	}
}

func TestWarmCombNativeRawBindingAndZeroAllocations(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("requires AVX-512 IFMA target")
	}
	keys, pubs, messages, signatures, verifier := prepareWarmCombNativeFixture(t)
	var keyPointers [X4Lanes]*WarmCombKeyA6R9
	for lane := range keyPointers {
		keyPointers[lane] = &keys[lane]
	}
	var ok [X4Lanes]bool
	allocations := testing.AllocsPerRun(100, func() {
		all, err := verifier.Verify(&keyPointers, pubs, messages, signatures, &ok)
		if err != nil || !all {
			panic("warm-comb zero-allocation verification failed")
		}
	})
	if allocations != 0 {
		t.Fatalf("warm-comb verification allocations=%v want=0", allocations)
	}

	mismatched := *pubs
	mismatched[1][0] ^= 1
	all, err := verifier.Verify(&keyPointers, &mismatched, messages, signatures, &ok)
	if err != nil {
		t.Fatal(err)
	}
	if all || ok[1] {
		t.Fatalf("raw-key mismatch all=%v verdicts=%v", all, ok)
	}
}

var warmCombNativeBenchmarkSink bool

func BenchmarkWarmCombNativeX4(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skip("requires AVX-512 IFMA target")
	}
	for _, messageSize := range []int{64, 200, 1232} {
		b.Run(fmt.Sprintf("verify/msg=%d", messageSize), func(b *testing.B) {
			inputs := makeHeterogeneousPartialCombCompleteInputsExperiment(
				b, X4Lanes, messageSize, heterogeneousPartialCombCompleteDistinctKeysExperiment,
			)
			var pubs [X4Lanes][32]byte
			var messages, signatures [X4Lanes][]byte
			var keys [X4Lanes]WarmCombKeyA6R9
			var keyPointers [X4Lanes]*WarmCombKeyA6R9
			for lane := 0; lane < X4Lanes; lane++ {
				pubs[lane] = inputs[lane].pub
				messages[lane] = inputs[lane].message
				signatures[lane] = inputs[lane].signature
				keyPointers[lane] = &keys[lane]
			}
			var build WarmCombBuildWorkspaceX4
			if err := build.BuildWarmCombKeysA6R9X4(&keyPointers, &pubs); err != nil {
				b.Fatal(err)
			}
			verifier, err := NewWarmCombStrictVerifierX4()
			if err != nil {
				b.Fatal(err)
			}
			var ok [X4Lanes]bool
			b.ReportAllocs()
			b.ResetTimer()
			var all bool
			for iteration := 0; iteration < b.N; iteration++ {
				all, err = verifier.Verify(&keyPointers, &pubs, &messages, &signatures, &ok)
				if err != nil || !all {
					b.Fatalf("warm-comb verify all=%v err=%v", all, err)
				}
			}
			warmCombNativeBenchmarkSink = all
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*X4Lanes)/1000, "us/sig")
		})
	}

	b.Run("build-A6r9", func(b *testing.B) {
		inputs := makeHeterogeneousPartialCombCompleteInputsExperiment(
			b, X4Lanes, 200, heterogeneousPartialCombCompleteDistinctKeysExperiment,
		)
		var pubs [X4Lanes][32]byte
		var keys [X4Lanes]WarmCombKeyA6R9
		var keyPointers [X4Lanes]*WarmCombKeyA6R9
		for lane := 0; lane < X4Lanes; lane++ {
			pubs[lane] = inputs[lane].pub
			keyPointers[lane] = &keys[lane]
		}
		var workspace WarmCombBuildWorkspaceX4
		b.ReportAllocs()
		b.ResetTimer()
		for iteration := 0; iteration < b.N; iteration++ {
			if err := workspace.BuildWarmCombKeysA6R9X4(&keyPointers, &pubs); err != nil {
				b.Fatal(err)
			}
		}
		b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*X4Lanes)/1000, "us/key")
	})
}
