package r51x5

import (
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"testing"
)

const warmCombWorkingSetBatch = ExperimentalIFMABatchEncodeMaxX4Groups * X4Lanes

var warmCombWorkingSetSink bool

// BenchmarkWarmCombWorkingSet measures the complete warm verifier while its
// immutable per-key tables cross the private-cache and LLC boundaries. The
// largest arm is the greatest multiple of 64 that fits in a 128 MiB payload
// budget using the current exact WarmCombKeyA6R9Bytes object size.
//
// Each timed call verifies 64 signatures and advances to the next disjoint
// key block. Four-key mode repeats those four keys across the batch; all other
// modes use every key once per working-set traversal. Preparation, signing,
// and table construction remain outside the timed region.
func BenchmarkWarmCombWorkingSet(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skip("requires AVX-512 IFMA target")
	}

	const maxTableBytes = 128 << 20
	maxKeys := (maxTableBytes / WarmCombKeyA6R9Bytes) / warmCombWorkingSetBatch * warmCombWorkingSetBatch
	for _, keyCount := range []int{4, 64, 512, 4096, maxKeys} {
		b.Run(fmt.Sprintf("keys=%d/payload=%dMiB", keyCount, keyCount*WarmCombKeyA6R9Bytes>>20), func(b *testing.B) {
			fixture := newWarmCombWorkingSetFixture(b, keyCount)
			verifier, err := NewWarmCombStrictVerifierX4()
			if err != nil {
				b.Fatal(err)
			}
			var ok [warmCombWorkingSetBatch]bool

			b.ReportAllocs()
			b.ReportMetric(float64(keyCount*WarmCombKeyA6R9Bytes), "working-set-bytes")
			b.ResetTimer()
			var all bool
			for iteration := 0; iteration < b.N; iteration++ {
				offset := 0
				if keyCount >= warmCombWorkingSetBatch {
					offset = iteration * warmCombWorkingSetBatch % keyCount
				}
				all, err = verifier.VerifyBatch(
					fixture.keyPointers[offset:offset+warmCombWorkingSetBatch],
					fixture.pubs[offset:offset+warmCombWorkingSetBatch],
					fixture.messages[offset:offset+warmCombWorkingSetBatch],
					fixture.signatures[offset:offset+warmCombWorkingSetBatch],
					ok[:],
				)
				if err != nil || !all {
					b.Fatalf("warm working-set verify all=%v err=%v", all, err)
				}
			}
			warmCombWorkingSetSink = all
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*warmCombWorkingSetBatch)/1000, "us/sig")
		})
	}
}

type warmCombWorkingSetFixture struct {
	keys        []WarmCombKeyA6R9
	keyPointers []*WarmCombKeyA6R9
	pubs        [][32]byte
	messages    [][]byte
	signatures  [][]byte
}

func newWarmCombWorkingSetFixture(tb testing.TB, distinctKeys int) *warmCombWorkingSetFixture {
	tb.Helper()
	storageKeys := distinctKeys
	inputCount := distinctKeys
	if distinctKeys < warmCombWorkingSetBatch {
		inputCount = warmCombWorkingSetBatch
	}
	fixture := &warmCombWorkingSetFixture{
		keys:        make([]WarmCombKeyA6R9, storageKeys),
		keyPointers: make([]*WarmCombKeyA6R9, inputCount),
		pubs:        make([][32]byte, inputCount),
		messages:    make([][]byte, inputCount),
		signatures:  make([][]byte, inputCount),
	}

	message := make([]byte, 1232)
	for index := range message {
		message[index] = byte(index*131 + 17)
	}
	publicKeys := make([][32]byte, storageKeys)
	privateKeys := make([]ed25519.PrivateKey, storageKeys)
	for index := 0; index < storageKeys; index++ {
		var counter [8]byte
		binary.LittleEndian.PutUint64(counter[:], uint64(index+1))
		digest := sha512.Sum512(counter[:])
		privateKeys[index] = ed25519.NewKeyFromSeed(digest[:ed25519.SeedSize])
		copy(publicKeys[index][:], privateKeys[index][ed25519.SeedSize:])
	}

	var build WarmCombBuildWorkspaceX4
	for base := 0; base < storageKeys; base += X4Lanes {
		var encoded [X4Lanes][32]byte
		var outputs [X4Lanes]*WarmCombKeyA6R9
		for lane := 0; lane < X4Lanes; lane++ {
			encoded[lane] = publicKeys[base+lane]
			outputs[lane] = &fixture.keys[base+lane]
		}
		if err := build.BuildWarmCombKeysA6R9X4(&outputs, &encoded); err != nil {
			tb.Fatal(err)
		}
	}

	for index := 0; index < inputCount; index++ {
		keyIndex := index % storageKeys
		fixture.keyPointers[index] = &fixture.keys[keyIndex]
		fixture.pubs[index] = publicKeys[keyIndex]
		fixture.messages[index] = message
		fixture.signatures[index] = ed25519.Sign(privateKeys[keyIndex], message)
	}
	return fixture
}
