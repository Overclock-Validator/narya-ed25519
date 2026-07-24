package ed25519

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	mrand "math/rand"
	"testing"
)

// buildMixedBatch assembles a batch of the given size mixing valid
// signatures, corrupted ones, undecodable pubkeys, edge-point
// encodings and wrong-length signatures, returning the inputs and the
// stdlib verdicts.
func buildMixedBatch(t *testing.T, rng *mrand.Rand, n int, hotPub *[32]byte, hotPriv ed25519.PrivateKey) (pubs []*[32]byte, msgs, sigs [][]byte, want []bool) {
	t.Helper()
	for i := 0; i < n; i++ {
		var pub [32]byte
		var msg, sig []byte
		switch rng.Intn(6) {
		case 0: // fresh valid
			pubk, priv, _ := ed25519.GenerateKey(rand.Reader)
			copy(pub[:], pubk)
			msg = make([]byte, rng.Intn(300))
			rng.Read(msg)
			sig = ed25519.Sign(priv, msg)
		case 1: // hot-key valid (drives the cache admission path)
			pub = *hotPub
			msg = make([]byte, 1+rng.Intn(200))
			rng.Read(msg)
			sig = ed25519.Sign(hotPriv, msg)
		case 2: // corrupted signature
			pubk, priv, _ := ed25519.GenerateKey(rand.Reader)
			copy(pub[:], pubk)
			msg = []byte("corrupted")
			sig = ed25519.Sign(priv, msg)
			sig[rng.Intn(64)] ^= 1 << rng.Intn(8)
		case 3: // edge-point pubkey, random signature
			raw, _ := hex.DecodeString(edgePoints[rng.Intn(len(edgePoints))])
			copy(pub[:], raw)
			msg = []byte("edge")
			sig = make([]byte, 64)
			rng.Read(sig)
			sig[63] &= 0x1f
		case 4: // wrong-length signature
			pubk, _, _ := ed25519.GenerateKey(rand.Reader)
			copy(pub[:], pubk)
			msg = []byte("short")
			sig = make([]byte, 63)
			rng.Read(sig)
		default: // random garbage everything
			rng.Read(pub[:])
			msg = make([]byte, rng.Intn(50))
			rng.Read(msg)
			sig = make([]byte, 64)
			rng.Read(sig)
		}
		pubs = append(pubs, &pub)
		msgs = append(msgs, msg)
		sigs = append(sigs, sig)
		want = append(want, referenceVerify(&pub, msg, sig))
	}
	return
}

// TestVerifyBatchConsistency pins the contract: for every batch size
// and item mix, VerifyBatch's per-index verdicts equal both stdlib
// verification and narya's own single-shot Verify, cached or not.
func TestVerifyBatchConsistency(t *testing.T) {
	rng := mrand.New(mrand.NewSource(3))
	hotk, hotPriv, _ := ed25519.GenerateKey(rand.Reader)
	var hotPub [32]byte
	copy(hotPub[:], hotk)
	c := &Cache{}

	for _, n := range []int{0, 1, 2, 7, 8, 9, 16, 33} {
		for round := 0; round < 8; round++ {
			pubs, msgs, sigs, want := buildMixedBatch(t, rng, n, &hotPub, hotPriv)

			ok := make([]bool, n)
			all := VerifyBatch(pubs, msgs, sigs, ok)
			wantAll := true
			for i := range want {
				if ok[i] != want[i] {
					t.Fatalf("size %d round %d item %d: VerifyBatch=%v stdlib=%v\npub %x\nmsg %x\nsig %x",
						n, round, i, ok[i], want[i], pubs[i], msgs[i], sigs[i])
				}
				if got := Verify(pubs[i], msgs[i], sigs[i]); got != want[i] {
					t.Fatalf("size %d item %d: single Verify=%v stdlib=%v", n, i, got, want[i])
				}
				wantAll = wantAll && want[i]
			}
			if all != wantAll {
				t.Fatalf("size %d: VerifyBatch returned %v, verdicts say %v", n, all, wantAll)
			}

			// The cached batch must agree item-for-item too, across
			// every cache state the hot key passes through (counting,
			// building, built).
			okC := make([]bool, n)
			allC := c.VerifyBatch(pubs, msgs, sigs, okC)
			for i := range want {
				if okC[i] != want[i] {
					t.Fatalf("size %d round %d item %d: Cache.VerifyBatch=%v stdlib=%v", n, round, i, okC[i], want[i])
				}
			}
			if allC != wantAll {
				t.Fatalf("size %d: Cache.VerifyBatch returned %v, verdicts say %v", n, allC, wantAll)
			}
		}
	}

	if s := c.Stats(); s.Tables == 0 {
		t.Fatal("hot key never earned a table; the cached-batch path went untested")
	}
}

// Batch benchmarks live in bench_test.go (BenchmarkVerifyBatch).
