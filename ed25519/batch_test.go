package ed25519

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	mrand "math/rand"
	"testing"
)

type rawBatchProbeBackend struct {
	rawCalls    int
	itemCalls   int
	lastProfile Profile
}

func (*rawBatchProbeBackend) name() string { return "raw-batch-probe" }

func (*rawBatchProbeBackend) verify(_ Profile, _ *[32]byte, _ []byte, sig []byte, _ *PrecomputedKey) bool {
	return len(sig) == ed25519.SignatureSize
}

func (b *rawBatchProbeBackend) verifyBatch(profile Profile, items []batchItem) {
	b.itemCalls++
	for index := range items {
		if !items[index].skip {
			items[index].ok = b.verify(profile, items[index].pub, items[index].msg, items[index].sig, items[index].pre)
		}
	}
}

func (b *rawBatchProbeBackend) verifyBatchRaw(profile Profile, pubs []*[32]byte, _ [][]byte, sigs [][]byte, ok []bool) bool {
	b.rawCalls++
	b.lastProfile = profile
	all := true
	for index := range ok {
		// rawBatchBackend owns the allocation-free profile pre-pass as part of
		// its private contract. A future native backend must not treat profile
		// as informational merely because verifyBatch cannot attach skip bits
		// without constructing batchItems.
		ok[index] = !rejectedByProfile(profile, pubs[index], sigs[index]) && len(sigs[index]) == ed25519.SignatureSize
		all = all && ok[index]
	}
	return all
}

func (*rawBatchProbeBackend) supportsPrecomp() bool { return false }

func (*rawBatchProbeBackend) buildPrecomp(pub *[32]byte) (*PrecomputedKey, error) {
	return &PrecomputedKey{raw: *pub}, nil
}

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

	sizes := append([]int{0}, benchBatchSizes...)
	for _, n := range sizes {
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

func TestRawBatchBackendUsesAllocationFreePublicShapeButCacheKeepsItems(t *testing.T) {
	backend := new(rawBatchProbeBackend)
	pubs := []*[32]byte{{0x03}, {0x04}}
	msgs := [][]byte{{0x03}, {0x04}}
	fullLength := make([]byte, ed25519.SignatureSize)
	fullLength[0] = 0x03 // avoid a strict small-order R encoding in this shape-only probe
	sigs := [][]byte{fullLength, make([]byte, ed25519.SignatureSize-1)}
	ok := make([]bool, len(pubs))

	if all := verifyBatch(backend, DalekStrict, pubs, msgs, sigs, ok, nil); all || ok[0] != true || ok[1] != false {
		t.Fatalf("raw verdicts all=%v ok=%v", all, ok)
	}
	if backend.rawCalls != 1 || backend.itemCalls != 0 {
		t.Fatalf("plain dispatch raw=%d items=%d", backend.rawCalls, backend.itemCalls)
	}
	if backend.lastProfile != DalekStrict {
		t.Fatalf("raw profile=%v, want DalekStrict", backend.lastProfile)
	}
	if allocs := testing.AllocsPerRun(100, func() {
		verifyBatch(backend, DalekStrict, pubs, msgs, sigs, ok, nil)
	}); allocs != 0 {
		t.Fatalf("raw public-shape dispatch allocations=%v", allocs)
	}

	lookup := func(*[32]byte) *PrecomputedKey { return nil }
	if all := verifyBatch(backend, StdlibCompat, pubs, msgs, sigs, ok, lookup); all || ok[0] != true || ok[1] != false {
		t.Fatalf("cache-shaped verdicts all=%v ok=%v", all, ok)
	}
	if backend.itemCalls != 1 {
		t.Fatalf("cache-shaped dispatch bypassed batch items: raw=%d items=%d", backend.rawCalls, backend.itemCalls)
	}
}

func TestRawBatchBackendOwnsStrictProfilePrecheck(t *testing.T) {
	backend := new(rawBatchProbeBackend)
	// y=1 is the identity encoding. StdlibCompat leaves small-order policy to
	// its ordinary equation, while DalekStrict must reject it before any native
	// arithmetic. The probe deliberately has no real equation; this test pins
	// the raw interface's obligation and proves the selected Profile reaches it.
	pub := &[32]byte{0x01}
	pubs := []*[32]byte{pub}
	msgs := [][]byte{nil}
	sigs := [][]byte{make([]byte, ed25519.SignatureSize)}
	ok := make([]bool, 1)

	if verifyBatch(backend, DalekStrict, pubs, msgs, sigs, ok, nil) || ok[0] {
		t.Fatal("raw strict backend bypassed the small-order precheck")
	}
	if backend.lastProfile != DalekStrict {
		t.Fatalf("raw strict profile=%v", backend.lastProfile)
	}
	if !verifyBatch(backend, StdlibCompat, pubs, msgs, sigs, ok, nil) || !ok[0] {
		t.Fatal("raw compat backend unexpectedly inherited strict rejection")
	}
	if backend.lastProfile != StdlibCompat {
		t.Fatalf("raw compat profile=%v", backend.lastProfile)
	}
}

func TestRawBatchBackendLengthMismatchPanicsBeforeDispatch(t *testing.T) {
	backend := new(rawBatchProbeBackend)
	defer func() {
		if recover() == nil {
			t.Fatal("length mismatch did not panic")
		}
		if backend.rawCalls != 0 || backend.itemCalls != 0 {
			t.Fatalf("mismatched batch reached backend: raw=%d items=%d", backend.rawCalls, backend.itemCalls)
		}
	}()
	verifyBatch(backend, DalekStrict, []*[32]byte{{}}, nil, nil, nil, nil)
}

// TestVerifyBatchInvalidLanePositions puts a failure that survives every
// scalar precheck into every lane. This pins per-index verdict placement at
// all x8 group and tail boundaries before vector backends arrive.
func TestVerifyBatchInvalidLanePositions(t *testing.T) {
	for _, n := range benchBatchSizes {
		fs := makeFixtures(t, n, 64)
		pubs := make([]*[32]byte, n)
		msgs := make([][]byte, n)
		sigs := make([][]byte, n)
		cache := &Cache{MaxTableBytes: 1}
		cache.bytes.Store(1)
		for i := range fs {
			pubs[i] = &fs[i].pub
			msgs[i] = fs[i].msg
			sigs[i] = fs[i].sig
			pre, err := Precompute(pubs[i])
			if err != nil {
				t.Fatalf("n=%d lane=%d: Precompute: %v", n, i, err)
			}
			cache.tables.Store(*pubs[i], pre)
		}

		for badLane := 0; badLane < n; badLane++ {
			caseMsgs := append([][]byte(nil), msgs...)
			badMsg := append([]byte(nil), msgs[badLane]...)
			badMsg[0] ^= 1
			caseMsgs[badLane] = badMsg

			want := make([]bool, n)
			for i := range want {
				want[i] = referenceVerify(pubs[i], caseMsgs[i], sigs[i])
			}
			if want[badLane] {
				t.Fatalf("n=%d lane=%d: invalid-lane fixture unexpectedly verifies", n, badLane)
			}

			for name, verify := range map[string]func([]bool) bool{
				"plain": func(ok []bool) bool { return VerifyBatch(pubs, caseMsgs, sigs, ok) },
				"cache": func(ok []bool) bool { return cache.VerifyBatch(pubs, caseMsgs, sigs, ok) },
			} {
				ok := make([]bool, n)
				all := verify(ok)
				if all {
					t.Fatalf("%s n=%d lane=%d: all=true with an invalid item", name, n, badLane)
				}
				for i := range want {
					if ok[i] != want[i] {
						t.Fatalf("%s n=%d bad-lane=%d item=%d: got=%v want=%v", name, n, badLane, i, ok[i], want[i])
					}
				}
			}
		}
	}
}

// Batch benchmarks live in bench_test.go (BenchmarkVerifyBatch).
