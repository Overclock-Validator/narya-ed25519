package ed25519

import "testing"

func TestGenericCompactBatchMatchesReference(t *testing.T) {
	generic := genericBackend{}
	for _, profile := range []Profile{StdlibCompat, DalekStrict} {
		for n := 1; n <= 17; n++ {
			bf := makeBatchFixture(t, n, 200)
			precomputed := make(map[[32]byte]*PrecomputedKey, n)
			for i := range bf.fs {
				pre, err := generic.buildCompactPrecomp(&bf.fs[i].pub)
				if err != nil {
					t.Fatal(err)
				}
				precomputed[bf.fs[i].pub] = pre
			}

			for invalidLane := -1; invalidLane < n; invalidLane++ {
				messages := append([][]byte(nil), bf.msgs...)
				if invalidLane >= 0 {
					bad := append([]byte(nil), messages[invalidLane]...)
					bad[0] ^= 1
					messages[invalidLane] = bad
				}
				got := make([]bool, n)
				for i := range got {
					got[i] = true // prove every output is overwritten
				}
				verifyBatch(generic, profile, bf.pubs, messages, bf.sigs, got, func(pub *[32]byte) *PrecomputedKey {
					return precomputed[*pub]
				})
				for lane := range got {
					want := referenceVerifyProfile(profile, bf.pubs[lane], messages[lane], bf.sigs[lane])
					if got[lane] != want {
						t.Fatalf("profile=%d n=%d invalid=%d lane=%d: got %v want %v", profile, n, invalidLane, lane, got[lane], want)
					}
				}
			}
		}
	}
}

func TestGenericCompactPrecompPreservesExactMixedOrderScalar(t *testing.T) {
	vector := makeR51MixedOrderValidVector(t)
	if !referenceVerifyProfile(DalekStrict, &vector.pub, vector.msg, vector.sig) {
		t.Fatal("mixed-order discriminator is not strict-valid")
	}
	generic := genericBackend{}
	pre, err := generic.buildCompactPrecomp(&vector.pub)
	if err != nil {
		t.Fatal(err)
	}
	if !verifyOne(generic, DalekStrict, &vector.pub, vector.msg, vector.sig, pre) {
		t.Fatal("compact table changed exact signed-integer mixed-order semantics")
	}

	pubs := []*[32]byte{&vector.pub}
	msgs := [][]byte{vector.msg}
	sigs := [][]byte{vector.sig}
	ok := []bool{false}
	if !verifyBatch(generic, DalekStrict, pubs, msgs, sigs, ok, func(*[32]byte) *PrecomputedKey { return pre }) || !ok[0] {
		t.Fatal("compact batch table changed exact signed-integer mixed-order semantics")
	}
}
