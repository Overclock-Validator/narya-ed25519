package ed25519

import (
	"fmt"
	"testing"

	"github.com/Overclock-Validator/narya-ed25519/internal/r51x5"
)

// A malformed signature anywhere in a promoted warm group used to crash the
// process, not merely fail. The warm verifier populates a per-key table only
// for lanes that pass its pre-checks, and the evaluator then read the group's
// table spec from lane 0 unconditionally, so a signature the pre-checks reject
// at lane 0 left a nil table to dereference.
//
// The position is chosen by the attacker: it is the batch index modulo the
// group width, so any caller verifying attacker-supplied signatures in batches
// could be crashed by one malformed input. This test sweeps every lane rather
// than only lane 0, because a fix that special-cased lane 0 would still be
// wrong for a future group whose first live lane sits elsewhere.
//
// Requires AVX512-IFMA. Where the vector kernels are unavailable this skips;
// the lane-selection logic itself is covered without IFMA by
// internal/r51x5.TestLiveHeterogeneousPartialCombSpecSkipsNilLanes.
func TestR51WarmGroupSurvivesMalformedSignatureAtEveryLane(t *testing.T) {
	backend := requireR51Backend(t)
	fixture := makeBatchFixture(t, r51x5.X4Lanes, 1232)
	cache := &Cache{MaxTableBytes: r51x5.X4Lanes * r51WarmTableBytes}
	for _, pub := range fixture.pubs {
		admitR51DecodedATestEntry(t, cache, backend, pub)
	}

	// Promote every key so the group actually takes the warm path. Without
	// this the batch runs cold and never reaches the faulting evaluator.
	for hit := int32(0); hit < backend.promotionThreshold(); hit++ {
		if !cache.verifyBatchWithBackend(backend, DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok) {
			t.Fatalf("valid promotion hit %d rejected", hit)
		}
	}
	if got := cache.Stats().PromotedTables; got != r51x5.X4Lanes {
		t.Fatalf("promoted tables=%d want %d; the warm path is not being exercised", got, r51x5.X4Lanes)
	}

	// Each of these is rejected by a different pre-check, and each therefore
	// leaves the lane's table nil. A small-order R is deliberately absent: the
	// shared strict pre-pass removes it before the warm verifier runs, so it
	// never produced the nil lane.
	corruptions := []struct {
		name  string
		apply func(sig []byte) []byte
	}{
		{"scalarHighBits", func(sig []byte) []byte {
			sig[63] |= 0xe0
			return sig
		}},
		{"scalarAtGroupOrder", func(sig []byte) []byte {
			copy(sig[32:], ed25519ScalarOrderEncoding[:])
			return sig
		}},
		{"nonCanonicalR", func(sig []byte) []byte {
			for i := 0; i < 32; i++ {
				sig[i] = 0xff
			}
			sig[31] = 0x7f
			return sig
		}},
		{"shortSignature", func(sig []byte) []byte {
			return sig[:63]
		}},
	}

	for _, corruption := range corruptions {
		for lane := 0; lane < r51x5.X4Lanes; lane++ {
			t.Run(fmt.Sprintf("%s/lane=%d", corruption.name, lane), func(t *testing.T) {
				sigs := append([][]byte(nil), fixture.sigs...)
				sigs[lane] = corruption.apply(append([]byte(nil), fixture.sigs[lane]...))
				verdicts := make([]bool, len(sigs))

				// The call itself is the assertion: before the fix this
				// panicked with a nil dereference for lane 0, and no recover()
				// exists anywhere in the library to contain it.
				if cache.verifyBatchWithBackend(backend, DalekStrict, fixture.pubs, fixture.msgs, sigs, verdicts) {
					t.Fatal("batch containing a malformed signature reported all-valid")
				}

				// One bad lane must not disturb its neighbours. A group that
				// bailed out wholesale would also avoid the crash while
				// silently rejecting three valid signatures.
				for index, got := range verdicts {
					want := index != lane
					if got != want {
						t.Fatalf("lane %d: verdict=%v want %v (corrupted lane %d)", index, got, want, lane)
					}
				}
			})
		}
	}

	// The group must still be usable afterwards: a malformed input should not
	// leave the promoted tables or the cache in a degraded state.
	if !cache.verifyBatchWithBackend(backend, DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok) {
		t.Fatal("valid batch rejected after malformed inputs")
	}
	if faults := backend.backendStats().InternalFaultFallbacks; faults != 0 {
		t.Fatalf("malformed inputs caused %d internal fault fallbacks; they should be ordinary rejections", faults)
	}
}
