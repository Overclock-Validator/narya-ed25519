package ed25519

import "testing"

// TestR51RawBatchNilPublicKeyFailsClosed pins the fail-closed contract on the
// raw-batch path. r51 is a rawBatchBackend, so verifyBatch hands it the caller's
// slices without running applyProfile; the backend has to apply the nil guard
// itself. The StdlibCompat singleton tail used to reach genericBackend.verify
// directly, which panics on pub[:] with a nil *[32]byte.
//
// Batch lengths congruent to 1 mod 4 are the interesting ones: they leave a
// one-element tail after the full x4 groups, and that tail is the branch that
// was unguarded. DalekStrict takes a different route (packedStrictBytePrechecksX4)
// and was already safe, but it is covered here so the two profiles cannot drift.
func TestR51RawBatchNilPublicKeyFailsClosed(t *testing.T) {
	backend := requireR51Backend(t)

	for _, profile := range []Profile{DalekStrict, StdlibCompat} {
		for _, count := range []int{1, 5, 9} {
			fixture := makeBatchFixture(t, count, 200)
			// The last element is the one-element tail.
			fixture.pubs[count-1] = nil
			for index := range fixture.ok {
				fixture.ok[index] = false
			}

			all := backend.verifyBatchRaw(profile, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok)
			if all {
				t.Fatalf("profile=%v n=%d: reported all-valid with a nil public key", profile, count)
			}
			if fixture.ok[count-1] {
				t.Fatalf("profile=%v n=%d: nil public key accepted", profile, count)
			}
			for index := 0; index < count-1; index++ {
				if !fixture.ok[index] {
					t.Fatalf("profile=%v n=%d: honest signature %d rejected", profile, count, index)
				}
			}
		}
	}
}
