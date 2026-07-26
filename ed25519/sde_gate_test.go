//go:build sde_gate && amd64

package ed25519

import "testing"

// TestSDEForcedR51PublicPath proves that SDE exposes every feature required by
// the supported forced backend, then executes its exported strict API. The
// broader differential tests run in separate processes so this test's global
// backend selection cannot affect them.
func TestSDEForcedR51PublicPath(t *testing.T) {
	if err := SetBackend("r51"); err != nil {
		t.Fatalf("force r51 under Intel SDE: %v", err)
	}
	if got := ActiveBackend(); got != "r51" {
		t.Fatalf("active backend=%q want r51", got)
	}

	previousProfile := DefaultProfile()
	defer SetDefaultProfile(previousProfile)

	for _, profile := range []Profile{DalekStrict, StdlibCompat} {
		SetDefaultProfile(profile)
		for _, count := range []int{1, 2, 4, 8, 9, 17} {
			messageSize := 200
			if count == 8 {
				messageSize = 1232
			}
			batch := makeBatchFixture(t, count, messageSize)
			verdicts := make([]bool, count)
			verify := VerifyBatch
			if profile == DalekStrict {
				// Exercise the explicit consensus-safe entry point rather than
				// relying on the mutable package default for strict semantics.
				verify = VerifyBatchStrict
			}
			if !verify(batch.pubs, batch.msgs, batch.sigs, verdicts) {
				t.Fatalf("profile=%d n=%d: valid public r51 batch rejected: %v", profile, count, verdicts)
			}

			badLane := count / 2
			badMessages := append([][]byte(nil), batch.msgs...)
			badMessages[badLane] = append([]byte(nil), badMessages[badLane]...)
			badMessages[badLane][0] ^= 1
			if verify(batch.pubs, badMessages, batch.sigs, verdicts) {
				t.Fatalf("profile=%d n=%d: invalid public r51 batch accepted", profile, count)
			}
			for lane, verdict := range verdicts {
				if want := lane != badLane; verdict != want {
					t.Fatalf("profile=%d n=%d lane=%d verdict=%v want=%v", profile, count, lane, verdict, want)
				}
			}
		}
	}
}
