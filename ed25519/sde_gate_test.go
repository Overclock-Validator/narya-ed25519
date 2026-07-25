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

	batch := makeBatchFixture(t, 5, 200)
	verdicts := make([]bool, len(batch.pubs))
	if !VerifyBatchStrict(batch.pubs, batch.msgs, batch.sigs, verdicts) {
		t.Fatalf("valid public r51 batch rejected: %v", verdicts)
	}

	badMessages := append([][]byte(nil), batch.msgs...)
	badMessages[3] = append([]byte(nil), badMessages[3]...)
	badMessages[3][0] ^= 1
	if VerifyBatchStrict(batch.pubs, badMessages, batch.sigs, verdicts) {
		t.Fatal("invalid public r51 batch accepted")
	}
	for lane, verdict := range verdicts {
		if verdict != (lane != 3) {
			t.Fatalf("lane=%d verdict=%v want=%v", lane, verdict, lane != 3)
		}
	}
}
