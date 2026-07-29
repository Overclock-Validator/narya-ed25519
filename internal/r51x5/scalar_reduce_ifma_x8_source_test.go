package r51x5

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestScalarReduceIFMAX8SourceTranscript pins the positional algebraic trace
// translated from the standalone Narya reducer. Range-safe register
// substitutions can preserve every interval while changing the represented
// scalar, so merely counting folds and carries is not enough: their exact
// radix positions and order are part of the contract.
//
// This is a source-level transcription gate. It complements, but does not
// replace, native differentials or a future assembled-opcode refinement proof.
func TestScalarReduceIFMAX8SourceTranscript(t *testing.T) {
	source, err := os.ReadFile("scalar_reduce_ifma_x8_amd64.s")
	if err != nil {
		t.Fatal(err)
	}
	pattern := regexp.MustCompile(`(?m)^\s*(SCALAR_(?:FOLD|CARRY_ROUNDED|CARRY)\([^\n]+\))\s*$`)
	matches := pattern.FindAllSubmatch(source, -1)
	got := make([]string, len(matches))
	for index, match := range matches {
		got[index] = strings.ReplaceAll(string(match[1]), " ", "")
	}

	want := []string{
		"SCALAR_FOLD(Z23,Z11,Z12,Z13,Z14,Z15,Z16)",
		"SCALAR_FOLD(Z22,Z10,Z11,Z12,Z13,Z14,Z15)",
		"SCALAR_FOLD(Z21,Z9,Z10,Z11,Z12,Z13,Z14)",
		"SCALAR_FOLD(Z20,Z8,Z9,Z10,Z11,Z12,Z13)",
		"SCALAR_FOLD(Z19,Z7,Z8,Z9,Z10,Z11,Z12)",
		"SCALAR_FOLD(Z18,Z6,Z7,Z8,Z9,Z10,Z11)",
		"SCALAR_CARRY_ROUNDED(Z6,Z7)",
		"SCALAR_CARRY_ROUNDED(Z8,Z9)",
		"SCALAR_CARRY_ROUNDED(Z10,Z11)",
		"SCALAR_CARRY_ROUNDED(Z12,Z13)",
		"SCALAR_CARRY_ROUNDED(Z14,Z15)",
		"SCALAR_CARRY_ROUNDED(Z16,Z17)",
		"SCALAR_CARRY_ROUNDED(Z7,Z8)",
		"SCALAR_CARRY_ROUNDED(Z9,Z10)",
		"SCALAR_CARRY_ROUNDED(Z11,Z12)",
		"SCALAR_CARRY_ROUNDED(Z13,Z14)",
		"SCALAR_CARRY_ROUNDED(Z15,Z16)",
		"SCALAR_FOLD(Z17,Z5,Z6,Z7,Z8,Z9,Z10)",
		"SCALAR_FOLD(Z16,Z4,Z5,Z6,Z7,Z8,Z9)",
		"SCALAR_FOLD(Z15,Z3,Z4,Z5,Z6,Z7,Z8)",
		"SCALAR_FOLD(Z14,Z2,Z3,Z4,Z5,Z6,Z7)",
		"SCALAR_FOLD(Z13,Z1,Z2,Z3,Z4,Z5,Z6)",
		"SCALAR_FOLD(Z12,Z0,Z1,Z2,Z3,Z4,Z5)",
		"SCALAR_CARRY_ROUNDED(Z0,Z1)",
		"SCALAR_CARRY_ROUNDED(Z2,Z3)",
		"SCALAR_CARRY_ROUNDED(Z4,Z5)",
		"SCALAR_CARRY_ROUNDED(Z6,Z7)",
		"SCALAR_CARRY_ROUNDED(Z8,Z9)",
		"SCALAR_CARRY_ROUNDED(Z10,Z11)",
		"SCALAR_CARRY_ROUNDED(Z1,Z2)",
		"SCALAR_CARRY_ROUNDED(Z3,Z4)",
		"SCALAR_CARRY_ROUNDED(Z5,Z6)",
		"SCALAR_CARRY_ROUNDED(Z7,Z8)",
		"SCALAR_CARRY_ROUNDED(Z9,Z10)",
		"SCALAR_CARRY_ROUNDED(Z11,Z12)",
		"SCALAR_FOLD(Z12,Z0,Z1,Z2,Z3,Z4,Z5)",
		"SCALAR_CARRY(Z0,Z1)",
		"SCALAR_CARRY(Z1,Z2)",
		"SCALAR_CARRY(Z2,Z3)",
		"SCALAR_CARRY(Z3,Z4)",
		"SCALAR_CARRY(Z4,Z5)",
		"SCALAR_CARRY(Z5,Z6)",
		"SCALAR_CARRY(Z6,Z7)",
		"SCALAR_CARRY(Z7,Z8)",
		"SCALAR_CARRY(Z8,Z9)",
		"SCALAR_CARRY(Z9,Z10)",
		"SCALAR_CARRY(Z10,Z11)",
		"SCALAR_CARRY(Z11,Z12)",
		"SCALAR_FOLD(Z12,Z0,Z1,Z2,Z3,Z4,Z5)",
		"SCALAR_CARRY(Z0,Z1)",
		"SCALAR_CARRY(Z1,Z2)",
		"SCALAR_CARRY(Z2,Z3)",
		"SCALAR_CARRY(Z3,Z4)",
		"SCALAR_CARRY(Z4,Z5)",
		"SCALAR_CARRY(Z5,Z6)",
		"SCALAR_CARRY(Z6,Z7)",
		"SCALAR_CARRY(Z7,Z8)",
		"SCALAR_CARRY(Z8,Z9)",
		"SCALAR_CARRY(Z9,Z10)",
		"SCALAR_CARRY(Z10,Z11)",
	}
	if len(got) != len(want) {
		t.Fatalf("source transcript has %d macros, want %d", len(got), len(want))
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("source transcript step %d = %q, want %q", index, got[index], want[index])
		}
	}

	for _, required := range []string{
		"VPBROADCASTQ ·scalarReduce666643(SB), Z24",
		"VPBROADCASTQ ·scalarReduce470296(SB), Z25",
		"VPBROADCASTQ ·scalarReduce654183(SB), Z26",
		"VPBROADCASTQ ·scalarReduce997805(SB), Z27",
		"VPBROADCASTQ ·scalarReduce136657(SB), Z28",
		"VPBROADCASTQ ·scalarReduce683901(SB), Z29",
		"VPBROADCASTQ ·scalarReduceRound21(SB), Z31",
	} {
		if !strings.Contains(string(source), required) {
			t.Fatalf("source transcript missing %q", required)
		}
	}
}
