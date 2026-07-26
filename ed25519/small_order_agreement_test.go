package ed25519

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/Overclock-Validator/narya-ed25519/internal/r51x5"
)

// The small-order classifier exists twice: once for the generic backend and the
// shared strict pre-pass, and once inside r51x5 for the packed path. They are
// independent copies of the same fourteen byte strings, with no shared source
// of truth and nothing in the type system tying them together.
//
// A one-byte edit to either table would not fail to compile and would not fail
// any existing test. It would make the two backends disagree about which public
// keys are acceptable, which under a consensus predicate is a fork rather than
// a local bug. This test is what makes that divergence loud.
//
// It needs no IFMA: the classifier is byte comparison, so it runs everywhere.
func TestSmallOrderClassifiersAgreeAcrossBackends(t *testing.T) {
	assertAgree := func(t *testing.T, label string, encoded []byte) {
		t.Helper()
		generic := smallOrderEncoding(encoded)
		packed := r51x5.ExperimentalEncodesSmallOrderPoint(encoded)
		if generic != packed {
			t.Fatalf("%s %x: generic=%v packed=%v", label, encoded, generic, packed)
		}
	}

	// The fourteen encodings both tables are supposed to contain. If either
	// copy has been edited, these fail immediately and name the input.
	smallOrder := smallOrderEncodingCorpus()
	if len(smallOrder) != 14 {
		t.Fatalf("built %d small-order encodings, want 14", len(smallOrder))
	}
	for index, encoded := range smallOrder {
		candidate := encoded
		t.Run(fmt.Sprintf("smallOrder=%d", index), func(t *testing.T) {
			if !smallOrderEncoding(candidate[:]) {
				t.Fatalf("%x: generic classifier does not recognise its own small-order encoding", candidate)
			}
			assertAgree(t, "small-order", candidate[:])
		})
	}

	// One-byte mutations of each small-order encoding. These are the near
	// misses: a table edited by a byte turns some of these into false accepts
	// on one side only, and a random sweep would need a very long time to
	// stumble onto them.
	for index, encoded := range smallOrder {
		for position := 0; position < 32; position++ {
			for _, delta := range []byte{0x01, 0x80} {
				mutated := encoded
				mutated[position] ^= delta
				assertAgree(t, fmt.Sprintf("mutation=%d/%d/%#x", index, position, delta), mutated[:])
			}
		}
	}

	// A broad sweep biased onto the first bytes that enter the comparison
	// branches at all. Without the bias almost every input exits at the switch
	// and the full-width comparisons are never reached.
	firstBytes := []byte{0x00, 0x01, 0x26, 0xc7, 0xec, 0xed, 0xee}
	rng := rand.New(rand.NewSource(20260726))
	for i := 0; i < 200000; i++ {
		var candidate [32]byte
		for j := range candidate {
			candidate[j] = byte(rng.Intn(256))
		}
		if i%2 == 0 {
			candidate[0] = firstBytes[i%len(firstBytes)]
		}
		assertAgree(t, "random", candidate[:])
	}

	// Lengths other than 32 must be rejected identically rather than panicking
	// in one implementation and returning false in the other.
	for _, length := range []int{0, 1, 31, 33, 64} {
		assertAgree(t, fmt.Sprintf("length=%d", length), make([]byte, length))
	}
}

// smallOrderEncodingCorpus returns the fourteen byte strings that the permissive
// decoder maps to a small-order point: seven low-255-bit values, each with both
// sign bits. It is built here from the definition rather than read from either
// implementation's table, so it is an independent third party to the comparison.
func smallOrderEncodingCorpus() [][32]byte {
	fill := func(first, middle, last byte) [32]byte {
		var out [32]byte
		out[0] = first
		for i := 1; i < 31; i++ {
			out[i] = middle
		}
		out[31] = last
		return out
	}

	// 0, 1, p-1, p, p+1, and the two order-eight y coordinates.
	base := [][32]byte{
		fill(0x00, 0x00, 0x00),
		fill(0x01, 0x00, 0x00),
		fill(0xec, 0xff, 0x7f),
		fill(0xed, 0xff, 0x7f),
		fill(0xee, 0xff, 0x7f),
		{
			0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f,
			0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
			0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6,
			0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a,
		},
		{
			0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0,
			0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
			0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39,
			0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05,
		},
	}

	out := make([][32]byte, 0, 2*len(base))
	for _, value := range base {
		clear, set := value, value
		clear[31] &= 0x7f
		set[31] |= 0x80
		out = append(out, clear, set)
	}
	return out
}
