package sha512mb

import (
	"bytes"
	"crypto/sha512"
	"math/rand"
	"testing"
)

// TestSum512Batch drives the batch API through varied part counts and
// lengths and checks every digest against crypto/sha512 of the
// concatenation. Lengths cover the block-boundary edge cases (0, 1,
// 111..112 around the padding split, 127..129 around the block size).
func TestSum512Batch(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	edge := []int{0, 1, 63, 64, 111, 112, 127, 128, 129, 176, 200, 512, 1024, 1232, 4096}

	var msgs [][][]byte
	var want [][64]byte
	for _, n := range edge {
		buf := make([]byte, n)
		rng.Read(buf)
		// Split into 1..3 parts at random boundaries.
		var parts [][]byte
		switch rng.Intn(3) {
		case 0:
			parts = [][]byte{buf}
		case 1:
			k := rng.Intn(n + 1)
			parts = [][]byte{buf[:k], buf[k:]}
		default:
			k1 := rng.Intn(n + 1)
			k2 := k1 + rng.Intn(n-k1+1)
			parts = [][]byte{buf[:k1], buf[k1:k2], buf[k2:]}
		}
		msgs = append(msgs, parts)
		want = append(want, sha512.Sum512(buf))
	}

	out := make([][64]byte, len(msgs))
	Sum512Batch(out, msgs)
	for i := range out {
		if !bytes.Equal(out[i][:], want[i][:]) {
			t.Fatalf("batch digest %d mismatch", i)
		}
	}

	var single [64]byte
	Sum512(&single, msgs[len(msgs)-1]...)
	if !bytes.Equal(single[:], want[len(want)-1][:]) {
		t.Fatal("Sum512 disagrees with crypto/sha512")
	}
}
