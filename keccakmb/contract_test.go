package keccakmb

import (
	"bytes"
	"math/rand/v2"
	"testing"
)

// TestBlockCountAliasedParts counts a 2 GiB message made of 2,048 parts that
// all alias one 1 MiB buffer. Summing the lengths into an int wraps negative
// on 32-bit Go, which made the scalar sponge absorb nothing. Run it there
// with GOARCH=386.
func TestBlockCountAliasedParts(t *testing.T) {
	buf := make([]byte, 1<<20)
	parts := make([][]byte, 2048)
	for i := range parts {
		parts[i] = buf
	}
	const total = uint64(1) << 31
	if got := messageLen(parts); got != total {
		t.Fatalf("messageLen = %d, want %d", got, total)
	}
	for _, rate := range []int{136, 168} {
		want := int(total/uint64(rate)) + 1
		if got := blockCount(parts, rate); got != want {
			t.Fatalf("rate %d: blockCount = %d, want %d", rate, got, want)
		}
		if l := newLane(parts, rate); l.blocks != want {
			t.Fatalf("rate %d: newLane blocks = %d, want %d", rate, l.blocks, want)
		}
	}
}

// TestSumBatchInPlace hashes each message into the start of its own input
// buffer, which both batch paths support.
func TestSumBatchInPlace(t *testing.T) {
	rng := rand.New(rand.NewPCG(21, 22))
	for _, batch := range []int{1, 5, 8, 11} {
		for _, v := range []Variant{Keccak256, SHAKE256} {
			want := make([][]byte, batch)
			bufs := make([][]byte, batch)
			for i := range bufs {
				bufs[i] = make([]byte, 32+rng.IntN(400))
				for k := range bufs[i] {
					bufs[i][k] = byte(rng.Uint32())
				}
				want[i] = make([]byte, 32)
				Sum(v, want[i], bufs[i])
			}
			run := func(name string, f func(out [][]byte, msgs [][][]byte) bool) {
				out := make([][]byte, batch)
				msgs := make([][][]byte, batch)
				for i := range bufs {
					b := append([]byte(nil), bufs[i]...)
					msgs[i] = [][]byte{b}
					out[i] = b[:32]
				}
				if !f(out, msgs) {
					return
				}
				for i := range out {
					if !bytes.Equal(out[i], want[i]) {
						t.Fatalf("%s batch %d lane %d: in-place digest mismatch", name, batch, i)
					}
				}
			}
			run("scalar", func(out [][]byte, msgs [][][]byte) bool { SumBatch(v, out, msgs); return true })
			run("native", func(out [][]byte, msgs [][][]byte) bool { return ExperimentalSumBatch(v, out, msgs) })
		}
	}
}

// TestSqueezeBlockPartialBatch prefills the output and checks that a partial
// batch writes exactly out[j][:rate] for the absorbed lanes, on both paths,
// for the unpermuted first block and for later blocks.
func TestSqueezeBlockPartialBatch(t *testing.T) {
	for _, v := range []Variant{SHAKE256, SHAKE128} {
		for _, lanes := range []int{1, 3, 7} {
			msgs := make([][][]byte, lanes)
			for j := range msgs {
				msgs[j] = [][]byte{bytes.Repeat([]byte{byte(j + 1)}, 50*j)}
			}
			check := func(name string, x *SpongeX8) {
				var ref SpongeX8
				NewSpongeX8Generic(&ref, v, msgs)
				for b := 0; b < 3; b++ {
					var blk, want [Lanes][200]byte
					for j := range blk {
						for k := range blk[j] {
							blk[j][k] = 0xa5
							want[j][k] = 0xa5
						}
					}
					x.SqueezeBlock(&blk)
					var full [Lanes][200]byte
					ref.SqueezeBlock(&full)
					for j := 0; j < lanes; j++ {
						copy(want[j][:v.Rate()], full[j][:v.Rate()])
					}
					if blk != want {
						t.Fatalf("%s variant %+v lanes %d block %d: output differs from the expected prefilled block", name, v, lanes, b)
					}
				}
			}
			var g SpongeX8
			NewSpongeX8Generic(&g, v, msgs)
			check("generic", &g)
			var n SpongeX8
			if ExperimentalNewSpongeX8(&n, v, msgs) {
				check("native", &n)
			}
		}
	}
}
