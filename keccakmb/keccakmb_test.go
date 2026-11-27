package keccakmb

import (
	"bytes"
	"crypto/sha3"
	"encoding/hex"
	"math/rand/v2"
	"testing"
)

// TestPermute1ZeroState checks the reference permutation against the
// Keccak team's published Keccak-f[1600] output for the all-zero state.
func TestPermute1ZeroState(t *testing.T) {
	var a [25]uint64
	permute1(&a)
	want := [25]uint64{
		0xF1258F7940E1DDE7, 0x84D5CCF933C0478A, 0xD598261EA65AA9EE, 0xBD1547306F80494D,
		0x8B284E056253D057, 0xFF97A42D7F8E6FD4, 0x90FEE5A0A44647C4, 0x8C5BDA0CD6192E76,
		0xAD30A6F71B19059C, 0x30935AB7D08FFC64, 0xEB5AA93F2317D635, 0xA9A6E6260D712103,
		0x81A57C16DBCF555F, 0x43B831CD0347C826, 0x01F22F1A11A5569F, 0x05E5635A21D9AE61,
		0x64BEFEF28CC970F2, 0x613670957BC46611, 0xB87C5A554FD00ECB, 0x8C3EE88A1CCF32C8,
		0x940C7922AE3A2614, 0x1841F924A2C509E4, 0x16F53526E70465C2, 0x75F644E97F30A13B,
		0xEAF1FF7B5CECA249,
	}
	if a != want {
		t.Fatalf("Keccak-f[1600](0) = %x, want %x", a, want)
	}
}

// TestLegacyKeccak256Vectors uses the well-known Ethereum Keccak-256 digests.
func TestLegacyKeccak256Vectors(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"},
		{"abc", "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"},
	} {
		var got [32]byte
		Sum(Keccak256, got[:], []byte(tc.in))
		if hex.EncodeToString(got[:]) != tc.want {
			t.Errorf("Keccak256(%q) = %x, want %s", tc.in, got, tc.want)
		}
	}
}

// interestingLengths covers empty input, every byte around one and two
// blocks of both rates, and long messages.
func interestingLengths() []int {
	var out []int
	for _, r := range []int{136, 168} {
		for k := 1; k <= 3; k++ {
			for d := -2; d <= 2; d++ {
				out = append(out, k*r+d)
			}
		}
	}
	return append(out, 0, 1, 7, 8, 9, 32, 64, 65, 1232, 4096)
}

func stdlibSum(v Variant, msg []byte, n int) []byte {
	switch v {
	case SHA3_256:
		d := sha3.Sum256(msg)
		return d[:]
	case SHAKE128:
		return sha3.SumSHAKE128(msg, n)
	case SHAKE256:
		return sha3.SumSHAKE256(msg, n)
	}
	panic("no stdlib reference")
}

// TestSumMatchesStdlib checks the scalar sponge, including multi-block
// squeezes, against crypto/sha3.
func TestSumMatchesStdlib(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	for _, v := range []Variant{SHA3_256, SHAKE128, SHAKE256} {
		for _, n := range interestingLengths() {
			msg := make([]byte, n)
			for i := range msg {
				msg[i] = byte(rng.Uint32())
			}
			outLen := 32
			if v != SHA3_256 {
				outLen = 1100 // Falcon-512 hash-to-point scale, several blocks
			}
			got := make([]byte, outLen)
			// Split the message in three parts to exercise segment crossings.
			a, b := n/3, 2*n/3
			Sum(v, got, msg[:a], msg[a:b], msg[b:])
			if want := stdlibSum(v, msg, outLen); !bytes.Equal(got, want) {
				t.Fatalf("variant %+v len %d: got %x, want %x", v, n, got, want)
			}
		}
	}
}

func randomState(rng *rand.Rand) StateX8 {
	var s StateX8
	for i := range s {
		for j := range s[i] {
			s[i][j] = rng.Uint64()
		}
	}
	return s
}

// TestPermuteX8 checks every lane of both multi-buffer permutations against
// the reference, on random states and with lanes differing in one bit.
func TestPermuteX8(t *testing.T) {
	rng := rand.New(rand.NewPCG(3, 4))
	for iter := 0; iter < 200; iter++ {
		s := randomState(rng)
		if iter%2 == 1 {
			// Lanes identical except for one bit, to catch cross-lane leaks.
			for i := range s {
				for j := range s[i] {
					s[i][j] = s[i][0]
				}
			}
			for j := 1; j < Lanes; j++ {
				s[rng.IntN(25)][j] ^= 1 << rng.IntN(64)
			}
		}
		want := s
		for j := 0; j < Lanes; j++ {
			var a [25]uint64
			for i := range a {
				a[i] = want[i][j]
			}
			permute1(&a)
			for i := range a {
				want[i][j] = a[i]
			}
		}
		g := s
		PermuteX8Generic(&g)
		if g != want {
			t.Fatalf("generic x8 permutation mismatch at iteration %d", iter)
		}
		n := s
		if ExperimentalPermuteX8(&n) {
			if n != want {
				t.Fatalf("native x8 permutation mismatch at iteration %d", iter)
			}
		}
	}
	if !ExperimentalNativeAvailable() {
		t.Log("AVX-512 kernel unavailable; native permutation not exercised")
	}
}

// TestSumBatchMixedLengths hashes batches whose lanes have different
// lengths, so lanes finish absorbing at different blocks, and compares with
// the scalar sponge and the standard library.
func TestSumBatchMixedLengths(t *testing.T) {
	rng := rand.New(rand.NewPCG(5, 6))
	lengths := interestingLengths()
	for _, v := range []Variant{Keccak256, SHA3_256, SHAKE128, SHAKE256} {
		for _, batch := range []int{1, 3, 7, 8, 9, 16, 17} {
			for iter := 0; iter < 40; iter++ {
				msgs := make([][][]byte, batch)
				out := make([][]byte, batch)
				gen := make([][]byte, batch)
				want := make([][]byte, batch)
				for i := range msgs {
					n := lengths[rng.IntN(len(lengths))]
					m := make([]byte, n)
					for k := range m {
						m[k] = byte(rng.Uint32())
					}
					// Up to five parts with random cut points, so blocks
					// start, end and straddle segment boundaries.
					msgs[i] = nil
					rest := m
					for p := rng.IntN(5); p > 0; p-- {
						cut := rng.IntN(len(rest) + 1)
						msgs[i] = append(msgs[i], rest[:cut])
						rest = rest[cut:]
					}
					msgs[i] = append(msgs[i], rest)
					outLen := 32
					if v == SHAKE128 || v == SHAKE256 {
						outLen = 1 + rng.IntN(700)
					}
					out[i] = make([]byte, outLen)
					gen[i] = make([]byte, outLen)
					want[i] = make([]byte, outLen)
					Sum(v, want[i], m)
					if v != Keccak256 {
						if s := stdlibSum(v, m, outLen); !bytes.Equal(s, want[i]) {
							t.Fatalf("scalar sponge disagrees with stdlib, len %d", n)
						}
					}
				}
				var x SpongeX8
				for first := 0; first < batch; first += Lanes {
					last := min(first+Lanes, batch)
					NewSpongeX8Generic(&x, v, msgs[first:last])
					x.squeezeInto(gen[first:last])
				}
				for i := range gen {
					if !bytes.Equal(gen[i], want[i]) {
						t.Fatalf("generic batch lane %d mismatch", i)
					}
				}
				if ExperimentalSumBatch(v, out, msgs) {
					for i := range out {
						if !bytes.Equal(out[i], want[i]) {
							t.Fatalf("native batch variant %+v batch %d lane %d mismatch", v, batch, i)
						}
					}
				}
			}
		}
	}
}

// TestSpongeX8Squeeze checks block-by-block squeezing, as Falcon
// hash-to-point uses it, against crypto/sha3's SHAKE256 reader.
func TestSpongeX8Squeeze(t *testing.T) {
	rng := rand.New(rand.NewPCG(7, 8))
	msgs := make([][][]byte, Lanes)
	readers := make([]*sha3.SHAKE, Lanes)
	for j := range msgs {
		nonce := make([]byte, 40)
		m := make([]byte, rng.IntN(1300))
		for k := range nonce {
			nonce[k] = byte(rng.Uint32())
		}
		for k := range m {
			m[k] = byte(rng.Uint32())
		}
		msgs[j] = [][]byte{nonce, m}
		readers[j] = sha3.NewSHAKE256()
		readers[j].Write(nonce)
		readers[j].Write(m)
	}
	check := func(name string, x *SpongeX8) {
		for j := range readers {
			readers[j].Reset()
			readers[j].Write(msgs[j][0])
			readers[j].Write(msgs[j][1])
		}
		var blk [Lanes][200]byte
		for b := 0; b < 10; b++ {
			x.SqueezeBlock(&blk)
			for j := 0; j < Lanes; j++ {
				want := make([]byte, 136)
				readers[j].Read(want)
				if !bytes.Equal(blk[j][:136], want) {
					t.Fatalf("%s: lane %d block %d mismatch", name, j, b)
				}
			}
		}
	}
	var g SpongeX8
	NewSpongeX8Generic(&g, SHAKE256, msgs)
	check("generic", &g)
	var n SpongeX8
	if ExperimentalNewSpongeX8(&n, SHAKE256, msgs) {
		check("native", &n)
	}
}

// FuzzSumBatch differentially checks the batch paths on arbitrary messages.
func FuzzSumBatch(f *testing.F) {
	f.Add([]byte("abc"), uint8(3), uint16(32))
	f.Add(make([]byte, 300), uint8(8), uint16(500))
	f.Fuzz(func(t *testing.T, data []byte, lanes uint8, outLen uint16) {
		batch := int(lanes%17) + 1
		n := int(outLen%1200) + 1
		msgs := make([][][]byte, batch)
		out := make([][]byte, batch)
		for i := range msgs {
			lo := (i * len(data)) / (batch + 1)
			hi := len(data) - (i*len(data))/(2*batch+1)
			if hi < lo {
				hi = lo
			}
			msgs[i] = [][]byte{data[lo:hi]}
			out[i] = make([]byte, n)
		}
		for _, v := range []Variant{Keccak256, SHAKE256} {
			if !ExperimentalSumBatch(v, out, msgs) {
				t.Skip("AVX-512 kernel unavailable")
			}
			for i := range msgs {
				want := make([]byte, n)
				Sum(v, want, msgs[i]...)
				if !bytes.Equal(out[i], want) {
					t.Fatalf("lane %d mismatch", i)
				}
			}
		}
	})
}
