package sha512mb

import (
	"crypto/sha512"
	"testing"
)

// FuzzSum512Differential checks the production segmented API and both
// multi-buffer scheduling references against crypto/sha512. Every lane sees
// the same original bytes split at different boundaries, including empty
// segments, so segmentation and lane/tail handling cannot change the digest.
func FuzzSum512Differential(f *testing.F) {
	for _, n := range []int{0, 1, 63, 64, 111, 112, 127, 128, 129, 176, 200, 512, 1024, 1232} {
		data := make([]byte, n)
		for i := range data {
			data[i] = byte(31*i + n)
		}
		f.Add(data, uint16(n/3), uint16(2*n/3), uint8(n%18))
	}

	f.Fuzz(func(t *testing.T, input []byte, first, second uint16, countByte uint8) {
		const maxFuzzMessage = 16 << 10
		if len(input) > maxFuzzMessage {
			input = input[:maxFuzzMessage]
		}
		count := int(countByte % 18)
		msgs := make([][][]byte, count)
		modulus := len(input) + 1
		for lane := range msgs {
			cut1 := (int(first) + 17*lane) % modulus
			cut2 := (int(second) + 29*lane) % modulus
			if cut1 > cut2 {
				cut1, cut2 = cut2, cut1
			}
			msgs[lane] = [][]byte{nil, input[:cut1], input[cut1:cut2], nil, input[cut2:]}
		}

		want := sha512.Sum512(input)
		implementations := []struct {
			name string
			fn   func([][64]byte, [][][]byte)
		}{
			{name: "production", fn: Sum512Batch},
			{name: "x4-reference", fn: sum512x4Reference},
			{name: "x8-reference", fn: sum512x8Reference},
		}
		if nativeX4Available() {
			implementations = append(implementations, struct {
				name string
				fn   func([][64]byte, [][][]byte)
			}{
				name: "native-x4",
				fn: func(out [][64]byte, msgs [][][]byte) {
					if !sum512x4Native(out, msgs) {
						t.Fatal("AVX2 availability changed during fuzzing")
					}
				},
			})
		}
		if nativeX8Available() {
			implementations = append(implementations, struct {
				name string
				fn   func([][64]byte, [][][]byte)
			}{
				name: "native-x8",
				fn: func(out [][64]byte, msgs [][][]byte) {
					if !ExperimentalSum512Batch(out, msgs, nativeX8Width) {
						t.Fatal("AVX-512F/BW availability changed during fuzzing")
					}
				},
			})
		}
		for _, implementation := range implementations {
			out := make([][64]byte, count)
			implementation.fn(out, msgs)
			for lane := range out {
				if out[lane] != want {
					t.Fatalf("%s lane=%d count=%d length=%d: digest mismatch", implementation.name, lane, count, len(input))
				}
			}
		}
	})
}
