package sha512mb

import (
	"crypto/sha512"
	"math/rand"
	"testing"
)

func TestReferenceMultiBufferDifferential(t *testing.T) {
	rng := rand.New(rand.NewSource(41))
	edges := []int{0, 1, 63, 64, 111, 112, 127, 128, 129, 176, 200, 512, 1024, 1232, 4096}
	for _, width := range []int{4, 8} {
		for count := 0; count <= 2*width+1; count++ {
			msgs := make([][][]byte, count)
			for lane := range msgs {
				n := edges[(lane+count*3+width)%len(edges)]
				buf := make([]byte, n)
				rng.Read(buf)
				msgs[lane] = splitReferenceMessage(buf, lane+count)
			}
			out := make([][64]byte, count)
			if width == 4 {
				sum512x4Reference(out, msgs)
			} else {
				sum512x8Reference(out, msgs)
			}
			checkReferenceDigests(t, width, msgs, out)
		}
	}
}

func TestReferenceRAMPrefixAndOriginalSegments(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	for _, messageLen := range []int{47, 48, 63, 64, 65, 176, 200, 512, 1024, 1232} {
		r := make([]byte, 32)
		a := make([]byte, 32)
		message := make([]byte, messageLen)
		rng.Read(r)
		rng.Read(a)
		rng.Read(message)
		contiguous := append(append(append([]byte(nil), r...), a...), message...)

		variants := [][][]byte{
			{r, a, message},
			{contiguous},
			{r[:7], r[7:], nil, a[:19], a[19:], message[:messageLen/2], message[messageLen/2:]},
			{contiguous[:64], contiguous[64:]},
		}
		for len(variants) < 8 {
			variants = append(variants, variants[len(variants)%4])
		}
		want := sha512.Sum512(contiguous)
		for _, run := range []struct {
			name string
			fn   func([][64]byte, [][][]byte)
		}{
			{"x4", sum512x4Reference},
			{"x8", sum512x8Reference},
		} {
			out := make([][64]byte, len(variants))
			run.fn(out, variants)
			for lane := range out {
				if out[lane] != want {
					t.Fatalf("%s message=%d lane=%d: R/A/M segmentation changed digest", run.name, messageLen, lane)
				}
			}
		}
	}
}

func TestReferenceUnequalPerLanePadding(t *testing.T) {
	// These totals force both sides of SHA-512's 111/112 padding split
	// and both sides of its 128-byte block boundary in one x8 group.
	lengths := []int{0, 111, 112, 127, 128, 129, 200, 1232}
	msgs := make([][][]byte, len(lengths))
	for lane, n := range lengths {
		buf := make([]byte, n)
		for i := range buf {
			buf[i] = byte(31*lane + i)
		}
		msgs[lane] = splitReferenceMessage(buf, lane)
	}
	out := make([][64]byte, len(msgs))
	sum512x8Reference(out, msgs)
	checkReferenceDigests(t, 8, msgs, out)
}

func TestReferenceDoesNotChangeProductionDispatch(t *testing.T) {
	if got := Lanes(); got != 1 {
		t.Fatalf("experimental references changed production Lanes to %d", got)
	}
}

func TestReferenceLengthMismatchPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("reference length mismatch did not panic")
		}
	}()
	sum512x4Reference(make([][64]byte, 1), nil)
}

func splitReferenceMessage(buf []byte, salt int) [][]byte {
	if len(buf) == 0 {
		return [][]byte{nil, buf, nil}
	}
	k1 := (salt*17 + len(buf)/3) % (len(buf) + 1)
	k2 := k1 + (salt*29+len(buf)/5)%(len(buf)-k1+1)
	return [][]byte{nil, buf[:k1], buf[k1:k2], nil, buf[k2:]}
}

func checkReferenceDigests(t *testing.T, width int, msgs [][][]byte, out [][64]byte) {
	t.Helper()
	for lane := range msgs {
		h := sha512.New()
		for _, part := range msgs[lane] {
			h.Write(part)
		}
		var want [64]byte
		h.Sum(want[:0])
		if out[lane] != want {
			t.Fatalf("x%d lane=%d parts=%d: digest mismatch", width, lane, len(msgs[lane]))
		}
	}
}
