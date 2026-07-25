package sha512mb

import (
	"crypto/sha512"
	"encoding/binary"
	"math/rand"
	"testing"
	"unsafe"
)

func TestNativeConstantsMatchReference(t *testing.T) {
	if nativeRoundConstants != referenceRoundConstants {
		t.Fatal("native SHA-512 round constants differ from the reference")
	}
}

func TestNativeCompressX4Differential(t *testing.T) {
	if !nativeX4Available() {
		t.Skip("requires AVX2")
	}
	rng := rand.New(rand.NewSource(51))
	for iteration := 0; iteration < 256; iteration++ {
		var got nativeStateX4
		var want [8][referenceMaxLanes]uint64
		for word := 0; word < 8; word++ {
			for lane := 0; lane < nativeX4Width; lane++ {
				value := rng.Uint64()
				got[word][lane] = value
				want[word][lane] = value
			}
		}

		var nativeBlock nativeBlockX4
		var blocks [referenceMaxLanes][128]byte
		var active [referenceMaxLanes]bool
		for lane := 0; lane < nativeX4Width; lane++ {
			active[lane] = true
			for word := 0; word < 16; word++ {
				value := rng.Uint64()
				nativeBlock[word][lane] = value
				binary.BigEndian.PutUint64(blocks[lane][word*8:], value)
			}
		}

		compressReference(&want, &blocks, &active, nativeX4Width)
		nativeCompressX4(&got, &nativeBlock)
		for word := 0; word < 8; word++ {
			for lane := 0; lane < nativeX4Width; lane++ {
				if got[word][lane] != want[word][lane] {
					t.Fatalf("iteration=%d word=%d lane=%d: got %016x, want %016x", iteration, word, lane, got[word][lane], want[word][lane])
				}
			}
		}
	}
}

func TestNativeCompressX8Differential(t *testing.T) {
	if !nativeX8Available() {
		t.Skip("requires AVX-512F")
	}
	rng := rand.New(rand.NewSource(54))
	for iteration := 0; iteration < 256; iteration++ {
		var got nativeStateX8
		var want [8][referenceMaxLanes]uint64
		for word := 0; word < 8; word++ {
			for lane := 0; lane < nativeX8Width; lane++ {
				value := rng.Uint64()
				got[word][lane] = value
				want[word][lane] = value
			}
		}

		var nativeBlock nativeBlockX8
		var blocks [referenceMaxLanes][128]byte
		var active [referenceMaxLanes]bool
		for lane := 0; lane < nativeX8Width; lane++ {
			active[lane] = true
			for word := 0; word < 16; word++ {
				value := rng.Uint64()
				nativeBlock[word][lane] = value
				binary.BigEndian.PutUint64(blocks[lane][word*8:], value)
			}
		}

		compressReference(&want, &blocks, &active, nativeX8Width)
		nativeCompressX8(&got, &nativeBlock)
		for word := 0; word < 8; word++ {
			for lane := 0; lane < nativeX8Width; lane++ {
				if got[word][lane] != want[word][lane] {
					t.Fatalf("iteration=%d word=%d lane=%d: got %016x, want %016x", iteration, word, lane, got[word][lane], want[word][lane])
				}
			}
		}
	}
}

func TestNativeCompressX8RollingDifferential(t *testing.T) {
	if !nativeX8Available() {
		t.Skip("requires AVX-512F")
	}
	rng := rand.New(rand.NewSource(0x5128a11))
	for iteration := 0; iteration < 100; iteration++ {
		var got nativeStateX8
		var want [8][referenceMaxLanes]uint64
		var nativeBlock nativeBlockX8
		var blocks [referenceMaxLanes][128]byte
		var active [referenceMaxLanes]bool
		for lane := 0; lane < nativeX8Width; lane++ {
			active[lane] = true
			for word := range nativeInitialState {
				value := rng.Uint64()
				got[word][lane] = value
				want[word][lane] = value
			}
			for word := range nativeBlock {
				value := rng.Uint64()
				nativeBlock[word][lane] = value
				binary.BigEndian.PutUint64(blocks[lane][word*8:], value)
			}
		}
		compressReference(&want, &blocks, &active, nativeX8Width)
		nativeCompressX8Rolling(&got, &nativeBlock)
		for word := range nativeInitialState {
			for lane := 0; lane < nativeX8Width; lane++ {
				if got[word][lane] != want[word][lane] {
					t.Fatalf("iteration=%d word=%d lane=%d: got=%016x want=%016x", iteration, word, lane, got[word][lane], want[word][lane])
				}
			}
		}
	}
}

func TestNativeCompressX8RollingAlias(t *testing.T) {
	if !nativeX8Available() {
		t.Skip("requires AVX-512F")
	}
	rng := rand.New(rand.NewSource(0x512a11a5))
	var storage nativeBlockX8
	for word := range storage {
		for lane := range storage[word] {
			storage[word][lane] = rng.Uint64()
		}
	}
	state := (*nativeStateX8)(unsafe.Pointer(&storage))
	var want [8][referenceMaxLanes]uint64
	for word := range *state {
		for lane := range (*state)[word] {
			want[word][lane] = (*state)[word][lane]
		}
	}
	var blocks [referenceMaxLanes][128]byte
	var active [referenceMaxLanes]bool
	for lane := 0; lane < nativeX8Width; lane++ {
		active[lane] = true
		for word := range storage {
			binary.BigEndian.PutUint64(blocks[lane][word*8:], storage[word][lane])
		}
	}
	compressReference(&want, &blocks, &active, nativeX8Width)
	nativeCompressX8Rolling(state, &storage)
	for word := range *state {
		for lane := range (*state)[word] {
			if (*state)[word][lane] != want[word][lane] {
				t.Fatalf("word=%d lane=%d: got=%016x want=%016x", word, lane, (*state)[word][lane], want[word][lane])
			}
		}
	}
}

func TestNativeX4Differential(t *testing.T) {
	if !nativeX4Available() {
		t.Skip("requires AVX2")
	}
	rng := rand.New(rand.NewSource(52))
	edges := []int{0, 1, 47, 48, 63, 64, 111, 112, 127, 128, 129, 176, 200, 512, 1024, 1232, 4096}
	for count := 0; count <= 17; count++ {
		msgs := make([][][]byte, count)
		for lane := range msgs {
			r := make([]byte, 32)
			a := make([]byte, 32)
			message := make([]byte, edges[(3*count+5*lane)%len(edges)])
			rng.Read(r)
			rng.Read(a)
			rng.Read(message)
			msgs[lane] = splitNativeRAM(r, a, message, count+lane)
		}
		out := make([][64]byte, count)
		if !sum512x4Native(out, msgs) {
			t.Fatal("AVX2 availability changed during the test")
		}
		checkNativeDigests(t, msgs, out)
	}
}

func TestNativeX8Differential(t *testing.T) {
	if !nativeX8Available() {
		t.Skip("requires AVX-512F")
	}
	rng := rand.New(rand.NewSource(55))
	edges := []int{0, 1, 47, 48, 63, 64, 111, 112, 127, 128, 129, 176, 200, 512, 1024, 1232, 4096}
	for count := 0; count <= 17; count++ {
		msgs := make([][][]byte, count)
		for lane := range msgs {
			r := make([]byte, 32)
			a := make([]byte, 32)
			message := make([]byte, edges[(7*count+3*lane)%len(edges)])
			rng.Read(r)
			rng.Read(a)
			rng.Read(message)
			msgs[lane] = splitNativeRAM(r, a, message, count+lane)
		}
		out := make([][64]byte, count)
		if !ExperimentalSum512Batch(out, msgs, nativeX8Width) {
			t.Fatal("AVX-512F availability changed during the test")
		}
		checkNativeDigests(t, msgs, out)
	}
}

func TestExperimentalSum512Batch3Differential(t *testing.T) {
	rng := rand.New(rand.NewSource(56))
	edges := []int{0, 1, 47, 48, 63, 64, 111, 112, 127, 128, 129, 176, 200, 512, 1024, 1232, 4096}
	tested := false
	for _, width := range []int{nativeX4Width, nativeX8Width} {
		if !ExperimentalNativeAvailable(width) {
			continue
		}
		tested = true
		for count := 0; count <= 17; count++ {
			msgs := make([][3][]byte, count)
			for lane := range msgs {
				for part := range msgs[lane] {
					length := edges[(11*count+7*lane+part)%len(edges)]
					msgs[lane][part] = make([]byte, length)
					_, _ = rng.Read(msgs[lane][part])
				}
			}
			out := make([][64]byte, count)
			if !ExperimentalSum512Batch3(out, msgs, width) {
				t.Fatalf("x%d availability changed during the test", width)
			}
			checkNativeDigests3(t, msgs, out)
		}
	}
	if !tested {
		t.Skip("requires AVX2 or AVX-512F")
	}
}

func TestNativeX4RandomizedDifferential(t *testing.T) {
	if !nativeX4Available() {
		t.Skip("requires AVX2")
	}
	rng := rand.New(rand.NewSource(53))
	for iteration := 0; iteration < 500; iteration++ {
		count := 1 + rng.Intn(17)
		msgs := make([][][]byte, count)
		for lane := range msgs {
			length := rng.Intn(4097)
			buf := make([]byte, length)
			rng.Read(buf)
			msgs[lane] = splitNativeMessage(buf, rng, iteration+lane)
		}
		out := make([][64]byte, count)
		if !sum512x4Native(out, msgs) {
			t.Fatal("AVX2 availability changed during the test")
		}
		checkNativeDigests(t, msgs, out)
	}
}

func TestNativeX4NoAllocations(t *testing.T) {
	if !nativeX4Available() {
		t.Skip("requires AVX2")
	}
	var storage [nativeX4Width][64 + 1232]byte
	var parts [nativeX4Width][3][]byte
	var msgs [nativeX4Width][][]byte
	var out [nativeX4Width][64]byte
	for lane := range msgs {
		parts[lane] = [3][]byte{storage[lane][:32], storage[lane][32:64], storage[lane][64:]}
		msgs[lane] = parts[lane][:]
	}
	if allocations := testing.AllocsPerRun(100, func() {
		if !sum512x4Native(out[:], msgs[:]) {
			panic("AVX2 availability changed")
		}
	}); allocations != 0 {
		t.Fatalf("native x4 allocated %.2f objects per batch", allocations)
	}
}

func TestNativeX8NoAllocations(t *testing.T) {
	if !nativeX8Available() {
		t.Skip("requires AVX-512F")
	}
	var storage [nativeX8Width][64 + 1232]byte
	var parts [nativeX8Width][3][]byte
	var msgs [nativeX8Width][][]byte
	var out [nativeX8Width][64]byte
	for lane := range msgs {
		parts[lane] = [3][]byte{storage[lane][:32], storage[lane][32:64], storage[lane][64:]}
		msgs[lane] = parts[lane][:]
	}
	if allocations := testing.AllocsPerRun(100, func() {
		if !ExperimentalSum512Batch(out[:], msgs[:], nativeX8Width) {
			panic("AVX-512F availability changed")
		}
	}); allocations != 0 {
		t.Fatalf("native x8 allocated %.2f objects per batch", allocations)
	}
}

func TestExperimentalSum512Batch3NoAllocations(t *testing.T) {
	const maxMessageSize = 1232
	var storage [17][64 + maxMessageSize]byte
	var msgs [17][3][]byte
	var out [17][64]byte
	for lane := range msgs {
		msgs[lane] = [3][]byte{
			storage[lane][:32],
			storage[lane][32:64],
			storage[lane][64:],
		}
	}
	tested := false
	for _, width := range []int{nativeX4Width, nativeX8Width} {
		if !ExperimentalNativeAvailable(width) {
			continue
		}
		tested = true
		for _, count := range []int{0, 1, 3, 4, 5, 7, 8, 9, 16, 17} {
			if allocations := testing.AllocsPerRun(100, func() {
				if !ExperimentalSum512Batch3(out[:count], msgs[:count], width) {
					panic("native fixed3 availability changed")
				}
			}); allocations != 0 {
				t.Fatalf("native fixed3 x%d count=%d allocated %.2f objects per batch", width, count, allocations)
			}
		}
	}
	if !tested {
		t.Skip("requires AVX2 or AVX-512F")
	}
}

func TestExperimentalUnavailableIsNonMutating(t *testing.T) {
	var out [3][64]byte
	for i := range out {
		for j := range out[i] {
			out[i][j] = byte(17*i + j)
		}
	}
	want := out
	var msgs [3][][]byte
	if ExperimentalSum512Batch(out[:], msgs[:], 3) {
		t.Fatal("unsupported width reported success")
	}
	if out != want {
		t.Fatal("unsupported width mutated output")
	}
	for _, width := range []int{nativeX4Width, nativeX8Width} {
		if ExperimentalNativeAvailable(width) {
			continue
		}
		if ExperimentalSum512Batch(out[:], msgs[:], width) {
			t.Fatalf("unavailable x%d kernel reported success", width)
		}
		if out != want {
			t.Fatalf("unavailable x%d kernel mutated output", width)
		}
	}

	fixedOut := want
	var fixedMsgs [3][3][]byte
	if ExperimentalSum512Batch3(fixedOut[:], fixedMsgs[:], 3) {
		t.Fatal("unsupported fixed3 width reported success")
	}
	if fixedOut != want {
		t.Fatal("unsupported fixed3 width mutated output")
	}
	for _, width := range []int{nativeX4Width, nativeX8Width} {
		if ExperimentalNativeAvailable(width) {
			continue
		}
		if ExperimentalSum512Batch3(fixedOut[:], fixedMsgs[:], width) {
			t.Fatalf("unavailable fixed3 x%d kernel reported success", width)
		}
		if fixedOut != want {
			t.Fatalf("unavailable fixed3 x%d kernel mutated output", width)
		}
	}
}

func TestNativeLengthMismatchPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("native length mismatch did not panic")
		}
	}()
	sum512x4Native(make([][64]byte, 1), nil)
}

func TestExperimentalSum512Batch3LengthMismatchPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("native fixed3 length mismatch did not panic")
		}
	}()
	ExperimentalSum512Batch3(make([][64]byte, 1), nil, nativeX4Width)
}

func splitNativeRAM(r, a, message []byte, salt int) [][]byte {
	messageCut := 0
	if len(message) != 0 {
		messageCut = (17*salt + len(message)/3) % (len(message) + 1)
	}
	return [][]byte{
		nil,
		r[:7], r[7:],
		a[:19], nil, a[19:],
		message[:messageCut], nil, message[messageCut:],
	}
}

func splitNativeMessage(buf []byte, rng *rand.Rand, salt int) [][]byte {
	if len(buf) == 0 {
		return [][]byte{nil, buf, nil}
	}
	partCount := 1 + rng.Intn(7)
	parts := make([][]byte, 0, 2*partCount+1)
	parts = append(parts, nil)
	previous := 0
	for part := 1; part < partCount; part++ {
		remainingCuts := partCount - part
		maximum := len(buf) - remainingCuts
		cut := previous
		if maximum > previous {
			cut += rng.Intn(maximum - previous + 1)
		}
		parts = append(parts, buf[previous:cut])
		if (salt+part)&1 == 0 {
			parts = append(parts, nil)
		}
		previous = cut
	}
	parts = append(parts, buf[previous:])
	return parts
}

func checkNativeDigests(t *testing.T, msgs [][][]byte, got [][64]byte) {
	t.Helper()
	for lane := range msgs {
		h := sha512.New()
		for _, part := range msgs[lane] {
			_, _ = h.Write(part)
		}
		var want [64]byte
		h.Sum(want[:0])
		if got[lane] != want {
			t.Fatalf("lane=%d parts=%d: native digest mismatch", lane, len(msgs[lane]))
		}
	}
}

func checkNativeDigests3(t *testing.T, msgs [][3][]byte, got [][64]byte) {
	t.Helper()
	for lane := range msgs {
		h := sha512.New()
		for _, part := range msgs[lane] {
			_, _ = h.Write(part)
		}
		var want [64]byte
		h.Sum(want[:0])
		if got[lane] != want {
			t.Fatalf("lane=%d: native fixed3 digest mismatch", lane)
		}
	}
}
