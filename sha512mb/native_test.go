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

func TestNativeCompressFinalX8RollingDifferential(t *testing.T) {
	if !nativeX8Available() {
		t.Skip("requires AVX-512F")
	}
	rng := rand.New(rand.NewSource(0x512f1a1))
	for tailWords := 0; tailWords <= 2; tailWords++ {
		for iteration := 0; iteration < 100; iteration++ {
			var got nativeStateX8
			var want [8][referenceMaxLanes]uint64
			var tail nativeTailX8
			var blocks [referenceMaxLanes][128]byte
			var active [referenceMaxLanes]bool
			totalBits := uint64(8 * (128 + iteration*17 + tailWords*8))
			for lane := 0; lane < nativeX8Width; lane++ {
				active[lane] = true
				for word := range nativeInitialState {
					value := rng.Uint64()
					got[word][lane] = value
					want[word][lane] = value
				}
				for word := 0; word < tailWords; word++ {
					value := rng.Uint64()
					tail[word][lane] = value
					binary.BigEndian.PutUint64(blocks[lane][word*8:], value)
				}
				blocks[lane][tailWords*8] = 0x80
				binary.BigEndian.PutUint64(blocks[lane][120:], totalBits)
			}
			compressReference(&want, &blocks, &active, nativeX8Width)
			nativeCompressFinalX8Rolling(&got, &tail, uint64(tailWords), totalBits)
			for word := range got {
				for lane := range got[word] {
					if got[word][lane] != want[word][lane] {
						t.Fatalf("tailWords=%d iteration=%d word=%d lane=%d: got=%016x want=%016x", tailWords, iteration, word, lane, got[word][lane], want[word][lane])
					}
				}
			}
		}
	}
}

func TestNativeTransposeX8Differential(t *testing.T) {
	if !nativeX8Available() {
		t.Skip("requires AVX-512F and AVX-512BW")
	}
	rng := rand.New(rand.NewSource(0x5127a95))
	for iteration := 0; iteration < 100; iteration++ {
		var raw [nativeX8Width][128]byte
		for lane := range raw {
			if _, err := rng.Read(raw[lane][:]); err != nil {
				t.Fatal(err)
			}
		}
		var got, want nativeBlockX8
		for word := range want {
			for lane := range want[word] {
				want[word][lane] = binary.BigEndian.Uint64(raw[lane][word*8:])
			}
		}
		nativeTransposeX8(&got, &raw)
		if got != want {
			t.Fatalf("iteration=%d: native transpose differs from scalar reference", iteration)
		}
	}
}

func TestNativeTransposePointersX8Differential(t *testing.T) {
	if !nativeX8Available() {
		t.Skip("requires AVX-512F and AVX-512BW")
	}
	rng := rand.New(rand.NewSource(0x512d1ec7))
	for iteration := 0; iteration < 100; iteration++ {
		var storage [nativeX8Width][129]byte
		var ptrs [nativeX8Width]*byte
		var raw [nativeX8Width][128]byte
		for lane := range storage {
			if _, err := rng.Read(storage[lane][:]); err != nil {
				t.Fatal(err)
			}
			// Deliberately use unaligned addresses to match arbitrary message
			// slice offsets in the segmented verifier input.
			ptrs[lane] = &storage[lane][1]
			copy(raw[lane][:], storage[lane][1:])
		}
		var got, want nativeBlockX8
		for word := range want {
			for lane := range want[word] {
				want[word][lane] = binary.BigEndian.Uint64(raw[lane][word*8:])
			}
		}
		nativeTransposePointersX8(&got, &ptrs)
		if got != want {
			t.Fatalf("iteration=%d: pointer transpose differs from scalar reference", iteration)
		}
	}
}

func TestNativeTransposeCompressX8RollingDifferential(t *testing.T) {
	if !nativeX8Available() {
		t.Skip("requires AVX-512F and AVX-512BW")
	}
	rng := rand.New(rand.NewSource(0x512f053d))
	for iteration := 0; iteration < 100; iteration++ {
		var got nativeStateX8
		var want [8][referenceMaxLanes]uint64
		var storage [nativeX8Width][129]byte
		var ptrs [nativeX8Width]*byte
		var blocks [referenceMaxLanes][128]byte
		var active [referenceMaxLanes]bool
		for lane := 0; lane < nativeX8Width; lane++ {
			active[lane] = true
			_, _ = rng.Read(storage[lane][:])
			ptrs[lane] = &storage[lane][1]
			copy(blocks[lane][:], storage[lane][1:])
			for word := range nativeInitialState {
				value := rng.Uint64()
				got[word][lane] = value
				want[word][lane] = value
			}
		}
		compressReference(&want, &blocks, &active, nativeX8Width)
		nativeTransposeCompressX8Rolling(&got, &ptrs, 0)
		for word := range got {
			for lane := range got[word] {
				if got[word][lane] != want[word][lane] {
					t.Fatalf("iteration=%d word=%d lane=%d: got=%016x want=%016x", iteration, word, lane, got[word][lane], want[word][lane])
				}
			}
		}

		var gotInitial nativeStateX8
		var wantInitial [8][referenceMaxLanes]uint64
		for word := range nativeInitialState {
			for lane := 0; lane < nativeX8Width; lane++ {
				wantInitial[word][lane] = nativeInitialState[word]
			}
		}
		compressReference(&wantInitial, &blocks, &active, nativeX8Width)
		nativeTransposeCompressX8Rolling(&gotInitial, &ptrs, 1)
		for word := range gotInitial {
			for lane := range gotInitial[word] {
				if gotInitial[word][lane] != wantInitial[word][lane] {
					t.Fatalf("initial iteration=%d word=%d lane=%d: got=%016x want=%016x", iteration, word, lane, gotInitial[word][lane], wantInitial[word][lane])
				}
			}
		}
	}
}

func TestNativeCompressVerifierFirstX8RollingDifferential(t *testing.T) {
	if !nativeX8Available() {
		t.Skip("requires AVX-512F and AVX-512BW")
	}
	rng := rand.New(rand.NewSource(0x512f1a57))
	for iteration := 0; iteration < 100; iteration++ {
		var rStorage, aStorage [nativeX8Width][33]byte
		var messageStorage [nativeX8Width][65]byte
		var rPtrs, aPtrs, messagePtrs [nativeX8Width]*byte
		var blocks [referenceMaxLanes][128]byte
		var active [referenceMaxLanes]bool
		var want [8][referenceMaxLanes]uint64
		for lane := 0; lane < nativeX8Width; lane++ {
			active[lane] = true
			_, _ = rng.Read(rStorage[lane][:])
			_, _ = rng.Read(aStorage[lane][:])
			_, _ = rng.Read(messageStorage[lane][:])
			rPtrs[lane] = &rStorage[lane][1]
			aPtrs[lane] = &aStorage[lane][1]
			messagePtrs[lane] = &messageStorage[lane][1]
			copy(blocks[lane][0:32], rStorage[lane][1:])
			copy(blocks[lane][32:64], aStorage[lane][1:])
			copy(blocks[lane][64:128], messageStorage[lane][1:])
			for word := range nativeInitialState {
				want[word][lane] = nativeInitialState[word]
			}
		}
		compressReference(&want, &blocks, &active, nativeX8Width)
		var got nativeStateX8
		nativeCompressVerifierFirstX8Rolling(&got, &rPtrs, &aPtrs, &messagePtrs)
		for word := range got {
			for lane := range got[word] {
				if got[word][lane] != want[word][lane] {
					t.Fatalf("iteration=%d word=%d lane=%d: got=%016x want=%016x", iteration, word, lane, got[word][lane], want[word][lane])
				}
			}
		}
	}
}

func TestNativeTransposeCompressX8RollingAlias(t *testing.T) {
	if !nativeX8Available() {
		t.Skip("requires AVX-512F and AVX-512BW")
	}
	rng := rand.New(rand.NewSource(0x512f053da11a5))
	var got nativeStateX8
	var want [8][referenceMaxLanes]uint64
	for word := range got {
		for lane := range got[word] {
			value := rng.Uint64()
			got[word][lane] = value
			want[word][lane] = value
		}
	}
	stateBytes := (*[512]byte)(unsafe.Pointer(&got))
	var ptrs [nativeX8Width]*byte
	var blocks [referenceMaxLanes][128]byte
	var active [referenceMaxLanes]bool
	for lane := 0; lane < nativeX8Width; lane++ {
		active[lane] = true
		ptrs[lane] = &stateBytes[0]
		copy(blocks[lane][:], stateBytes[:128])
	}
	compressReference(&want, &blocks, &active, nativeX8Width)
	nativeTransposeCompressX8Rolling(&got, &ptrs, 0)
	for word := range got {
		for lane := range got[word] {
			if got[word][lane] != want[word][lane] {
				t.Fatalf("word=%d lane=%d: got=%016x want=%016x", word, lane, got[word][lane], want[word][lane])
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
		t.Skip("requires AVX-512F and AVX-512BW")
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
			t.Fatal("AVX-512F/BW availability changed during the test")
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

func TestExperimentalSum512Batch3UniformVerifierShapesX8(t *testing.T) {
	if !nativeX8Available() {
		t.Skip("requires AVX-512F and AVX-512BW")
	}
	rng := rand.New(rand.NewSource(0x512f13d))
	for _, messageSize := range []int{64, 200, 1232} {
		for _, count := range []int{nativeX8Width, 2 * nativeX8Width} {
			msgs := make([][3][]byte, count)
			for lane := range msgs {
				msgs[lane][0] = make([]byte, 32)
				msgs[lane][1] = make([]byte, 32)
				msgs[lane][2] = make([]byte, messageSize)
				for part := range msgs[lane] {
					_, _ = rng.Read(msgs[lane][part])
				}
			}
			out := make([][64]byte, count)
			if !ExperimentalSum512Batch3(out, msgs, nativeX8Width) {
				t.Fatal("AVX-512 availability changed during the test")
			}
			checkNativeDigests3(t, msgs, out)
		}
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

func TestNativeX8RandomizedDifferential(t *testing.T) {
	if !nativeX8Available() {
		t.Skip("requires AVX-512F and AVX-512BW")
	}
	rng := rand.New(rand.NewSource(57))
	for iteration := 0; iteration < 500; iteration++ {
		count := 1 + rng.Intn(17)
		msgs := make([][][]byte, count)
		for lane := range msgs {
			length := rng.Intn(4097)
			buf := make([]byte, length)
			_, _ = rng.Read(buf)
			msgs[lane] = splitNativeMessage(buf, rng, iteration+lane)
		}
		out := make([][64]byte, count)
		if !ExperimentalSum512Batch(out, msgs, nativeX8Width) {
			t.Fatal("AVX-512 availability changed during the test")
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
