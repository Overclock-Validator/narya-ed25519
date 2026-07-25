package sha512mb

import "encoding/binary"

// The native multi-buffer implementation is intentionally disconnected from
// the public Lanes and Sum512Batch dispatch. Its hardware-gated Experimental
// entry points are used by the explicitly forced r51 verifier and by direct
// tests/benchmarks; automatic backend selection never reaches them.

const (
	// ExperimentalWidthX4 selects the AVX2 four-stream prototype.
	ExperimentalWidthX4 = 4
	// ExperimentalWidthX8 selects the AVX-512F eight-stream prototype.
	ExperimentalWidthX8 = 8

	nativeX4Width = ExperimentalWidthX4
	nativeX8Width = ExperimentalWidthX8
)

var nativeInitialState = [8]uint64{
	0x6a09e667f3bcc908,
	0xbb67ae8584caa73b,
	0x3c6ef372fe94f82b,
	0xa54ff53a5f1d36f1,
	0x510e527fade682d1,
	0x9b05688c2b3e6c1f,
	0x1f83d9abfb41bd6b,
	0x5be0cd19137e2179,
}

// nativeRoundConstants is read directly by both native compression kernels.
// Keep it as a fixed array (rather than a slice) so the assembly symbol
// contains the words themselves and has no pointer indirection.
var nativeRoundConstants = [80]uint64{
	0x428a2f98d728ae22,
	0x7137449123ef65cd,
	0xb5c0fbcfec4d3b2f,
	0xe9b5dba58189dbbc,
	0x3956c25bf348b538,
	0x59f111f1b605d019,
	0x923f82a4af194f9b,
	0xab1c5ed5da6d8118,
	0xd807aa98a3030242,
	0x12835b0145706fbe,
	0x243185be4ee4b28c,
	0x550c7dc3d5ffb4e2,
	0x72be5d74f27b896f,
	0x80deb1fe3b1696b1,
	0x9bdc06a725c71235,
	0xc19bf174cf692694,
	0xe49b69c19ef14ad2,
	0xefbe4786384f25e3,
	0x0fc19dc68b8cd5b5,
	0x240ca1cc77ac9c65,
	0x2de92c6f592b0275,
	0x4a7484aa6ea6e483,
	0x5cb0a9dcbd41fbd4,
	0x76f988da831153b5,
	0x983e5152ee66dfab,
	0xa831c66d2db43210,
	0xb00327c898fb213f,
	0xbf597fc7beef0ee4,
	0xc6e00bf33da88fc2,
	0xd5a79147930aa725,
	0x06ca6351e003826f,
	0x142929670a0e6e70,
	0x27b70a8546d22ffc,
	0x2e1b21385c26c926,
	0x4d2c6dfc5ac42aed,
	0x53380d139d95b3df,
	0x650a73548baf63de,
	0x766a0abb3c77b2a8,
	0x81c2c92e47edaee6,
	0x92722c851482353b,
	0xa2bfe8a14cf10364,
	0xa81a664bbc423001,
	0xc24b8b70d0f89791,
	0xc76c51a30654be30,
	0xd192e819d6ef5218,
	0xd69906245565a910,
	0xf40e35855771202a,
	0x106aa07032bbd1b8,
	0x19a4c116b8d2d0c8,
	0x1e376c085141ab53,
	0x2748774cdf8eeb99,
	0x34b0bcb5e19b48a8,
	0x391c0cb3c5c95a63,
	0x4ed8aa4ae3418acb,
	0x5b9cca4f7763e373,
	0x682e6ff3d6b2b8a3,
	0x748f82ee5defb2fc,
	0x78a5636f43172f60,
	0x84c87814a1f0ab72,
	0x8cc702081a6439ec,
	0x90befffa23631e28,
	0xa4506cebde82bde9,
	0xbef9a3f7b2c67915,
	0xc67178f2e372532b,
	0xca273eceea26619c,
	0xd186b8c721c0c207,
	0xeada7dd6cde0eb1e,
	0xf57d4f7fee6ed178,
	0x06f067aa72176fba,
	0x0a637dc5a2c898a6,
	0x113f9804bef90dae,
	0x1b710b35131c471b,
	0x28db77f523047d84,
	0x32caab7b40c72493,
	0x3c9ebe0a15c9bebc,
	0x431d67c49c100d4c,
	0x4cc5d4becb3e42b6,
	0x597f299cfc657e2a,
	0x5fcb6fab3ad6faec,
	0x6c44198c4a475817,
}

type nativeStateX4 [8][nativeX4Width]uint64
type nativeBlockX4 [16][nativeX4Width]uint64
type nativeStateX8 [8][nativeX8Width]uint64
type nativeBlockX8 [16][nativeX8Width]uint64
type nativeTailX8 [2][nativeX8Width]uint64

type nativeLane struct {
	parts          [][]byte
	part           int
	offset         int
	totalBytes     uint64
	blocks         uint64
	paddingWritten bool
}

func newNativeLane(parts [][]byte) nativeLane {
	var total uint64
	for _, part := range parts {
		if uint64(len(part)) > ^uint64(0)-total {
			panic("sha512mb: native message length overflow")
		}
		total += uint64(len(part))
	}
	blocks := total/128 + 1
	if total%128 >= 112 {
		blocks++
	}
	return nativeLane{parts: parts, totalBytes: total, blocks: blocks}
}

func (lane *nativeLane) fill(block *[128]byte, blockIndex uint64) {
	position := 0
	for position < len(block) {
		for lane.part < len(lane.parts) && lane.offset == len(lane.parts[lane.part]) {
			lane.part++
			lane.offset = 0
		}
		if lane.part == len(lane.parts) {
			break
		}
		n := copy(block[position:], lane.parts[lane.part][lane.offset:])
		position += n
		lane.offset += n
	}
	if !lane.paddingWritten && lane.part == len(lane.parts) && position < len(block) {
		block[position] = 0x80
		lane.paddingWritten = true
	}
	if blockIndex+1 == lane.blocks {
		// SHA-512 appends a 128-bit bit length. Go slices make the input byte
		// count fit in uint64 on every supported architecture.
		binary.BigEndian.PutUint64(block[112:120], lane.totalBytes>>61)
		binary.BigEndian.PutUint64(block[120:128], lane.totalBytes<<3)
	}
}

// takeDirectBlock returns the next complete 128-byte block when it lies in one
// contiguous input segment. Segment crossings and final padding blocks stay on
// fill, which is the exact segmented-hash reference path.
func (lane *nativeLane) takeDirectBlock() (*byte, bool) {
	for lane.part < len(lane.parts) && lane.offset == len(lane.parts[lane.part]) {
		lane.part++
		lane.offset = 0
	}
	if lane.part == len(lane.parts) || len(lane.parts[lane.part])-lane.offset < 128 {
		return nil, false
	}
	ptr := &lane.parts[lane.part][lane.offset]
	lane.offset += 128
	return ptr, true
}

// sum512x4Native hashes arbitrary batches in independent groups of four. It
// returns false, without touching out, when the AVX2 kernel is unavailable.
// Production dispatch does not call this function.
func sum512x4Native(out [][64]byte, msgs [][][]byte) bool {
	if len(out) != len(msgs) {
		panic("sha512mb: native out/msgs length mismatch")
	}
	if !nativeX4Available() {
		return false
	}
	for first := 0; first < len(msgs); first += nativeX4Width {
		lanes := len(msgs) - first
		if lanes > nativeX4Width {
			lanes = nativeX4Width
		}
		sum512NativeGroupX4(out[first:first+lanes], msgs[first:first+lanes], lanes)
	}
	return true
}

// ExperimentalNativeAvailable reports whether width selects a native kernel
// that is safe to execute on this machine. Availability never changes the
// public Lanes or Sum512Batch behavior and never enables a verifier backend
// automatically.
func ExperimentalNativeAvailable(width int) bool {
	switch width {
	case nativeX4Width:
		return nativeX4Available()
	case nativeX8Width:
		return nativeX8Available()
	default:
		return false
	}
}

// ExperimentalSum512Batch explicitly forces a hardware-gated multi-buffer
// SHA-512 experiment. width must be 4 or 8. The call returns false and leaves
// out untouched when that kernel is unavailable. len(out) must equal
// len(msgs), even for an unavailable kernel. General callers should use
// Sum512Batch; the forced r51 backend is the reviewed internal consumer of
// this explicit-width surface.
func ExperimentalSum512Batch(out [][64]byte, msgs [][][]byte, width int) bool {
	if len(out) != len(msgs) {
		panic("sha512mb: experimental out/msgs length mismatch")
	}
	switch width {
	case nativeX4Width:
		return sum512x4Native(out, msgs)
	case nativeX8Width:
		return sum512x8Native(out, msgs)
	default:
		return false
	}
}

// ExperimentalSum512Batch3 is the fixed-three-segment counterpart of
// ExperimentalSum512Batch. It computes SHA-512 over
//
//	msgs[i][0] ‖ msgs[i][1] ‖ msgs[i][2]
//
// for every row. Accepting a slice of three-element arrays lets verifier
// callers pass their fixed R/A/message descriptors directly, without building
// a second [][][]byte view whose row slices point back into the descriptor
// array. The function does not retain msgs or any segment backing array after
// it returns.
//
// width must be 4 or 8. The call returns false and leaves out untouched when
// that kernel is unavailable. len(out) must equal len(msgs), even for an
// unavailable or unsupported kernel. General callers should continue to use
// Sum512Batch; the forced r51 backend is the reviewed internal consumer of
// this fixed-three-segment surface.
func ExperimentalSum512Batch3(out [][64]byte, msgs [][3][]byte, width int) bool {
	if len(out) != len(msgs) {
		panic("sha512mb: experimental fixed3 out/msgs length mismatch")
	}
	switch width {
	case nativeX4Width:
		return sum512x4Native3(out, msgs)
	case nativeX8Width:
		return sum512x8Native3(out, msgs)
	default:
		return false
	}
}

func sum512x4Native3(out [][64]byte, msgs [][3][]byte) bool {
	if len(out) != len(msgs) {
		panic("sha512mb: native fixed3 out/msgs length mismatch")
	}
	if !nativeX4Available() {
		return false
	}
	for first := 0; first < len(msgs); first += nativeX4Width {
		lanes := len(msgs) - first
		if lanes > nativeX4Width {
			lanes = nativeX4Width
		}
		sum512NativeGroup3X4(out[first:first+lanes], msgs[first:first+lanes], lanes)
	}
	return true
}

func sum512x8Native(out [][64]byte, msgs [][][]byte) bool {
	if len(out) != len(msgs) {
		panic("sha512mb: native out/msgs length mismatch")
	}
	if !nativeX8Available() {
		return false
	}
	for first := 0; first < len(msgs); first += nativeX8Width {
		lanes := len(msgs) - first
		if lanes > nativeX8Width {
			lanes = nativeX8Width
		}
		sum512NativeGroupX8(out[first:first+lanes], msgs[first:first+lanes], lanes)
	}
	return true
}

func sum512x8Native3(out [][64]byte, msgs [][3][]byte) bool {
	if len(out) != len(msgs) {
		panic("sha512mb: native fixed3 out/msgs length mismatch")
	}
	if !nativeX8Available() {
		return false
	}
	for first := 0; first < len(msgs); first += nativeX8Width {
		lanes := len(msgs) - first
		if lanes > nativeX8Width {
			lanes = nativeX8Width
		}
		sum512NativeGroup3X8(out[first:first+lanes], msgs[first:first+lanes], lanes)
	}
	return true
}

func sum512NativeGroupX4(out [][64]byte, msgs [][][]byte, lanes int) {
	var lane [nativeX4Width]nativeLane
	var maxBlocks uint64
	for i := 0; i < nativeX4Width; i++ {
		if i < lanes {
			lane[i] = newNativeLane(msgs[i])
			if lane[i].blocks > maxBlocks {
				maxBlocks = lane[i].blocks
			}
		}
	}
	sum512NativeLanesX4(out, &lane, lanes, maxBlocks)
}

func sum512NativeGroup3X4(out [][64]byte, msgs [][3][]byte, lanes int) {
	var lane [nativeX4Width]nativeLane
	var maxBlocks uint64
	for i := 0; i < nativeX4Width; i++ {
		if i < lanes {
			lane[i] = newNativeLane(msgs[i][:])
			if lane[i].blocks > maxBlocks {
				maxBlocks = lane[i].blocks
			}
		}
	}
	sum512NativeLanesX4(out, &lane, lanes, maxBlocks)
}

func sum512NativeLanesX4(out [][64]byte, lane *[nativeX4Width]nativeLane, lanes int, maxBlocks uint64) {
	var state nativeStateX4
	for i := 0; i < nativeX4Width; i++ {
		for word := range nativeInitialState {
			state[word][i] = nativeInitialState[word]
		}
	}
	var raw [nativeX4Width][128]byte
	var block nativeBlockX4
	for blockIndex := uint64(0); blockIndex < maxBlocks; blockIndex++ {
		raw = [nativeX4Width][128]byte{}
		for i := 0; i < lanes; i++ {
			if blockIndex < lane[i].blocks {
				lane[i].fill(&raw[i], blockIndex)
			}
		}
		for word := 0; word < 16; word++ {
			for i := 0; i < nativeX4Width; i++ {
				block[word][i] = binary.BigEndian.Uint64(raw[i][word*8:])
			}
		}

		nativeCompressX4(&state, &block)
		for i := 0; i < lanes; i++ {
			if blockIndex+1 != lane[i].blocks {
				continue
			}
			for word := range nativeInitialState {
				binary.BigEndian.PutUint64(out[i][word*8:], state[word][i])
			}
		}
	}
}

func sum512NativeGroupX8(out [][64]byte, msgs [][][]byte, lanes int) {
	var lane [nativeX8Width]nativeLane
	var maxBlocks uint64
	for i := 0; i < nativeX8Width; i++ {
		if i < lanes {
			lane[i] = newNativeLane(msgs[i])
			if lane[i].blocks > maxBlocks {
				maxBlocks = lane[i].blocks
			}
		}
	}
	sum512NativeLanesX8(out, &lane, lanes, maxBlocks)
}

func sum512NativeGroup3X8(out [][64]byte, msgs [][3][]byte, lanes int) {
	if lanes == nativeX8Width && sum512NativeFixed3X8(out, msgs) {
		return
	}
	var lane [nativeX8Width]nativeLane
	var maxBlocks uint64
	for i := 0; i < nativeX8Width; i++ {
		if i < lanes {
			lane[i] = newNativeLane(msgs[i][:])
			if lane[i].blocks > maxBlocks {
				maxBlocks = lane[i].blocks
			}
		}
	}
	sum512NativeLanesX8(out, &lane, lanes, maxBlocks)
}

// sum512NativeFixed3X8 recognizes the equal-width verifier shapes that are
// important to sigverify: R and A are each 32 bytes, followed by a message of
// 64, 200, or 1232 bytes. In those shapes the first block always consists of
// R || A || message[:64], every middle block is a direct slice of message,
// and the final block contains only 0, 8, or 16 variable bytes. Building the
// latter directly in transposed word form avoids eight 128-byte padding
// buffers, their pointer scan, and a full 8x8 input transpose.
//
// The generic segmented implementation remains the fallback and differential
// oracle for every other shape and for partial x8 groups.
func sum512NativeFixed3X8(out [][64]byte, msgs [][3][]byte) bool {
	if len(out) != nativeX8Width || len(msgs) != nativeX8Width {
		return false
	}
	messageSize := len(msgs[0][2])
	switch messageSize {
	case 64, 200, 1232:
	default:
		return false
	}
	for lane := range msgs {
		if len(msgs[lane][0]) != 32 || len(msgs[lane][1]) != 32 || len(msgs[lane][2]) != messageSize {
			return false
		}
	}

	var state nativeStateX8
	var first [nativeX8Width][128]byte
	var ptrs [nativeX8Width]*byte
	for lane := range msgs {
		copy(first[lane][0:32], msgs[lane][0])
		copy(first[lane][32:64], msgs[lane][1])
		copy(first[lane][64:128], msgs[lane][2][:64])
		ptrs[lane] = &first[lane][0]
	}
	nativeTransposeCompressX8Rolling(&state, &ptrs, 1)

	middleBlocks := (messageSize - 64) / 128
	for block := 0; block < middleBlocks; block++ {
		offset := 64 + block*128
		for lane := range msgs {
			ptrs[lane] = &msgs[lane][2][offset]
		}
		nativeTransposeCompressX8Rolling(&state, &ptrs, 0)
	}

	tailBytes := (messageSize - 64) % 128
	var tail nativeTailX8
	for lane := range msgs {
		offset := messageSize - tailBytes
		if tailBytes >= 8 {
			tail[0][lane] = binary.BigEndian.Uint64(msgs[lane][2][offset:])
		}
		if tailBytes == 16 {
			tail[1][lane] = binary.BigEndian.Uint64(msgs[lane][2][offset+8:])
		}
	}
	nativeCompressFinalX8Rolling(&state, &tail, uint64(tailBytes/8), uint64(64+messageSize)*8)

	for lane := range out {
		for word := range nativeInitialState {
			binary.BigEndian.PutUint64(out[lane][word*8:], state[word][lane])
		}
	}
	return true
}

func sum512NativeLanesX8(out [][64]byte, lane *[nativeX8Width]nativeLane, lanes int, maxBlocks uint64) {
	var state nativeStateX8
	var raw [nativeX8Width][128]byte
	var zero [128]byte
	var ptrs [nativeX8Width]*byte
	for blockIndex := uint64(0); blockIndex < maxBlocks; blockIndex++ {
		for i := 0; i < nativeX8Width; i++ {
			ptrs[i] = &zero[0]
			if i < lanes && blockIndex < lane[i].blocks {
				if direct, ok := lane[i].takeDirectBlock(); ok {
					ptrs[i] = direct
					continue
				}
				raw[i] = [128]byte{}
				lane[i].fill(&raw[i], blockIndex)
				ptrs[i] = &raw[i][0]
			}
		}
		initial := uint64(0)
		if blockIndex == 0 {
			initial = 1
		}
		nativeTransposeCompressX8Rolling(&state, &ptrs, initial)
		for i := 0; i < lanes; i++ {
			if blockIndex+1 != lane[i].blocks {
				continue
			}
			for word := range nativeInitialState {
				binary.BigEndian.PutUint64(out[i][word*8:], state[word][i])
			}
		}
	}
}
