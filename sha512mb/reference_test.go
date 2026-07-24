package sha512mb

import (
	"encoding/binary"
	"math/bits"
)

// This file is a correctness and scheduling reference compiled only into
// package tests and benchmarks. It deliberately does not affect Lanes or the
// production Sum512Batch dispatch.

const referenceMaxLanes = 8

var referenceInitialState = [8]uint64{
	0x6a09e667f3bcc908,
	0xbb67ae8584caa73b,
	0x3c6ef372fe94f82b,
	0xa54ff53a5f1d36f1,
	0x510e527fade682d1,
	0x9b05688c2b3e6c1f,
	0x1f83d9abfb41bd6b,
	0x5be0cd19137e2179,
}

var referenceRoundConstants = [80]uint64{
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

type referenceLane struct {
	parts          [][]byte
	part           int
	offset         int
	totalBytes     uint64
	blocks         uint64
	paddingWritten bool
}

func newReferenceLane(parts [][]byte) referenceLane {
	var total uint64
	for _, part := range parts {
		if uint64(len(part)) > ^uint64(0)-total {
			panic("sha512mb: reference message length overflow")
		}
		total += uint64(len(part))
	}
	blocks := total/128 + 1
	if total%128 >= 112 {
		blocks++
	}
	return referenceLane{parts: parts, totalBytes: total, blocks: blocks}
}

func (l *referenceLane) fill(block *[128]byte, blockIndex uint64) {
	pos := 0
	for pos < len(block) {
		for l.part < len(l.parts) && l.offset == len(l.parts[l.part]) {
			l.part++
			l.offset = 0
		}
		if l.part == len(l.parts) {
			break
		}
		n := copy(block[pos:], l.parts[l.part][l.offset:])
		pos += n
		l.offset += n
	}
	if !l.paddingWritten && l.part == len(l.parts) && pos < len(block) {
		block[pos] = 0x80
		l.paddingWritten = true
	}
	if blockIndex+1 == l.blocks {
		// SHA-512 appends a 128-bit bit length. A Go segmented message is
		// bounded by uint64 bytes here, so the high word is total>>61.
		binary.BigEndian.PutUint64(block[112:120], l.totalBytes>>61)
		binary.BigEndian.PutUint64(block[120:128], l.totalBytes<<3)
	}
}

func sum512x4Reference(out [][64]byte, msgs [][][]byte) {
	sum512MultiReference(out, msgs, 4)
}

func sum512x8Reference(out [][64]byte, msgs [][][]byte) {
	sum512MultiReference(out, msgs, 8)
}

func sum512MultiReference(out [][64]byte, msgs [][][]byte, width int) {
	if len(out) != len(msgs) {
		panic("sha512mb: reference out/msgs length mismatch")
	}
	if width != 1 && width != 4 && width != 8 {
		panic("sha512mb: unsupported reference width")
	}
	for first := 0; first < len(msgs); first += width {
		lanes := width
		if remaining := len(msgs) - first; remaining < lanes {
			lanes = remaining
		}
		sum512ReferenceGroup(out[first:first+lanes], msgs[first:first+lanes], lanes)
	}
}

func sum512ReferenceGroup(out [][64]byte, msgs [][][]byte, lanes int) {
	var lane [referenceMaxLanes]referenceLane
	var state [8][referenceMaxLanes]uint64
	var maxBlocks uint64
	for i := 0; i < lanes; i++ {
		lane[i] = newReferenceLane(msgs[i])
		if lane[i].blocks > maxBlocks {
			maxBlocks = lane[i].blocks
		}
		for word := range referenceInitialState {
			state[word][i] = referenceInitialState[word]
		}
	}

	for blockIndex := uint64(0); blockIndex < maxBlocks; blockIndex++ {
		var blocks [referenceMaxLanes][128]byte
		var active [referenceMaxLanes]bool
		for i := 0; i < lanes; i++ {
			if blockIndex < lane[i].blocks {
				active[i] = true
				lane[i].fill(&blocks[i], blockIndex)
			}
		}
		compressReference(&state, &blocks, &active, lanes)
	}

	for i := 0; i < lanes; i++ {
		for word := 0; word < 8; word++ {
			binary.BigEndian.PutUint64(out[i][word*8:], state[word][i])
		}
	}
}

func compressReference(state *[8][referenceMaxLanes]uint64, blocks *[referenceMaxLanes][128]byte, active *[referenceMaxLanes]bool, lanes int) {
	var schedule [80][referenceMaxLanes]uint64
	for lane := 0; lane < lanes; lane++ {
		if !active[lane] {
			continue
		}
		for round := 0; round < 16; round++ {
			schedule[round][lane] = binary.BigEndian.Uint64(blocks[lane][round*8:])
		}
	}
	for round := 16; round < 80; round++ {
		for lane := 0; lane < lanes; lane++ {
			if !active[lane] {
				continue
			}
			v1 := schedule[round-2][lane]
			sigma1 := bits.RotateLeft64(v1, -19) ^ bits.RotateLeft64(v1, -61) ^ v1>>6
			v2 := schedule[round-15][lane]
			sigma0 := bits.RotateLeft64(v2, -1) ^ bits.RotateLeft64(v2, -8) ^ v2>>7
			schedule[round][lane] = sigma1 + schedule[round-7][lane] + sigma0 + schedule[round-16][lane]
		}
	}

	var a, b, c, d, e, f, g, h [referenceMaxLanes]uint64
	for lane := 0; lane < lanes; lane++ {
		if !active[lane] {
			continue
		}
		a[lane], b[lane], c[lane], d[lane] = state[0][lane], state[1][lane], state[2][lane], state[3][lane]
		e[lane], f[lane], g[lane], h[lane] = state[4][lane], state[5][lane], state[6][lane], state[7][lane]
	}
	for round := 0; round < 80; round++ {
		for lane := 0; lane < lanes; lane++ {
			if !active[lane] {
				continue
			}
			bigSigma1 := bits.RotateLeft64(e[lane], -14) ^ bits.RotateLeft64(e[lane], -18) ^ bits.RotateLeft64(e[lane], -41)
			choice := e[lane]&f[lane] ^ ^e[lane]&g[lane]
			t1 := h[lane] + bigSigma1 + choice + referenceRoundConstants[round] + schedule[round][lane]
			bigSigma0 := bits.RotateLeft64(a[lane], -28) ^ bits.RotateLeft64(a[lane], -34) ^ bits.RotateLeft64(a[lane], -39)
			majority := a[lane]&b[lane] ^ a[lane]&c[lane] ^ b[lane]&c[lane]
			t2 := bigSigma0 + majority

			h[lane] = g[lane]
			g[lane] = f[lane]
			f[lane] = e[lane]
			e[lane] = d[lane] + t1
			d[lane] = c[lane]
			c[lane] = b[lane]
			b[lane] = a[lane]
			a[lane] = t1 + t2
		}
	}
	for lane := 0; lane < lanes; lane++ {
		if !active[lane] {
			continue
		}
		state[0][lane] += a[lane]
		state[1][lane] += b[lane]
		state[2][lane] += c[lane]
		state[3][lane] += d[lane]
		state[4][lane] += e[lane]
		state[5][lane] += f[lane]
		state[6][lane] += g[lane]
		state[7][lane] += h[lane]
	}
}
