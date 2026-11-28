package keccakmb

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/bits"
)

// Variant selects a Keccak sponge: its rate in bytes and its domain
// separation byte, which pad10*1 merges with the first padding bit.
type Variant struct {
	rate int
	ds   byte
}

var (
	// Keccak256 is the legacy pre-FIPS Keccak-256 (Ethereum, sol_keccak256,
	// the secp256k1 precompile). Its padding byte is 0x01.
	Keccak256 = Variant{rate: 136, ds: 0x01}
	// SHA3_256 is FIPS 202 SHA3-256.
	SHA3_256 = Variant{rate: 136, ds: 0x06}
	// SHAKE128 is the FIPS 202 extendable-output function SHAKE128.
	SHAKE128 = Variant{rate: 168, ds: 0x1f}
	// SHAKE256 is the FIPS 202 extendable-output function SHAKE256, used by
	// Falcon (FN-DSA) hash-to-point.
	SHAKE256 = Variant{rate: 136, ds: 0x1f}
)

// Rate reports the sponge rate in bytes: the size of each absorbed and
// squeezed block.
func (v Variant) Rate() int { return v.rate }

func (v Variant) check() {
	if v.rate <= 0 || v.rate >= 200 || v.rate%8 != 0 || v.ds == 0 {
		panic(fmt.Sprintf("keccakmb: invalid variant rate=%d ds=%#x", v.rate, v.ds))
	}
}

// Sum writes the first len(out) output bytes of v over
// parts[0] || parts[1] || ... to out, using the scalar reference sponge.
// out may share storage with the parts: every input byte is read before out
// is written.
func Sum(v Variant, out []byte, parts ...[]byte) {
	v.check()
	var a [25]uint64
	lane := newLane(parts, v.rate)
	var block [200]byte
	for b := 0; b < lane.blocks; b++ {
		lane.next(block[:v.rate], b+1 == lane.blocks, v.ds)
		for w := 0; w < v.rate/8; w++ {
			a[w] ^= binary.LittleEndian.Uint64(block[8*w:])
		}
		permute1(&a)
	}
	for len(out) > 0 {
		for w := 0; w < v.rate/8; w++ {
			binary.LittleEndian.PutUint64(block[8*w:], a[w])
		}
		n := copy(out, block[:v.rate])
		out = out[n:]
		if len(out) > 0 {
			permute1(&a)
		}
	}
}

// SumBatch computes v for every message, where message i is the
// concatenation of msgs[i] and out[i] receives the first len(out[i]) output
// bytes. It is the portable scalar loop and never dispatches.
//
// out[i] may share storage with msgs[i] (in-place hashing), but must not
// overlap any msgs[k] with k != i. Batch entry points read and write lanes in
// different orders, so cross-lane overlap would make the result depend on
// the path taken; it is not supported, and its result is unspecified.
func SumBatch(v Variant, out [][]byte, msgs [][][]byte) {
	if len(out) != len(msgs) {
		panic("keccakmb: out/msgs length mismatch")
	}
	for i := range msgs {
		Sum(v, out[i], msgs[i]...)
	}
}

// ExperimentalSumBatch is SumBatch through the AVX-512 eight-lane
// permutation, with the same overlap rule. Messages are hashed in
// independent groups of eight. It returns false, leaving out untouched, when
// the kernel is unavailable.
func ExperimentalSumBatch(v Variant, out [][]byte, msgs [][][]byte) bool {
	if len(out) != len(msgs) {
		panic("keccakmb: out/msgs length mismatch")
	}
	v.check()
	if !nativeX8Available() {
		return false
	}
	for first := 0; first < len(msgs); first += Lanes {
		last := min(first+Lanes, len(msgs))
		var x SpongeX8
		x.absorbAuto(v, msgs[first:last])
		x.squeezeInto(out[first:last])
	}
	return true
}

// SpongeX8 runs up to eight sponges of one variant side by side. After
// Absorb, every lane is in its squeezing phase, so the lanes advance in
// lockstep: each SqueezeBlock produces one rate-sized block per lane. That
// matches Falcon hash-to-point, where the caller rejection-samples each
// lane's stream and keeps squeezing while any lane needs more coefficients.
type SpongeX8 struct {
	s      StateX8
	v      Variant
	lanes  int
	fresh  bool // the next squeezed block needs no permutation
	native bool // permute and squeeze through the AVX-512 kernels
}

// permuteState permutes x.s with direct calls only, so the state does not
// escape to the heap through a function value.
func (x *SpongeX8) permuteState() {
	if x.native {
		permuteX8Native(&x.s)
	} else {
		permuteX8Generic(&x.s)
	}
}

// ExperimentalNewSpongeX8 absorbs up to eight messages, each the
// concatenation of its parts, with the AVX-512 kernel. It returns false when
// the kernel is unavailable.
func ExperimentalNewSpongeX8(x *SpongeX8, v Variant, msgs [][][]byte) bool {
	v.check()
	if !nativeX8Available() {
		return false
	}
	x.absorbAuto(v, msgs)
	return true
}

// NewSpongeX8Generic is ExperimentalNewSpongeX8 with the portable reference
// permutation. It never dispatches.
func NewSpongeX8Generic(x *SpongeX8, v Variant, msgs [][][]byte) {
	v.check()
	x.absorb(v, msgs, false)
}

// Lanes reports how many messages x absorbed.
func (x *SpongeX8) Lanes() int { return x.lanes }

// SqueezeBlock writes the next v.Rate() output bytes of every lane to
// out[j][:v.Rate()] for j < x.Lanes(). It does not write out[j] for
// j >= x.Lanes(), nor out[j][v.Rate():].
func (x *SpongeX8) SqueezeBlock(out *[Lanes][200]byte) {
	if x.native {
		permute := 1
		if x.fresh {
			permute = 0
		}
		x.fresh = false
		squeezeX8Native(&x.s, out, x.v.rate/8, permute, 1<<x.lanes-1)
		return
	}
	if !x.fresh {
		x.permuteState()
	}
	x.fresh = false
	for j := 0; j < x.lanes; j++ {
		for w := 0; w < x.v.rate/8; w++ {
			binary.LittleEndian.PutUint64(out[j][8*w:], x.s[w][j])
		}
	}
}

func (x *SpongeX8) absorb(v Variant, msgs [][][]byte, native bool) {
	if len(msgs) > Lanes {
		panic("keccakmb: more than eight messages in one SpongeX8")
	}
	*x = SpongeX8{v: v, lanes: len(msgs), fresh: true, native: native}
	var lanes [Lanes]laneReader
	maxBlocks := 0
	for j := range msgs {
		lanes[j] = newLane(msgs[j], v.rate)
		maxBlocks = max(maxBlocks, lanes[j].blocks)
	}
	// A lane that has absorbed its final block must not be permuted again.
	// Its state is saved after that block, the group keeps permuting for the
	// longer lanes, and the saved states are restored at the end.
	var saved [Lanes][25]uint64
	var block [200]byte
	words := v.rate / 8
	for b := 0; b < maxBlocks; b++ {
		for j := 0; j < x.lanes; j++ {
			if b >= lanes[j].blocks {
				continue
			}
			lanes[j].next(block[:v.rate], b+1 == lanes[j].blocks, v.ds)
			for w := 0; w < words; w++ {
				x.s[w][j] ^= binary.LittleEndian.Uint64(block[8*w:])
			}
		}
		x.permuteState()
		for j := 0; j < x.lanes; j++ {
			if b+1 == lanes[j].blocks && lanes[j].blocks != maxBlocks {
				for i := 0; i < 25; i++ {
					saved[j][i] = x.s[i][j]
				}
			}
		}
	}
	for j := 0; j < x.lanes; j++ {
		if lanes[j].blocks != maxBlocks {
			for i := 0; i < 25; i++ {
				x.s[i][j] = saved[j][i]
			}
		}
	}
}

func (x *SpongeX8) squeezeInto(out [][]byte) {
	maxLen := 0
	for j := range out {
		maxLen = max(maxLen, len(out[j]))
	}
	if x.fresh && maxLen <= x.v.rate {
		// Digests fit in the first block, which is the state as absorbed:
		// copy just the words each lane needs.
		x.fresh = false
		var word [8]byte
		for j := range out {
			for o := 0; o < len(out[j]); o += 8 {
				binary.LittleEndian.PutUint64(word[:], x.s[o/8][j])
				copy(out[j][o:], word[:])
			}
		}
		return
	}
	var block [Lanes][200]byte
	for done := 0; done < maxLen; done += x.v.rate {
		x.SqueezeBlock(&block)
		for j := range out {
			if done < len(out[j]) {
				copy(out[j][done:], block[j][:x.v.rate])
			}
		}
	}
}

// laneReader streams one message, given as parts, in rate-sized blocks and
// applies pad10*1 with the variant's domain byte to the final block.
type laneReader struct {
	parts  [][]byte
	part   int
	offset int
	blocks int // total blocks, including the padded final block
	taken  int // blocks consumed so far
}

func newLane(parts [][]byte, rate int) laneReader {
	return laneReader{parts: parts, blocks: blockCount(parts, rate)}
}

// messageLen returns the total length of parts, panicking rather than
// wrapping if it does not fit in a uint64. Parts may alias one buffer, so on
// 32-bit Go the total can exceed the int range without a matching
// allocation; summing into an int there could wrap negative and skip
// absorption entirely.
func messageLen(parts [][]byte) uint64 {
	var total, carry uint64
	for _, p := range parts {
		total, carry = bits.Add64(total, uint64(len(p)), 0)
		if carry != 0 {
			panic("keccakmb: message too long")
		}
	}
	return total
}

// blockCount returns the number of rate-sized blocks a message occupies
// after padding. pad10*1 always adds at least one byte (the domain byte and
// the final 0x80 share a byte when one byte of the block is left), so a
// message takes total/rate + 1 blocks. It panics if that count does not fit
// in an int, rather than letting it wrap.
func blockCount(parts [][]byte, rate int) int {
	blocks := messageLen(parts)/uint64(rate) + 1
	if blocks > math.MaxInt {
		panic("keccakmb: message too long")
	}
	return int(blocks)
}

func (l *laneReader) next(block []byte, last bool, ds byte) {
	l.taken++
	clear(block)
	n := 0
	for n < len(block) && l.part < len(l.parts) {
		c := copy(block[n:], l.parts[l.part][l.offset:])
		n += c
		l.offset += c
		if l.offset == len(l.parts[l.part]) {
			l.part++
			l.offset = 0
		}
	}
	if last {
		block[n] ^= ds
		block[len(block)-1] ^= 0x80
	}
}

// directBlocks reports how many of the lane's next blocks are complete and
// contiguous in the current part, excluding the padded final block, so the
// kernel can read them in place.
func (l *laneReader) directBlocks(rate int) int {
	for l.part < len(l.parts) && l.offset == len(l.parts[l.part]) {
		l.part++
		l.offset = 0
	}
	if l.part == len(l.parts) {
		return 0
	}
	return min((len(l.parts[l.part])-l.offset)/rate, l.blocks-1-l.taken)
}

// absorbAuto absorbs with the native kernels. When every message is a
// single padded block, which must be staged anyway, the Go XOR loop plus the
// permutation kernel measured faster on Zen 4 (about 610 ns against 700 ns
// for eight 64-byte messages) than staging and gathering, so that case
// skips absorbNative entirely.
func (x *SpongeX8) absorbAuto(v Variant, msgs [][][]byte) {
	single := true
	for _, parts := range msgs {
		if messageLen(parts) >= uint64(v.rate) {
			single = false
			break
		}
	}
	if single {
		x.absorb(v, msgs, true)
		return
	}
	x.absorbNative(v, msgs)
}

// zeroBlock is absorbed by lanes that are absent or already finished, whose
// states are discarded or restored afterwards.
var zeroBlock [200]byte

// absorbNative is absorb through the fused AVX-512 kernel. Each kernel call
// covers k blocks during which every active lane reads complete blocks in
// place from one contiguous segment. A lane whose next block crosses a
// segment boundary or is its padded final block is staged into a buffer, and
// that call covers one block.
func (x *SpongeX8) absorbNative(v Variant, msgs [][][]byte) {
	if len(msgs) > Lanes {
		panic("keccakmb: more than eight messages in one SpongeX8")
	}
	*x = SpongeX8{v: v, lanes: len(msgs), fresh: true, native: true}
	words := v.rate / 8
	if words != 17 && words != 21 {
		panic("keccakmb: native absorb supports rates 136 and 168")
	}
	var lanes [Lanes]laneReader
	maxBlocks := 0
	for j := range msgs {
		lanes[j] = newLane(msgs[j], v.rate)
		maxBlocks = max(maxBlocks, lanes[j].blocks)
	}
	var (
		saved   [Lanes][25]uint64
		stage   [Lanes][200]byte
		ptrs    [Lanes]*byte
		strides [Lanes]uint64
		direct  [Lanes]int
	)
	for b := 0; b < maxBlocks; {
		k := maxBlocks - b
		staged := false
		for j := 0; j < Lanes; j++ {
			direct[j] = -1 // inactive
			if j >= x.lanes || lanes[j].taken == lanes[j].blocks {
				continue
			}
			direct[j] = lanes[j].directBlocks(v.rate)
			if direct[j] == 0 {
				staged = true
			} else {
				k = min(k, direct[j])
			}
		}
		if staged {
			k = 1
		}
		for j := 0; j < Lanes; j++ {
			switch {
			case direct[j] < 0:
				ptrs[j], strides[j] = &zeroBlock[0], 0
			case direct[j] == 0:
				l := &lanes[j]
				l.next(stage[j][:v.rate], l.taken+1 == l.blocks, v.ds)
				ptrs[j], strides[j] = &stage[j][0], 0
			default:
				l := &lanes[j]
				ptrs[j], strides[j] = &l.parts[l.part][l.offset], uint64(v.rate)
				l.offset += k * v.rate
				l.taken += k
			}
		}
		absorbX8Native(&x.s, &ptrs, &strides, words, k)
		b += k
		for j := 0; j < x.lanes; j++ {
			// Final blocks are always staged, so a lane can only finish on a
			// one-block call.
			if direct[j] == 0 && lanes[j].taken == lanes[j].blocks && lanes[j].blocks != maxBlocks {
				for i := 0; i < 25; i++ {
					saved[j][i] = x.s[i][j]
				}
			}
		}
	}
	for j := 0; j < x.lanes; j++ {
		if lanes[j].blocks != maxBlocks {
			for i := 0; i < 25; i++ {
				x.s[i][j] = saved[j][i]
			}
		}
	}
}
