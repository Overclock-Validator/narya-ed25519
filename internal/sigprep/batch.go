package sigprep

import (
	"github.com/Overclock-Validator/narya-ed25519/sha512mb"
)

// Batch is reusable scratch for preparing many signatures at once. It is
// worker-local: one Batch per goroutine, reset and refilled per group, so a hot
// loop allocates nothing after the first group of a given size.
//
// Results are index-aligned with the input slices rather than compacted. A
// caller can therefore map a verdict straight back to its signature with no
// bookkeeping, which is what makes per-item attribution survive batching. The
// compaction that the multi-buffer hash needs happens internally and is not
// visible at this boundary.
type Batch struct {
	prepared []Prepared
	live     []bool

	// Hash scratch, compacted to live items only. A dead item must not occupy
	// a hash lane: lanes are the scarce resource the multi-buffer kernel
	// parallelizes over, and hashing a signature already known to be rejected
	// spends one for nothing.
	//
	// segmentStore owns the three-segment arrays and segments holds slice
	// headers into it. Building the array as a local and slicing it instead
	// would move it to the heap once per signature, which is exactly the cost
	// worker-local scratch exists to avoid. It is sized before the fill loop so
	// no growth can invalidate a header already handed out.
	segmentStore [][3][]byte
	segments     [][][]byte
	digests      [][64]byte
	lanes        []int

	// filled is how many segmentStore entries the previous Prepare wrote, so
	// Reset can release exactly those message references and no more.
	filled int

	reducer Reducer
}

// Reset prepares the batch to hold n signatures, reusing existing capacity.
func (b *Batch) Reset(n int) {
	// The segment store holds slice headers into the caller's messages. A
	// worker-local Batch outlives the group it prepared, so leaving them in
	// place would pin every message of the previous group until some later
	// group happened to overwrite the entry. Clearing exactly the prefix that
	// was written bounds that without memsetting the whole capacity.
	clear(b.segmentStore[:b.filled])
	b.filled = 0

	b.prepared = resize(b.prepared, n)
	b.live = resize(b.live, n)
	clear(b.prepared)
	clear(b.live)
	b.segments = b.segments[:0]
	b.digests = b.digests[:0]
	b.lanes = b.lanes[:0]
}

func resize[T any](s []T, n int) []T {
	if cap(s) >= n {
		return s[:n]
	}
	return make([]T, n)
}

// Prepare runs the byte-level gates over every input, hashes the survivors in
// one multi-buffer round, and reduces each challenge. It returns the number of
// live items.
//
// The slices must all have the same length; callers that accept untrusted
// lengths should check before calling. Gating before hashing is the point of
// the two-pass shape: a group where most signatures are rejected on bytes alone
// costs one pass over the bytes, not a hash per item.
func (b *Batch) Prepare(rules Rules, pubs []*[32]byte, msgs, sigs [][]byte) int {
	n := len(pubs)
	b.Reset(n)
	b.segmentStore = resize(b.segmentStore, n)

	count := 0
	for i := 0; i < n; i++ {
		prepared, ok := Parse(rules, pubs[i], sigs[i])
		if !ok {
			continue
		}
		b.prepared[i] = prepared
		b.live[i] = true
		b.segmentStore[count] = ChallengeSegments(pubs[i], msgs[i], sigs[i])
		b.segments = append(b.segments, b.segmentStore[count][:])
		b.lanes = append(b.lanes, i)
		count++
	}
	b.filled = count

	if count == 0 {
		return 0
	}

	b.digests = resize(b.digests, count)
	sha512mb.Sum512Batch(b.digests, b.segments)

	for compact, index := range b.lanes {
		b.reducer.Reduce(&b.digests[compact], &b.prepared[index].K)
	}
	return count
}

// Live reports whether item i passed the byte-level gates. A false verdict here
// is final: the equation is never evaluated for that item.
func (b *Batch) Live(i int) bool { return b.live[i] }

// At returns the prepared form of item i. It is only meaningful when Live(i).
func (b *Batch) At(i int) *Prepared { return &b.prepared[i] }

// Len reports how many items the last Prepare covered, live or not.
func (b *Batch) Len() int { return len(b.prepared) }
