package ed25519

import (
	"sync"
	"sync/atomic"
)

// Cache verifies signatures, building a per-key table for public keys
// that keep recurring. It is safe for concurrent use.
//
// A Cache must not be copied after first use. MaxTableBytes must be configured
// before first use and must not be changed concurrently with verification.
//
// The current conservative policy waits for buildThreshold successful
// verifications, while invalid signatures and one-shot keys never earn a
// table. The threshold is an implementation default, not a claim about a
// production signer distribution; real Mithril traces must validate policy
// before a process-wide cache is enabled. Admission state has a hard entry
// limit and is never cleared, so a counter cannot be detached from its key
// while another goroutine is using it and deterministic build failures are
// not retried.
// Once the limit is reached, previously unseen keys remain on the plain path.
// Tables are never evicted; MaxTableBytes stops admission when its strict
// memory budget is spent.
type Cache struct {
	// MaxTableBytes strictly bounds the memory held by per-key tables. Zero
	// means DefaultMaxTableBytes. Configure it before the Cache's first use.
	MaxTableBytes int64

	tables    sync.Map // [32]byte -> *PrecomputedKey
	count     atomic.Int64
	bytes     atomic.Int64
	hits      atomic.Int64
	misses    atomic.Int64
	seen      sync.Map // [32]byte -> *atomic.Int32
	seenCount atomic.Int64
}

// DefaultMaxTableBytes is a strict 128 MiB table-memory ceiling. The number of
// entries it admits depends on the active backend's native table size.
const DefaultMaxTableBytes = 128 << 20

const buildThreshold = 8

const (
	admissionBuilding int32 = -1
	admissionDisabled int32 = -2
	admissionComplete int32 = -3
)

// admissionEntryLimit bounds bookkeeping independently of the table budget.
// Reaching it can only reduce acceleration: signatures still verify normally.
const admissionEntryLimit = 1 << 17

// Verify reports whether sig is a valid signature of message by pub,
// exactly like the package-level Verify.
func (c *Cache) Verify(pub *[32]byte, message, sig []byte) bool {
	return c.verify(DefaultProfile(), pub, message, sig)
}

// VerifyStrict reports whether sig is a valid signature of message by
// pub under DalekStrict semantics, regardless of the package default
// profile. Strictly rejected inputs do not affect cache admission.
func (c *Cache) VerifyStrict(pub *[32]byte, message, sig []byte) bool {
	return c.verify(DalekStrict, pub, message, sig)
}

func (c *Cache) verify(profile Profile, pub *[32]byte, message, sig []byte) bool {
	return c.verifyWithBackend(active(), profile, pub, message, sig)
}

func (c *Cache) verifyWithBackend(b backend, profile Profile, pub *[32]byte, message, sig []byte) bool {
	if rejectedByProfile(profile, pub, sig) {
		return false
	}
	// A backend without native tables cannot turn a lookup into useful work.
	// Bypass cache bookkeeping entirely; in particular this preserves the raw,
	// allocation-free r51 batch path.
	if !b.supportsPrecomp() {
		return b.verify(profile, pub, message, sig, nil)
	}
	if _, batchOnly := b.(batchOnlyPrecompBackend); batchOnly {
		ok := b.verify(profile, pub, message, sig, nil)
		if ok {
			c.admit(b, pub)
		}
		return ok
	}
	pre := c.lookup(pub)
	ok := b.verify(profile, pub, message, sig, pre)
	if ok && pre == nil {
		c.admit(b, pub)
	}
	return ok
}

// VerifyBatch verifies n independent signatures through the cache,
// exactly like calling Verify for each: table hits use their tables, and
// successful misses bump sighting counters after the backend has produced
// its verdicts. A threshold crossing builds a table for a later call; an
// invalid item never earns admission credit. Verdict semantics match the
// package-level VerifyBatch.
func (c *Cache) VerifyBatch(pubs []*[32]byte, msgs, sigs [][]byte, ok []bool) bool {
	return c.verifyBatch(DefaultProfile(), pubs, msgs, sigs, ok)
}

// VerifyBatchStrict verifies n independent signatures through the
// cache under DalekStrict semantics, regardless of the package default
// profile. Its inputs and outputs otherwise match VerifyBatch.
func (c *Cache) VerifyBatchStrict(pubs []*[32]byte, msgs, sigs [][]byte, ok []bool) bool {
	return c.verifyBatch(DalekStrict, pubs, msgs, sigs, ok)
}

func (c *Cache) verifyBatch(profile Profile, pubs []*[32]byte, msgs, sigs [][]byte, ok []bool) bool {
	return c.verifyBatchWithBackend(active(), profile, pubs, msgs, sigs, ok)
}

func (c *Cache) verifyBatchWithBackend(b backend, profile Profile, pubs []*[32]byte, msgs, sigs [][]byte, ok []bool) bool {
	if !b.supportsPrecomp() {
		return verifyBatch(b, profile, pubs, msgs, sigs, ok, nil)
	}
	var all bool
	if raw, supported := b.(cachedRawBatchBackend); supported {
		all = raw.verifyBatchRawCached(profile, pubs, msgs, sigs, ok, c)
		return all
	} else {
		all = verifyBatch(b, profile, pubs, msgs, sigs, ok, func(pub *[32]byte) *PrecomputedKey {
			return c.lookup(pub)
		})
	}
	for i := range ok {
		if ok[i] {
			c.admit(b, pubs[i])
		}
	}
	return all
}

// lookup returns an existing table for the current verification. A miss is
// deliberately side-effect-free with respect to admission: only admit,
// called after a successful verdict, may increment a sighting counter.
func (c *Cache) lookup(pub *[32]byte) *PrecomputedKey {
	if t, ok := c.tables.Load(*pub); ok {
		c.hits.Add(1)
		return t.(*PrecomputedKey)
	}
	c.misses.Add(1)
	return nil
}

// admit records one successful uncached verification and, at the threshold,
// grants exactly one goroutine permission to build. It never changes the
// verdict of the verification that supplied the sighting.
func (c *Cache) admit(b backend, pub *[32]byte) {
	if !b.supportsPrecomp() {
		return
	}
	// A table may have appeared while the successful plain verification was
	// running. It is authoritative; this call remains a miss for statistics.
	if _, ok := c.tables.Load(*pub); ok {
		return
	}

	max := c.MaxTableBytes
	if max == 0 {
		max = DefaultMaxTableBytes
	}
	if max < 1 || c.bytes.Load() >= max {
		// Tables never leave the cache, so a full budget cannot become
		// admissible later. Avoid consuming bookkeeping slots for new keys.
		return
	}

	counter, ok := c.admissionCounter(pub)
	if !ok {
		return
	}
	if !claimAdmissionBuild(counter) {
		return
	}

	if max < 1 || c.bytes.Load() >= max {
		// The cache never evicts tables and MaxTableBytes is configured before
		// first use, so this key cannot become admissible later.
		counter.Store(admissionDisabled)
		return
	}

	pre, err := b.buildPrecomp(pub)
	if err != nil || pre == nil || pre.table == nil || pre.size <= 0 {
		// Point decoding and backend table support are deterministic for a
		// selected backend, so retrying this key can never produce a table.
		counter.Store(admissionDisabled)
		return
	}
	if _, loaded := c.tables.Load(*pub); loaded {
		counter.Store(admissionComplete)
		return
	}
	if !c.reserveTableBytes(pre.size, max) {
		// Tables are never evicted, so the remaining budget cannot grow.
		counter.Store(admissionDisabled)
		return
	}
	_, loaded := c.tables.LoadOrStore(*pub, pre)
	if loaded {
		c.bytes.Add(-pre.size)
		counter.Store(admissionComplete)
		return
	}
	c.count.Add(1)
	counter.Store(admissionComplete)
}

// admissionCounter returns the stable counter for pub, creating it only when
// a slot can be atomically reserved. Entries are never removed: this both
// bounds memory and prevents a goroutine from building through a detached
// counter after another goroutine installed a replacement for the same key.
func (c *Cache) admissionCounter(pub *[32]byte) (*atomic.Int32, bool) {
	if v, ok := c.seen.Load(*pub); ok {
		return v.(*atomic.Int32), true
	}
	if !c.reserveAdmissionSlot() {
		// A concurrent creator may have reserved the final slot but not yet
		// published it when the first Load ran.
		if v, ok := c.seen.Load(*pub); ok {
			return v.(*atomic.Int32), true
		}
		return nil, false
	}
	candidate := new(atomic.Int32)
	actual, loaded := c.seen.LoadOrStore(*pub, candidate)
	if loaded {
		c.seenCount.Add(-1)
		return actual.(*atomic.Int32), true
	}
	return candidate, true
}

func (c *Cache) reserveAdmissionSlot() bool {
	for {
		used := c.seenCount.Load()
		if used >= admissionEntryLimit {
			return false
		}
		if c.seenCount.CompareAndSwap(used, used+1) {
			return true
		}
	}
}

// claimAdmissionBuild increments the bounded sighting counter and grants one
// goroutine the build at the threshold. Concurrent sightings neither duplicate
// an expensive table build nor overflow a counter for a permanently hot key.
func claimAdmissionBuild(counter *atomic.Int32) bool {
	for {
		seen := counter.Load()
		if seen < 0 {
			return false
		}
		if seen >= buildThreshold-1 {
			if counter.CompareAndSwap(seen, admissionBuilding) {
				return true
			}
			continue
		}
		if counter.CompareAndSwap(seen, seen+1) {
			return false
		}
	}
}

// reserveTableBytes atomically reserves size without ever allowing the
// observable total to exceed max, even when different keys cross their
// admission thresholds concurrently.
func (c *Cache) reserveTableBytes(size, max int64) bool {
	if size <= 0 || size > max {
		return false
	}
	for {
		used := c.bytes.Load()
		if used > max-size {
			return false
		}
		if c.bytes.CompareAndSwap(used, used+size) {
			return true
		}
	}
}

// CacheStats is a point-in-time snapshot of cache behavior, for
// metrics export.
type CacheStats struct {
	Tables     int64 // per-key tables held
	TableBytes int64 // memory held by tables
	Hits       int64 // table-capable backend verifications that found a table
	Misses     int64 // table-capable backend verifications that did not
}

func (c *Cache) Stats() CacheStats {
	return CacheStats{
		Tables:     c.count.Load(),
		TableBytes: c.bytes.Load(),
		Hits:       c.hits.Load(),
		Misses:     c.misses.Load(),
	}
}
