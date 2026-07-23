package ed25519

import (
	"sync"
	"sync/atomic"
)

// Cache verifies signatures, building a per-key table for public keys
// that keep recurring. It is safe for concurrent use.
//
// A table costs about eight verifications to build, so admission waits
// for buildThreshold sightings: vote authorities and busy fee payers
// cross it immediately, one-shot keys never earn a table. The sighting
// counters are cleared when their map grows large, which only makes a
// hot key re-earn its table. Tables are never evicted: a stale entry
// costs tens of KiB and hot keys are stable on the scale of epochs;
// MaxTableBytes stops admission when the budget is spent.
type Cache struct {
	// MaxTableBytes bounds the memory held by per-key tables. Zero
	// means DefaultMaxTableBytes.
	MaxTableBytes int64

	tables    sync.Map // [32]byte -> *PrecomputedKey
	count     atomic.Int64
	bytes     atomic.Int64
	hits      atomic.Int64
	misses    atomic.Int64
	seen      sync.Map // [32]byte -> *atomic.Int32
	seenCount atomic.Int64
}

// DefaultMaxTableBytes admits ~4,300 generic tables — comfortable
// margin over a validator set's vote authorities plus busy fee payers.
const DefaultMaxTableBytes = 128 << 20

const buildThreshold = 8

const seenResetThreshold = 1 << 17

// Verify reports whether sig is a valid signature of message by pub,
// exactly like the package-level Verify.
func (c *Cache) Verify(pub *[32]byte, message, sig []byte) bool {
	b := active()
	if t, ok := c.tables.Load(*pub); ok {
		c.hits.Add(1)
		return b.verify(pub, message, sig, t.(*PrecomputedKey))
	}
	c.misses.Add(1)

	v, seenBefore := c.seen.LoadOrStore(*pub, new(atomic.Int32))
	if !seenBefore {
		if c.seenCount.Add(1) > seenResetThreshold {
			c.seenCount.Store(0)
			c.seen.Clear()
		}
	}
	if v.(*atomic.Int32).Add(1) < buildThreshold {
		return b.verify(pub, message, sig, nil)
	}

	max := c.MaxTableBytes
	if max == 0 {
		max = DefaultMaxTableBytes
	}
	if c.bytes.Load() < max {
		if pre, err := b.buildPrecomp(pub); err == nil && pre.table != nil {
			if _, loaded := c.tables.LoadOrStore(*pub, pre); !loaded {
				c.count.Add(1)
				c.bytes.Add(pre.size)
			}
			return b.verify(pub, message, sig, pre)
		}
	}
	return b.verify(pub, message, sig, nil)
}

// CacheStats is a point-in-time snapshot of cache behavior, for
// metrics export.
type CacheStats struct {
	Tables     int64 // per-key tables held
	TableBytes int64 // memory held by tables
	Hits       int64 // verifications that found a table
	Misses     int64 // verifications that did not
}

func (c *Cache) Stats() CacheStats {
	return CacheStats{
		Tables:     c.count.Load(),
		TableBytes: c.bytes.Load(),
		Hits:       c.hits.Load(),
		Misses:     c.misses.Load(),
	}
}
