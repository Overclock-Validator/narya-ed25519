package ed25519

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	"github.com/Overclock-Validator/narya/internal/cpufeat"
)

// A backend implements signature verification. Exactly one backend is
// active per process: tables built by one backend are meaningless to
// another, and a single choice keeps every Cache entry compatible.
type backend interface {
	name() string
	// verify evaluates the Ed25519 equation under profile after the
	// shared entry point has applied that profile's rejection pre-pass.
	// pre is nil, or a PrecomputedKey this backend built for pub.
	verify(profile Profile, pub *[32]byte, message, sig []byte, pre *PrecomputedKey) bool
	// verifyBatch verifies each item independently, writing item.ok;
	// results must be exactly what per-item verify would produce.
	// Cache lookup has already populated item.pre where applicable. Keeping
	// admission outside backends makes Cache.VerifyBatch's sighting policy
	// identical across scalar and vector implementations.
	verifyBatch(profile Profile, items []batchItem)
	// supportsPrecomp reports whether buildPrecomp can return a native table.
	// Cache uses it to avoid running point decoding at every hot-key threshold
	// on rollback and reference backends that always verify plainly.
	supportsPrecomp() bool
	// buildPrecomp returns a non-nil error exactly when pub fails
	// point decoding. Backends without table support return a
	// PrecomputedKey with a nil table (plain verification).
	buildPrecomp(pub *[32]byte) (*PrecomputedKey, error)
}

// rawBatchBackend is an optional allocation-free batch entry point for
// backends whose native pipeline already consumes the public raw-slice shape.
// It must apply profile rejection itself and write every ok element. Cache
// batches use this path when the selected backend has no native per-key
// representation; a table-capable native backend may additionally implement
// cachedRawBatchBackend to retain this allocation-free shape on cache hits.
//
// Keeping this interface private preserves the public API while allowing a
// native SIMD backend to avoid allocating and copying one batchItem per
// signature merely to unpack it again into lane-native storage.
type rawBatchBackend interface {
	verifyBatchRaw(profile Profile, pubs []*[32]byte, msgs, sigs [][]byte, ok []bool) bool
}

// precomputedKeyLookup is the cache lookup boundary used by native raw batch
// backends. Keeping lookup behind this private interface lets the backend fill
// fixed-size native scratch directly without allocating batchItem or a slice
// of precomputed-key pointers merely to cross the public batch wrapper.
type precomputedKeyLookup interface {
	lookup(pub *[32]byte) *PrecomputedKey
}

// cachedRawBatchBackend is the cache-aware counterpart of rawBatchBackend.
// It must perform exactly one lookup for each item the shared profile pre-pass
// would leave live, preserve per-item verdicts, and fail closed just like the
// ordinary raw entry point. Cache admission remains outside the backend and
// occurs only after successful verdicts have been written.
type cachedRawBatchBackend interface {
	verifyBatchRawCached(profile Profile, pubs []*[32]byte, msgs, sigs [][]byte, ok []bool, lookup precomputedKeyLookup) bool
}

// batchOnlyPrecompBackend marks a backend whose native precomputation is
// useful only to its batch pipeline. Cache still grants admission after a
// successful singleton, but skips a lookup that the singleton verifier could
// not consume.
type batchOnlyPrecompBackend interface {
	batchOnlyPrecomp()
}

// activatingBackend is implemented only by explicitly gated native backends.
// Activation happens after a backend name has been selected, never as part of
// registration or automatic CPU dispatch.
type activatingBackend interface {
	activate() error
}

// A batchItem is one signature in a batch: the inputs and the
// per-item verdict. skip marks an item already rejected by a profile
// pre-pass, so the backend leaves ok false and does no arithmetic.
type batchItem struct {
	pub  *[32]byte
	msg  []byte
	sig  []byte
	pre  *PrecomputedKey
	ok   bool
	skip bool
}

// applyProfile marks items the selected profile rejects outright, so
// batch backends skip them. Called by every batch entry point before
// the selected profile is passed to the backend.
func applyProfile(profile Profile, items []batchItem) {
	for i := range items {
		if rejectedByProfile(profile, items[i].pub, items[i].sig) {
			items[i].skip = true
		}
	}
}

func rejectedByProfile(profile Profile, pub *[32]byte, sig []byte) bool {
	// All bool-returning public verification APIs fail closed on a missing
	// public key. Keeping this in the shared pre-pass makes the behavior
	// backend- and profile-independent.
	if pub == nil {
		return true
	}
	switch profile {
	case DalekStrict:
		return rejectedByStrict(pub, sig)
	case StdlibCompat:
		return false
	default:
		panic("ed25519: unknown verification profile")
	}
}

var (
	registry  = map[string]backend{}
	current   atomic.Pointer[backendBox]
	selectMu  sync.Mutex
	requested string
)

type backendBox struct{ b backend }

// BackendStats is a point-in-time snapshot of the selected arithmetic
// backend. InternalFaultFallbacks counts operations that encountered an
// unexpected native-backend error and were recomputed by the portable generic
// verifier. A nonzero value is an operational fault signal, not an invalid
// signature count.
type BackendStats struct {
	InternalFaultFallbacks uint64
}

type backendStatsReporter interface {
	backendStats() BackendStats
}

func register(name string, b backend) { registry[name] = b }

// ActiveBackend returns the name of the backend in use ("r51", "ifma",
// "generic", "stdlib"), selecting one if none is active yet.
func ActiveBackend() string { return active().name() }

// ActiveBackendStats reports operational counters for the selected backend.
// Backends without native fault recovery return the zero value.
func ActiveBackendStats() BackendStats {
	b := active()
	if reporter, ok := b.(backendStatsReporter); ok {
		return reporter.backendStats()
	}
	return BackendStats{}
}

// SetBackend forces a backend by name. It must be called before the
// first verification; once a backend is active it cannot be changed.
func SetBackend(name string) error {
	selectMu.Lock()
	defer selectMu.Unlock()
	if cur := current.Load(); cur != nil {
		if cur.b.name() == name {
			return nil
		}
		return fmt.Errorf("ed25519: cannot switch backend, %q already active", cur.b.name())
	}
	b, ok := registry[name]
	if !ok {
		return fmt.Errorf("ed25519: unknown backend %q", name)
	}
	if (name == "ifma" || name == "r51") && !cpufeat.IFMA() {
		return fmt.Errorf("ed25519: %s backend requires AVX512-IFMA (Ice Lake / Zen 4 or newer)", name)
	}
	// Explicit selection is also an explicit startup health check. Complete
	// activation here so SetBackend cannot report success only for the first
	// Verify or ActiveBackend call to panic later.
	if a, ok := b.(activatingBackend); ok {
		if err := a.activate(); err != nil {
			return fmt.Errorf("ed25519: activating backend %q: %w", name, err)
		}
	}
	requested = name
	current.Store(&backendBox{b: b})
	return nil
}

func active() backend {
	if box := current.Load(); box != nil {
		return box.b
	}
	selectMu.Lock()
	defer selectMu.Unlock()
	if box := current.Load(); box != nil {
		return box.b
	}
	name := requested
	if name == "" {
		name = os.Getenv("OVERCLOCK_ED25519_BACKEND")
	}
	b := pick(name)
	current.Store(&backendBox{b: b})
	return b
}

// pick resolves a backend name. The empty/auto choice deliberately remains
// generic even though the forced ifma reference and cold r51 backend are
// registered. They can be exercised only through SetBackend or
// OVERCLOCK_ED25519_BACKEND until a separately reviewed automatic-dispatch
// policy exists. A requested name that cannot be honored panics rather than
// silently degrading because it represents explicit operator intent.
func pick(name string) backend {
	if name == "" {
		return registry["generic"]
	}
	b, ok := registry[name]
	if !ok {
		panic(fmt.Sprintf("ed25519: unknown backend %q", name))
	}
	if (name == "ifma" || name == "r51") && !cpufeat.IFMA() {
		panic(fmt.Sprintf("ed25519: %s backend requested but CPU lacks AVX512-IFMA", name))
	}
	if a, ok := b.(activatingBackend); ok {
		if err := a.activate(); err != nil {
			panic(fmt.Sprintf("ed25519: activating backend %q: %v", name, err))
		}
	}
	return b
}
