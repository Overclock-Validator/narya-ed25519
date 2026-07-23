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
	// verify must be bit-identical to crypto/ed25519.Verify. pre is
	// nil, or a PrecomputedKey this backend built for pub.
	verify(pub *[32]byte, message, sig []byte, pre *PrecomputedKey) bool
	// buildPrecomp returns a non-nil error exactly when pub fails
	// point decoding. Backends without table support return a
	// PrecomputedKey with a nil table (plain verification).
	buildPrecomp(pub *[32]byte) (*PrecomputedKey, error)
}

var (
	registry  = map[string]backend{}
	current   atomic.Pointer[backendBox]
	selectMu  sync.Mutex
	requested string
)

type backendBox struct{ b backend }

func register(name string, b backend) { registry[name] = b }

// ActiveBackend returns the name of the backend in use ("ifma",
// "generic", "stdlib"), selecting one if none is active yet.
func ActiveBackend() string { return active().name() }

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
	if _, ok := registry[name]; !ok {
		return fmt.Errorf("ed25519: unknown backend %q", name)
	}
	if name == "ifma" && !cpufeat.IFMA() {
		return fmt.Errorf("ed25519: ifma backend requires AVX512-IFMA (Ice Lake / Zen 4 or newer)")
	}
	requested = name
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

// pick resolves a backend name. The empty name selects the best
// available: ifma when the kernel is built in and the CPU supports it,
// generic otherwise. A name that cannot be honored panics rather than
// silently degrading — it only arrives via the OVERCLOCK_ED25519_BACKEND
// escape hatch or SetBackend, both explicit operator intent.
func pick(name string) backend {
	if name == "" {
		if b, ok := registry["ifma"]; ok && cpufeat.IFMA() {
			return b
		}
		return registry["generic"]
	}
	b, ok := registry[name]
	if !ok {
		panic(fmt.Sprintf("ed25519: unknown backend %q", name))
	}
	if name == "ifma" && !cpufeat.IFMA() {
		panic("ed25519: ifma backend requested but CPU lacks AVX512-IFMA")
	}
	return b
}
