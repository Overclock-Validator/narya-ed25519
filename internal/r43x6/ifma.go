package r43x6

import (
	"errors"
	"sync/atomic"

	"github.com/Overclock-Validator/narya-ed25519/internal/cpufeat"
)

var experimentalIFMAEnabled atomic.Bool

var (
	// ErrIFMAUnavailable is returned when the experimental primitive is called
	// on a machine without the complete IFMA feature set used by Narya.
	ErrIFMAUnavailable = errors.New("r43x6: experimental IFMA primitive unavailable")
	errIFMARange       = errors.New("r43x6: experimental IFMA primitive violated its output range")
)

// ExperimentalIFMAAvailable reports whether the runtime CPU feature gate
// permits executing the experimental assembly primitive. Availability never
// changes normal field or Ed25519 backend dispatch.
func ExperimentalIFMAAvailable() bool { return cpufeat.IFMA() }

// EnableExperimentalIFMA makes Element.Multiply and Element.Square use the
// experimental assembly kernel for the rest of the process. The transition is
// one-way: a mixture of field implementations inside one group operation would
// still be mathematically correct, but allowing disable/re-enable would make
// backend selection and benchmark results needlessly difficult to audit.
//
// This function is intentionally not called by package initialization or
// automatic CPU dispatch. The explicitly selected Ed25519 IFMA backend owns
// activation. On an unsupported CPU it returns ErrIFMAUnavailable and leaves
// the scalar reference implementation active.
func EnableExperimentalIFMA() error {
	if !ExperimentalIFMAAvailable() {
		return ErrIFMAUnavailable
	}
	experimentalIFMAEnabled.Store(true)
	return nil
}

// ExperimentalIFMAEnabled reports whether the one-way field dispatch switch
// has been enabled. Availability alone is not sufficient: normal r43x6 users
// remain on the pure-Go reference path until explicit activation.
func ExperimentalIFMAEnabled() bool { return experimentalIFMAEnabled.Load() }

// ExperimentalIFMAMultiply sets z=x*y modulo p using the amd64 AVX-512 IFMA
// correctness kernel. x and y are reduced Elements. The assembly kernel emits
// Firedancer's unreduced u47 range after its unsigned fold; this wrapper then
// performs the final canonical reduction required by Element.
//
// It returns ErrIFMAUnavailable without modifying z unless cpufeat.IFMA is
// true. Inputs and output may alias.
func ExperimentalIFMAMultiply(z, x, y *Element) error {
	if !ExperimentalIFMAAvailable() {
		return ErrIFMAUnavailable
	}
	return ifmaMultiply(z, x, y)
}

func ifmaMultiply(z, x, y *Element) error {
	xl, yl := x.limbs, y.limbs
	var loose Limbs
	ifmaMulRaw(&loose, &xl, &yl)
	if !IsUnreduced(loose) {
		return errIFMARange
	}
	var accum [6]uint128
	for i := range loose {
		accum[i].lo = loose[i]
	}
	z.limbs = reduceAccumulators(&accum)
	return nil
}

// ExperimentalIFMASquare sets z=x^2 modulo p. This first correctness version
// deliberately reuses the multiply kernel; a dedicated symmetric square
// schedule is deferred until the multiply primitive is validated on hardware.
func ExperimentalIFMASquare(z, x *Element) error {
	return ExperimentalIFMAMultiply(z, x, x)
}
