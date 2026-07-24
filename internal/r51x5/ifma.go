package r51x5

import (
	"errors"

	"github.com/Overclock-Validator/narya/internal/cpufeat"
)

var (
	// ErrIFMAUnavailable is returned when an experimental x51 vector kernel is
	// called on a machine without Narya's complete AVX-512 IFMA feature set.
	ErrIFMAUnavailable = errors.New("r51x5: experimental IFMA primitive unavailable")
	errIFMAInputRange  = errors.New("r51x5: experimental IFMA input is not reduced")
	errIFMAOutputRange = errors.New("r51x5: experimental IFMA output is outside u60")
)

// ExperimentalIFMAAvailable reports whether this CPU may execute both the x8
// ZMM kernel and the x4 AVX-512VL YMM kernel. Merely being available never
// changes field arithmetic or Ed25519 backend dispatch.
func ExperimentalIFMAAvailable() bool { return cpufeat.IFMA() }

// ExperimentalIFMAMultiplyLooseX8 computes eight independent products using
// ZMM VPMADD52 instructions. x and y must contain reduced radix-2^51 elements.
// The result has the IFMALooseX8 contract and is not a composable field value.
// On any error, out is unchanged.
func ExperimentalIFMAMultiplyLooseX8(out *IFMALooseX8, x, y *ElementX8) error {
	if !ExperimentalIFMAAvailable() {
		return ErrIFMAUnavailable
	}
	if !IsReducedX8(x.limbs) || !IsReducedX8(y.limbs) {
		return errIFMAInputRange
	}
	var product IFMAProductX8
	ifmaMulRawX8(&product, &x.limbs, &y.limbs)
	raw := IFMALooseX8(product)
	if !IsIFMALooseX8(raw) {
		return errIFMAOutputRange
	}
	*out = raw
	return nil
}

// ExperimentalIFMAMultiplyX8 computes eight independent products using the
// experimental ZMM kernel and canonically reduces all lanes. Inputs and output
// may alias. On error, z is unchanged.
func ExperimentalIFMAMultiplyX8(z, x, y *ElementX8) error {
	var raw IFMALooseX8
	if err := ExperimentalIFMAMultiplyLooseX8(&raw, x, y); err != nil {
		return err
	}
	reduced, ok := reduceIFMALooseX8(&raw)
	if !ok {
		return errIFMAOutputRange
	}
	z.limbs = reduced
	return nil
}

// ExperimentalIFMASquareX8 computes eight independent squares. The initial
// correctness implementation deliberately reuses the multiply kernel.
func ExperimentalIFMASquareX8(z, x *ElementX8) error {
	return ExperimentalIFMAMultiplyX8(z, x, x)
}

// ExperimentalIFMAMultiplyLooseX4 computes four independent products using
// YMM VPMADD52 instructions (AVX-512VL, not a masked ZMM operation). x and y
// must be reduced. The result is non-composable; on error, out is unchanged.
func ExperimentalIFMAMultiplyLooseX4(out *IFMALooseX4, x, y *ElementX4) error {
	if !ExperimentalIFMAAvailable() {
		return ErrIFMAUnavailable
	}
	if !IsReducedX4(x.limbs) || !IsReducedX4(y.limbs) {
		return errIFMAInputRange
	}
	var product IFMAProductX4
	ifmaMulRawX4(&product, &x.limbs, &y.limbs)
	raw := IFMALooseX4(product)
	if !IsIFMALooseX4(raw) {
		return errIFMAOutputRange
	}
	*out = raw
	return nil
}

// ExperimentalIFMAMultiplyX4 computes four independent products using the
// experimental AVX-512VL YMM kernel and canonically reduces all lanes. Inputs
// and output may alias. On error, z is unchanged.
func ExperimentalIFMAMultiplyX4(z, x, y *ElementX4) error {
	var raw IFMALooseX4
	if err := ExperimentalIFMAMultiplyLooseX4(&raw, x, y); err != nil {
		return err
	}
	reduced, ok := reduceIFMALooseX4(&raw)
	if !ok {
		return errIFMAOutputRange
	}
	z.limbs = reduced
	return nil
}

// ExperimentalIFMASquareX4 computes four independent squares. The initial
// correctness implementation deliberately reuses the multiply kernel.
func ExperimentalIFMASquareX4(z, x *ElementX4) error {
	return ExperimentalIFMAMultiplyX4(z, x, x)
}
