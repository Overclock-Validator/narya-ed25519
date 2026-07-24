// Package r51x5 is a correctness-first radix-2^51 model of GF(2^255-19)
// for a future lane-per-signature AVX-512 IFMA backend.
//
// An Element with limbs x0 through x4 represents
//
//	x0 + x1*2^51 + x2*2^102 + x3*2^153 + x4*2^204 (mod p).
//
// Element maintains the unique reduced representation: every limb is less
// than 2^51 and the represented integer is in [0,p). All exported arithmetic
// methods require reduced Element inputs and return a reduced Element. The
// zero value is a valid zero element, and receivers may alias inputs.
//
// ElementX4 and ElementX8 store [limb][lane] data. They deliberately perform
// scalar lane-by-lane arithmetic: their purpose is to specify packing, lane
// independence, and exact field semantics before an IFMA kernel replaces the
// implementation. They make no performance claim and are not wired into any
// verification backend.
//
// IFMAMultiplicandBits documents the wider per-limb bound accepted by the
// VPMADD52 instructions. IFMAElementX4/X8 expose that non-canonical,
// composable representation for experimental point formulas. They are
// separate types so a 52-bit IFMA limb cannot be mistaken for Element's
// unique reduced representation.
package r51x5
