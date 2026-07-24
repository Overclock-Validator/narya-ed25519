// Package r43x6 implements a pure-Go reference model of Firedancer's
// radix-2^43, six-limb representation of GF(2^255-19).
//
// # An element with limbs x0 through x5 represents
//
//	x0 + x1*2^43 + x2*2^86 + x3*2^129 + x4*2^172 + x5*2^215 (mod p).
//
// Firedancer uses several representation ranges to avoid unnecessary carry
// propagation in SIMD code:
//
//   - unsigned: every limb is in [0, 2^62)
//   - unreduced: every limb is in [0, 2^47)
//   - unpacked: limbs 0-4 are in [0, 2^43), limb 5 is in [0, 2^41)
//   - nearly reduced: unpacked and the represented integer is in [0, 2p)
//   - reduced: limbs 0-4 are in [0, 2^43), limb 5 is in [0, 2^40),
//     and the represented integer is in [0, p)
//
// Element deliberately maintains only the reduced representation. Point and
// Scalar build a permissive Edwards25519 decoder, extended-coordinate group
// operations, and a variable-time verification multiplication on that field.
// Together they form a correctness oracle for the SIMD implementation. The
// package also contains an explicitly gated experimental IFMA multiplication
// primitive, but it does not participate in automatic backend dispatch and
// makes no performance claim. Limbs and the range predicates expose the wider
// contracts that optimized SIMD code must preserve.
package r43x6
