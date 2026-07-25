// Copyright 2026 Overclock Validator
// Licensed under the Apache License, Version 2.0; see the LICENSE file at
// the root of this repository.
//
// This file is part of narya and is NOT vendored upstream code. The
// BSD-3-Clause LICENSE in this directory governs the vendored Go /
// filippo.io edwards25519 files only, and does not apply here.
//
// Small-order detection for verify_strict semantics.

package edwards25519

// IsSmallOrder reports whether v has order dividing the cofactor 8,
// i.e. [8]v is the identity. This is exactly ed25519-dalek's
// EdwardsPoint::is_small_order (self.mul_by_cofactor().is_identity()).
// Production strict verification uses the equivalent compressed-byte
// classifier; this method is retained as its independent differential oracle.
func (v *Point) IsSmallOrder() bool {
	var eightV Point
	eightV.MultByCofactor(v)
	return eightV.Equal(NewIdentityPoint()) == 1
}
