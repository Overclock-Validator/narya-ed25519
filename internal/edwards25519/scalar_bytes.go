// Copyright 2026 Overclock Validator
// Licensed under the Apache License, Version 2.0; see the LICENSE file at
// the root of this repository.
//
// This file is part of narya and is NOT vendored upstream code. The
// BSD-3-Clause LICENSE in this directory governs the vendored Go /
// filippo.io edwards25519 files only, and does not apply here.
//
// Allocation-free scalar encoding.

package edwards25519

// BytesInto writes the canonical 32-byte little-endian encoding of s into out.
//
// It is the allocation-free counterpart of Bytes, which allocates a fresh slice
// on every call. A batch preparation stage reduces one challenge scalar per
// signature, so on a deep group that allocation is paid once per signature for
// a value the caller already has storage for.
func (s *Scalar) BytesInto(out *[32]byte) { copy(out[:], s.s[:]) }
