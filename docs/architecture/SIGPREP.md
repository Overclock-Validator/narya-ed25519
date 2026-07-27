# The preparation stage

[Documentation index](../README.md) · Architecture

`internal/sigprep` owns everything between the raw bytes of a signature and the
group equation: length and encoding checks, the predicate's byte-level gates,
and the challenge `k = H(R ‖ A ‖ M) mod l`.

## Why it is separate

Before this, the sequence was written three times, once per backend, each
spelled differently and each fused into its own equation. `generic` open-coded
it inside `verify`, `ifma` open-coded a variant with the canonical-R gate in the
middle, and `r51` had `prepareR51Signature` plus its own copy of the scalar
predicate. A predicate change had three edit sites and no single place to test.

## The shape

The gates are data, not a switch on a profile enum:

```go
type Rules struct {
	RejectSmallOrderA bool
	RejectSmallOrderR bool
	RequireCanonicalR bool
}
```

which makes the differences between predicates readable in one place:

|              | small-order A | small-order R | canonical R | equation      |
|--------------|---------------|---------------|-------------|---------------|
| DalekStrict  | reject        | reject        | require     | cofactorless  |
| StdlibCompat | accept        | accept        | accept      | cofactorless  |
| ZIP215       | accept        | accept        | accept      | cofactored    |

A canonical `S` is required by all three, so it is unconditional rather than a
field.

**StdlibCompat and ZIP215 have identical byte-level rules.** They differ only in
the equation. That is the reason this is worth building ahead of any decision
about SIMD-0376: a cofactored predicate needs no new front-half code at all, so
none of this work is speculative on the outcome.
`TestZIP215SharesStdlibByteRules` pins the identity, since it is the claim the
package rests on.

## What is deliberately not here

**Point decompression.** A decoded point is a backend-native representation, and
hiding that behind a shared interface would cost more than the duplication it
removes. `DecodedKeys` names the seam a decoded-key cache would attach to, and
nothing implements it.

**Scalar reduction, for the vector paths.** `Reduce` exists for scalar callers,
but the vector backends reduce eight digests at once, which is a measured win
this package must not take away. Those callers use `ChallengeSegments` and
reduce the digests themselves.

So the rule each backend follows is: take the gates and the challenge from
`sigprep`, reduce and decode natively.

## `Batch`

The structure-of-arrays entry point, for a consumer that wants many signatures
prepared at once.

- **Index-aligned, not compacted.** A verdict maps straight back to its
  signature with no bookkeeping, which is what lets per-item attribution survive
  batching. Compaction for the multi-buffer hash happens internally.
- **Gates before hashing.** A signature already rejected on bytes alone never
  occupies a hash lane. Lanes are the resource the kernel parallelizes over.
- **Worker-local, allocation-free after warmup.** Pinned by a test. The segment
  arrays are backed by reusable storage; built as locals they would escape once
  per signature, which is the cost this type exists to avoid.

`Batch` has no production consumer yet and is on no hot path. It is the shape a
deep-chunk or multi-scalar pipeline would consume.

## Verification

The move was made verbatim and the in-package names in `ed25519` remain as thin
delegates, so the existing corpora, differential, edge-case and fuzz suites keep
exercising the same predicates under the same names. Those suites are the proof
the extraction was faithful, not new tests written alongside it.

New tests cover what the old spelling had no home for:

- `SmallOrderEncoding` against a decode-and-ask-the-point oracle over the 14
  small-order encodings and 200k biased random inputs. The fast path is a byte
  classification; this is the first test that checks it against the actual
  curve rather than against a second byte classification.
- The `S < l` boundary at `l-1`, `l`, `l+1`, and the proof that the old
  `sig[63]&224` fast reject is exactly subsumed by it.
- Challenge segment order and content, since substituting a re-encoded `A`
  would silently change `k` for every non-canonical public key.
- `Batch` against per-item `Prepare` across 20 widths straddling the x4 and x8
  group boundaries, with a rejected item swept through every position.

## Measurement

Flat. Geomean −0.33% across `BenchmarkVerify` and `BenchmarkVerifyBatch` on an
M-series host (generic backend, the only one that runs there), which is inside
the noise band: `stdlib`, which this does not touch, moves by up to 2.3% between
the same two runs.

The native gate was subsequently run on a Ryzen 7 PRO 8700GE with Go 1.26.4.
The complete repository suite, the race-selected packages, and the forced r51
path passed. Focused public-API comparisons at 1232 bytes placed the r51 n=8
and n=64 steady-state bands within 0.1% of the pre-extraction baseline, with
zero allocations and zero internal-fault fallbacks. A later repeat on the same
host became bimodal at almost exactly 2x throughput, so those samples are kept
as a host-state warning rather than interpreted as a source change. The exact
regime and commands are recorded in
[`results/zen4-sigprep-2026-07-26`](../results/zen4-sigprep-2026-07-26/README.md).

## Where this points

Two things become cheap that were not:

1. **A decoded-key tier.** Roughly 160 bytes per key for an extended point in
   radix-51 limbs, against 19,200 for the comb table, with no minimum group
   width and no requirement that a group be homogeneous. Those two constraints
   are what make the comb tier hard to fill on diverse fee-payer traffic, and
   this tier has neither. Whether it pays depends on signer recurrence, which is
   still unmeasured.

2. **A cofactored equation.** It would consume `Batch` unchanged and contribute
   only `ZIP215` rules plus the equation itself. Note this is not an activation
   signal: SIMD-0376 is in Review with no mainnet feature gate, and a predicate
   change is slot-activated, so it must not become reachable by configuration
   before that gate exists.
