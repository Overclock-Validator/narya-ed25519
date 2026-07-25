# Experimental SHA-512 Digest Reduction

`internal/r51x5` contains the fixed-storage scalar-reduction component used by
the explicitly forced r51 verifier. The implementation remains portable Go;
the SIMD/native reducer variants discussed below are benchmark-only. This
component does not alter automatic backend selection.

## API and semantics

The entry points are:

```go
ExperimentalReduceUniformScalarsX4(
    out *[4][32]byte,
    in *[4][64]byte,
    active uint8,
) uint8

ExperimentalReduceUniformScalarsX8(
    out *[8][32]byte,
    in *[8][64]byte,
    active uint8,
) uint8
```

Every active 64-byte lane is interpreted as a little-endian integer and
reduced modulo the Ed25519 subgroup order. The result is the canonical
32-byte encoding and is exactly equivalent to
`edwards25519.Scalar.SetUniformBytes`. Inactive outputs are zero. The x4 API
masks away bits above lane three; the x8 mask already occupies one byte.

Both APIs use caller-owned fixed arrays and allocate zero objects. The
implementation is portable pure Go, so there is no unsupported-host fallback
or accidental instruction trap. In particular, it does not expose a native
entry point that merely aliases a scalar implementation.

## Independent oracles

The callable candidate uses the public-domain radix-2^21 reduction schedule.
Tests compare it with two structurally different references:

1. Narya's `edwards25519.Scalar.SetUniformBytes` implementation.
2. A fixed-width bit-at-a-time modular-reduction oracle.

An unsigned radix-2^64 Barrett implementation is retained as a third internal
oracle. Tests cover boundary values, arbitrary 512-bit inputs, all 256 active
masks, every lane position, tails from zero through eight, x8 versus two x4
groups, fuzz input, and allocation counts.

## SIMD decision

No scalar-reduction assembly is included yet. AVX-512 IFMA is a poor direct
fit for reduction modulo the scalar order: the existing schedule uses signed
limbs, signed carries, and small-constant products rather than the radix-2^51
field products handled by `VPMADD52`. A separate AVX-512DQ lane-vectorized
radix-2^21 schedule is possible, but it also needs digest unpacking and scalar
packing. It should only be implemented if target-machine profiles show this
stage is material after native SHA-512 and DSM are composed.

## SHA-512 layout and possible fusion

The native SHA-512 API already emits `[lane][64]byte`, exactly the input layout
accepted here. The x8 verifier passes that fixed digest array directly, with no
transpose, heap allocation, or staging copy. The explicit two-x4 comparison
copies each four-lane half into its fixed x4 array and copies the canonical
outputs back into compact-lane order; that cost is intentionally included in
its complete-path benchmark rather than hidden behind the x8 reducer.

A deeper assembly fusion is only speculative. SHA-512's internal state is
word-major and its words are serialized big-endian, while Ed25519 interprets
the resulting digest byte string as a little-endian integer. A fused kernel
could avoid the final state store/reload and perform byte reversal in vector
registers, but it would couple two independently testable components and
increase register pressure. Do not add that coupling until a native reducer
has independently won on Zen 4 and the saved round trip is visible in a full
verifier profile.

## Ryzen measurement

Pin one process to one physical core and keep primitive measurements single
threaded. Run enough samples for `benchstat`:

```sh
GOMAXPROCS=1 taskset -c CORE go test \
  -run '^$' \
  -bench '^BenchmarkExperimentalUniformScalarReduction$' \
  -benchmem -benchtime=3s -count=10 \
  ./internal/r51x5 | tee scalar-reduce.txt
```

The benchmark includes x4, x8, two-x4, the current `SetUniformBytes` baseline,
and every x8 tail width. Treat x8 and two-x4 as equivalent when the difference
is below the plan's two-percent decision threshold. Reduction-only results do
not justify dispatch; the complete forced verifier remains the deciding
benchmark.
