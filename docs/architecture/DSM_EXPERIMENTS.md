# Double-scalar multiplication experiments

[Documentation index](../README.md) · Architecture

> **Current status.** Zen 4 measurements selected two-x4 radix-64 DSM for the
> registered, forced-only r51 batch backend. The other widths and true-x8
> shapes below remain comparison candidates; x8 is retained for Zen 5.

The current r43x6 scalar reference keeps width-5 signed NAF for the
variable-base point and width 8 for the basepoint. Widths 4, 5, and 6 remain
test-only comparisons; no result from a non-target scalar benchmark changes
dispatch.

The native ordinary-verifier candidates are:

1. x4 signed radix 32 with a projective-cached variable-base table;
2. x8 signed radix 16;
3. x8 signed radix 32;
4. x4/x8 signed radix 64 with a 32-point table and 43 fixed rounds;
5. x8 versus two independent x4 groups on Zen 4.

Radix 64 was deliberately evaluated as a complete-path candidate rather than
accepted from operation counts alone.
For four-coordinate tables its nominal payload is 20 KiB at x4 and 40 KiB at
x8; a two-term x8 DSM retains 80 KiB if both point tables are materialized.
The shared-B complete candidate retains only the cold 40 KiB A table, but must
still pay to build it for an unseen key. Table construction, L1 pressure, and
worker concurrency may outweigh the 43-round schedule.

The composable IFMA tables now use radix-specific fixed arrays: 8, 16, or 32
positive points for radix 16, 32, or 64. Builders overwrite the active points
and metadata directly; they no longer zero a 32-entry maximum object before a
radix-16/radix-32 build. On a 64-bit Go target, each table has 16 bytes of
metadata beyond its active coordinate payload. The x8 physical sizes are
therefore 10,256 / 20,496 / 40,976 bytes, and the complete ordinary x8
workspace sizes (two tables plus fixed digit storage) are 21,800 / 42,280 /
83,240 bytes. These are physical retained sizes, not estimates of cache lines
actually fetched by a particular schedule.

The decisive comparison must use actual IFMA kernels on the Ryzen target. It
must include variable-table generation, scalar recoding, lane packing, the DSM
loop, tails and verdict mapping, and complete verification. Choose the simpler
kernel when complete-path results differ by less than the plan's 2% gate.

`internal/r43x6/scalarmult_window_experiment_test.go` supplies a correctness
and scalar-cost seed, not an SIMD implementation or backend selector. It
contains full projective tables for radix 16 (`A..8A`) and radix 32 (`A..16A`),
along with separate table-build, scalar-loop, complete scalar-multiplication,
DSM, and verification benchmarks. The r51 candidate additionally implements
radix 64 (`A..32A`) in fixed allocation-free storage. The scalar model cannot predict
projective-cached SIMD register pressure, instruction-level parallelism,
shuffle cost, or x8 downclock behavior.

All radix recoders preserve the canonical scalar as an exact integer. They
must never silently replace it with an equality only modulo the prime subgroup
order: Dalek-strict accepts mixed-order points, where torsion makes that rewrite
observable. Tests reconstruct every recoding as an integer before curve
comparisons, cover the required carry and upper-bound scalars, and compare
against the vendored Edwards implementation on `P+T` for every canonical
torsion component.

Run the scalar reference phases with:

```sh
go test -run 'TestExperimental' ./internal/r43x6
go test -run '^$' -bench 'BenchmarkExperimental' ./internal/r43x6
```

On Zen 4, record table build and loop separately first, then complete `[k]A`,
complete DSM, and finally message-size/batch verification. Only the final two
levels can justify production selection.

The r51 forced-only component benchmark is:

```sh
go test -run '^$' -bench 'BenchmarkExperimentalIFMAFixedDSM' -benchmem ./internal/r51x5
```

It reports the prepared loop, cold arbitrary-key A-table construction plus the
loop while retaining B, and an explicitly labeled full-cold path that rebuilds
both tables. The full-cold number is diagnostic; normal verification must not
rebuild the fixed B table for every key or batch. Both x8 and two-x4 rows use
the same fixed scalar schedules and exact `[s]B+[-k]A` semantics. The current
two-x4 row invokes the two YMM groups sequentially from Go; it is a component
baseline, not yet a custom assembly schedule that interleaves both groups for
maximum instruction-level parallelism.

Every row reports `active-*-table-B` coordinate payload separately from
`physical-table-B` and `physical-workspace-B`, both derived from
`unsafe.Sizeof` for the concrete radix specialization. The architecture-neutral
footprint-only benchmark is `BenchmarkIFMATableFootprint`.
