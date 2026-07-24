# Experimental r51 Fixed-Base Comb

This experiment evaluates a wider fixed-base table for the Ed25519 generator
`B`. Its complete verifier artifact is private and compiled in normal source,
but remains unregistered and benchmark-only: production dispatch cannot
select it.

The central implementation choice is to store each `B` multiple once as a
scalar affine-cached point `(y+x, y-x, 2dxy)`. Public digits from four or eight
independent signatures are gathered into a temporary SoA cached point. The
table therefore does not duplicate identical `B` points across SIMD lanes.

This is separate from the arbitrary-key `A` table. Each lane has a different
public key, so the existing `A` table remains a per-lane SoA table and must be
built for cold keys (or supplied by a validated key cache). A shared `B` table
does not make that cost disappear.

## Comb shape and exact storage

The two-way comb stores positive multiples of
`[2^(2*w*i)]B`. It accumulates odd digits, performs `w` doublings, and then
accumulates even digits.

Each scalar affine-cached point occupies exactly `3 * 5 * 8 = 120` coordinate
bytes. The payload figures below exclude a 32-byte Go table descriptor on
64-bit platforms and allocator rounding.

| signed width | rounds | positions | entries/position | worst-case mixed adds | doublings | scalar shared-B payload | fraction of 32 KiB L1D |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 4 | 64 | 32 | 8 | 64 | 4 | 30,720 B (30 KiB) | 93.75% |
| 5 | 51 | 26 | 16 | 51 | 5 | 49,920 B (48.75 KiB) | 152.34% |
| 8 | 32 | 16 | 128 | 32 | 8 | 245,760 B (240 KiB) | 750% |

The width-8 table is **one process-shared/read-only B table**, not 240 KiB per
public key and not 240 KiB per x8 group. A layout that duplicated the same
cached coordinates in every x8 lane would instead consume 240 KiB, 390 KiB,
and 1,920 KiB for widths 4, 5, and 8 respectively.

The current x8 radix-32 arbitrary-point table uses 20,480 B of four-coordinate
payload. Thus the group-arithmetic benchmark has these combined table working
sets:

| design | x8 table payload |
|---|---:|
| current shared-doubling B + A, both radix 32 | 40,960 B (40 KiB) |
| radix-32 A + scalar shared-B width 4 | 51,200 B (50 KiB) |
| radix-32 A + scalar shared-B width 5 | 70,400 B (68.75 KiB) |
| radix-32 A + scalar shared-B width 8 | 266,240 B (260 KiB) |

Only the width-4 B payload nominally fits in a Zen 4 32 KiB L1D, and it leaves
too little room for the accumulator, scalar schedules, A table, hash state,
and concurrent verifier data. Width 5 and especially width 8 deliberately
trade L1 residency for fewer mixed additions. The width-8 random lookup set
should be treated as an L2-resident candidate until target counters prove
otherwise.

## Arithmetic and semantics

The mixed addition consumes the three cached coordinates and costs seven field
multiplications in the current extended-coordinate formula. Scalar recoding is
fixed-storage and supports widths 4, 5, and 8. It:

- accepts only canonical 32-byte scalars below `L`;
- preserves the exact nonnegative integer represented by `s`;
- returns an explicit usable-lane mask;
- writes identity to inactive and invalid lanes;
- performs no heap allocation during evaluation.

The implementation has scalar x4/x8 paths and hardware-gated composable IFMA
x4/x8 paths. Table selection is intentionally variable-time in public
verification scalars. Production dispatch remains unchanged.

Tests compare against independent Edwards scalar multiplication for random and
boundary scalars, every lane/tail shape, x8 versus two x4 groups, and an
order-four torsion base. A separate test verifies that splitting `[s]B` from
the variable-base `-[k]A` loop matches the current shared-doubling DSM result.

## What the local model says

The complete group-arithmetic comparison keeps `A` on the current radix-32
doubling chain, evaluates `B` with the comb, and includes the final point add.
On an Apple M4 Pro scalar model (`-benchtime=750ms -count=3`), medians were:

| design | x8 time | result versus current |
|---|---:|---:|
| current shared-doubling radix-32 DSM | ~1.92 ms | baseline |
| split B, width 4 | ~1.92 ms | roughly even |
| split B, width 5 | ~1.86 ms | about 2.7% faster |
| split B, width 8 | ~1.79 ms | about 6.8% faster |

These revised split rows use a true one-table arbitrary-A workspace; they do
not retain or recode a dummy identity term. The direct scalar selection cost
was roughly 95--101 ns per x8 cached point, and all timed evaluators reported
zero allocations.

The correctness-first runtime builder performs two setup allocations (the
32-byte descriptor plus the backing table allocation) and normalizes entries
individually. On the same M4 it took about 3.5 ms, 5.6 ms, and 27 ms for widths
4, 5, and 8. That is a one-time shared-B setup cost, not a per-signature or
per-key cost. A production candidate should use generated read-only constants
or batch normalization, then measure startup and binary-data costs separately.
This table is not a substitute for hot-public-key A-table caching.

The forced complete verifier also composes the one-table A workspace with the
shared B comb for x4, x8, and two-x4 paths. Tables of a given width are built
once with `sync.Once` and shared across non-concurrent worker workspaces, so a
future worker pool would not duplicate the 30--240 KiB immutable B payload.

These are scheduling-model results, not Zen 4 performance evidence. The
width-8 result is especially exposed to target-specific L1/L2 behavior. It
must not drive dispatch without the hardware-gated IFMA benchmark on the Ryzen
7 PRO 8700GE and a complete verifier benchmark that includes decode, SHA-512,
scalar reduction, the arbitrary-key A table, equality, stack traffic, and
normal worker concurrency. A complete-path improvement below 2% should be
rejected even if standalone `[s]B` improves.

Exact benchmark regexes:

```text
GOMAXPROCS=1 go test ./internal/r51x5 -run '^$' \
  -bench 'BenchmarkExperimentalFixedBaseComb(Build|SelectionX8|ScalarMult)$' \
  -benchtime 3s -count=10

GOMAXPROCS=1 go test ./internal/r51x5 -run '^$' \
  -bench 'BenchmarkExperimentalFixedBaseCombCompleteDSMTradeoffX8$' \
  -benchtime 3s -count=10
```

The `ifma/...` sub-benchmarks are emitted only when AVX-512 IFMA is available.

## Code footprint

The table is generated at setup time, so the experiment embeds no 30--240 KiB
basepoint blob in `.rodata`. In a Go 1.25.5 linux/amd64 test binary, the
contiguous implementation text from table construction through the final IFMA
mixed-add helper measured 17,536 bytes. The four evaluator entry points were
832 B (scalar x4), 800 B (scalar x8), 928 B (IFMA x4), and 928 B (IFMA x8).
These linker-symbol measurements are toolchain/build dependent. Because no
production path references the experiment, normal linker dead-code elimination
can omit it; any future production/static-table version must remeasure both
`.text` and `.rodata` on the release toolchain.
