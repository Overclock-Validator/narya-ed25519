# 5x51 lane-per-signature IFMA track

This is the correctness and benchmark plan for Narya's throughput backend.
It is deliberately separate from `internal/r43x6`:

| Backend | Vector interpretation | Intended job |
|---|---|---|
| r43x6 | six limbs of one field element in a vector | single-signature latency and a forced correctness baseline |
| r51x5 x4/x8 | one signature per SIMD lane, five vectors per field element | batch throughput |

Neither representation is an automatic production choice. The Ryzen 7 PRO
8700GE measurements decide the first dispatch policy.

The representation is supported by independent implementation evidence:
[ENG25519](https://www.usenix.org/conference/usenixsecurity24/presentation/zhang-jipeng)
uses radix 2^51 with AVX-512IFMA, and the
[Eclipse throughput report](https://www.eclipselabs.io/blogs/breaking-10-million-tps)
describes five 51-bit limbs with signatures transposed across eight lanes.
Those sources motivate this candidate; neither establishes Narya's exact
predicate or its performance on Zen 4.

## Layout

An x8 field value is a structure of arrays:

```text
limb 0: a0[0] a0[1] ... a0[7]
limb 1: a1[0] a1[1] ... a1[7]
...
limb 4: a4[0] a4[1] ... a4[7]
```

Each lane represents

```text
a0 + a1*2^51 + a2*2^102 + a3*2^153 + a4*2^204  (mod 2^255-19).
```

The x4 form uses the same limb order with four lanes. Packing, arithmetic,
table lookup, hashing, scalar recoding, and verdict extraction must preserve
lane identity. Every invalid-lane position is tested independently.

The first reference type stores canonical limbs. The experimental
`IFMAElementX4/X8` types store composable, non-canonical representatives with
every limb below 2^52. The private limb storage makes the range part of the
type invariant. `folded` never means canonical by itself.

## IFMA multiplication identity

`VPMADD52LUQ/HUQ` naturally splits a product at bit 52. The field radix is
still 51, so the reduction schedule must account for that one-bit offset.
For a full nine-coefficient convolution, coefficients 5 through 8 fold into
0 through 3 using

```text
2^(51*5) = 2^255 = 19  (mod p).
```

For a coefficient represented as `lo + 2^52*hi`, its radix-51 carry is

```text
(lo >> 51) + 2*hi.
```

For u52 multiplicands, the low/high-half schedule bounds convolution degrees
0 through 9 by respectively 1, 4, 7, 10, 13, 14, 11, 8, 5, and 2 terms of
less than 2^52. Folding gives output weights 267, 213, 159, 105, and 51, so
every raw output limb is strictly below 267*2^52 < 2^61. All assembly
accumulators and the 19x fold therefore remain below uint64 overflow.

One radix-2^51 carry pass returns that u61 product to the composable domain.
Carries are at most 1024. Limbs 1 through 4 finish below 2^51; limb zero
finishes below

```text
2^51 + 19*1024 < 2^52.
```

Addition enters the normalizer below 2^53. Subtraction and negation add four
copies of p limb-wise before subtracting, entering below 6*2^51 < 2^54 with
no unsigned underflow. These bounds enable chained extended-coordinate add
and double formulas without canonical reduction between multiplications.

## Table footprint is layout-dependent

For eight independent keys, a radix-32 16-entry table with four coordinates
occupies

```text
16 entries * 4 coordinates * 5 limbs * 8 lanes * 8 bytes = 20 KiB.
```

That arithmetic is useful but conditional. A three-coordinate cached/Niels
form is 15 KiB; alignment, digit-selection scratch, and any duplicated signed
entries add to it. Benchmarks report the actual allocated and touched bytes,
not just the nominal coordinate payload.

The current experimental implementation does not reserve the radix-64 maximum
for smaller radices. Its composable table type is specialized over fixed
8/16/32-entry arrays without an unsafe union. On a 64-bit Go target, the exact
x8 physical table sizes are:

| radix | active coordinate payload | physical table (`unsafe.Sizeof`) |
| ---: | ---: | ---: |
| 16 | 10,240 B | 10,256 B |
| 32 | 20,480 B | 20,496 B |
| 64 | 40,960 B | 40,976 B |

The 16-byte difference is table metadata. Builders write every active entry
and that metadata, but do not clear inactive capacity first. The ordinary
two-table x8 workspace additionally owns fixed digit schedules, making its
physical sizes 21,800 / 42,280 / 83,240 bytes. Benchmark metrics name active
payload and physical table/workspace sizes separately; they do not claim that
every retained byte causes a cache miss.

The ordinary radix-64 candidate doubles the positive table to 32 entries:

```text
x4 four-coordinate table: 20 KiB
x8 four-coordinate table: 40 KiB
two x8 point tables:       80 KiB
```

Its loop has 43 fixed rounds instead of 51 for radix 32, but the larger cold-A
build and L1 footprint are included in the complete benchmark. HEEA continues
to benchmark radix 16/32 in the complete harness. A radix-64 HEEA storage
specialization exists for footprint/correctness experiments, but that does not
make it a selected QSM candidate.

The cold path includes table construction. Cache benchmarks distinguish:

1. compressed key only;
2. decoded point;
3. backend-native precomputed table.

No tier or admission threshold is enabled from a synthetic cache-hit result.
Mithril recurrence traces select policy after arithmetic stabilizes.

An x8 SoA table is a batch object, not a per-key cache entry: its eight lanes
normally contain tables for eight independent public keys. A radix-32,
four-coordinate table therefore has a 2,560-byte coordinate payload per key
and a 20,480-byte payload only after eight keys have been packed together.
Caching one 20 KiB x8 table for each hot key would either waste seven lanes or
incorrectly bind unrelated future batches to the original lane group. A real
precomputation cache must instead retain a per-key scalar/native table (or only
the decoded point), then measure the cost of packing the current batch into
SoA form. Replicating one key across all lanes is a separate same-key batching
optimization and is eligible only when the trace shows that grouping occurs
naturally without added latency.

## Implementation sequence

1. Pure-Go scalar and x4/x8 SoA models with canonical pack/unpack and
   differential field tests.
2. Runtime-gated x8 and x4 IFMA multiply/square correctness kernels. Normal
   backend selection remains unchanged.
3. Loose-range add/subtract/negate and extended-coordinate point formulas.
4. Paired A/R decompression across lanes, preserving the permissive decoder
   and the original compressed bytes.
5. Regular signed radix-16, radix-32, and ordinary-path radix-64 DSM including
   per-key table build.
6. Segmented SIMD SHA-512 and digest reduction, proved equivalent before
   fusion.
7. Exact signed four-term QSM for the optional modulo-8L HEEA path.

## Current correctness checkpoint

The first, second, third, fourth, fifth, and seventh items now have reference
implementations, with an important performance boundary:

- scalar and SoA x4/x8 field and extended-point models provide independent
  lane packing, permissive decoding, group arithmetic, projective/affine
  equality, and verdict-mask oracles;
- real ZMM x8 and AVX-512VL/YMM x4 `VPMADD52` kernels implement reduced-input
  multiplication and expose a proved non-composable u60 folded result;
- the same kernels accept named u52 composable inputs, produce a proved u61
  raw product, and restore u52 with one non-canonical carry/fold pass;
- typed x4/x8 composable point-add and point-double formulas can be chained
  directly; randomized field, torsion/mixed-order point, every-lane, alias,
  and x4-versus-x8 tests compare them with canonical reference arithmetic;
- checked x4/x8 point-add, point-double, and projective/affine helpers exercise
  those kernels, but canonically reduce after every multiply and are therefore
  correctness bridges rather than final schedules;
- paired x4/x8 lane-decompression references retain full A and compact affine
  R, preserve independent validity masks and permissive decoding, and allocate
  no heap memory. Forced-only IFMA counterparts now run both independent
  `pow22523` chains in the composable u52 domain, interleaving corresponding A
  and R operations and reducing only at root classification/sign selection and
  the final public output boundary;
- regular signed radix-16, radix-32, and radix-64 references include cold table building,
  round-major digits, direct SoA public table selection, masked tails, and
  every-lane tests. Forced-only x4/x8 IFMA DSM workspaces build both positive
  tables with composable point additions and keep selected points and the
  shared-doubling accumulator in the u52 domain. Fixed B preparation is
  separate from cold per-key A preparation, and exact negative digits preserve
  `-k` rather than substituting `L-k`; and
- a dormant, unregistered complete batch verifier now connects strict byte predicates,
  canonical S, segmented hashing of the original bytes, canonical challenge
  reduction, paired A/R decode, two-term exact-integer DSM, compact-affine
  strict equality, and compatibility encoded-Q equality. CCTV, Wycheproof,
  x4/x8, ordinary radix-16/32/64, every-lane, tail, and randomized mixture tests all run
  through this boundary, including the ordinary radix-64 candidate; and
- the four-slot QSM accepts arbitrary-width signed integers and implements the
  exact modulo-8L HEEA equation without reducing A/R multipliers modulo L; and
- a forced strict HEEA verifier now carries selector admission and fallback
  masks atomically into a fixed-storage x4/x8 QSM, with a non-IFMA complete
  semantic oracle and a same-harness benchmark against ordinary r51 DSM. Its
  lane misses use retained radix-32 ordinary r51 workspaces of the same SIMD
  width, reusing decode/hash results; kernel errors remain explicit and clear
  all verdicts rather than being disguised as lane fallback.

None of this changes backend dispatch. The forced complete verifier now
connects the paired IFMA decompressor, native x4/x8 SHA-512, fixed-storage
challenge reduction, composable IFMA DSM, and both final-equation forms. Its
x4, true-x8, and two-x4 paths are allocation-free and include cold arbitrary-A
table construction in the timed boundary. A second complete-path candidate
splits `[s]B` into the scalar-stored shared comb and keeps exactly one SoA table
for `-[k]A`, so wider-B measurements no longer retain a dummy identity table.

The public batch dispatcher has a private optional raw-slice backend contract.
The forced candidate benchmarks enter through that contract, including public
length/dispatch checks, instead of bypassing the wrapper while charging the
generic baseline for a `batchItem` allocation. Cache batches deliberately keep
the item path because lookup results are per signature. No registered backend
or automatic selection uses the raw contract yet.

### Promotion boundary

The complete ordinary verifier kernel now lives in
`ed25519/backend_r51experiment.go`, a normal non-`_test.go` compilation unit.
This makes the x8/two-x4, radix-16/32/64, and fixed-B-comb code exercised by
the complete-pipeline benchmarks the exact private artifact that could later
be registered after the release gates pass. It is not a second test-only copy.

That move does **not** enable the artifact. The file has no `init`, implements
no registered backend, exposes no public API, and is unreachable from
`SetBackend`, automatic selection, and production `Verify`/`VerifyBatch`
calls. The raw-dispatch adapter, fixtures, assertions, fuzz entry point, and
benchmarks remain in `backend_r51ifma_test.go`. A registration-boundary test
checks both that automatic selection stays `generic` and that no r51 adapter
appears in the backend registry.

The remaining Go carry/fold, field add/subtract, scalar unpacking, digest
compaction for the two-x4 reducer, final mask work, and compiler-selected spills
are still correctness-first schedules. Every IFMA multiplication carry/folds
and validates its raw output before reuse. Zen 4 hardware execution and
profiling—not source-level operation counts—must decide whether any of these
forced candidates deserve production dispatch. A fused native scalar reducer
or tighter carry/add/sub assembly remains optional follow-up only if the full
profile shows those stages are material.

## x8 versus two x4 groups

Zen 4 executes 512-bit vector work through narrower execution resources, but
that does not determine the complete result. One x8 kernel can reduce decoded
instruction, loop, and packing overhead; two independent x4 groups can expose
more scheduling freedom and may have different register or frequency costs.
Measure both implementations on the same inputs and active lane counts 1--17.

The x8 candidate wins dispatch only when complete verification, including
packing, table construction, hashing, tails, and verdict mapping, is at least
2% better. If the difference is smaller, select the simpler implementation.
The checked-in numerical evaluator applies that rule coherently across all
release message sizes rather than choosing a different path for every row.

Single-core results are followed by
`BenchmarkR51IFMAPipelineParallel`, which runs all twelve complete
release-candidate configurations (shared-B radix 16/32/64 and radix-32 with
comb16/32/256 for each x8/two-x4 shape) at n=8/64 and release message sizes.
`GOMAXPROCS` determines
the number of concurrent verifier workers. Each worker owns a separately
prepared mutable pipeline and verdict buffer; only input bytes and the
immutable scalar B-comb table are shared. This measures concurrent table/cache
pressure without making the forced pipeline concurrent or changing backend
dispatch. The release evaluator chooses one coherent worker configuration
across both counts and all release messages. It first requires that exact
configuration to clear the serial 15% batch gate at n=8 and n=64, admits
optional radix/comb variants only after a 2% complete-path win over the same
path's radix-32/shared-B baseline in both the serial and worker matrices, and
requires at least a 15% win over a same-harness concurrent stdlib loop. It also
rejects a greater than 1% wall-ns/op regression versus that identical serial
configuration or an increase in either B/op or allocs/op. Release evidence
uses at least two workers:

```text
taskset -c 0-7 env GOMAXPROCS=8 go test -run '^$' \
  -bench '^BenchmarkR51IFMAPipelineParallel$' -benchmem \
  -benchtime=3s -count=10 ./ed25519
```

The optional W132/radix-32 HEEA experiment repeats its x8/two-x4 n=8/64
release matrix with `BenchmarkR51HEEACompletePipelineParallel`. HEEA promotion
is evaluated only after the ordinary worker winner is known. The same HEEA
shape must beat that exact ordinary configuration by at least 5% in every
serial and worker row without increasing allocations. Its old same-path
radix-32 ordinary row is diagnostic and cannot serve as a promotion baseline
when a radix-64 or fixed-B-comb ordinary configuration wins.

The companion `BenchmarkR51HEEACompletePipelineFallback` matrix uses W132,
not the earlier W128 diagnostic width. At n=8 it covers every possible single
fallback lane and an all-fallback group for both SIMD shapes and every release
message size. Promotion is fail-closed if any case is more than 5% slower than
the exact selected ordinary n=8 configuration, or increases B/op or allocs/op.

The standalone x4 path remains a diagnostic/tail benchmark. For batches of at
most four, two-x4 already runs only its first x4 half, so adding x4 to the
release matrix would duplicate that measured kernel while inventing a third
top-level dispatch policy outside the x8-versus-two-x4 decision.

## Semantic boundary

The throughput backend receives the selected verification profile. It must
not infer strictness from a batch call. For `DalekStrict` it preserves:

- canonical `S`;
- permissive, possibly noncanonical `A`;
- canonical `R`;
- exact rejection of small-order `A` and `R` aliases;
- acceptance of mixed-order non-small-order points;
- `H(original R || original A || message)`;
- the cofactorless full-group equation.

The existing generic encoded-Q equation and slow small-order checks remain
independent test oracles. `StdlibCompat` must not inherit strict prechecks.

## Gates

The implementation stays private, unregistered, and benchmark-only until it has:

- zero corpus, fuzz, mixed-order, and lane-mask mismatches;
- hardware execution on Zen 4 (a skipped test is not a result);
- complete-verifier x8 versus two-x4 measurements;
- release-size rows at 64, 200, and 1232 bytes plus diagnostic rows at 176,
  512, and 1024 bytes;
- no allocation increase or greater than 1% regression in the identical public
  StdlibCompat harness compiled against the frozen pre-plan revision and the
  current source tree;
- the repository's cold and batch performance thresholds.

Published throughput from a different verifier is architectural evidence,
not a performance or consensus-semantic gate for Narya.

The hardware fuzz pass inserts an arbitrary tuple at a selected position in
batches of 1--17/32/64 signatures while the other lanes contain distinct
valid, equation-invalid, and precheck-invalid inputs. It runs radix 16, 32,
and 64 through true x8 and two-x4 via the public-shaped raw batch dispatcher;
the deterministic every-lane corpus remains an independent check.

Run the hardware-gated primitive and complete-operation comparisons with:

```text
taskset -c 2 env GOMAXPROCS=1 go test -run '^$' \
  -bench 'Benchmark(ExperimentalIFMA|RegularRadix)' -benchmem \
  -benchtime=3s -count=10 ./internal/r51x5

taskset -c 2 env GOMAXPROCS=1 go test -run '^$' \
  -bench '^BenchmarkR51ReferenceBatch$' -benchmem \
  -benchtime=3s -count=10 ./ed25519
```

`BenchmarkExperimentalIFMADecode2NoT` reports paired-interleaved, paired with
sequential power chains, and two-complete-decoder controls, plus active x8
tails, x4, and two-x4 groups. Checked-every-multiply x4/x8 controls quantify
the input-scan overhead removed from the candidate schedule. Those rows measure
the decompressor only; the complete verifier remains the dispatch gate.

An `ErrIFMAUnavailable` result or skipped hardware test is not a Ryzen result.
