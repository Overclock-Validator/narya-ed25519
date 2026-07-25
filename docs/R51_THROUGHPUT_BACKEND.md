# 5x51 lane-per-signature IFMA track

This is the correctness and benchmark plan for Narya's throughput backend.
It is deliberately separate from `internal/r43x6`:

> **Current status.** The reviewed Zen 4/Zen 5 composition is registered as
> backend `r51` for explicit selection. Automatic selection remains `generic`.
> `r51` uses a packed paired-A/R singleton plus a radix-32 A table, the shared
> radix-256 B comb, and batch-Q finalization. Zen 4 uses two x4/YMM groups;
> AMD family 1Ah (Zen 5) uses x8/ZMM for complete eight-signature groups and
> x4 for the tail. Warm per-key comb and HEEA variants remain experiments.

| Backend | Vector interpretation | Intended job |
|---|---|---|
| r43x6 | six limbs of one field element in a vector | single-signature latency and a forced correctness baseline |
| r51x5 x4/x8 | one signature per SIMD lane, five vectors per field element | batch throughput |

Neither representation is an automatic global backend choice. Measurements on
the Ryzen 7 PRO 8700GE selected x4-oriented r51; measurements on the Ryzen 7
9700X selected x8 for complete groups by about 32--33% at 1232-byte messages.
The registered forced backend now chooses that internal width using CPUID
vendor/family rather than the shared IFMA feature bit. Every x8 differential
remains enabled on both targets, and x4 remains the tail and rollback shape.

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

Table footprint alone did not predict measured selection cost on Zen 4. A
dense full-lane x8 selector stayed near 206 ns for radix 16, 32, and 64 even
though the per-table footprint grew from 10 to 40 KiB. Removing the temporary
identity and final full-point copy reduced it to roughly 159--160 ns and
improved complete x8 verification by about 2.4%. Therefore the private
internally-recoded path writes directly into non-aliasing output, while the
checked public selector remains the safety oracle. A lane-contiguous packed
table is deferred: it would require transposing back into the SoA vectors
consumed by IFMA addition. The dense benchmark uses predictable accesses to
one table, while the real DSM alternates two tables with irregular public
digits, and privileged PMU counters are unavailable; current timing therefore
does not establish L1/L2 traffic as the bottleneck.

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

### Same-key grouping and batch-local preparation reuse

Keep same-key grouping as a measurement-gated scheduling candidate, distinct
from a persistent key cache. A dispatcher may inspect only work already
available in its nonblocking drain, group exact repeated public-key byte
strings, carry an original-result index through the permutation, and send all
resulting `Q` points through the same cross-group finalizer. It must never wait
for another occurrence merely to fill a same-key group.

An all-same-key x4 group does **not** by itself imply that three x4 decodes or
three table builds disappear. The current lane-parallel decoder and radix-64
builder already execute four independent keys with one SIMD instruction
schedule; duplicating one key in every lane ordinarily executes that same
schedule. A claimed `4 decodes -> 1` or `4 builds -> 1` speedup therefore needs
a different measured implementation, not an operation-count assumption.

The more credible opportunities are:

1. one raw key occurs in multiple x4 groups in the same drained dispatch, so
   one batch-local decoded point or scalar/native table can be reused by later
   groups;
2. a retained backend-native table can be packed or selected more cheaply when
   every lane uses the same base; or
3. a scalar-stored table plus lane-specific digit selection is cheaper than
   rebuilding duplicate SoA state.

The scalars remain independent, so same-base lanes can request different table
entries in the same round. A broadcast-table design must include that
selection and packing cost; it cannot assume that one selected entry is shared
by all lanes. Grouping and table reuse also must preserve the original public
key bytes in `H(R || A || message)`. Use the complete raw `[32]byte` key (or a
hash followed by a complete raw-key collision check), never an unchecked
prefix such as the first eight bytes.

A bounded, allocation-free scheduling experiment should compare:

- all-distinct keys as the no-benefit and adversarial-overhead control;
- one same-key x4 group;
- the same key spanning 2, 4, 8, and 16 x4 groups;
- naturally clustered and randomly interleaved occurrences;
- cold batch-local decoded-point reuse, prepared-table reuse, and the ordinary
  independent-key path; and
- scheduler-only time separately from complete verification time.

Extract same-key work before cold/warm phase compaction, but do not split it
into a separate verifier call that loses cross-group inversion amortization.
Unprofitable remainders return to the ordinary full-occupancy path. All-distinct
traffic must degrade to one bounded classification pass, zero heap allocation,
and no persistent admission, so rotating-key spam cannot pollute a cache.

Mithril scheduling-simulation traces already report naturally contiguous x4
and x8 same-key groups. Before implementing a broadcast kernel, extend the
analysis to report the number of full same-key x4 groups obtainable by
regrouping *within each existing dispatch* and the number of keys spanning
multiple x4 groups. This estimates batch-local reuse without pretending that
work from different dispatches can be combined. Keep the candidate only if it
improves the complete selected verifier by at least 2% on a representative
trace, retains exact predicates and result mapping, and adds no batching wait.

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
- a complete batch verifier connects strict byte predicates, canonical S,
  segmented hashing of the original bytes, canonical challenge reduction,
  point decoding, exact-integer DSM, and profile-specific final equality.
  The selected forced backend decodes only A for full x4 groups and
  batch-encodes Q; the paired A/R form remains the strict singleton path and a
  complete comparison oracle. CCTV, Wycheproof, x4/x8, ordinary
  radix-16/32/64, every-lane, tail, and randomized mixture tests all run
  through this boundary; and
- the four-slot QSM accepts arbitrary-width signed integers and implements the
  exact modulo-8L HEEA equation without reducing A/R multipliers modulo L; and
- a forced strict HEEA verifier now carries selector admission and fallback
  masks atomically into a fixed-storage x4/x8 QSM, with a non-IFMA complete
  semantic oracle and a same-harness benchmark against ordinary r51 DSM. Its
  lane misses use retained radix-32 ordinary r51 workspaces of the same SIMD
  width, reusing decode/hash results; kernel errors remain explicit and clear
  all verdicts rather than being disguised as lane fallback.

The selected composition now changes explicitly forced `r51` dispatch, but
not automatic dispatch. It connects the packed strict singleton, native x4/x8
SHA-512, fixed-storage challenge reduction, composable radix-32 A DSM, the
process-shared radix-256 B comb, and cross-group Q encoding. The broader
alternate-radix, table, HEEA, and warm-comb matrix remains allocation-free
benchmarking infrastructure. Cold rows include arbitrary-A table construction.

The public batch dispatcher has optional ordinary and cache-aware raw-slice
backend contracts. The registered forced `r51` backend and candidate
benchmarks enter through those contracts, including public length/dispatch
checks, instead of allocating `batchItem` records. The cache-aware form keeps
lookup, exact-key binding, verdicts, and post-valid-miss admission allocation
free. Its immutable decoded-A entry is 192 bytes; it never replaces the
original A bytes used by the challenge hash.

Complete Cache A/B measurements enable this decoded-A tier only when
`cpufeat.PreferWideIFMA()` selects native-wide Zen 5. Zen 4 reports
`supportsPrecomp() == false`, so `Cache.VerifyBatchStrict` bypasses cache
bookkeeping and uses the ordinary raw r51 path. On Zen 5, all-hit chunks of
width at least four use decoded A; mixed hits are admitted to the prepared path
only for a complete 64-item chunk at at least 25% density. Automatic backend
selection still does not use either raw contract.

### Promotion boundary

The complete ordinary verifier core lives in
`ed25519/backend_r51experiment.go`, a normal non-`_test.go` compilation unit;
`ed25519/backend_r51.go` registers and pools the selected composition. The
same normal-source core continues to expose the wider x8/two-x4,
radix-16/32/64, and fixed-B-comb matrix to complete-pipeline benchmarks, so
there is no divergent test-only implementation. Tests require automatic
selection to remain `generic`, hardware activation to fail closed, and forced
`r51` to preserve every public profile and batch contract.

The remaining Go carry/fold, field add/subtract, scalar unpacking, digest
compaction for the two-x4 reducer, final mask work, and compiler-selected spills
are still correctness-first schedules. Every IFMA multiplication carry/folds
and validates its raw output before reuse. Zen 4 and Zen 5 hardware execution
selected the current width-specific forced composition; the same complete-path
measurement rule still decides whether any additional candidate belongs in
dispatch. A fused native scalar reducer or tighter carry/add/sub assembly
remains optional follow-up only if a complete profile shows those stages are
material.

## x8 versus two x4 groups

Zen 4 measurements kept two x4 groups: x8 improved complete wide verification
by only about 1%, below the keep threshold. Zen 5 measurements selected x8:
at 1232-byte messages the complete x8 path measured about 8.2 us/signature at
n=64 versus about 12.2 us for two-x4. Public-wrapper measurements stayed within
2% of the private core and allocated zero.

The width rule is deliberately a step: on Zen 5, every complete eight-lane
group uses x8 and the remainder uses x4; Zen 4 uses x4 throughout. A half-full
x8 group pays roughly 96% of full-group cost, so masked arithmetic cannot make
it occupancy-elastic. Leading-zero shortening, vector-wide sparse-digit
skipping, and an x4-by-two hybrid do not beat the existing x4 tail on the
measured cost bound. Cross-call lane refill can reduce how often a tail exists,
but belongs to a latency-aware caller/integration queue rather than this
cryptographic backend.

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

### Zen 5 bring-up contract

Zen 5 bring-up is complete inside forced `r51`: CPUID vendor/family selects x8
only for AMD family 1Ah and newer, complete groups use the native x8 core, and
tails reuse x4. Unknown IFMA machines conservatively retain x4. This does not
change the global automatic backend, which remains `generic`.

Comb parameters are part of the lane-width candidate configuration, not global
constants. Eight live signatures roughly double the distinct per-key A-table
working set relative to x4, while cheaper native-width arithmetic can change
the best doubling/table tradeoff. Zen 5 must therefore re-sweep `(w_A,r_A)`
and `(w_B,r_B)` rather than inheriting Zen 4's choice.

The per-key storage format remains independent of an x4 batch object. The x4
four-source transpose is not assumed to widen mechanically to eight sources;
an x8 selector needs its own measured packing schedule. The previously proposed
two-signatures-by-four-coordinates ZMM hybrid is not a current candidate. Its
optimistic arithmetic bound merely reaches the measured x4 tail while adding
another carry schedule and table layout. Revisit it only if a future formula or
microarchitecture invalidates that bound.

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

The selected cold x4 composition has crossed the explicit-registration gate.
Every additional variant remains private and benchmark-only until it has:

- zero corpus, fuzz, mixed-order, and lane-mask mismatches;
- hardware execution on its target microarchitecture (a skipped test is not a
  result);
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
