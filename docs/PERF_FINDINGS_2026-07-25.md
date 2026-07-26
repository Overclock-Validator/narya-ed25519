# Performance findings and open opportunities — 2026-07-25

Written alongside branch `claude/narya-perf`. Measurements are in
`docs/ZEN5_9700X_2026-07-25.md`; this document is the reasoning, the structural
constraints found while integrating, and what is worth doing next.

The original warm-comb measurements below were taken on Zen 5 (Ryzen 7 9700X).
Subsequent convergence gates also measured the promoted cold path, decoded-A
tier, occupancy crossover, and HEEA screen on Zen 4 (Ryzen 7 PRO 8700GE).
Architecture-specific conclusions are labeled rather than transferred between
the two CPUs.

## Current cold-path convergence checkpoint

The later `7layer/narya-convergence` work changed the cold Zen 5 baseline
substantially. These rows are the exported forced-r51 path at n=64,
msg=1232, one pinned 9700X core, `GOMAXPROCS=1`, and zero allocations:

| checkpoint | us/signature | change from preceding row |
|---|---:|---:|
| pre-traffic-removal baseline | 7.291 | — |
| direct outputs plus reusable double/add scratch (`e594ada`) | 6.617 | -9.2% |
| exact 160-byte micro-AoS A tables (`db2807e`) | 6.404 | -3.2% |
| pre-signed micro-AoS A tables (`997d9b9`) | 6.072 | -5.2% |
| unchecked x4/x8 linear point ops (`3499fdd`) | 5.782 | -4.8% |

The micro-AoS and pre-signed values are medians of ten two-second public-API
samples; the unchecked-linear row is the median of the six-sample A/B below. The
micro-AoS record is exactly `[5][Y+X,Y-X,Z,2dT]uint64` (160 bytes), and its
assembly performs five exact 32-byte loads at offsets 0, 32, 64, 96, and 128.
It does not issue a 64-byte tail load or read beyond the record. Pre-signing
doubles the per-worker cold A-table workspace from about 20.6 to 40.6 KiB, but
the complete cold build+loop still improved by about 7.2%; this is why it was
admitted rather than judged from the prepared loop alone.

After pre-signing, a CPU profile attributes only 1.8% cumulatively to the
selector and 1.1% flat to the transpose. The runtime Niels-negation symbol is
gone. `ls_bad_status2.stli_other / ls_dispatch.ld_dispatch` moved only from
about 5.28% to 5.03%, showing that most remaining store-forwarding failures are
outside selection. A selector-to-first-multiply fusion is therefore deferred:
it should be reopened only if a future profile again puts material time in
selection or an isolated exact prototype improves the complete verifier by at
least 1%. The larger next target is point doubling, which remains about 45.5%
cumulative in the post-selector profile.

Experiment regime tags matter. The earlier micro-AoS production A/B regressed
on the pre-scratch x8 loop and was reverted; the same exact layout wins after
the double/add workspaces stopped being re-zeroed every operation. Keep both
records rather than treating either result as timeless.

The unchecked-linear checkpoint came from a generated-assembly audit: the
portable `IFMAElementX4/X8` methods reserved 496/976-byte frames even though
the native branch never used their raw fallback product. Splitting those
fallbacks reduced the wrapper frames, while the already-IFMA-gated point
schedules now call the same audited native add/subtract/negate leaves directly,
just as they already did for multiplication. A same-host public-API A/B at
msg=1232, six two-second samples per row, measured:

| width | before us/signature | `3499fdd` us/signature | change |
|---:|---:|---:|---:|
| 1 | 22.86 | 22.85 | neutral |
| 2 | 22.91 | 22.88 | about -0.1% |
| 4 | 12.81 | 12.60 | about -1.7% |
| 8 | 6.40 | 6.10 | about -4.7% |
| 64 | 6.073 | 5.782 | about -4.8% |

All rows remained zero-allocation. Widths one and two use the separate packed
singleton/tail kernel, so their neutral result is expected. The n=4 row is the
primary small-batch gate; n=8 and n=64 retain the full-width throughput check.

The x4 full-add still copied both 640-byte inputs and then copied a 640-byte
result even though its inputs are dead before final output. Existing native
tests already covered both `out==left` and `out==right`. Promoting the proven
input-copy removal moved n=4 from about 12.60 to 12.46 us/signature; writing the
four final products directly to `out` moved it again to 12.36--12.37. Commit
`c6c27c3` contains both changes. Ten two-second public-API samples remained
zero-allocation, and n=4 is about 3.5% faster than the 12.81-us pre-wrapper
baseline. Full x8 groups do not execute this x4 add, so this is intentionally a
small-batch/tail optimization rather than a new n=64 headline.

The next n=4 profile put `conditionalNegateIFMAElementX4` at about 4.1%
cumulative. The old implementation built a 320-byte raw product in scalar Go,
selected `x` or `bias-x` lane by lane, and then called the native normalizer.
The admitted replacement performs the same public-mask blend and the same
carry/fold pass entirely in YMM registers. It deliberately normalizes both
selected and unselected lanes, preserving the portable reference bit for bit;
all five input limbs are loaded before the first store, preserving in-place
aliasing.

A paired same-core public-API gate at n=4/msg=1232, six two-second samples per
side, measured 12.33 us/signature for exact commit `0dfa3d1` and 11.82
us/signature for the native masked implementation: **-4.1%**, 0 B/op, and 0
allocs/op. The existing direct oracle exhausts all 16 public masks over zero,
maximum-u52, and mixed boundary fixtures; it passed on the Zen 5 hardware, as
did the complete native r51 and Ed25519 suites. The requested follow-up width
matrix measured 22.41--22.43 (n=1), 22.50--22.51 (n=2), 11.80 (n=4), 6.14
(n=8), and 5.82 (n=64) us/signature. The n=1/2 packed path and complete x8
groups are structurally unaffected, so only n=4 is used to attribute the gain.

The remaining scalar x4 lane gather measured 34.4--35.5 ns per four-lane
selection, while the existing exact 160-byte micro-AoS transpose measured 5.94
ns with one 20 KiB table set and about 9.9 ns while cycling 20 MiB. The cold
radix-32 workspace now builds four fixed 16-entry micro-AoS tables directly,
rather than allocating slices or building grouped SoA and converting it. A new
oracle compares every entry, limb, lane, and coordinate against the original
grouped builder. Existing all-radix selector differentials, active-mask scalar
multiplication differentials, alias tests, and zero-allocation gates remain in
place.

The complete public n=4/msg=1232 gate moved from 11.80--11.83 to
**11.62--11.63 us/signature (-1.6%)**, with 0 B/op and 0 allocs/op. This is an
x4-only cold-table layout improvement; it does not change the x8 n>=8 path or
introduce any per-key persistence.

The next x4 doubling checkpoint promotes the previously test-only raw-product
Stage 2. Stage 1 writes exact folded u61 `[X^2,Y^2,Z^2,XY]` products into a
private typed workspace. One assembly leaf then computes the direct-XY linear
stage with the independently checked 535/1068/1069 whole-modulus biases and
carries E/F/G/H once each into u52. All point inputs have been consumed before
the four final products, so those native leaves write directly to `out`,
including the `out==q` case, without a separate 640-byte result copy.

The arbitrary-precision Stage-2 oracle proves non-negative u63 intermediates,
the exact parallel carry/fold representation, and u52 outputs. Boundary,
multiplicand-derived, chained point/scalar, alias, and zero-allocation tests run
on both the scalar fallback and native IFMA schedule. At exact implementation
commit `d356878`, the full Zen 5 suite passed and an eight-sample public-API A/B
at n=4/msg=1232 measured 11.61--11.62 us/signature before and 10.82--10.83
after: **about -6.8%**, 0 B/op, and 0 allocs/op. The shorter four-sample release
matrix at that commit was:

| message bytes | n=1 | n=2 | n=4 | n=8 | n=64 |
|---:|---:|---:|---:|---:|---:|
| 64 | 21.55 | 21.62 | **9.68** | 5.80 | 5.48 |
| 200 | 21.60 | 21.60 | **9.81** | 5.83 | 5.52 |
| 1232 | 22.50 | 22.49 | **10.80** | 6.08 | 5.75 |

Only n=4 is used to attribute the Stage-2 gain: singleton/two-item calls use
the packed tail kernel and full groups use x8. The width matrix is retained to
guard that dispatch boundary.

**Regime tag — half-full x8 on Zen 5 remains closed.** Immediately after the
masked-negate checkpoint, routing exactly four signatures through the existing
x8 cold kernel (four active and four inactive lanes) measured 11.97--12.03
us/signature versus 11.80 for x4 on the same pinned 9700X core. Native r51 and
batch-Q tests passed, so this is a performance rejection rather than a
correctness limitation. Keep x4 at n=4 and native x8 at n>=8; remeasure only on
a materially different microarchitecture or after a major x8-only kernel
change.

**Regime tag — the normalized dedicated x4 square remains test-only.** The
symmetry-aware square still returns the exact same u52 representation as the
general multiply and retains its boundary, alias, scalar-differential, chaining,
and zero-allocation coverage. On the pinned Zen 5 core, however, a dependent
point-double chain measured about 82.75 ns with the dedicated square versus
79.18 ns with the production general multiply (about 4.5% slower). The prepared
radix-64 loop measured about 55.94 us versus 54.46 us (about 2.7% slower). This
supersedes the older Zen 4 primitive-only keep result for production dispatch:
fewer IFMA product instructions did not overcome the dedicated schedule's
dependency/register costs in the real loop. Keep the experiment and its tests,
but do not wire it into the Zen 5 cold path. A future fused Stage-1/Stage-2
doubling may reuse its algebra without inheriting this normalized-call boundary.

**Regime tag — the raw-u61 x8 square is CPU-dispatched.** The x8 candidate is
not the normalized x4 schedule above: it feeds exact folded-u61 square products
directly into the fused linear/carry stage. A same-binary complete-verifier A/B
at commit `c31522d` on the pinned Zen 4 host retained a 2.6--3.2% improvement
at n=8 and n=64 across 200, 1232, and 4096-byte messages, with zero
allocations. The registered worker therefore selects it only on AMD family
19h with IFMA. Family 1Ah (Zen 5) keeps the general-multiply schedule because
the earlier complete Zen 5 gate found the dedicated schedule slower. CPU width,
decoded-A policy, warm width, and square policy remain separate feature bits.

**Regime tag — retain `VPMULLQ` for the normalized x8 multiply on Zen 4.** An
older port-pressure model proposed replacing the five AVX-512DQ
multiplication-by-19 folds with shift/add sequences when the IFMA pipes were
saturated. That model no longer predicts the current fused verifier. A pinned,
same-source complete public-verifier A/B at control commit `c964b84` applied
only the assembly diff from `d9ddf53`: at msg=1232 the shift/add candidate
regressed from median 7.889 to 8.166 us/signature at n=8 (+3.5%) and from
7.674 to 7.965 at n=64 (+3.8%). Both paths remained allocation-free with zero
native-fault fallbacks. Keep the experiment as a regime-tagged negative and
remeasure only after a material multiply/point-loop rewrite or on another
microarchitecture. Raw samples are under
`docs/results/zen4-mul19-fold-2026-07-26/`.

The same Zen 4 checkpoint rechecked the n=4 boundary. Four active x8 lanes
measured 15.785 and 16.750 us/signature for 200 and 1232-byte messages, versus
9.913 and 10.680 for one full x4 group. The full-width x8 advantage must not be
misapplied to a half-empty group; production retains x4 at n=4 on both measured
AMD generations.

---

## 1. What landed on this branch

Five commits, none of which change verification behaviour:

| commit | change |
|---|---|
| `c923dba` | comb core + asymmetric fixed-B DSM moved out of `_test.go` |
| `5ed081e` | parallel warm-comb benchmark matrix (n x msg) |
| `95a6a67` | vectorised A6/r9 builder moved out; cold bench extended to n=4 |
| `ef89df8` | production constructor returning errors instead of `testing.TB` |
| `7e9cbcd` | Zen 5 measurement record; bench extended to n=16/32 |

The first three are verbatim file moves with symbol names unchanged. The fourth
reshapes one constructor's error reporting and keeps a `testing.TB` wrapper, so
no test file needed editing.

**The point of all of it:** the entire warm partial comb originally lived in
`_test.go` files, so `go build ./...` did not cover it and no backend could
reach it. The convergence branch now exposes a private immutable r51 warm key,
builds four keys with one inversion, and reaches it through the opt-in public
`Cache` path. Automatic backend selection remains generic.

---

## 2. The single most important number

| path | us/sig | vs stdlib |
|---|---:|---:|
| stdlib | 27.5 | — |
| registered cold (two-x4 / radixA=64 / shared) | 13.32 | 2.06x |
| best cold measured (x8 / radixA=32 / comb256, n>=8) | 9.24 | 2.97x |
| warm partial comb (A6r9-B10r5) | 4.49 | 6.12x |

The warm comb was worth roughly **3x the then-current cold path** in the private
experiment. It is now reachable through forced r51's Cache; the complete
public/private seam, including lookup and width-aware dispatch, measures
4.49 us/signature on Zen 5 and 5.73 on Zen 4 at n=64/msg=1232 when fully warm.
These are warm-key results, not cold-key headline numbers.

### Why the cache is justified

- table size **19,200 B/key** (A6/r9: 43 digits, 5 rows, 32 entries)
- vectorised build **13,053 ns/key** (52.2 us per x4 group, zero allocations)
- scalar build 2,411,108 ns/key — 185x slower, do not use
- saving per warm verify **8.30 us**
- **break-even = 13.05 / 8.30 = 1.6 verifies**

The isolated arithmetic paid for its table near the second reuse when four
keys built together, but production also pays admission, grouping, and a solo
flush when four candidates do not coincide. The library therefore retains the
conservative thresholds of eight successful sightings, eight valid strict
hits before group eligibility, and 32 hits for a stranded solo candidate.
Traffic traces, not this microbenchmark, should tune integration policy.

---

## 3. Structural constraints and their resolutions

These shape mismatches were found while connecting the warm comb to Cache. They
remain useful constraints even though the current branch now implements the
resolution described for each one.

### 3.1 The warm comb cannot verify fewer than four signatures

The verifier requires an input count that is a positive multiple of `X4Lanes`.
Consequence: `backend.verify` — the **singleton** path — can never use a cached
table, no matter what is in the cache. Only batches can. Any design that assumes
"cache hit => fast single verify" is wrong for this backend.

**Resolution:** singleton Cache calls retain the ordinary verifier while still
earning valid admission credit. Warm arithmetic starts at one complete x4 batch.

### 3.2 A warm group must be homogeneous

The constructor prepares tables for *every* input in the group. There is no
representation for "lanes 0-2 cached, lane 3 cold". A group with three hits and
one miss therefore falls **entirely** to the cold path.

**Current resolution:** the dispatcher consumes complete warm x4 groups that
are already aligned in caller order. Unmatched or scattered hits remain on the
cold/decoded path. Zen 5 additionally requires two adjacent warm x4 groups
before consuming them, unless exactly four signatures remain. Regrouping across
the current call, or refilling across calls, remains integration work.

### 3.3 Single-key builds cost 4x the headline figure

The 13.05 us/key number comes from sharing one modular inversion across four
lanes. Building one key alone still costs the whole 52.2 us group operation,
moving break-even from 1.6 to **6.3 verifies**.

The Cache is per-key throughout (`admit(pub)`, `buildPrecomp(pub)`,
`lookup(pub)`), so a naive integration lands on the expensive figure.

**Resolution:** batch admissions hold eligible keys in a bounded pending set and
build once four accumulate. A partially-filled set flushes one key only after
the higher solo threshold, so it cannot remain stranded indefinitely.

### 3.4 The registered batch pipeline historically supported one shape

This was the original integration blocker, not the current status. The branch
now has matching evaluation paths for the promoted radix-32/comb256 x4 and x8
cores, and CPUID chooses the native width. The old one-line constructor swap
would still have been invalid; the lesson is that preparation and evaluation
shape must be promoted together and protected by the complete-pipeline tests.

---

## 4. Specified and ready to build

### 4.1 comb evaluation path in batchQ — smaller, unconditional

`two-x4 / radixA=32 / comb256` measures 12.50 us/sig at **every** width (n=4
through 64) against 13.32 for the registered shape. About 6% everywhere, no
dispatch logic, and the comb is one process-wide table rather than per-key state.
Lowest-risk win available. Commit `832e751` wires this arithmetic shape into
the same cross-group batch-Q finalizer as a complete-verifier candidate; it does
not change registered dispatch. Ten pinned one-second samples at `msg=1232`
retained the win on both machines:

| CPU | n | radix64 shared (us/sig) | radix32 comb256 (us/sig) | change |
|---|---:|---:|---:|---:|
| Zen 4 8700GE | 4 | 16.108 | 15.265 | -5.23% |
| Zen 4 8700GE | 8 | 15.730 | 14.915 | -5.18% |
| Zen 4 8700GE | 64 | 15.423 | 14.597 | -5.35% |
| Zen 5 9700X | 4 | 13.528 | 12.907 | -4.59% |
| Zen 5 9700X | 8 | 13.119 | 12.537 | -4.44% |
| Zen 5 9700X | 64 | 12.766 | 12.185 | -4.55% |

Both native differential corpora and the zero-allocation gate passed before the
benchmark. Zen 4 reported the `performance` governor. Zen 5 reported `powersave`,
so its absolute times remain provisional; the within-host candidate delta was
stable. Raw output and checksums are in
`docs/results/cold-comb-batchq-2026-07-25/`.

### 4.2 x8 evaluation path in batchQ — bigger, needs dispatch

`x8 / radixA=32 / comb256` measures 9.24 us/sig from n=8 upward (2.97x stdlib)
but **17.68 us at n=4**, where it fills half its lanes and pays for all of them.

The crossover is a step, not a curve:

| n | two-x4 | x8 |
|---:|---:|---:|
| 4 | 12.50 | 17.68 |
| 8 | 12.47 | **9.24** |
| 16 | 12.50 | 9.30 |
| 32 | 12.51 | 9.31 |
| 64 | 12.53 | 9.46 |

two-x4 is flat across a 16x range in n; x8 is flat from 8 upward. So the dispatch
rule is simply `n >= 8 -> x8`. Note this aligns with the streaming/catch-up split
already in the plan: small batches happen at the tip when traffic is light and
speed does not matter; deep batches happen when catching up, which is exactly
when it does.

### 4.3 C2a step 4 — landed: warm comb through Cache

Forced r51 now reports `supportsPrecomp() == true`. The first tier is an
exact-byte-bound decoded A; four eligible valid strict keys are promoted
together into immutable 19,424-byte entries containing A6/r9. Batch dispatch
consumes naturally aligned all-warm x4 groups and sends every other group
through the ordinary cold/decoded path. Zen 5 consumes warm groups in aligned
pairs to preserve native x8 occupancy, except for one final four-item tail.
Invalid signatures never promote, failed builds retain the decoded tier, and
timed verification remains allocation-free.

---

## 5. Open questions worth research rather than coding

### 5.0 HEEA performance — closed

The exact W132/radix-32 HEEA verifier is allocation-free and passed its semantic
gates, but it is substantially slower than even the older same-shape ordinary
radix-32 diagnostic at 1232 bytes: about +59% on Zen 5 x8 and +46% on Zen 4
two-x4 at both n=8 and n=64. The registered ordinary comb path is faster still.
Do not spend more implementation time on the current HEEA/QSM construction;
retain it as proof and differential-test evidence. Exact commands and medians
are recorded in `docs/HEEA.md`.

This closure is width-specific. It closes HEEA as a scalar-count trade in the
already-full lane-per-signature x8/two-x4 batch kernels. It does **not** close a
future singleton design that packs four coordinates from each of two
independent point chains into one ZMM register. The current packed singleton is
one YMM coordinate-parallel chain; mechanically widening it would leave half a
ZMM idle. A future HEEA or separate-`[S]B`/`[k]A` singleton experiment is
interesting only if it creates two independent chains and should first A/B one
two-point ZMM doubling against `quadPointDoubleHardwareUncheckedX4`. Results
from that experiment must be reported separately from x8 HEEA.

### 5.1 Mixed warm/cold lanes in one SIMD group — deferred

The comb and cold paths have incompatible doubling schedules, so a
heterogeneous lane kernel would add a third consensus-critical arithmetic path
without evidence that its complexity pays. The implemented lower-risk policy
uses only complete warm x4 sets already aligned in caller order and sends every
other group through the ordinary full-occupancy path. On Zen 5, one isolated
warm x4 is deliberately ignored inside an otherwise complete x8 group.
Result-index-preserving regrouping and cross-call refill are future integration
policies, not cryptographic-library dispatch.

### 5.2 Partial-group efficiency for x8 — closed

A half-full x8 group costs full price — that is the entire n=4 cliff. AVX-512 has
native mask registers, so the question is whether masking can actually skip work,
or whether the cost is inherently in the shared doubling chain, which runs once
per group regardless of how many lanes are live.

The measurements settle this. One half-full x8 group costs about 70.72 us and a
full group about 73.92 us. Adding four live lanes changes group time by only
4.3%, so roughly 96% of the work is occupancy-independent. Register masks can
avoid some lane-specific loads and stores but cannot turn ZMM arithmetic into a
YMM schedule. Leading-zero shortening and vector-wide sparse-digit skipping do
not materially change the fixed doubling chain and are adversarially removable.

Keep the dual-kernel rule: two-x4 below eight usable signatures, x8 for complete
eight-lane groups on CPUs where native ZMM wins. Do not build a masked-elastic
x8 kernel or an x4-by-two hybrid unless new hardware measurements overturn this
bound.

### 5.3 Comb width versus cache capacity

Capacity is simply budget divided by table size, so narrowing the comb buys keys
at the cost of online work:

| spec | rows | entries/row | bytes/key | keys @128 MiB |
|---|---:|---:|---:|---:|
| A6/r9 (current) | 5 | 32 | 19,200 | 7,158 |
| A5/r9 | 6 | 16 | 11,520 | 11,930 |
| A4/r9 | 8 | 8 | 7,680 | 17,895 |

Whether 2.5x the keys is worth a slower warm path depends entirely on the
fee-payer recurrence distribution, which nobody has measured. **That measurement
is more valuable than any further tuning here** — it decides both the comb width
and whether the cache is worth its complexity at all.

### 5.4 Broad decoded-A cache tier

`r51IFMABatchQPipeline.verifyBatchWithDecodedA` is already a private exact-path
measurement seam. A hit bypasses only public-key decompression; it still hashes
the caller's original public-key bytes, performs every strict precheck, and runs
the full scalar multiplication. It therefore composes with a much smaller hot
comb tier instead of competing with it.

The exact-byte-bound production entry is 192 bytes per key, versus 19,200 bytes
for A6/r9. Ignoring map/key metadata, 128 MiB can hold roughly 699,000 entries
rather than 7,158 comb tables. The current admission-entry limit is 131,072, so
that arithmetic capacity is not the effective default and must not be quoted as
one.

The decoded tier now composes with the hot comb. At n=64/msg=1232, Zen 5 moves
from 8.242 us raw to 7.756 decoded and 4.492 fully warm. Zen 4 deliberately
retains decoded A only as promotion staging: it moves from 14.52 raw to 15.51
at 0% warm, then 12.27/10.10/7.957/5.729 at 25/50/75/100% warm. Consequently
the r51 Cache is opt-in on both CPUs, but Zen 4 integration should reserve it
for recurrence-rich workloads rather than arbitrary TPU ingress.

Invalid signatures never earn admission or promotion. Reuse distance, memory
budget, concurrency, eviction, and adversarial churn remain traffic-policy
questions rather than arithmetic questions.

### 5.5 Mixed warm/cold lanes and cross-call lane refill

Mixed per-key comb and cold arithmetic in one SIMD group remains a high-ceiling
research question, but the schedules currently have incompatible doubling
chains. Do not add a third consensus-critical kernel on speculation.

The lower-risk way to recover occupancy is a result-index-preserving ready queue:
fill an incomplete group with compatible signatures from later arrivals, and
compact survivors again after cheap prechecks/decode. Narya already compacts
decode misses within one call; refill across calls belongs at the eventual
integration boundary so it can respect each caller's latency and failure policy.
It should use no batching timer: nonblocking drain for replay/repair/backlogs,
with x4 tails retained for thin traffic at the tip.

### 5.6 Zen 5 x8 selector and projective-Niels Stage 2

Three later x8 changes were measured independently rather than grouped under
one headline:

1. Removing the two 1,280-byte input copies and final result copy from the
   general x8 extended-point addition was representation-identical under
   left-, right-, and all-input alias tests, but performance-neutral in the
   registered verifier: about +0.06% at n=8 and no significant change at n=64.
   It is a direct-output simplification, not an attributed speedup.
2. Replacing the portable x8 conditional-negation loop with a native ZMM leaf
   moved the old grouped-SoA radix-32 selector from 121.10 to 59.90 ns
   (-50.54%). The registered cold verifier already uses a pre-signed
   micro-AoS A table, so it does not execute this operation in its evaluation
   loop. Complete n=8 moved about -0.5% while n=64 was statistically neutral;
   retain the leaf for non-pre-signed experiments, but do not present the
   selector result as a registered cold-path gain.
3. The registered projective-Niels mixed addition still normalized raw A/B/C/D
   products separately and made five more linear element calls. Commit
   `72bdf65` introduces a typed raw-product Stage-2 boundary analogous to the
   doubling: it forms `E=B-A`, `F=2D-C`, `G=2D+C`, and `H=B+A`, with a proven
   535-p subtraction bias, then carries all four outputs once.

The Stage-2 gate uses an independent arbitrary-precision oracle over boundary
and multiplicand-derived inputs. It proves non-negative intermediates below
2^62, carry-outs at most 1603, and u52 outputs; native tests also cover every
lane, point aliasing, mixed-order points, the pre-signed selector, and zero
allocations. The full Zen 5 repository suite passed before timing.

Ten pinned one-second samples at msg=1232 measured:

| measurement | before | `72bdf65` | change |
|---|---:|---:|---:|
| projective-Niels mixed add | 78.45 ns | 65.37 ns | -16.67% |
| public cold n=8 | 5.698 us/signature | 5.604 us/signature | -1.64% |
| public cold n=64 | 5.374 us/signature | 5.249 us/signature | -2.34% |

Every timed public row remained 0 B/op, 0 allocs/op, and reported zero internal
fault fallbacks. This is a supported complete-path win, unlike the selector and
general-add micro-results above.

### 5.7 Round-major x8 scalar recoding

The post-Stage-2 profile put fixed scalar recoding at about 3.5% cumulative.
Two extraction designs were gated independently on Zen 5. A stateful streaming
bit reader was rejected immediately: radix-32 recoding regressed from about
1.19 to 1.34 us per eight scalars because its refill branch and state updates
cost more than the avoided loads.

The retained design preserves the original two-byte extractor and changes the
x8 loop orientation to match its output: validate the lanes once, then process
one round across all eight lanes. Commit `586e764` measured about 27% faster at
radix 32 (1.188 us to 0.871 us per eight scalars), 27% at radix 16, and 29% at
radix 64. Ten pinned public-API samples at msg=1232 moved n=8 from 5.442 to
5.421 us/signature (-0.4%) and n=64 from 5.136 to 5.099 us/signature (-0.7%).
The n=1/2/4 paths were neutral within run drift, and all rows retained zero
allocations and zero internal-fault fallbacks. See
`docs/results/zen5-round-major-recode-2026-07-26/` for raw output.

### 5.8 Packed-singleton doubling scratch — retained

Static inspection found a width-specific mechanical lead that did not overlap
the x8 work: `quadPointDoubleHardwareUncheckedX4`, used by the packed singleton
path, had a roughly 992-byte frame and six zeroing sequences for six
`IFMAElementX4` scratch values. Each value was fully overwritten before use,
but a singleton verification paid that clearing cost roughly 253 times.

Commit `9f5659d` moves five intermediates to a reusable per-evaluation workspace
and writes the final multiplication directly to the output. The alias proof is
local: the input point is fully permuted into the workspace before the final
output write. Existing random-projective, torsion, range-envelope, input-T,
and repeated-alias tests remain; a new poisoned-scratch test fills every
workspace limb with unrelated patterns before comparing repeated in-place
doublings. Generated amd64 code reduced the hot helper to a 64-byte frame with
no scratch zeroing.

Ten pinned Zen 5 samples moved the isolated packed doubling from 49.13 to
42.69 ns (-13.1%). Through the exported strict API at msg=1232, n=1 moved from
22.50 to 20.91 us/signature (-7.1%) and n=2 from 22.25 to 20.81
us/signature (-6.5%). The unchanged n=4/8/64 paths remained at about
10.14/5.43/5.10 us/signature. All timed rows retained zero allocations and
zero internal-fault fallbacks; the complete native repository suite passed.
Raw output is under
`docs/results/zen5-packed-singleton-scratch-2026-07-26/`.

### 5.9 Packed-singleton cached-add scratch — retained

The packed cached-point addition had the same dead-initialization shape as the
former singleton doubling. Five fully-overwritten 160-byte element locals were
created inside every addition. Commit `12941c8` reuses four intermediate
elements across the scalar multiplication and writes the final multiplication
directly to the result after the input point and cached addend are no longer
live.

The proof and gate mirror the doubling: the existing random projective,
torsion, range-envelope, and in-place alias oracles remain; a new test poisons
every scratch limb before comparing 32 repeated in-place additions with a clean
workspace. Ten pinned Zen 5 samples moved the cached add from 48.97 to 43.79 ns
(-10.6%). Incrementally after the doubling change, the public msg=1232 path
moved from 20.90 to 20.38 us/signature at n=1 (-2.5%) and 20.81 to 20.45 at
n=2 (-1.7%). Timed rows retained zero allocations and zero internal-fault
fallbacks, and the complete native repository suite passed. Raw output is
under `docs/results/zen5-packed-singleton-add-scratch-2026-07-26/`.

### 5.10 Packed-singleton doubling Stage 2 — retained

The reusable-workspace doubling still normalized four packed field products,
then returned to Go for the E/F/G/H linear layer before issuing the four final
multiplications. Commit `8fb91a2` replaces only that linear layer with one x4
assembly leaf. Its input is the normalized packed vector
`[A=X^2,B=Y^2,C=Z^2,D=XY]`; its outputs are the two packed operand vectors
needed by the unchanged final multiplications:

```text
left  = [E, G, E, F]
right = [F, H, H, G]
E = 2D
G = B - A
H = -A - B
F = B - A - 2C
```

The native leaf adds eight whole moduli to the three signed expressions,
proving non-negative pre-carry limbs below `12*2^51`, then applies one parallel
carry/fold. All five packed input vectors are loaded before either output is
stored, so the input may alias either output; the two outputs must be distinct.
The portable Go construction remains the independent representation oracle.
Direct tests compare the native result bit for bit over zero, maximum-u52, and
1,024 random inputs, exercise input/output aliasing, and assert zero
allocations. Existing projective, torsion, range, and poisoned-workspace tests
remain unchanged.

Ten pinned Zen 5 samples moved the isolated reusable-workspace doubling from
42.69 to 34.94 ns (-18.2%). Through exported `VerifyBatchStrict` at msg=1232,
n=1 moved from 20.38 to 18.61 us/signature (-8.7%) and n=2 from 20.45 to
18.68 us/signature (-8.7%). The n=4/8/64 dispatches were neutral at about
10.16/5.43/5.11 us/signature. Every timed row retained zero allocations and
zero internal-fault fallbacks, and the complete native repository suite
passed. Raw output is under
`docs/results/zen5-packed-singleton-stage2-2026-07-26/`.

### 5.11 Packed-singleton cached-add Stage 2 — retained

The post-doubling profile exposed the analogous cached-add linear layer at
about 5.7% cumulative. Commit `067188b` adds a second x4 assembly leaf over the
normalized `[A,B,C,D]` products. It computes E=`B-A`, G=`D+C`, H=`B+A`, and
F=`D-C`, adds eight whole moduli only to E/F, performs one parallel carry/fold,
and emits the same packed left/right operands consumed by the unchanged final
multiplication.

This uses the same narrow safety boundary as the doubling Stage 2. The five
inputs are loaded before the outputs are stored; either output may therefore
alias the input, while the outputs must be distinct. A direct portable oracle
checks exact representations over zero, maximum-u52, and 1,024 random inputs,
including both input/output alias directions. Existing projective, torsion,
range, poisoned-workspace, and zero-allocation tests remain unchanged.

Ten pinned Zen 5 samples moved the reused-workspace cached addition from 43.79
to 34.95 ns (-20.2%). Incrementally after the doubling Stage 2, exported
`VerifyBatchStrict` at msg=1232 moved n=1 from 18.61 to 17.72 us/signature
(-4.8%) and n=2 from 18.68 to 17.83 us/signature (-4.6%). The n=4/8/64
dispatches remained at about 10.20/5.43/5.10 us/signature. Every timed row
retained zero allocations and zero internal-fault fallbacks, and the complete
native repository suite passed. Raw output is under
`docs/results/zen5-packed-singleton-cached-stage2-2026-07-26/`.

### 5.12 Packed-singleton doubling input permutation — retained

After both Stage-2 leaves, the remaining scalar
`quadDoubleFirstOperandsX4` loop was about 3.3% of the singleton profile. It
copied each packed `[X,Y,T,Z]` limb into U=`[X,Y,Z,X]` and V=`[X,Y,Z,Y]` in
Go, then the multiply leaf immediately loaded those ten vectors again. Commit
`bdaa628` replaces the scalar lane extraction with five input loads, ten YMM
permutations, and ten output stores. This is deliberately a narrow mechanical
step rather than the larger multiply fusion.

The native helper loads all five inputs before any output store, so the input
may alias U or V while U and V remain distinct. A direct oracle compares every
limb bit over zero, maximum-u52, and 1,024 random inputs, exercises both alias
directions, and asserts zero allocations. The unchanged full point-operation
oracles continue to cover random projective, torsion, range, and repeated
in-place cases.

Ten pinned Zen 5 samples moved the isolated reused-workspace doubling from
34.94 to 32.75 ns (-6.3%). Incrementally after both Stage-2 changes, exported
`VerifyBatchStrict` at msg=1232 moved n=1 from 17.72 to 17.23 us/signature
(-2.8%) and n=2 from 17.83 to 17.17 us/signature (-3.7%). The n=4/8/64
dispatches remained around 10.13/5.42/5.12 us/signature. Timed rows retained
zero allocations and zero internal-fault fallbacks, and the complete native
repository suite passed. Raw output is under
`docs/results/zen5-packed-singleton-first-permute-2026-07-26/`.

### 5.13 Packed-singleton cached-add input normalization — retained

The last analogous scalar packed operation was
`quadCachedAddFirstOperandX4`, about 4.0% cumulative in the post-Stage-2
profile. It formed `[Y-X,Y+X,T,Z]` with a 320-byte raw product and then called
the normalizer. Commit `3961d6e` moves that exact construction into one YMM
leaf: it adds 4p only to the subtraction lane, proves every pre-carry limb
non-negative and below `6*2^51`, and performs one parallel carry/fold.

All five point vectors are loaded before output, preserving in-place aliasing.
The portable function remains the exact representation oracle across zero,
maximum-u52, and 1,024 random inputs; direct tests also cover aliasing and zero
allocations, while the unchanged point tests cover projective, torsion, range,
and repeated cached-add chains.

Ten pinned Zen 5 samples moved the isolated cached add from 34.95 to 33.72 ns
(-3.5%). Through exported `VerifyBatchStrict` at msg=1232, n=1 moved from
17.23 to 16.75 us/signature (-2.8%) and n=2 from 17.17 to 16.74 us/signature
(-2.5%). The n=4/8/64 dispatches remained around 10.15/5.43/5.10
us/signature. Timed rows retained zero allocations and zero internal-fault
fallbacks, and the complete native repository suite passed. Raw output is
under `docs/results/zen5-packed-singleton-cached-input-2026-07-26/`.

### 5.14 Packed-singleton doubling Stage-2 reschedule — retained

The native doubling Stage 2 initially selected each algebraic term with vector
ANDs. Commit `2724c44` instead forms `[D,B,B,B]` and `[D,A,A,A]`, takes their
sum and difference, selects E/H with public mask registers, and subtracts 2C
only from the F lane. The carried `[E,G,H,F]` representation remains bit for
bit identical to the portable oracle.

The first draft incorrectly used the cached-add F=`D-C` expression in the
doubling schedule. The direct representation oracle rejected maximum-u52 input
and full verifier tests rejected honest signatures before any benchmark ran.
That variant was corrected locally and never pushed. This is a useful regime
note: cached-add and doubling share the same packed output shape but not the F
formula.

Ten pinned Zen 5 samples moved the isolated doubling from 32.75 to 31.96 ns
(-2.4%). Through exported `VerifyBatchStrict` at msg=1232, n=1 moved from
16.75 to 16.61 us/signature (-0.8%) and n=2 from 16.74 to 16.52
us/signature (-1.3%). The n=4/8/64 dispatches stayed around
10.18/5.43/5.10 us/signature. The change is retained because it removes
instructions, introduces no new representation or branch, remains
zero-allocation, and passed the complete native suite. Raw output is under
`docs/results/zen5-packed-singleton-stage2-reschedule-2026-07-26/`.

### 5.15 Register-resident decoder square chains — retained

The strict decoder's exponentiation consisted of short runs of 1--100 true
field squares separated by fixed addition-chain multiplies. Each square called
the general 25-product multiply, reloaded five limb vectors, and stored them
again. That old schedule remained appropriate as the portable and
fault-injection reference, but it was not a good native dependent-chain ABI.

Commit `1ac9fde` promotes the existing exact x8 chain and adds its x4 analogue.
The native unchecked decoder now retains the five running limbs in YMM/ZMM
registers for an entire square run, uses the 15-product symmetry schedule, and
stores only at the next addition-chain boundary. The final multiply by the
boundary's distinct operand still uses the common multiply kernel. Checked,
portable, and injected-fault schedules deliberately retain their former
per-operation path.

The direct oracle covers counts 0/1/2/5/10/20/50/100/252, random maximum-u52
inputs, exact output-representation equality against repeated production
multiplies, in-place aliasing, and zero allocations at both widths. The native
repository suite and complete verifier differentials passed.

On a pinned Zen 5 core at msg=1232, public cold verification moved from about
16.61 to 15.33 µs/signature at n=1 (-7.7%), 16.52 to 15.33 at n=2 (-7.2%),
10.18 to 9.55 at n=4 (-6.2%), 5.43 to 5.10 at n=8 (-6.1%), and 5.12 to
4.92 at n=64 (-3.9%). Every timed row retained zero allocations and zero
internal-fault fallbacks.

**Regime tag:** the older dedicated-square rejection remains valid for the
point loop. Packed doubling includes `[X^2,Y^2,Z^2,XY]`, not four copies of one
field square, and the signature-parallel point A/B showed the standalone
square call losing in that schedule. Decoder exponentiation is different: it
is a long, genuinely dependent sequence of true squares, so register residency
and symmetry both apply. Reopen either verdict only within its own arithmetic
regime.

### 5.16 Packed doubling final-linear/multiply fusion — retained

After the decoder square-chain change, a fresh n=1 profile at msg=1232 put
53.5% cumulative time in packed doubling. The standalone
`ifmaQuadDoubleFinalOperandsUncheckedX4` linear/carry stage accounted for
13.4% flat time because it materialized two five-vector operands that the next
field multiply immediately reloaded.

Commit `b7d8acb` adds one packed final-stage kernel that preserves the existing
linear formula and carry schedule, expands `[E,G,H,F]` into both multiplication
operands in registers, and performs the existing 5x51 normalized multiply
before the first output store. The former split helper remains as an
independent native oracle. Direct tests compare exact redundant
representations for zero, maximum-u52, and 512 deterministic random inputs;
exercise output/input aliasing; poison prior workspace contents; and assert
zero allocations. The complete native repository suite passed.

On a pinned Zen 5 core, the reused-workspace doubling median moved from 31.96
to 30.575 ns/op (-4.3%). At msg=1232, the public cold path moved from 15.440
to 15.085 µs/signature at n=1 (-2.3%) and from 15.380 to 14.960 at n=2
(-2.7%). The unaffected n=4 signature-parallel path remained within noise at
9.538 versus 9.550 µs/signature. All public rows retained zero allocations
and zero internal-fault fallbacks. Raw output is under
`docs/results/zen5-packed-singleton-final-fusion-2026-07-26/`.

**Regime tag:** this fusion is specific to the packed/intra-signature x4
doubling used by singleton and pair tails. It does not change the x8
lane-per-signature point loop. The split helper is intentionally retained as
an exact-representation oracle and as a reusable measurement seam.

### 5.17 Two independent packed chains in one ZMM — positive gate

The packed singleton normally uses one YMM register's four lanes for one
point's `[X,Y,T,Z]` coordinates. Mechanically widening that representation to
ZMM would leave four lanes idle and is not an optimization. An algorithm that
produces two independent point chains—separate `[s]B` and `[k]A` terms, or a
torsion-safe HEEA transform—can instead place one packed point in each 256-bit
half.

Commit `d01b574` adds a test-only Zen 5 regime probe for that shape. The same
packed doubling formulas and range contracts execute independently in both
halves, while one native x8 IFMA multiply services both points. It deliberately
does not add a verifier or dispatch path.

On a pinned Zen 5 core, two separately maintained packed-x4 chains cost 50.30
ns per pair. The two-chain ZMM operation cost 30.42 ns per pair (-39.5%),
essentially the same as the 30.575 ns cost of one packed-x4 chain. Exact
redundant representations matched two independent x4 oracles through random
mixed-order, non-unit-projective doubling chains; the operation remained
zero-allocation; and the complete native repository suite passed.

This closes only the doubling premise. A complete candidate still needs an x8
packed cached-add layer, two independently recoded/table-selected terms, final
term combination, and complete strict-predicate differentials. HEEA additionally
retains its modulo-8L congruence, odd/nonzero multiplier, width, and fallback
guards. No complete-verifier speedup is claimed from this gate alone. Raw
output is under `docs/results/zen5-two-chain-zmm-double-gate-2026-07-26/`.

**Regime tag:** a negative batch-HEEA result cannot close singleton HEEA. The
batch x8 orientation already fills all lanes with signatures, while this
singleton orientation has a second 256-bit half available only when the scalar
algorithm exposes a second independent chain.

### 5.18 Current modulo-8L HEEA selector — improved, still below the integration gate

The positive two-chain doubling result does not include coefficient selection.
The first exact allocation-free `SelectShiftSubtract` implementation was
therefore measured before extending the two-chain cached-add/table layer.

On a pinned Zen 5 core, ordinary admitted selection cost approximately 7.12
µs at W128, 6.87 µs at W132, and 6.68 µs at W136, all with zero
allocations. The post-fusion cold singleton measured 14.84 µs/signature.
Halving the roughly 255-doubling chain cannot recover a selector cost of this
size: the profile assigns about 48% of the verifier to doubling, so even an
otherwise-free half-length replacement saves only roughly 3.6 µs before its
extra tables, additions, and final term combination.

The later exact Lehmer selector advances the same principal Euclidean sequence
in batches. Three locally differential-tested passes reduced a same-binary
W128 selector on the Zen 4 Ryzen 7 PRO 8700GE from 3.978 to 3.647 us (one limb
pass), then 2.949 us (direct signed-product pairs), and finally 2.698 us (fused
exact coefficient step). Every row allocated zero bytes. The matrix application
alone moved from 415.4 to 327.35 and then 156.05 ns. The first result supersedes
an earlier 8.0--8.3 us absolute measurement collected in a slower
host-throughput regime; only same-binary or adjacent-checkpoint comparisons are
used as algorithmic deltas.

The new reducer is materially better but still does not clear the integration
gate. At 2.698 us it is about 35% of the current 1232-byte, n=64 cold r51 cost
on that CPU before coefficient preparation, the extra point/table work, the
transformed equation, or ordinary fallback. Keep the exactness work,
modulo-8L guards, mixed-torsion vectors, and two-chain ZMM kernel as useful
foundations. Do not wire a production HEEA route until a complete exact path
beats the ordinary verifier. Raw output is in
`docs/results/zen4-heea-matrix-fusion-2026-07-26/`.

### 5.19 Ordinary two-chain ZMM singleton loop — architecture split

The positive Zen 5 doubling gate was extended into a complete ordinary scalar
loop without changing the verification equation. The low 256-bit half
evaluates `-[k]A`, the high half evaluates `[s]B`, zero digits select the
cached identity in the inactive half, and the completed terms are combined
with the established packed-x4 cached-add path. The candidate uses the same
width-5 A NAF and width-8 B NAF as the shared-chain oracle; no HEEA reduction
or scalar congruence assumption is involved.

Native differentials compare exact final encodings against the existing
shared-chain evaluator for zero, `L-1`, 256 dense canonical scalar pairs, and
a mixed-order public key. The cached-add leaf separately matches two x4
oracles in exact redundant representation over 1,024 mixed-order cases,
including in-place aliasing. Both layers are zero-allocation and reject a
noncanonical scalar fail-closed.

On a pinned Ryzen 7 PRO 8700GE (Zen 4), the prepared scalar loop measured
10.72 µs for the shared packed-x4 chain and 17.83 µs for the two-chain ZMM
candidate. This approximately 66% regression is the expected cost of using a
native-width design on a core that executes 512-bit vector arithmetic as two
256-bit passes. The result excludes the candidate from Zen 4 dispatch.

**Regime tag:** this does not close the design on Zen 5. Zen 5's earlier
component gate measured two ZMM-packed chains at essentially the cost of one
packed-x4 chain. The complete-loop benchmark must be rerun unchanged on native
512-bit hardware; only that result can decide whether selection, identity
padding, and final term combination preserve the component-level gain.

### 5.20 Fixed-base affine cached-add Stage 2 — retained

A fresh Zen 5 profile at `f80de02` placed approximately 19% of complete
n=64 strict verification in the fixed-base comb, including about 8% in its
affine cached additions and 8% in selection/gather. The x4 and x8 fixed-base
point-add implementations still used the pre-fusion schedule: three
individually normalized products, five normalized linear operations, four
output products, defensive input/result copies, and fresh per-add scratch.

Commits `6fa4c4f` and `fd117ae` give both widths the already-proven Stage-2
shape. Four raw products feed one linear carry layer, the existing Niels
Stage-2 leaf accepts affine `D=Z` under a documented tighter-u52 alternative
to its raw-product contract, the output products write directly to the
accumulator, and one scratch object is reused across the 32 fixed-base adds.
Independent arbitrary-precision oracles cover the broadened `D` contract;
point differentials cover the old and new schedules; alias/in-place,
poisoned-scratch, range, and zero-allocation tests cover both widths.

On the pinned Zen 5 core, median fixed-base radix-256 group time changed from
4,935 to 4,068 ns for x4 (-17.6%) and from 7,970 to 6,247.5 ns for x8
(-21.6%). Complete public 1232-byte strict verification at the same final
commit measured 9.274 µs/signature at n=4, 4.995 at n=8, and 4.794 at n=64,
all with zero allocations and zero internal-fault fallbacks. The warm path
also benefits because it shares the fixed-base term: at 1232 bytes it measured
4.179, 3.940, and 3.776 µs/signature at n=4/8/64 with 64 promoted keys.

Raw A/B output and the full cold/warm/comparison snapshot are under
`docs/results/zen5-fixed-base-affine-stage2-2026-07-26/`.

**Regime tag:** the result applies to the shared fixed-base affine cached-add
inside both cold and warm r51 paths. It does not claim that the scalar gather
is solved; after this arithmetic reduction, fixed-base selection is a larger
relative share and remains the next independent cold-path candidate.

### 5.21 Fixed-base pre-signed 2dT — retained

The post-Stage-2 n=64 profile assigned 9.0% of complete verification to
`selectFixedBaseIFMACachedX8`. Scalar `Element.Negate` under that selector
accounted for 3.6% of the complete profile because every negative public digit
recomputed `-2dT` before gathering it into a SIMD lane.

Commit `afe5c65` retains one additional scalar field element per shared
fixed-base table entry. Selection still indexes the same positive point and
implements exact affine-cached negation by swapping `Y+X`/`Y-X`; it now chooses
the retained negative `2dT` rather than performing field arithmetic. The
radix-256 B table grows from 245,760 to 327,680 bytes, a process-wide 80 KiB
cost with no per-key or timed-path allocation.

On the pinned Zen 5 core, fixed-base group time improved 4,068 -> 3,576.5 ns
for x4 (-12.1%) and 6,247.5 -> 5,171.5 ns for x8 (-17.2%). Complete public
1232-byte cold verification improved 9.274 -> 9.139 µs/signature at n=4,
4.995 -> 4.850 at n=8, and 4.794 -> 4.673 at n=64. Every row remained
zero-allocation with zero internal-fault fallbacks, and the complete native
suite passed.

Raw output is under
`docs/results/zen5-fixed-base-presigned-t2d-2026-07-26/`.

**Regime tag:** this removes only online `2dT` negation. The per-lane scalar
gather and SoA stores remain visible and are a separate candidate. Because B
is shared process-wide, the 80 KiB storage trade does not scale with the public
key population.

### 5.22 Direct strict singleton dispatch — retained

The exported `VerifyStrict` path previously applied the shared profile layer
and then entered the r51 backend's packed verifier, while batch-of-one reached
the packed verifier through the allocation-free raw-batch seam. A diagnostic
split showed that the strict small-order precheck itself cost only 3.36 ns;
the measurable loss was the generic singleton dispatch stack, not the
acceptance predicate.

The private `rawStrictSingleBackend` interface is the singleton analogue of
the existing `rawBatchBackend`. Forced r51 consumes the public byte shape
directly and retains the packed verifier's complete strict byte prechecks.
Unsupported backends keep the original shared path. Native faults still
increment `InternalFaultFallbacks` and recompute with the generic strict
verifier.

On the pinned Zen 4 host, an immediate 1232-byte A/B moved `VerifyStrict` from
about 19.60 to 17.46 µs (-10.9%), while batch-of-one measured 17.40 µs. A
separate six-sample size sweep measured `VerifyStrict` at 16.681-16.700 µs
for 200-byte messages, 17.743-17.747 µs for 1232 bytes, and 20.253-20.258 µs
for 4096 bytes. It remained within 0.3-0.6% of batch-of-one at every size and
allocated zero bytes.

The complete native repository suite, direct fault fallback, nil/short/invalid
input cases, and CCTV/Wycheproof strict differentials passed. Raw output is
under `docs/results/zen4-raw-strict-singleton-2026-07-26/`.

**Regime tag:** the optimization applies only to the explicit `VerifyStrict`
API when the selected backend implements the private raw singleton contract.
It does not alter `Verify`, batch dispatch, profile selection, or the
generic/stdlib implementations.

---

## 6. Smaller observations

- **`single-A-batch-Q` beats `paired-AR-projective` by 4-5%** at both 1 and 4
  cores (84,899 vs 81,079 sig/s single-core). That finalizer choice looks settled.
- **Multicore scaling is 93-98%**, far above the usual 80-85%. Zero allocations
  means no GC pressure, and warm tables are shared read-only. Six cores reach
  ~1.25M sig/s warm and ~509k cold at max transaction size.
- **Hashing matters more as point arithmetic gets faster.** Going 200 -> 1232
  bytes costs the cold path +6% but the warm path +21%, because SHA-512 is a
  larger fraction of a 4.5 us verify than of a 12 us one. So multi-buffer SHA-512
  is worth *more* after the warm path lands, not less — and it is the only win
  that is independent of cache hit rate, since every signature hashes regardless.
- **narya's strict path is faster than stdlib** (25.79 vs 26.48 us) while doing
  strictly more work, on both Zen 5 and arm64. That is the honest shipping claim.

---

## 7. Deliberately not done

- **Do not optimise `internal/r43x6`.** It is a documented correctness oracle
  (`doc.go:22`, `scalarmult.go:68`), and its apparent inefficiencies — full
  projective tables, no leading-zero skip, defensive struct copies — are
  deliberate. I scoped work there before checking and it would have been wasted.
- **Cached Y+-X tables and AffineNiels mixed addition** (open tasks) are ~3-6% on
  the cold path. Real, but not before §4.
- **No default was changed.** Automatic dispatch still selects `generic`.
  The two-tier Cache is available only when callers explicitly force r51 and
  choose the Cache API. Raw forced-r51 and every automatic path retain their
  former routing.
