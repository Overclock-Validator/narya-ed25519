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

The final two values are medians of ten two-second public-API samples. The
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
