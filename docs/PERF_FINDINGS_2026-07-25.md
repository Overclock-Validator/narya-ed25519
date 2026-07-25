# Performance findings and open opportunities — 2026-07-25

Written alongside branch `claude/narya-perf`. Measurements are in
`docs/ZEN5_9700X_2026-07-25.md`; this document is the reasoning, the structural
constraints found while integrating, and what is worth doing next.

Everything below was measured on Zen 5 (Ryzen 7 9700X). **No conclusion here has
been checked on Zen 4.** Zen 4 double-pumps 512-bit operations as 2x256, which is
very likely why the current two-x4 default was chosen, so treat every ranking as
Zen-5-specific until the 8700GE confirms it.

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

**The point of all of it:** the entire warm partial comb lived in `_test.go`
files, so `go build ./...` did not cover it and no backend could reach it. It now
builds without test files. That was the blocker in front of C2, not the
arithmetic, which was already finished and tested.

---

## 2. The single most important number

| path | us/sig | vs stdlib |
|---|---:|---:|
| stdlib | 27.5 | — |
| registered cold (two-x4 / radixA=64 / shared) | 13.32 | 2.06x |
| best cold measured (x8 / radixA=32 / comb256, n>=8) | 9.24 | 2.97x |
| warm partial comb (A6r9-B10r5) | 4.49 | 6.12x |

The warm comb is worth roughly **3x the cold path**, and it is gated entirely
behind `r51Backend.supportsPrecomp() == false`. Everything else on this list is
worth 6-30%. If only one thing gets done, it should be the warm path.

### Why the cache is justified

- table size **19,200 B/key** (A6/r9: 43 digits, 5 rows, 32 entries)
- vectorised build **13,053 ns/key** (52.2 us per x4 group, zero allocations)
- scalar build 2,411,108 ns/key — 185x slower, do not use
- saving per warm verify **8.30 us**
- **break-even = 13.05 / 8.30 = 1.6 verifies**

A key pays for its table the *second* time it is seen. This is a much lower bar
than the Alpenglow key-diversity concern assumed, and it argues the planned
`AdmitAfter = 8` is far too conservative. **Recommend 2.**

---

## 3. Structural constraints (found by trying to build it)

These are the reasons C2a stopped at step 4. None are performance problems; they
are shape mismatches between the warm comb and the Cache.

### 3.1 The warm comb cannot verify fewer than four signatures

The verifier requires an input count that is a positive multiple of `X4Lanes`.
Consequence: `backend.verify` — the **singleton** path — can never use a cached
table, no matter what is in the cache. Only batches can. Any design that assumes
"cache hit => fast single verify" is wrong for this backend.

### 3.2 A warm group must be homogeneous

The constructor prepares tables for *every* input in the group. There is no
representation for "lanes 0-2 cached, lane 3 cold". A group with three hits and
one miss therefore falls **entirely** to the cold path.

This is the biggest limiter on realised cache value. With diverse fee-payers,
hits will be scattered, and requiring four cached keys to line up in one group
wastes most of them. See §5.1 for the research question this raises.

### 3.3 Single-key builds cost 4x the headline figure

The 13.05 us/key number comes from sharing one modular inversion across four
lanes. Building one key alone still costs the whole 52.2 us group operation,
moving break-even from 1.6 to **6.3 verifies**.

The Cache is per-key throughout (`admit(pub)`, `buildPrecomp(pub)`,
`lookup(pub)`), so a naive integration lands on the expensive figure.

**Decision taken:** batch admissions. Hold keys that cross the threshold in a
small pending set and build once four accumulate. Needs a flush policy so a
partially-filled pending set does not strand keys indefinitely.

### 3.4 The registered batch pipeline supports exactly one shape

`verifyChunk` in `backend_r51batchq.go` evaluates through `core.x4[half]`.
`newR51IFMACombPipeline` populates `variableX4` plus a shared fixed-base comb and
leaves `x4` empty; the x8 kind populates `x8` instead. So **neither faster shape
is reachable by changing the constructor call** — both need a matching evaluation
path. This is recorded at the call site; a one-line attempt panics with
`uninitialized forced r51 IFMA x4 workspace`.

---

## 4. Specified and ready to build

### 4.1 comb evaluation path in batchQ — smaller, unconditional

`two-x4 / radixA=32 / comb256` measures 12.50 us/sig at **every** width (n=4
through 64) against 13.32 for the registered shape. About 6% everywhere, no
dispatch logic, and the comb is one process-wide table rather than per-key state.
Lowest-risk win available.

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

### 4.3 C2a step 4 — wire the warm comb into the backend

`supportsPrecomp() -> true`; `buildPrecomp` builds the A6r9 table and sets
`table` + `size = 19200` instead of the current 32-byte stub; `verify` stops
ignoring its `*PrecomputedKey`. Plus the batch-partitioning layer that §3.1-3.3
force: group cached keys into homogeneous x4 sets, send the remainder cold,
batch admissions four at a time.

---

## 5. Open questions worth research rather than coding

### 5.1 Mixed warm/cold lanes in one SIMD group

The highest-value unknown. If lanes could independently choose comb-table versus
from-scratch evaluation inside one group, §3.2 disappears and realised cache
value rises sharply.

The obstacle is that the two paths have different loop structures: the comb runs
a fixed number of passes over precomputed rows, while the cold path runs a
windowed DSM with a doubling chain. They do not share a schedule, so lanes cannot
step in lockstep.

Worth asking whether anyone has published a heterogeneous-lane scalar
multiplication scheme, or a way to express the comb's schedule as a special case
of the windowed one so both can run together with per-lane digit selection.

### 5.2 Partial-group efficiency for x8

A half-full x8 group costs full price — that is the entire n=4 cliff. AVX-512 has
native mask registers, so the question is whether masking can actually skip work,
or whether the cost is inherently in the shared doubling chain, which runs once
per group regardless of how many lanes are live.

My reading is the latter: doublings dominate and they are per-group, not per-lane.
If that is right, masking cannot help and the dual-kernel dispatch in §4.2 is
unavoidable. If some windowing trick can shorten the chain for a partially filled
group, the n=4 cliff disappears and one kernel suffices.

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
- **No default was changed.** Automatic dispatch still selects `generic`;
  `supportsPrecomp()` is still false. Everything here is additive.
