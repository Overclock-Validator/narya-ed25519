# Zen 5 warm partial-comb x8 evaluator gate

This directory records the promotion gate for an eight-lane heterogeneous
partial-comb evaluator at implementation commit `d42d75d`.

## What was measured, and what it is not

The promoted warm-comb verifier is x4-only. Its *scheduling* unit can already be
eight signatures, because `r51WarmDispatchWidth` consumes aligned pairs to keep
x8 occupancy in the surrounding pipeline, but the arithmetic underneath is two
sequential YMM groups. This gate compares that against one ZMM group over the
same eight signatures.

The benchmarked function is the whole evaluator, not a single kernel: the merged
exponent loop, every doubling, both comb passes, and the balanced recoding are
inside it. That distinction matters here. The two-chain ZMM candidate passed its
component gate and then regressed roughly 66% at the loop level on Zen 4
(`zen4-two-chain-zmm-loop-gate-2026-07-26`), so a component measurement is not
evidence about a loop.

**This is still an upper bound on the complete-verifier gain.** Hashing, public
key decoding, promotion bookkeeping and finalization sit outside this loop and
do not widen with the lane count.

## Environment

- AMD Ryzen 7 9700X (Zen 5), performance governor;
- Go 1.26.4, linux/amd64, kernel 7.0.0-28-generic;
- one pinned physical core (`taskset -c 2`), `GOMAXPROCS=1`;
- cores 0–7 are physical, 8–15 are SMT siblings; core 2 is physical;
- ten one-second samples per row.

## Result

Both rows verify the same eight signatures, so nanoseconds per signature is
directly comparable and is the quantity a dispatch decision turns on.

| evaluator form | median ns/signature | min | max | allocations |
| --- | ---: | ---: | ---: | ---: |
| two x4 groups (current shape) | 2,229 | 2,227 | 2,230 | 0 |
| one x8 group (candidate) | 1,534 | 1,530 | 1,537 | 0 |

That is a **31.2% reduction per signature**, a 1.45x speedup, with the spread
inside 0.5% on both rows.

Both rows moved down from an earlier capture (2,287 and 1,577) because the
balanced recoder in this branch no longer divides; see below. The ratio is
unchanged, since the recoder is shared by both forms.

For context, the same structural change on the cold path measured 26%
(`x8 / radixA=32 / comb256` at 9.24 µs/sig against two-x4 at 12.50). The warm
evaluator gains slightly more, not less.

## Correctness

`correctness.txt` is the same-host run of the differential. The x8 evaluator is
compared against **two x4 evaluators**, not against a scalar reference, because
the x4 path is what ships: any disagreement is a behaviour change regardless of
which side is wrong.

Coverage is eight rounds of distinct mixed-torsion bases under random projective
scaling, swept over active masks `0xff`, `0x0f`, `0xf0`, `0b10110101`, a single
low lane, a single high lane, and zero. A separate test nulls each lane's table
in turn, carrying forward the guard added for the warm-comb nil-lane crash.

## What this does not yet establish

- **No complete-verifier number.** The evaluator is roughly half of the warm
  path, so a 31% evaluator gain implies something closer to 15% end to end. That
  needs its own A/B through the public API and has not been run.
- **Not wired.** The evaluator exists; the warm verifier still calls the x4 one.
- **Zen 4 unmeasured.** Zen 4 double-pumps 512-bit operations, and it is exactly
  where the two-chain candidate died. This result does not transfer to it.
- **Fill rate unaddressed, and it may dominate.** A true x8 warm group needs
  eight homogeneous warm lanes, not four, and mixed warm/cold lanes in one group
  are deliberately out of scope (incompatible doubling schedules). Today a pair
  that fails to be fully warm still runs one warm x4 group plus a cold one; with
  a genuine x8 kernel there is no such partial credit. Whether eight consecutive
  promoted keys occur often enough depends on the fee-payer recurrence
  distribution, which remains unmeasured.

Files: `bench.txt` (ten samples per row), `correctness.txt`, `environment.txt`,
`SHA256SUMS`.


## Cost model

`components.txt` measures each operation the evaluator's loop performs, so the
gap between their sum and the whole is measured rather than assumed. The shape
is fixed by the specs: A6/r9 contributes 43 digits at an online depth of 48,
B10/r5 contributes 26 digits at depth 40, so one group is 47 doublings, 43 A
selections and adds, and 26 B selections and adds.

| operation | each | count | total | share |
| --- | ---: | ---: | ---: | ---: |
| cached add | 72.5 ns | 69 | 5,002 ns | 40.7% |
| point double | 55.9 ns | 47 | 2,627 ns | 21.4% |
| scalar recode | 792 ns | 2 | 1,584 ns | 12.9% |
| select A (per-key) | 32.4 ns | 43 | 1,393 ns | 11.3% |
| select B (shared) | 13.8 ns | 26 | 359 ns | 2.9% |
| **explained** | | | **10,966 ns** | **89.2%** |
| unexplained (loop, init, final copy) | | | 1,330 ns | 10.8% |

Two things follow that were not obvious before measuring.

**Recoding was 16.5% of a pure-bookkeeping pass.** The generated assembly showed
why: `carry = (digit + half) / radix` compiled to a hardware `IDIVL` in the
innermost loop, once per digit per lane, so 344 divisions for A and 208 for B on
every group. The numerator is provably non-negative and the radix is a power of
two, so a shift is exactly the same value. Replacing it took the recoder from
1,043 to 792 ns and, because the x4 recoder carried the identical expression,
moved the **shipping** two-x4 form from 2,287 to 2,229 ns/signature.

**Selection is not the bottleneck.** A/B selection together is 14.2%, and the
addition and doubling arithmetic is 62.1%. Any further large gain has to come
from performing fewer group operations or cheaper ones, not from faster table
lookup.

### What reaching 1 microsecond would require

At 1,534 ns/signature, a sub-microsecond warm path needs 4,300 ns off a
12,272 ns group, about 35%. The levers, sized against the model above:

| lever | estimated saving | cost |
| --- | ---: | --- |
| vectorize the recoder across its eight lanes | up to 1,400 ns | none, it is scalar Go today |
| reduce online depth: A6/r5 with B10/r3 (23 doublings instead of 47) | ~1,340 ns | per-key table 19,200 to 34,560 B; shared B 369 KB to 553 KB |
| cheaper cached add (72.5 ns for what should be about seven field multiplies) | 700-1,400 ns | new fused leaf |
| wider A window, A6 to A8 (43 digits to 32) | ~800 ns | per-key table to 61,440 B, 3.2x |

The first three land near 1,050-1,100 ns/signature without touching the A
window. Going decisively below 1 microsecond needs the wider window, which is
per-key memory, and per-key memory is capacity: the choice is therefore gated on
the same unmeasured fee-payer recurrence distribution as the comb width itself.
