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
| two x4 groups (current shape) | 2,287 | 2,285 | 2,287 | 0 |
| one x8 group (candidate) | 1,577 | 1,572 | 1,582 | 0 |

That is a **31.0% reduction per signature**, a 1.45x speedup, with the spread
inside 0.5% on both rows.

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
