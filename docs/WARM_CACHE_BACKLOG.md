# Warm-cache performance backlog

This is a parking lot, not the active optimization plan. Cold arbitrary-key
verification has priority while measured cold opportunities remain. Warm-only
ideas stay here so they are not lost or accidentally presented as shipped
gains.

## High-ceiling measurements

1. **Re-measure realistic key populations.** Sweep distinct prepared keys
   across L1, L2, LLC, and DRAM regimes. Report both hit rate and per-hit cost;
   a tiny all-resident fixture is not a capacity result.
2. **Choose cache size from a recurrence curve.** Replay exact key sequences
   over several byte budgets. Record the knee rather than inheriting the
   current 128 MiB limit.
3. **Compare A6/r9 with smaller-table shapes after the point kernel settles.**
   The smaller table buys population locality but performs more additions and
   gathers. Only a complete verifier at the intended key population can decide
   the trade.
4. **Measure mixed warm/cold scheduling.** Grouping complete warm lanes avoids
   masked phases but can reduce occupancy. Compare occupancy-first, warmth-
   segregated, and same-key grouping with stable result-index permutation.

## Structural candidates

- Keep a broad decoded-A tier underneath the narrower comb tier. Its saving per
  hit is smaller, but its roughly point-sized entries cover a much longer key
  tail and work below the comb's minimum useful recurrence.
- For known trusted key sets, preload or lazily build entries without exposing
  an attacker-controlled admission channel.
- Explore per-key scalar/micro-AoS storage followed by x8 packing, including a
  same-key broadcast path. Treat packing cost as part of verification.
- Compact phase subsets rather than masking them when enough lanes need the
  same warm-only phase. Preserve the original result indices explicitly.
- If the population grows beyond LLC, evaluate a pointer-free mmap arena with
  huge-page advice and separately measure TLB walks, GC scan cost, and eviction
  behavior.
- Test a probationary recurrence tier that cannot evict established hot keys.
  Invalid signatures must never earn admission.

## Promotion rule

No item above belongs in dispatch from an isolated table or selector result.
It needs exact predicate differentials, zero-allocation gates, adversarial
churn tests where applicable, and a complete-verifier A/B at realistic key
population and message sizes.
