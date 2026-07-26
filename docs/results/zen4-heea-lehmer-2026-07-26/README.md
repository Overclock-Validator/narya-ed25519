# Zen 4 modulo-8L Lehmer reducer checkpoint — 2026-07-26

Implementation commits: `aa695cb` and `957212d`.

This is research code. It is not imported by a verifier, has no dispatch path,
and makes no side-channel claim.

## Correctness boundary

The selector advances the exact principal Euclidean sequence in batches and
must stop on the same row. Tests compare complete candidates over 60,000
deterministic random challenges at widths 128, 132, and 136. An independent
`big.Int` oracle checks `rho = tau*k (mod 8L)` and that `tau` is a unit modulo
`8L`. Edge, iteration, batching-engagement, and zero-allocation tests passed on
both the development host and an AMD Ryzen 7 PRO 8700GE with Go 1.26.4.

## Same-input result

`BenchmarkSelectLehmerComparison` feeds Lehmer, exact principal Euclid, and
shift/subtract the same 512 canonical challenges. At width 128, the stable
high-throughput bands on the Ryzen host were:

| selector | ns/selection | reading |
|---|---:|---|
| Lehmer | 8,008–8,319 | retained research checkpoint |
| exact principal Euclid | 19,702–20,161 | Lehmer is approximately 2.4x faster |

Every timed row reported zero allocations. The host changed to a slower
throughput regime partway through the comparator run, so the later
shift/subtract rows and the slow principal samples are not used for a ratio.
The absolute Lehmer cost is already comparable to a complete wide cold
verification and therefore fails the integration gate despite the improvement
over exact Euclid.

## Next reducer question

The remaining wide cost is `applyLehmerMatrix`: four signed 320-bit combines
per batch. Narrowing the proven coefficient range and applying all four matrix
outputs in one pass is the next isolated experiment. It must beat the complete
verifier opportunity cost before any point kernel or public HEEA route is
considered.

That follow-up is complete. The same-binary result at commit `69e8374` is
recorded in
[`../zen4-heea-matrix-fusion-2026-07-26`](../zen4-heea-matrix-fusion-2026-07-26/README.md).
It reduced complete W128 selection from 3.978 to 3.647 us. The older absolute
8.0--8.3 us band above is retained as provenance, not as the current cost.

## Reproduction

```sh
go test -count=1 ./internal/heea8l

taskset -c 2 env GOMAXPROCS=1 go test -run '^$' \
  -bench '^BenchmarkSelectLehmerComparison$/^width=128$/.*' \
  -benchmem -benchtime=750ms -count=8 ./internal/heea8l
```

No machine addresses, account names, or local filesystem paths are recorded
here.
