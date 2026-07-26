# Zen 5 public parallel scaling — 2026-07-26

This directory records the public-API parallel scaling gate introduced at
commit `ac8c1abd1ed017921cf6440b2465f0993ae01c1a`.

Each benchmark operation calls exported `VerifyBatchStrict` over either four
or eight valid, distinct-key, 1232-byte messages. `RunParallel` distributes
complete operations across `GOMAXPROCS` workers. The r51 worker pools are
primed concurrently before the timer starts, so the rows measure steady-state
verification rather than pool construction.

Logical CPUs 0--7 are separate physical cores on this host; their SMT sibling
pairs are 0/8, 1/9, ..., 7/15. Each run used only the first P physical CPUs for
`GOMAXPROCS=P`.

## Median results

| physical cores | n=4 signatures/s | n=4 scaling | n=8 signatures/s | n=8 scaling |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 99,120 | 1.00x | 175,633 | 1.00x |
| 2 | 196,862 | 1.99x | 352,288 | 2.01x |
| 4 | 386,848 | 3.90x | 688,638 | 3.92x |
| 6 | 560,078 | 5.65x | 978,018 | 5.57x |
| 8 | 705,648 | 7.12x | 1,216,888 | 6.93x |

Values are medians of six one-second samples. Every timed row reports 0 B/op,
0 allocs/op, and zero `InternalFaultFallbacks`. The aggregate eight-core costs
are 1.417 us/signature at n=4 and 0.822 us/signature at n=8; these throughput
ratios are not individual-request latency.

An on-host race-detector run was attempted, but the benchmark host deliberately
lacks a C compiler and Go's race runtime requires cgo. This artifact therefore
makes no new race-detector claim; it records native correctness/fault gates and
steady-state scaling only.

## Files

- `p1.txt`, `p2.txt`, `p4.txt`, `p6.txt`, `p8.txt` — raw Go benchmark output
- `commands.txt` — exact commands
- `environment.txt` — source, CPU, topology, and toolchain
- `SHA256SUMS` — checksums for every evidence file except itself

