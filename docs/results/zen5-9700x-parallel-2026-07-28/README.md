# Zen 5 public parallel scaling refresh — 2026-07-28

This directory records the Go library's public-API parallel scaling at
`da0d045dae9df86a4a8550620c108913107e664c`. That commit includes the
register-resident decoder square chain from `1ac9fde` and is the exact source
used by the current GitHub-main README update.

Each benchmark operation calls exported `VerifyBatchStrict` over either four
or eight valid, distinct-key, 1232-byte messages. `RunParallel` distributes
complete operations across `GOMAXPROCS` workers. The r51 worker pools are
primed concurrently before the timer starts, so the rows measure steady-state
verification rather than pool construction.

Logical CPUs 0--7 are separate physical cores on this host; their SMT sibling
pairs are 0/8, 1/9, ..., 7/15. Each run used only the first P physical CPUs for
`GOMAXPROCS=P`.

## Current medians

| physical cores | n=4 signatures/s | n=4 scaling | n=8 signatures/s | n=8 scaling |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 113,683 | 1.00x | 214,557 | 1.00x |
| 2 | 227,249 | 2.00x | 428,237 | 2.00x |
| 4 | 446,454 | 3.93x | 844,757 | 3.94x |
| 6 | 648,426 | 5.70x | 1,200,035 | 5.59x |
| 8 | 817,310 | 7.19x | 1,482,474 | 6.91x |

Values are medians of six one-second samples. Every timed row reports 0 B/op,
0 allocs/op, and zero `InternalFaultFallbacks`. The aggregate eight-core costs
are 1.224 us/signature at n=4 and 0.675 us/signature at n=8; these throughput
ratios are not individual-request latency.

## Previous versus current

The previous README checkpoint at `ac8c1ab` measured 99,120 and 175,633
signatures/s on one core and 386,848 and 688,638 on four cores for n=4 and n=8
respectively. The current one-core results are +14.69% and +22.16%; the current
four-core results are +15.41% and +22.67%.

This is not an isolated square-chain A/B. All production changes between
`ac8c1ab` and `da0d045` are included. The isolated square-chain comparison is
recorded separately at implementation commits `c3fec3f` and `1ac9fde`.

Before timing, `go test ./internal/r51x5 ./ed25519` passed on the benchmark
host. The source worktree was clean after the tests.

## Files

- `p1.txt`, `p2.txt`, `p4.txt`, `p6.txt`, `p8.txt` — raw Go benchmark output
- `commands.txt` — exact commands
- `environment.txt` — source, CPU, topology, and toolchain
- `SHA256SUMS` — checksums for every evidence file except itself
