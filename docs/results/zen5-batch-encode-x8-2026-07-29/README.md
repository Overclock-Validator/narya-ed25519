# Zen 5 x8 batch encoding — 2026-07-29

This bundle records the native gate for implementation commit `e1c253a` on an
AMD Ryzen 7 9700X (Zen 5), Linux amd64, Go 1.26.4, the performance governor,
one fixed physical core, and `GOMAXPROCS=1`. The exact implementation parent is
`c5e4ee2`.

The earlier literal-Q finalizer converted projective points to compressed bytes
four signatures at a time. The candidate retains the same Montgomery prefix
schedule and its single inversion per at-most-64-signature chunk, while doing
the prefix, reverse, affine, and reduction work in eight lanes. A direct x8
handoff avoids splitting an already-wide equation result only to join it again
before finalization.

All table values are microseconds per signature. Lower is better.

## Crossover gate

The path order was x8/x4/x4/x8. Each median contains twelve one-second samples
on 1,232-byte messages:

| batch size | x4 encoder | x8 encoder | change |
|---:|---:|---:|---:|
| 16 | 3.9975 | 3.9825 | -0.38% |
| 32 | 3.9405 | 3.9215 | -0.48% |

The prior n=8 A/B was neutral after removing the split/repack round trip, while
n=64 improved by about 0.27%. The registered Zen 5 policy therefore selects x8
only from 16 signatures. Zen 4 and unmeasured CPUs retain x4.

## Message-size gate

Each median contains six one-second samples:

| batch | bytes | x4 encoder | x8 encoder | change |
|---:|---:|---:|---:|---:|
| 16 | 200 | 3.7345 | 3.7410 | +0.17% |
| 16 | 1,232 | 4.0110 | 3.9945 | -0.41% |
| 16 | 4,096 | 4.7320 | 4.7250 | -0.15% |
| 64 | 200 | 3.6720 | 3.6550 | -0.46% |
| 64 | 1,232 | 3.9190 | 3.9045 | -0.37% |
| 64 | 4,096 | 4.6680 | 4.6280 | -0.86% |

The noise-sized n=16/200 regression is accepted because the 1,232-byte cold
path is the hard non-regression target, all other measured rows improve, and
the dispatch remains x4 below n=16. This is a small throughput refinement, not
the approximately 1.35% originally projected: the fixed inversion already runs
once per chunk and remains the dominant part of this finalizer.

## Registered public API

Ten two-second samples through `SetBackend("r51")` and
`VerifyBatchStrict` reported medians of 4.204 us/signature at n=8 and
3.961 us/signature at n=64 for 1,232-byte messages. Every sample reported zero
allocations and zero internal-fault fallbacks. The n=8 row deliberately retains
the x4 encoder.

## Correctness gates

- x8 versus x4 output differentials for all 256 one-group active masks and
  sparse multi-group masks;
- independent model versus native IFMA output equality;
- canonical-zero and modulus-alias-zero `Z` rejection before inversion;
- inactive-coordinate isolation, invalid-range rejection, exact operation
  counts, and exhaustive injected arithmetic-failure output atomicity;
- both supported predicates, mixed valid/invalid inputs, counts across and
  beyond the threshold, and zero-allocation complete-path tests;
- explicit CPU-policy tests for Zen 5 selection, Zen 4 retention, missing IFMA,
  and unmeasured future AMD families;
- full native and local `go test -count=1 ./...`, plus local `go vet ./...`.

The first native threshold run rejected n=8/n=9 and was not accepted as
evidence. It exposed stale width routing: the evaluator wrote x8 scratch while
the sub-threshold x4 finalizer read x4 scratch. The final code derives one
per-chunk width state used by both storage and finalization, and a direct
threshold regression test pins the boundary.

## Files

- `crossover-abba.txt`: balanced n=16/n=32 1,232-byte A/B.
- `all-message-sizes.txt`: n=16/n=64 200/1,232/4,096-byte gate.
- `public-after.txt`: registered public-API n=8/n=64 output.
- `commands.txt`: reproducible native commands without machine-specific paths.
- `SHA256SUMS`: hashes for every other artifact in this directory.
