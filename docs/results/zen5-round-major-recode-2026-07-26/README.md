# Zen 5 x8 scalar-recoding gate — 2026-07-26

This directory records the scalar-recoding A/B on an AMD Ryzen 7 9700X
(Zen 5), Go 1.26.4, one pinned physical core, `GOMAXPROCS=1`, and the
performance governor. All timings below are nanoseconds per eight-scalar
recoding operation or microseconds per verified signature, as labeled.

The baseline is `e353884`. The retained candidate is `586e764` (which includes
the intermediate `11ee611`).

## Result

The first design in `11ee611` used a stateful streaming bit reader. It was
rejected at the microbenchmark gate: radix-32 recoding increased from about
1.19 to 1.34 microseconds per eight scalars. The per-window refill branch and
reader-state updates cost more than the avoided byte loads.

`586e764` restores the simple random-access extractor and instead changes only
the x8 loop orientation. It validates lanes first, then constructs the existing
round-major output in round-major order. This computes the public bit offset
once per round and keeps one output round hot while installing all eight lanes.

| recoding radix | baseline ns/op | round-major ns/op | approximate change |
|---|---:|---:|---:|
| 16 | 1,468 | 1,078 | -26.6% |
| 32 | 1,188 | 871 | -26.7% |
| 64 | 1,049 | 742 | -29.3% |

Ten one-second public-API samples at message length 1232 measured:

| public cold batch | baseline us/signature | round-major us/signature | approximate change |
|---|---:|---:|---:|
| n=8 | 5.442 | 5.421 | -0.4% |
| n=64 | 5.136 | 5.099 | -0.7% |

A separate six-sample n=1/2/4/8/64 matrix confirmed that n=1, n=2, and n=4
remain neutral within roughly 0.5% run drift, as expected because those paths
do not use the changed x8 recoders. Every timed row reported 0 B/op,
0 allocs/op, and zero internal fault fallbacks. The complete native repository
test suite passed at `586e764`.

## Reproduction

Microbenchmark:

```sh
taskset -c 2 env GOMAXPROCS=1 go test -run '^$' \
  -bench '^BenchmarkFixedScalarRecodingX8$' -benchmem \
  -benchtime=500ms -count=10 ./internal/r51x5
```

Complete public path:

```sh
taskset -c 2 env GOMAXPROCS=1 go test -tags r51_release_bench -run '^$' \
  -bench '^BenchmarkPublicR51VerifyBatchStrict$/^msg=1232$/^n=(8|64)$' \
  -benchmem -benchtime=1s -count=10 ./ed25519
```

Width validation matrix:

```sh
taskset -c 2 env GOMAXPROCS=1 go test -tags r51_release_bench -run '^$' \
  -bench '^BenchmarkPublicR51VerifyBatchStrict$/^msg=1232$/^n=(1|2|4|8|64)$' \
  -benchmem -benchtime=750ms -count=6 ./ed25519
```

The raw files contain no machine addresses, account names, or local paths.
