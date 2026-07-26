# Zen 5 packed-singleton Stage-2 reschedule — 2026-07-26

This directory records the packed x4 doubling Stage-2 reschedule on an AMD
Ryzen 7 9700X (Zen 5), Go 1.26.4, one pinned physical core,
`GOMAXPROCS=1`, and the performance governor. The baseline is `fa2b9cc`; the
retained implementation is `2724c44`.

The native leaf now constructs the same `[E,G,H,F]` values with two source
permutations, sum/difference vectors, and public lane masks. Its exact
representation oracle, alias tests, zero-allocation gate, full point tests, and
complete repository suite all passed on IFMA hardware.

An earlier local draft substituted cached-add F=`D-C` for doubling
F=`B-A-2C`. The direct oracle and honest-signature suite rejected it before
timing; it was corrected before publication.

## Measurements

| measurement | `fa2b9cc` | `2724c44` | change |
|---|---:|---:|---:|
| doubling, ns/operation | 32.75 | 31.96 | -2.4% |
| public n=1, us/signature | 16.75 | 16.61 | -0.8% |
| public n=2, us/signature | 16.74 | 16.52 | -1.3% |

All public rows use 1232-byte messages and reported 0 B/op, 0 allocs/op, and
zero internal fault fallbacks. n=4/8/64 were structurally unaffected.

## Reproduction

```sh
taskset -c 2 env GOMAXPROCS=1 go test -run '^$' \
  -bench '^BenchmarkExperimentalCoordinateParallelDoubleX4$/^chained/quad-packed-reused-workspace$' \
  -benchmem -benchtime=500ms -count=10 ./internal/r51x5

taskset -c 2 env GOMAXPROCS=1 go test -tags r51_release_bench -run '^$' \
  -bench '^BenchmarkPublicR51VerifyBatchStrict$/^msg=1232$/^n=(1|2)$' \
  -benchmem -benchtime=1s -count=10 ./ed25519
```

The raw files contain no machine addresses, account names, or local paths.
