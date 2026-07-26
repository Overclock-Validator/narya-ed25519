# Zen 5 packed-singleton doubling scratch gate — 2026-07-26

This directory records the packed x4 singleton A/B on an AMD Ryzen 7 9700X
(Zen 5), Go 1.26.4, one pinned physical core, `GOMAXPROCS=1`, and the
performance governor. The baseline is `5cd6585`; the retained implementation
is `9f5659d`.

## Change and safety boundary

The singleton doubling previously declared six 160-byte packed field elements
inside every call. Generated amd64 code allocated a 992-byte frame and emitted
six zeroing sequences even though each element was fully overwritten before
its first read. A singleton verification performs roughly 253 dependent
doublings.

The retained code moves five intermediate elements into a reusable workspace
owned by the scalar-multiplication call and writes the final multiply directly
to the output point. Input/output aliasing remains valid because the input point
is fully permuted into the workspace before the output write. A poisoned-scratch
test fills every workspace limb with unrelated out-of-range bit patterns, then
compares 32 repeated in-place doublings with a clean workspace. The native
helper's generated frame is 64 bytes and contains no scratch-clearing sequence.

## Measurements

Ten pinned samples measured the isolated dependent doubling:

| kernel | ns/doubling | change from baseline |
|---|---:|---:|
| baseline packed x4 | 49.13 | — |
| retained reused workspace | 42.69 | -13.1% |

Ten one-second samples through exported `VerifyBatchStrict`, using 1232-byte
messages, measured:

| public cold batch | baseline us/signature | retained us/signature | change |
|---|---:|---:|---:|
| n=1 | 22.50 | 20.91 | -7.1% |
| n=2 | 22.25 | 20.81 | -6.5% |

The unchanged n=4, n=8, and n=64 paths were re-run separately and remained at
approximately 10.14, 5.43, and 5.10 us/signature. Every timed row reported
0 B/op, 0 allocs/op, and zero internal fault fallbacks. The full native
repository suite passed before the change was retained.

## Reproduction

```sh
taskset -c 2 env GOMAXPROCS=1 go test -run '^$' \
  -bench '^BenchmarkExperimentalCoordinateParallelDoubleX4$/^chained/quad-packed-(xytz|reused-workspace)$' \
  -benchmem -benchtime=500ms -count=10 ./internal/r51x5

taskset -c 2 env GOMAXPROCS=1 go test -tags r51_release_bench -run '^$' \
  -bench '^BenchmarkPublicR51VerifyBatchStrict$/^msg=1232$/^n=(1|2)$' \
  -benchmem -benchtime=1s -count=10 ./ed25519

taskset -c 2 env GOMAXPROCS=1 go test -tags r51_release_bench -run '^$' \
  -bench '^BenchmarkPublicR51VerifyBatchStrict$/^msg=1232$/^n=(4|8|64)$' \
  -benchmem -benchtime=750ms -count=6 ./ed25519
```

The raw files contain no machine addresses, account names, or local paths.
