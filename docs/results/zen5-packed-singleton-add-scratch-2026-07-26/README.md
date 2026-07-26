# Zen 5 packed-singleton cached-add scratch gate — 2026-07-26

This directory records the packed x4 cached-add A/B on an AMD Ryzen 7 9700X
(Zen 5), Go 1.26.4, one pinned physical core, `GOMAXPROCS=1`, and the
performance governor. The baseline includes the retained doubling workspace at
`9f5659d`; the retained cached-add implementation is `12941c8`.

## Change and safety boundary

The packed cached-point addition had the same dead-initialization shape as the
former singleton doubling: five fully-overwritten 160-byte temporaries were
declared inside each operation. The retained implementation reuses four
temporaries across the scalar multiplication and writes the final
multiplication directly to the output point.

Input/output aliasing remains valid because the input point is fully permuted
into the workspace and multiplied with the cached addend before the output is
written. A poisoned-scratch test fills every workspace limb with unrelated
out-of-range patterns, then compares 32 repeated in-place additions against a
clean workspace. The existing random projective, torsion, and range-envelope
oracles remain unchanged.

## Measurements

Ten pinned samples measured:

| cached-add kernel | ns/addition | change from baseline |
|---|---:|---:|
| baseline packed x4 | 48.97 | — |
| retained reused workspace | 43.79 | -10.6% |

Ten one-second samples through exported `VerifyBatchStrict`, with 1232-byte
messages, measured the incremental effect after the doubling optimization:

| public cold batch | doubling-only us/signature | plus add workspace us/signature | change |
|---|---:|---:|---:|
| n=1 | 20.90 | 20.38 | -2.5% |
| n=2 | 20.81 | 20.45 | -1.7% |

Every timed row reported 0 B/op, 0 allocs/op, and zero internal fault
fallbacks. The complete native repository suite passed before retaining the
change. The n=4/8/64 kernels do not use this packed singleton operation and
were already gated as unaffected by the preceding workspace checkpoint.

## Reproduction

```sh
taskset -c 2 env GOMAXPROCS=1 go test -run '^$' \
  -bench '^BenchmarkExperimentalCoordinateParallelCachedAddX4$/^chained/quad-packed-cached(-reused-workspace)?$' \
  -benchmem -benchtime=500ms -count=10 ./internal/r51x5

taskset -c 2 env GOMAXPROCS=1 go test -tags r51_release_bench -run '^$' \
  -bench '^BenchmarkPublicR51VerifyBatchStrict$/^msg=1232$/^n=(1|2)$' \
  -benchmem -benchtime=1s -count=10 ./ed25519
```

The raw files contain no machine addresses, account names, or local paths.
