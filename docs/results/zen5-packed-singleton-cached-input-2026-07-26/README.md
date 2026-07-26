# Zen 5 packed-singleton cached-input gate — 2026-07-26

This directory records the packed x4 cached-add input-normalization A/B on an
AMD Ryzen 7 9700X (Zen 5), Go 1.26.4, one pinned physical core,
`GOMAXPROCS=1`, and the performance governor. The baseline includes the native
doubling permutation at `7c5500a`; the retained cached-input implementation is
`3961d6e`.

## Change and safety boundary

The change replaces scalar Go construction and normalization of
`[Y-X,Y+X,T,Z]` with one assembly leaf. It adds 4p only to the subtraction
lane, keeps every pre-carry limb non-negative and below `6*2^51`, then applies
one carry/fold. Every input vector is loaded before output, preserving in-place
aliasing.

Direct tests compare the native result bit for bit with the portable
construction over boundary and random u52 vectors, aliasing, and
zero-allocation execution. Existing point-operation tests remain the semantic
oracle.

## Measurements

Ten pinned samples measured:

| cached-add kernel | ns/addition | change from baseline |
|---|---:|---:|
| final-Stage-2 baseline (`345e996`) | 34.95 | — |
| native cached input (`3961d6e`) | 33.72 | -3.5% |

Ten one-second samples through exported `VerifyBatchStrict`, with 1232-byte
messages, measured:

| public cold batch | `7c5500a` us/signature | `3961d6e` us/signature | change |
|---|---:|---:|---:|
| n=1 | 17.23 | 16.75 | -2.8% |
| n=2 | 17.17 | 16.74 | -2.5% |

A four-sample dispatch-boundary check measured n=4/8/64 at approximately
10.15/5.43/5.10 us/signature. Every timed row reported 0 B/op, 0 allocs/op,
and zero internal fault fallbacks.

The exact public baseline is in the adjacent
`zen5-packed-singleton-first-permute-2026-07-26/quad-first-permute-public.after`
file.

## Reproduction

```sh
taskset -c 2 env GOMAXPROCS=1 go test -run '^$' \
  -bench '^BenchmarkExperimentalCoordinateParallelCachedAddX4$/^chained/quad-packed-cached-reused-workspace$' \
  -benchmem -benchtime=500ms -count=10 ./internal/r51x5

taskset -c 2 env GOMAXPROCS=1 go test -tags r51_release_bench -run '^$' \
  -bench '^BenchmarkPublicR51VerifyBatchStrict$/^msg=1232$/^n=(1|2)$' \
  -benchmem -benchtime=1s -count=10 ./ed25519
```

The raw files contain no machine addresses, account names, or local paths.
