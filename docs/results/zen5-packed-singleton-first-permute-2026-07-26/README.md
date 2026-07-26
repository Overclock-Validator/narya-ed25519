# Zen 5 packed-singleton first-permutation gate — 2026-07-26

This directory records the packed x4 doubling input-permutation A/B on an AMD
Ryzen 7 9700X (Zen 5), Go 1.26.4, one pinned physical core,
`GOMAXPROCS=1`, and the performance governor. The baseline includes both
retained Stage-2 leaves at `345e996`; the retained permutation implementation
is `bdaa628`.

## Change and safety boundary

The change replaces scalar Go extraction of packed `[X,Y,T,Z]` lanes into
U=`[X,Y,Z,X]` and V=`[X,Y,Z,Y]` with one assembly leaf. It performs no field
arithmetic. All five input vectors are loaded before the first output store, so
the input may alias either output; the two outputs must be distinct.

Direct tests compare the native result bit for bit with the portable
construction over boundary and random u52 vectors, both alias directions, and
zero-allocation execution. Existing full point-operation tests remain the
independent semantic oracle.

## Measurements

Ten pinned samples measured:

| doubling kernel | ns/doubling | change from baseline |
|---|---:|---:|
| cached-add Stage-2 baseline (`345e996`) | 34.94 | — |
| native first permutation (`bdaa628`) | 32.75 | -6.3% |

Ten one-second samples through exported `VerifyBatchStrict`, with 1232-byte
messages, measured:

| public cold batch | `345e996` us/signature | `bdaa628` us/signature | change |
|---|---:|---:|---:|
| n=1 | 17.72 | 17.23 | -2.8% |
| n=2 | 17.83 | 17.17 | -3.7% |

A four-sample dispatch-boundary check measured n=4/8/64 at approximately
10.13/5.42/5.12 us/signature. Those widths do not execute this helper. Every
timed row reported 0 B/op, 0 allocs/op, and zero internal fault fallbacks.

The exact public baseline is in the adjacent
`zen5-packed-singleton-cached-stage2-2026-07-26/quad-cached-stage2-public.after`
file.

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
