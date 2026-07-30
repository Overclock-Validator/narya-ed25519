# Zen 5 cold profile and radix-32 recoder — 2026-07-29

This bundle records cold strict verification on an AMD Ryzen 7 9700X
(Zen 5), Linux amd64, Go 1.26.4, the performance governor, one fixed physical
core, and `GOMAXPROCS=1`. The baseline is commit `dc6fb0e`; the retained
implementation is commit `b1c1ccc`.

All verifier inputs used 1,232-byte messages and distinct cold public keys.
Every public sample reported zero allocations and zero internal-fault
fallbacks. Timing values are microseconds per signature unless a table says
otherwise.

## Profile result

Ten-second 999 Hz cycle profiles identified these principal flat costs before
the change:

| width | largest flat symbols |
|---:|---|
| 1 | packed-x4 final multiply 31.73%; x4 normalized multiply 24.42%; repeated square 10.68%; SHA-512 7.30% |
| 8 | x8 final products 26.05%; double raw-products/Stage-2 leaf 15.04%; SHA-512 7.76%; generic scalar recoder 2.94% |
| 64 | x8 final products 27.53%; double raw-products/Stage-2 leaf 17.11%; SHA-512 7.59%; generic scalar recoder 3.30% |

After specialization, the recoder row fell to 1.52% at n=8 and 1.55% at
n=64. The large point-arithmetic symbols remained the dominant costs.

## Direct and complete A/B

The direct six-sample recoder median changed from 909.9 to 467.8 ns per eight
scalars (-48.6%). Ten two-second public samples measured:

| width | baseline | retained | change |
|---:|---:|---:|---:|
| 8 | 4.239 | 4.188 | -1.2% |
| 64 | 4.031 | 3.970 | -1.5% |

The n=1/n=2/n=4 comparison stayed within 0.4% in either direction. Those
paths do not call the full-x8 specialization, so their small differences are
treated as binary-layout/measurement drift rather than claimed gains.

## Method

The release benchmark binary was built with:

```sh
go test -c -tags r51_release_bench ./ed25519 -o "$BINARY"
```

The deciding n=8/n=64 public A/B used:

```sh
taskset -c 6 env GOMAXPROCS=1 "$BINARY" \
  -test.run '^$' \
  -test.bench '^BenchmarkPublicR51VerifyBatchStrict$/^msg=1232$/^n=(8|64)$' \
  -test.benchmem -test.benchtime=2s -test.count=10
```

The n=1/n=2/n=4 non-regression check used the same command with
`^n=(1|2|4)$` and six samples.

Profiles used one width per invocation:

```sh
perf record -F 999 -g -o "$PERF_DATA" -- \
  taskset -c 6 env GOMAXPROCS=1 "$BINARY" \
  -test.run '^$' \
  -test.bench '^BenchmarkPublicR51VerifyBatchStrict$/^msg=1232$/^n=8$' \
  -test.benchtime=10s -test.count=1

perf report --stdio --no-children -g none --percent-limit 0.20 \
  --sort symbol -i "$PERF_DATA"
```

The same profile command was run independently for n=1, n=8, and n=64.
`SHA256SUMS` authenticates the raw text artifacts. Binary `perf.data` files
are intentionally excluded.
