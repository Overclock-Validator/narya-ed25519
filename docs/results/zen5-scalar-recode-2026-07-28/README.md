# Zen 5 scalar-recoding gate — 2026-07-28

This gate measures balanced scalar-recoding changes on an AMD Ryzen 7 9700X
(Zen 5), Linux x86-64, Go 1.26.4, one pinned physical core,
`GOMAXPROCS=1`, and the performance governor. Timings are microseconds per
signature unless a table explicitly says nanoseconds per recoding operation.

The code baseline is `bff2afa`, which differs from `a8e35ae` only by the
recoder microbenchmark. The retained candidate is `7871582`.

## Result

The compiler emitted a signed integer divide and multiply for every active
balanced digit because the power-of-two radix remained a runtime value. The
numerator is nevertheless provably nonnegative: an extracted digit is in
`[0, 2^w-1]`, the incoming carry is zero or one, and the half-radix bias is
positive. Replacing division and multiplication by right and left shifts is
therefore exact.

The registered basepoint comb uses radix 256. Those digits are byte-aligned,
so its retained specialization reads `scalar[round]` directly instead of
running the general two-byte bit extractor. This reduces the fixed-base x8
recoder from approximately 584 to 337 ns/group, a 42% reduction.

The warm A6/B10 recoders benefit from loading each scalar into four 64-bit
words plus a zero guard. The complete cold x8 path does not: although its
isolated radix-32 recoder improved by 7.5%, the larger stack frame regressed
complete cold n=8 and n=64 verification by about 0.6%. Word preloading is
therefore retained only in the warm asymmetric recoder.

| public strict path, 1232-byte messages | baseline | retained | change |
|---|---:|---:|---:|
| cold n=1 | 16.172 | 15.842 | -2.04% |
| cold n=2 | 16.065 | 15.896 | -1.05% |
| cold n=4 | 8.682 | 8.575 | -1.24% |
| cold n=8 | 4.604 | 4.590 | -0.31% |
| cold n=64 | 4.405 | 4.382 | -0.51% |
| cache API n=1 (warm tables bypassed) | 16.333 | 16.196 | -0.84% |
| cache API n=2 (warm tables bypassed) | 16.228 | 16.099 | -0.80% |
| warm n=4 | 4.149 | 4.050 | -2.37% |
| warm n=8 | 3.910 | 3.814 | -2.47% |
| warm n=64 | 3.755 | 3.665 | -2.42% |

The n=4/8/64 rows used ten one-second samples; `benchstat` reported `p=0.000`
for those comparisons. The n=1/n=2 rows are medians from an isolated rerun of
the exact documented commits, with six two-second samples. That rerun corrected
four previously published narrow rows that contained an approximately twofold
timing discontinuity from CPU contention. The raw correction runs are committed
as `narya-scalar-recode-narrow-*-rerun.txt`. Every retained sample reported zero
allocations and zero internal fault fallbacks.

The warm-only word preload changed the isolated x4 recoders as follows:

| radix | shift-only ns/op | word preload ns/op | change |
|---|---:|---:|---:|
| 64 | 402.5 | 362.7 | -9.89% |
| 256 | 303.6 | 270.6 | -10.87% |
| 512 | 275.9 | 253.0 | -8.28% |
| 1024 | 247.9 | 228.0 | -8.03% |

## Rejected variants

- Clearing only the live digit rounds with `clear(out.rounds[:rounds])` caused
  Go to replace an inline Duff-zero sequence with a call to
  `runtime.memclrNoHeapPointers`. Relative to shift-only it regressed cold
  n=4/n=8 and warm n=4/n=8, so `c80a6f7` was reverted by `a83f56d`.
- An indexed loop assigning `RadixRoundX8{}` to each live round was retested at
  `ee4606f`. Go 1.26.4 kept all three recoder loops inline, with no `memclr` or
  `duffzero` in the hot symbols. Complete verification nevertheless regressed:
  cold n=1/n=2 by about 1.1--1.3% and cold n=8/n=64 by about 0.6--0.7%; warm
  results were flat or slightly slower. It was reverted by `8ff9976`. The
  stale-output reuse tests remain, because clearing every used round is a
  correctness property independent of the rejected implementation.
- Preloading words in `RecodeCanonicalScalarsX8` reduced its isolated
  radix-32 time from about 872 to 807 ns/group, but increased its frame from
  32 to 368 bytes and regressed complete cold n=8/n=64 by about 0.6%. The
  broad experiment at `bccd783` was narrowed by `f19f5b1`.
- The proposed explicit inlining of `setRadixRoundDigitX8` was unnecessary.
  Go 1.26.4 already inlines it and `signedDigitMagnitude`; generated code had
  no helper call to remove.

## Commands

Microbenchmarks:

```sh
taskset -c 2 env GOMAXPROCS=1 go test -run '^$' \
  -bench '^(BenchmarkFixedScalarRecodingX8|BenchmarkExperimentalFixedBaseCombRecodingX8|BenchmarkAsymmetricFixedBRecodingX4)$' \
  -benchmem -benchtime=1s -count=10 ./internal/r51x5
```

Complete public APIs:

```sh
taskset -c 2 env GOMAXPROCS=1 go test -tags r51_release_bench -run '^$' \
  -bench '^(BenchmarkPublicR51VerifyBatchStrict|BenchmarkPublicR51CacheVerifyBatchStrict)$/^msg=1232$/^n=(1|2|4|8|64)$' \
  -benchmem -benchtime=1s -count=10 ./ed25519
```

The old division-based scalar recoder remains in `RecodeRegularRadix`, which
the differential tests use as an implementation-independent oracle for the
fixed-storage recoders.

`SHA256SUMS` authenticates the committed correction, indexed-loop A/B, and
code-generation evidence.
