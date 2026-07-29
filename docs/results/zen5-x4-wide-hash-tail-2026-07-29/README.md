# Zen 5 x4-curve / x8-hash cold tails — 2026-07-29

This bundle records the retention gate for implementation commit
`45da721d8b98d59e16be7a225c15c367ee88bf4a` on an AMD Ryzen 7 9700X
(Zen 5), Linux amd64, Go 1.26.4, the performance governor, one fixed physical
core, and `GOMAXPROCS=1`. The production baseline is `edb0270`.

The change keeps x4 point arithmetic for four-to-seven-signature cold tails
but hashes and reduces their compacted challenges through the native x8 path.
AMD family 1Ah selects it. Zen 4 and unknown IFMA CPUs retain the measured x4
hash path. Counts below four also retain x4 hashing.

Every timed row reported zero allocations. The public release wrapper also
reported zero internal-fault fallbacks. Timing values below are microseconds
per signature unless stated otherwise.

## Same-binary result

Ten two-second samples compared the two hash widths in the same binary:

| count | message bytes | x4 hash | x8 hash | change |
|---:|---:|---:|---:|---:|
| 2 | 200 | 14.95 | 14.97 | +0.17% |
| 2 | 1,232 | 16.98 | 16.98 | no significant difference |
| 2 | 4,096 | 22.36 | 22.35 | no significant difference |
| 4 | 200 | 7.740 | 7.550 | -2.46% |
| 4 | 1,232 | 8.748 | 8.050 | -7.99% |
| 4 | 4,096 | 11.480 | 9.367 | -18.41% |

The two-lane result is the reason production requires at least four active
lanes. The 1,232-byte case is a hard non-regression gate: the 4,096-byte gain
was not accepted by trading away the primary 1,232-byte workload.

## Rejected half-active x8 curve route

A six-sample three-way check compared x4 curve/x4 hash, x4 curve/x8 hash, and
four-active-lane x8 curve/x8 hash. The half-active x8 curve route improved the
two longer messages but was slower at 200 bytes and was dominated by the
retained composition at all three sizes:

| message bytes | x4 curve/x4 hash | x4 curve/x8 hash | partial x8 curve/x8 hash |
|---:|---:|---:|---:|
| 200 | 7.700 | **7.524** | 7.736 |
| 1,232 | 8.753 | **8.046** | 8.204 |
| 4,096 | 11.510 | **9.401** | 9.582 |

The dormant partial-x8 seam remains differential-tested and explicitly
experimental. It is not selected by the registered backend.

## Correctness gates

- both `DalekStrict` and `StdlibCompat` were compared with the independent
  reference over mixed valid, invalid, noncanonical, and mixed-order vectors;
- counts 4--7, 12--15, and 17 exercised direct tails and a full x8 group plus
  tail;
- both candidate paths reported zero allocations at counts 4, 5, 7, 12, 15,
  and 64;
- CPU-policy tests prove family 19h keeps x4 hashing, family 1Ah selects wide
  hashing, and the SDE-only policy override actually reaches the path; and
- full `go test -count=1 ./...` and `go vet ./...` passed locally and on the
  native Zen 5 host.

## Commands

The same-binary A/B used:

```sh
taskset -c 6 env GOMAXPROCS=1 "$BINARY" \
  -test.run '^$' \
  -test.bench '^BenchmarkR51IFMAPartialX8TailCompletePipeline$/^path=(x4|x4-wide-hash)/n=(2|4)/msg=(200|1232|4096)$' \
  -test.benchmem -test.benchtime=2s -test.count=10
```

The compact three-way regime check changed the path expression to
`(x4|x4-wide-hash|partial-x8)`, fixed `n=4`, and used six one-second samples.
The exported-wrapper gate used `BenchmarkPublicR51VerifyBatchStrict` at
`n=1/2/4/8/64`, 200/1,232/4,096 bytes, and ten two-second samples.

## Files

- `direct-x4-vs-wide-hash.txt` and `-benchstat.txt`: decisive same-binary gate.
- `three-way-n4.txt` and `-benchstat.txt`: retained versus rejected composition.
- `public-before.txt`: full exported-wrapper baseline matrix.
- `public-after-final.txt`: final n=1/n=2/n=4 exported-wrapper gate.
- `public-after-full-pre-narrow.txt`: full candidate matrix before the final
  n<4 dispatch restriction; n=4/n=8/n=64 execute the final production routes.
- `public-before-reverse-control.txt`: reverse-order narrow-width control.
- `SHA256SUMS`: hashes for every raw and summarized artifact.
