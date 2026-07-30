# Zen 5 packed cached-add final-stage fusion — 2026-07-29

This bundle records the native gate for implementation commit `90384db` on an
AMD Ryzen 7 9700X (Zen 5), Linux amd64, Go 1.26.4, the performance governor,
one fixed physical core, and `GOMAXPROCS=1`. The exact parent is `0b438ce`.
Both release binaries were built from `git archive` checkouts with the same Go
toolchain and `r51_release_bench` build tag.

The candidate fuses the packed cached-add final linear/carry layer with the
normalized field multiply that consumes it. It also explicitly aligns the
dominant x8 multiply and the new packed leaf so adding packed-only text cannot
silently move the full-x8 hot loop between cache-line halves.

All timing values are microseconds per signature unless the table says
otherwise. Lower is better.

## Results

The direct same-binary leaf gate was 33.78 ns split versus 31.75 ns fused
(-6.0%), with zero allocations.

| message bytes | parent n=1 | fused n=1 | change |
|---:|---:|---:|---:|
| 200 | 14.20 | 13.98 | -1.51% |
| 1,232 | 15.05 | 14.85 | -1.33% |
| 4,096 | 17.03 | 16.79 | -1.41% |

Every public row reported zero allocations and zero internal-fault fallbacks.
The 1,232-byte result was a hard non-regression gate; the 4,096-byte result was
not allowed to buy a gain at its expense.

The authoritative post-change public matrix is the median of ten two-second
samples at each width:

| batch size | 200 bytes | 1,232 bytes | 4,096 bytes |
|---:|---:|---:|---:|
| 1 | 13.900 | 14.580 | 16.840 |
| 2 | 13.970 | 14.710 | 16.820 |
| 4 | 7.497 | 8.024 | 9.363 |
| 8 | 3.930 | 4.189 | 4.895 |
| 64 | 3.713 | 3.963 | 4.685 |

The initial separate-binary n=8/n=64 control was sensitive to host frequency
drift at the sub-percent scale. `public-1232-unaffected-abba.txt` therefore
runs exact parent, final candidate, final candidate, exact parent in one
sequence. The two binaries track the same time drift, as expected because
those widths do not execute the packed fused leaf. The explicit alignments
remove the repeatable half-cache-line placement difference found in the first
uncontrolled comparison.

## Correctness gates

- fused versus split native exact-representation differential over zero,
  maximum-u52, and 512 deterministic random vectors;
- output/input aliasing and zero-allocation checks;
- packed mixed-order point, NAF, cached-add, and doubling differentials;
- full `go test -count=1 ./...` locally and on native Zen 5; and
- `go vet ./...` and `git diff --check`.

## Commands

The public n=1 message-size gate used:

```sh
taskset -c 6 env GOMAXPROCS=1 "$BINARY" \
  -test.run '^$' \
  -test.bench '^BenchmarkPublicR51VerifyBatchStrict$/^msg=(200|1232|4096)$/^n=1$' \
  -test.benchmem -test.benchtime=1s -test.count=6
```

The authoritative matrix changed the message expression to
`^msg=(200|1232|4096)$`, the width expression to `^n=(1|2|4|8|64)$`, and used
ten two-second samples. The ABBA control used n=8/64, five one-second samples
per binary per leg, and the order parent/candidate/candidate/parent.

The direct leaf gate used:

```sh
taskset -c 6 env GOMAXPROCS=1 "$R51X5_BINARY" \
  -test.run '^$' \
  -test.bench '^BenchmarkExperimentalCoordinateParallelCachedAddX4$/chained/quad-packed-cached-(reused-workspace|split-control)$' \
  -test.benchmem -test.benchtime=1s -test.count=10
```

## Files

- `public-n1-before.txt`, `public-n1-after.txt`, and
  `public-n1-benchstat.txt`: exact parent/final complete n=1 gate.
- `public-1232-before.txt` and `public-1232-after.txt`: standard width matrix.
- `public-1232-unaffected-abba.txt`: ordered code-layout/frequency control.
- `public-1232-unaffected-before.txt` and `-after.txt`: earlier isolated
  control retained so the reason for the ABBA rerun is auditable.
- `direct-leaf-and-focused-tests.txt` and `direct-leaf-benchstat.txt`: native
  direct differential status and same-binary component measurement.
- `public-final-matrix.txt`: authoritative post-change public cold matrix.
- `environment.txt`: CPU, kernel, Go toolchain, governor, and frequency-policy
  snapshot from the benchmark host.
- `SHA256SUMS`: hashes for every raw and summarized artifact.
