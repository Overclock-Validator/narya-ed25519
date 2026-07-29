# Zen 5 packed doubling input/multiply fusion — 2026-07-29

This bundle records the native gate for implementation commit `9f9df33` on an
AMD Ryzen 7 9700X (Zen 5), Linux amd64, Go 1.26.4, the performance governor,
one fixed physical core, and `GOMAXPROCS=1`. The exact implementation parent is
`90384db`. Both release binaries used the same Go toolchain and
`r51_release_bench` build tag. The full environment is unchanged from the
snapshot in
[`../zen5-packed-cached-add-fusion-2026-07-29/environment.txt`](../zen5-packed-cached-add-fusion-2026-07-29/environment.txt).

The candidate fuses the packed doubling input permutations with their
immediate normalized field multiply. It removes ten temporary vector stores
and ten reloads without changing the convolution, fold, carry schedule, point
formula, or verification predicate.

All table values are microseconds per signature unless explicitly labelled
otherwise. Lower is better.

## Results

The same-binary dependent doubling benchmark measured 30.73 ns/op for the
split control and 28.24 ns/op for the fused path (-8.1%), with zero
allocations.

The ordered exact-parent/candidate singleton control measured:

| message bytes | parent | fused | change |
|---:|---:|---:|---:|
| 200 | 13.975 | 13.460 | -3.7% |
| 1,232 | 14.790 | 14.070 | -4.9% |
| 4,096 | 16.800 | 16.360 | -2.6% |

The authoritative post-change public matrix is the median of ten two-second
samples at each width:

| batch size | 200 bytes | 1,232 bytes | 4,096 bytes |
|---:|---:|---:|---:|
| 1 | 13.330 | 14.370 | 16.300 |
| 2 | 13.370 | 14.250 | 16.290 |
| 4 | 7.500 | 8.025 | 9.338 |
| 8 | 3.938 | 4.165 | 4.900 |
| 64 | 3.704 | 3.949 | 4.682 |

Every public row reported zero allocations and zero internal-fault fallbacks.
The 1,232-byte row was the hard non-regression gate. The 4,096-byte result was
not allowed to buy a gain at its expense.

## Correctness gates

- fused versus split native exact-representation differential over zero,
  maximum-u52, and 512 deterministic random vectors;
- output/input aliasing, stale-workspace, and zero-allocation checks;
- packed mixed-order point, NAF, cached-add, and doubling differentials;
- full `go test -count=1 ./...` locally and on native Zen 5; and
- native `go vet ./...` and `git diff --check`.

## Files

- `direct-double-ab.txt`: same-binary dependent packed-doubling comparison.
- `public-n1-abba.txt`: ordered exact-parent/candidate singleton control at all
  three message sizes.
- `public-final-matrix.txt`: authoritative post-change public cold matrix.
- `correctness.txt`: raw native full-suite and vet transcript.
- `SHA256SUMS`: hashes for every artifact in this directory.
