# Zen 5 full-x8 radix-256 fixed-base recoder — 2026-07-29

This bundle records the retention gate for commit `f0a1bbb` on an AMD Ryzen 7
9700X (Zen 5), Linux amd64, Go 1.26.4, the performance governor, one fixed
physical core, and `GOMAXPROCS=1`. The baseline is parent commit `763e307`.

All complete-verifier inputs used 1,232-byte messages and distinct cold public
keys. Every row reported zero allocations and zero internal-fault fallbacks.
Timing values are microseconds per signature unless the table says otherwise.

## Result

Nine two-second direct samples measured 342.1 ns for the generic radix-256
recoder and 238.1 ns for the full-x8 specialization, a 30.4% median reduction.

Ten three-second public samples, baseline first:

| width | baseline | specialized | change |
|---:|---:|---:|---:|
| 8 | 4.176 | 4.165 | -0.28% (p=0.041) |
| 64 | 3.975 | 3.952 | -0.59% (p=0.021) |

Ten two-second public samples with candidate order reversed:

| width | baseline | specialized | change |
|---:|---:|---:|---:|
| 8 | 4.184 | 4.170 | -0.33% (p=0.013) |
| 64 | 3.967 | 3.954 | -0.33% (p=0.133) |

The n=64 reverse run contained several frequency-scale discontinuities in the
candidate samples, so its direction is recorded but not called significant.
The repeated n=8 result and deterministic 104 ns group-level reduction are the
retention evidence. The complete gain is intentionally described as
sub-percent.

## Correctness gate

The specialized output was compared byte-for-byte with the generic recoder
over 10,000 deterministic eight-lane fixtures. The corpus includes periodic
noncanonical scalars, exercises fallback semantics, poisons unused output
rounds before reuse, and reports zero allocations. The complete native suite
passed both locally and on the Zen 5 host:

```sh
go test -count=1 ./...
```

## Benchmark commands

The tagged public binaries were built with:

```sh
go test -c -tags r51_release_bench ./ed25519 -o "$BINARY"
```

The public A/B used:

```sh
taskset -c 6 env GOMAXPROCS=1 "$BINARY" \
  -test.run '^$' \
  -test.bench '^BenchmarkPublicR51VerifyBatchStrict$/^msg=1232$/^n=(8|64)$' \
  -test.benchmem -test.benchtime=3s -test.count=10
```

The reversed-order confirmation used the same command with
`-test.benchtime=2s`. The direct recoder used:

```sh
taskset -c 6 env GOMAXPROCS=1 go test ./internal/r51x5 \
  -run '^$' \
  -bench '^BenchmarkExperimentalFixedBaseCombRecodingX8/radix=256-full' \
  -benchmem -benchtime=2s -count=9
```

## Files

- `forward-before.txt` / `forward-after.txt`: baseline-first ten-sample gate.
- `reverse-before.txt` / `reverse-after.txt`: candidate-first confirmation.
- `SHA256SUMS`: hashes for the four raw public benchmark outputs.

The initial forward regex also selected the parallel n=8 sub-benchmark; the
retention table uses only the explicitly named non-parallel rows. The reverse
run used the corrected slash-separated selector shown above.
