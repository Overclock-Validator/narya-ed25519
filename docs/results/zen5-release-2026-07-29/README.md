# Zen 5 release benchmark — 2026-07-29

This bundle records the exported Narya APIs at exact commit
`2880e1fa52738d07b49735547fbca8e715df2a58` on an AMD Ryzen 7 9700X
(Zen 5), Linux amd64, Go 1.26.4, the performance governor, and no other
benchmark pinned to the measured cores. Serial runs used physical CPU 6 and
`GOMAXPROCS=1`. Multicore runs used CPUs 0 through P-1, which are distinct
physical cores on this host; SMT siblings 8 through 15 were excluded.

Every Narya sample reported zero allocations and zero internal-fault
fallbacks. Values below are medians. Timing cells are microseconds per
signature, lower is better.

## Cold exported API

Ten three-second samples through `SetBackend("r51")` and
`VerifyBatchStrict`, with distinct keys and no retained per-key state:

| batch width | 200 bytes | 1,232 bytes | 4,096 bytes |
|---:|---:|---:|---:|
| 1 | 14.175 | 15.010 | 17.065 |
| 2 | 14.180 | 15.025 | 17.180 |
| 4 | 7.736 | 8.753 | 11.530 |
| 8 | 4.002 | 4.257 | 5.003 |
| 64 | 3.796 | 4.039 | 4.772 |

## Warm exported cache API

Ten three-second samples through `Cache.VerifyBatchStrict`, with 64 promoted
keys occupying 1,243,136 table bytes:

| batch width | 200 bytes | 1,232 bytes | 4,096 bytes |
|---:|---:|---:|---:|
| 1 | 14.145 | 15.185 | 17.115 |
| 2 | 14.220 | 15.045 | 17.105 |
| 4 | 3.378 | 4.119 | 6.212 |
| 8 | 3.141 | 3.875 | 5.968 |
| 64 | 2.961 | 3.734 | 5.821 |

The cache deliberately bypasses prepared tables below width four. At 4,096
bytes the current warm x4-oriented path is slower than cold x8 at widths 8
and 64 because message hashing is a larger share and the two paths use
different scheduling. Warm is not an unconditional speedup; message size,
width, population, and locality all belong in the result.

## Cross-library comparison

Six two-second serial samples at 1,232 bytes. Every implementation performed
ordinary per-signature strict verification and returned one verdict per
input. The Voi expanded-key row excludes expansion cost.

| implementation | n=1 | n=2 | n=4 | n=8 | n=64 |
|---|---:|---:|---:|---:|---:|
| Narya r51, cold strict | 15.090 | 14.940 | 8.722 | 4.393 | 4.171 |
| Go `crypto/ed25519` | 27.640 | 27.520 | 27.585 | 27.530 | 27.630 |
| curve25519-voi, cold strict | 22.060 | 21.890 | 21.930 | 22.025 | 22.145 |
| curve25519-voi, expanded key | 19.245 | 19.060 | 19.130 | 19.255 | 19.360 |

The comparison binary includes the opt-in Voi dependency and therefore has a
different link layout from the release-benchmark binary. Use this table for
within-binary library ratios and the exported cold table above for Narya's
release latency.

## Multicore scaling

Six two-second samples per point at 1,232 bytes. Values are aggregate
signatures per second, higher is better.

| physical cores | n=4 sig/s | n=4 scaling | n=8 sig/s | n=8 scaling |
|---:|---:|---:|---:|---:|
| 1 | 114,774 | 1.00x | 237,490 | 1.00x |
| 2 | 229,436 | 2.00x | 472,369 | 1.99x |
| 4 | 448,942 | 3.91x | 930,732 | 3.92x |
| 6 | 651,252 | 5.67x | 1,329,275 | 5.60x |
| 8 | 819,306 | 7.14x | 1,638,712 | 6.90x |

The sub-microsecond amortized values printed by the eight-core benchmark are
aggregate throughput divided by the signature count, not single-core latency.

## Commands

The tagged release binary was built once:

```sh
go test -c -tags r51_release_bench ./ed25519 \
  -o /tmp/narya-2880e1f-release.test
```

Serial cold and warm:

```sh
taskset -c 6 env GOMAXPROCS=1 /tmp/narya-2880e1f-release.test \
  -test.run '^$' \
  -test.bench '^BenchmarkPublicR51VerifyBatchStrict$/^msg=(200|1232|4096)$/^n=(1|2|4|8|64)$' \
  -test.benchmem -test.benchtime=3s -test.count=10

taskset -c 6 env GOMAXPROCS=1 /tmp/narya-2880e1f-release.test \
  -test.run '^$' \
  -test.bench '^BenchmarkPublicR51CacheVerifyBatchStrict$/^msg=(200|1232|4096)$/^n=(1|2|4|8|64)$' \
  -test.benchmem -test.benchtime=3s -test.count=10
```

Cross-library:

```sh
go test -modfile=go.oasis.mod -c -tags oasis_compare ./ed25519 \
  -o /tmp/narya-2880e1f-crosslib.test
taskset -c 6 env GOMAXPROCS=1 /tmp/narya-2880e1f-crosslib.test \
  -test.run '^$' \
  -test.bench '^BenchmarkEd25519CrossLibrary$/^mode=independent$/^impl=(narya-r51-dispatch|go-stdlib-loop|oasis-strict-cold-loop|oasis-strict-expanded-loop)$/^n=(1|2|4|8|64)$/^msg=1232$' \
  -test.benchmem -test.benchtime=2s -test.count=6
```

Multicore used the release binary above, `GOMAXPROCS=P`, CPUs `0-(P-1)`, and:

```sh
-test.run '^$' \
-test.bench '^BenchmarkPublicR51VerifyBatchStrictParallel$/^msg=1232$/^n=(4|8)$' \
-test.benchmem -test.benchtime=2s -test.count=6
```

`SHA256SUMS` authenticates the four raw outputs.
