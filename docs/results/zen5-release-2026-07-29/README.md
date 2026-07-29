# Zen 5 release benchmark — 2026-07-29

This bundle records the exported Narya APIs at exact commit
`f0a1bbbc9561d4204965cd4668c69c6409acdf70` on an AMD Ryzen 7 9700X
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
| 1 | 14.220 | 15.010 | 16.970 |
| 2 | 14.310 | 15.000 | 17.010 |
| 4 | 7.724 | 8.718 | 11.500 |
| 8 | 3.921 | 4.182 | 4.899 |
| 64 | 3.705 | 3.972 | 4.688 |

## Warm exported cache API

Ten three-second samples through `Cache.VerifyBatchStrict`, with 64 promoted
keys occupying 1,243,136 table bytes:

| batch width | 200 bytes | 1,232 bytes | 4,096 bytes |
|---:|---:|---:|---:|
| 1 | 14.230 | 14.910 | 16.840 |
| 2 | 14.260 | 14.910 | 16.880 |
| 4 | 3.368 | 4.141 | 6.213 |
| 8 | 3.141 | 3.896 | 5.967 |
| 64 | 2.975 | 3.747 | 5.831 |

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
| Narya r51, cold strict | 15.095 | 15.050 | 8.746 | 4.299 | 4.095 |
| Go `crypto/ed25519` | 27.785 | 27.635 | 27.660 | 27.690 | 27.680 |
| curve25519-voi, cold strict | 22.110 | 22.055 | 22.050 | 22.160 | 22.160 |
| curve25519-voi, expanded key | 19.320 | 19.250 | 19.230 | 19.345 | 19.360 |

The comparison binary includes the opt-in Voi dependency and therefore has a
different link layout from the release-benchmark binary. Use this table for
within-binary library ratios and the exported cold table above for Narya's
release latency.

## Multicore scaling

Six two-second samples per point at 1,232 bytes. Values are aggregate
signatures per second, higher is better.

| physical cores | n=4 sig/s | n=4 scaling | n=8 sig/s | n=8 scaling |
|---:|---:|---:|---:|---:|
| 1 | 115,422 | 1.00x | 242,381 | 1.00x |
| 2 | 228,694 | 1.98x | 483,292 | 1.99x |
| 4 | 450,808 | 3.91x | 948,642 | 3.91x |
| 6 | 652,385 | 5.65x | 1,353,448 | 5.58x |
| 8 | 822,218 | 7.12x | 1,674,807 | 6.91x |

The sub-microsecond amortized values printed by the eight-core benchmark are
aggregate throughput divided by the signature count, not single-core latency.

## Commands

The tagged release binary was built once:

```sh
go test -c -tags r51_release_bench ./ed25519 \
  -o /tmp/narya-f0a1bbb-release.test
```

Serial cold and warm:

```sh
taskset -c 6 env GOMAXPROCS=1 /tmp/narya-f0a1bbb-release.test \
  -test.run '^$' \
  -test.bench '^BenchmarkPublicR51VerifyBatchStrict$/^msg=(200|1232|4096)$/^n=(1|2|4|8|64)$' \
  -test.benchmem -test.benchtime=3s -test.count=10

taskset -c 6 env GOMAXPROCS=1 /tmp/narya-f0a1bbb-release.test \
  -test.run '^$' \
  -test.bench '^BenchmarkPublicR51CacheVerifyBatchStrict$/^msg=(200|1232|4096)$/^n=(1|2|4|8|64)$' \
  -test.benchmem -test.benchtime=3s -test.count=10
```

Cross-library:

```sh
go test -modfile=go.oasis.mod -c -tags oasis_compare ./ed25519 \
  -o /tmp/narya-f0a1bbb-crosslib.test
taskset -c 6 env GOMAXPROCS=1 /tmp/narya-f0a1bbb-crosslib.test \
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
