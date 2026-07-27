# Zen 5 uniform SHA-512 and two-wave component gates

Date: 2026-07-27

Machine and run policy:

- AMD Ryzen 7 9700X (Zen 5), AVX-512F/BW/VL available
- Go 1.26.4, linux/amd64
- performance governor
- one pinned physical core (`taskset -c 2`)
- `GOMAXPROCS=1`
- zero allocations in every reported timed row

Revisions:

- baseline: `13dc06d4a5f0ad8be62412a89de3a44de57bd504`
- uniform-shape implementation: `1752241`
- 4096-byte benchmark harness: `5a5459b`
- two-wave component experiment: `2615086`

The baseline used the benchmark-only `BenchmarkNativeX8` storage-size change
from `5a5459b` so it could construct 4096-byte inputs. Its implementation code
remained exactly `13dc06d`.

## Correctness

The candidate passed the complete native `sha512mb` suite, including:

- every padding boundary exercised by the uniform-shape test;
- an explicit assertion that the fast helper, not its generic fallback, ran;
- randomized complete-hash differentials;
- compression, transpose, alias, and first/final-block differentials;
- the 4096-byte zero-allocation gate.

The complete repository then passed on the same machine. The two-wave
component matched two independent calls to the production rolling-x8 kernel
for 256 randomized state/block pairs before its benchmark ran.

## Uniform-shape A/B

Hash-only command shape:

```text
taskset -c 2 env GOMAXPROCS=1 go test -run '^$' \
  -bench '^BenchmarkNativeX8$/impl=native-x8-fixed3/msg=(1232|4096)$' \
  -benchmem -benchtime=2s -count=10 ./sha512mb
```

Representative medians:

| message bytes | baseline ns/message | candidate ns/message | change |
|---:|---:|---:|---:|
| 1232 | 337.7 | 338.3 | effectively unchanged; sequential-run drift |
| 4096 | 1051 | 1004 | -4.5% |

Complete public strict command shape:

```text
taskset -c 2 env GOMAXPROCS=1 go test -tags r51_release_bench -run '^$' \
  -bench '^BenchmarkPublicR51VerifyBatchStrict$/msg=(1232|4096)/n=(4|8|64)$' \
  -benchmem -benchtime=2s -count=6 ./ed25519
```

Representative medians in microseconds per signature:

| message bytes | n | baseline | candidate | reading |
|---:|---:|---:|---:|---|
| 1232 | 4 | 8.697 | 8.670 | unaffected x4 control |
| 1232 | 8 | 4.614 | 4.623 | +0.2%; run-order drift |
| 1232 | 64 | 4.407 | 4.441 | noisy sequential control |
| 4096 | 4 | 11.48 | 11.47 | unaffected x4 control |
| 4096 | 8 | 5.337 | 5.304 | -0.6% |
| 4096 | 64 | 5.126 | 5.102 | about -0.5% |

The 1232-byte hash-only row is the load-bearing unaffected-path control: the
implementation deliberately retains its prior assembly finalizer. Complete
verifier rows were run baseline first and candidate second, so sub-percent
movement in the controls is not attributed to the change.

## Two-wave component A/B

Command:

```text
taskset -c 2 env GOMAXPROCS=1 go test -run '^$' \
  -bench '^BenchmarkNativeCompress2X8Expanded$' \
  -benchmem -benchtime=3s -count=10 ./sha512mb
```

| implementation | median ns/op for 16 messages | ns/message | change |
|---|---:|---:|---:|
| two production rolling-x8 calls | 461.8 | 28.86 | baseline |
| interlaced expanded-schedule 2x8 | 484.4 | 30.28 | +4.9% |

The experiment is therefore not dispatched. Its code remains as a
regime-tagged differential and benchmark so a future microarchitecture can
remeasure the question directly.

