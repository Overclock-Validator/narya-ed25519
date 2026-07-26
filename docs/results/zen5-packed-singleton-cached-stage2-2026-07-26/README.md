# Zen 5 packed-singleton cached-add Stage-2 gate — 2026-07-26

This directory records the packed x4 cached-add Stage-2 A/B on an AMD Ryzen 7
9700X (Zen 5), Go 1.26.4, one pinned physical core, `GOMAXPROCS=1`, and the
performance governor. The baseline includes both scratch workspaces and the
retained doubling Stage 2 at `8fb91a2`; the retained cached-add Stage 2 is
`067188b`.

## Change and safety boundary

The change replaces the Go E/F/G/H linear layer between the four normalized
cached-add products and four unchanged final multiplications with one x4
assembly leaf. It computes E=`B-A`, G=`D+C`, H=`B+A`, and F=`D-C`; whole-
modulus biases make both subtractions non-negative before one carry/fold.

The native helper is tested bit for bit against the portable construction over
boundary and random u52 inputs. Tests exercise both legal input/output alias
directions, poisoned scratch, random projective and torsion points, repeated
in-place additions, range envelopes, and zero allocations. The complete
repository test suite ran on IFMA hardware before retention.

## Measurements

Ten pinned samples measured:

| cached-add kernel | ns/addition | change from baseline |
|---|---:|---:|
| reused-workspace baseline (`12941c8`) | 43.79 | — |
| retained Stage 2 (`067188b`) | 34.95 | -20.2% |

Ten one-second samples through exported `VerifyBatchStrict`, with 1232-byte
messages, measured the incremental effect after the doubling Stage 2:

| public cold batch | `8fb91a2` us/signature | `067188b` us/signature | change |
|---|---:|---:|---:|
| n=1 | 18.61 | 17.72 | -4.8% |
| n=2 | 18.68 | 17.83 | -4.6% |

A six-sample dispatch-boundary check measured n=4/8/64 at approximately
10.20/5.43/5.10 us/signature. Those widths do not execute the packed cached-add
leaf. Every timed row reported 0 B/op, 0 allocs/op, and zero internal fault
fallbacks.

The exact pre-change public baseline is in the adjacent
`zen5-packed-singleton-stage2-2026-07-26/quad-stage2-public.after` file; the
reused-workspace cached-add baseline is in
`zen5-packed-singleton-add-scratch-2026-07-26/singleton-add.after`.

## Reproduction

```sh
taskset -c 2 env GOMAXPROCS=1 go test -run '^$' \
  -bench '^BenchmarkExperimentalCoordinateParallelCachedAddX4$/^chained/quad-packed-cached-reused-workspace$' \
  -benchmem -benchtime=500ms -count=10 ./internal/r51x5

taskset -c 2 env GOMAXPROCS=1 go test -tags r51_release_bench -run '^$' \
  -bench '^BenchmarkPublicR51VerifyBatchStrict$/^msg=1232$/^n=(1|2)$' \
  -benchmem -benchtime=1s -count=10 ./ed25519

taskset -c 2 env GOMAXPROCS=1 go test -tags r51_release_bench -run '^$' \
  -bench '^BenchmarkPublicR51VerifyBatchStrict$/^msg=1232$/^n=(4|8|64)$' \
  -benchmem -benchtime=750ms -count=6 ./ed25519
```

The raw files contain no machine addresses, account names, or local paths.
