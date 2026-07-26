# Zen 5 packed-singleton doubling Stage-2 gate — 2026-07-26

This directory records the packed x4 doubling Stage-2 A/B on an AMD Ryzen 7
9700X (Zen 5), Go 1.26.4, one pinned physical core, `GOMAXPROCS=1`, and the
performance governor. The baseline includes the retained doubling and
cached-add workspaces at `13511c4`; the retained Stage-2 implementation is
`8fb91a2`.

## Change and safety boundary

The change replaces the Go E/F/G/H linear layer between the four normalized
input products and four unchanged final multiplications with one x4 assembly
leaf. It uses whole-modulus biases, one parallel carry/fold, and the same
direct-XY Edwards doubling formula as the portable reference.

The native helper is tested bit for bit against the portable construction over
boundary and random u52 inputs. Tests also cover input/output aliasing, poisoned
scratch, random projective points, torsion points, repeated in-place doubling,
range envelopes, and zero allocations. The complete repository test suite ran
on the IFMA hardware before retention.

## Measurements

Ten pinned samples measured:

| doubling kernel | ns/doubling | change from baseline |
|---|---:|---:|
| reused-workspace baseline (`9f5659d`) | 42.69 | — |
| retained Stage 2 (`8fb91a2`) | 34.94 | -18.2% |

Ten one-second samples through exported `VerifyBatchStrict`, with 1232-byte
messages, measured the incremental effect after both scratch-workspace changes:

| public cold batch | `13511c4` us/signature | `8fb91a2` us/signature | change |
|---|---:|---:|---:|
| n=1 | 20.38 | 18.61 | -8.7% |
| n=2 | 20.45 | 18.68 | -8.7% |

A six-sample dispatch-boundary check measured n=4/8/64 at approximately
10.16/5.43/5.11 us/signature, consistent with those widths not using the packed
singleton doubling. Every timed row reported 0 B/op, 0 allocs/op, and zero
internal fault fallbacks.

The exact pre-Stage-2 public baseline is in the adjacent
`zen5-packed-singleton-add-scratch-2026-07-26/singleton-add-public.after` file;
the reusable-doubling baseline is in
`zen5-packed-singleton-scratch-2026-07-26/singleton-double.after`.

## Reproduction

```sh
taskset -c 2 env GOMAXPROCS=1 go test -run '^$' \
  -bench '^BenchmarkExperimentalCoordinateParallelDoubleX4$/^chained/quad-packed-reused-workspace$' \
  -benchmem -benchtime=500ms -count=10 ./internal/r51x5

taskset -c 2 env GOMAXPROCS=1 go test -tags r51_release_bench -run '^$' \
  -bench '^BenchmarkPublicR51VerifyBatchStrict$/^msg=1232$/^n=(1|2)$' \
  -benchmem -benchtime=1s -count=10 ./ed25519

taskset -c 2 env GOMAXPROCS=1 go test -tags r51_release_bench -run '^$' \
  -bench '^BenchmarkPublicR51VerifyBatchStrict$/^msg=1232$/^n=(4|8|64)$' \
  -benchmem -benchtime=750ms -count=6 ./ed25519
```

The raw files contain no machine addresses, account names, or local paths.
