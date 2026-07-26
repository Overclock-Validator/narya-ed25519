# PR 1 Zen 4 release evidence — 2026-07-25

This directory is the compact reproducibility record for Narya PR 1's forced
`r51` backend. The implementation measured on hardware is
`2302d40ced851c72d9a1737047971c5f9f681cb4`; later commits in the audit branch
change documentation and CI only. The comparison base is
`aa483fad49ef18e3947b850e3c73e83dd90cb288`.

## Boundary

The supported PR contract is the public generic and stdlib backends plus
explicitly forced cold `r51` verification. Automatic selection remains
`generic`, and `r51.supportsPrecomp()` remains false. The warm A6/r9+B10 comb,
x8, wider-table, HEEA, and fusion candidates remain test-only evidence and are
not represented as production performance here.

## Authority

- CPU: AMD Ryzen 7 PRO 8700GE (Zen 4)
- OS: Ubuntu Linux/amd64
- Go: 1.26.4
- governor: `performance`
- benchmark affinity: CPU 2, `GOMAXPROCS=1`
- valid public release benchmark: ten three-second samples
- same-binary stdlib/curve25519-voi comparison: six two-second samples

`environment.txt` contains the complete CPU flags, kernel, toolchain, governor,
and implementation SHA. `commands.txt` records the exact command shapes.
Captured text is otherwise verbatim; trailing spaces and tabs were stripped so
the evidence can pass `git diff --check` without changing any value or status.

## Public forced-r51 result

Median microseconds per signature through exported `SetBackend("r51")` and
`VerifyBatchStrict`; every timed row reports zero allocations:

| message bytes | n=1 | n=4 | n=8 | n=64 |
| ---: | ---: | ---: | ---: | ---: |
| 64 | 26.14 | 15.05 | 14.68 | 14.38 |
| 200 | 26.28 | 15.24 | 14.81 | 14.51 |
| 1232 | 27.12 | 16.02 | 15.58 | 15.30 |

The raw sweep also includes n=2/3/5/12/16/17/32. Strict n=2 is routed through
two packed singleton verifications; n=3 uses a partial x4 group. The public
wrapper was no more than 2% slower than the private dispatcher core in a
same-binary paired diagnostic. Some public rows were faster due to code layout.

## Same-binary comparison at 200 bytes

Median microseconds per signature:

| implementation | n=1 | n=4 | n=8 | n=64 |
| --- | ---: | ---: | ---: | ---: |
| Narya public r51, cold strict | 27.35 | 15.78 | 15.29 | 15.01 |
| Go `crypto/ed25519` loop | 36.48 | 36.60 | 36.59 | 36.68 |
| curve25519-voi cold strict | 25.50 | 25.34 | 25.44 | 25.49 |
| curve25519-voi expanded strict | 21.41 | 21.44 | 21.41 | 21.39 |

The Oasis-tagged comparison executable has a different code layout from the
lean release executable, so only rows from this table should be compared. The
expanded row excludes key expansion and is a warm-key result.

## Invalid inputs

`public-r51-invalid.txt` covers an early canonical-scalar failure and a late
equation failure through the exported API. `crosslib-invalid.txt` processes
every lane for every library so an early invalid lane cannot shorten one loop.
All r51 timed rows remain allocation-free.

## Correctness

`correctness-full.txt` is the complete repository test run on Zen 4.
`hardware-focused.txt` covers IFMA availability, range and alias contracts,
lane masks, fallback behavior, native SHA, independent batch-encoding oracles,
and zero-allocation gates. Intel SDE logs provide automated instruction-path
coverage independent of the Ryzen release authority. Differential fuzz logs
record the exact requested durations:

- r51 pipeline: 189,008 executions in 10 minutes, pass;
- public verifier: 3,452,054 executions in 10 minutes, pass;
- multi-buffer SHA-512: 953,814 executions in 5 minutes, pass.

`sde-public-r51-final.txt` and `sde-ed25519-differential-final.txt` rerun the
public dispatch and affected differentials at implementation `2302d40`.
`sde-r51x5-dfd2dc0.txt` and `sde-sha512mb-dfd2dc0.txt` cover the unchanged
low-level kernels at the earlier CI checkpoint named in each filename.

After the hardware run, a test-only assertion was added to state explicitly
that canonical sign-bit-zero encodings of both x=0 points are accepted by the
standalone canonical-R helper. The full local suite, vet, race detector, and
isolated Oasis differential all pass with that audit-only test change; no
measured implementation code changed.

`SHA256SUMS` covers every evidence file except itself.
