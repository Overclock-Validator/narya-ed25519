# Zen 5 native x8 scalar reduction — 2026-07-29

## Scope

This bundle records the promotion gate for commit
`54d6430ec3ef105b2f70981a303e6941f5b072ec`, which replaces eight serial Go
reductions of 64-byte Ed25519 challenges with one structure-of-arrays AVX-512DQ
radix-`2^21` schedule on measured AMD family 1Ah processors. The portable
reducer remains the explicit oracle and the fallback on Zen 4, unknown IFMA
CPUs, non-amd64 builds, and pure-Go builds.

No cached public-key state is used by any public-verifier measurement in this
bundle. Every timed verifier row reported zero allocations and zero internal
fault fallbacks.

## What was independently confirmed on the current tree

The initial optimization notes predated the merged-B10 cold path. Inspection
at parent `a3188cf` established that the hot recoders had already replaced
balanced power-of-two division and multiplication with shifts, and that the
radix-256 specialization already assigns mask/magnitude fields directly. The
live missed call site was the merged-B10 variable scalar, fixed separately in
`db0a239`. The remaining current profile then identified scalar reduction—not
the already-fixed recoder—as the surviving 2--3% leaf.

The native reduction is not new algebra. It is a Go-assembly translation of
the project-owned standalone Narya reducer at commit
`571f224057b11faa1f0fd968d6d282d515a4a7bf`. The two sources have the same
positional 60-macro transcript: 14 modular folds, 23 centered carries, and 23
ordinary carries. A source test pins every register/radix position and every
constant broadcast in the Go tree.

The standalone source has a 389-intermediate signed-range certificate and a
Lean proof of the canonical tail. Those artifacts are relevant evidence, not
a claim that the standalone binary proves the Go object: assembled-opcode and
Go-ABI refinement remain separate trust boundaries. Narya therefore also
keeps the original Go reducer callable as an independent oracle.

## Correctness gates

- 2,048 native scalar/assembly differentials, cycling all 256 active masks;
- random and carry-heavy 512-bit digests, exact 32-byte output equality;
- existing `SetUniformBytes` differential and x8-versus-two-x4 tests;
- input immutability and zero-allocation checks;
- source-transcript position/constant test;
- ordinary and `narya_test_amd_policy` CPU-policy tests;
- full native `internal/r51x5`, `ed25519`, and `sha512mb` suites;
- `go vet ./...` and `git diff --check`.

All passed. See `final-tests.txt`.

## Performance

Pinned Ryzen 7 9700X, performance governor, Go 1.26.4,
`GOMAXPROCS=1`. Values below are microseconds per signature.

The direct eight-scalar leaf changed from approximately 535 ns to 225 ns per
group (about -58%) while remaining allocation-free. The exact-parent public
A/B is in `exact-parent-abba.txt`. Its six-sample medians are:

| message bytes | width | parent µs/signature | final µs/signature | change |
| ---: | ---: | ---: | ---: | ---: |
| 200 | 8 | 3.6990 | 3.6545 | -1.20% |
| 200 | 64 | 3.4675 | 3.4385 | -0.84% |
| 1,232 | 8 | 3.9425 | 3.9085 | -0.86% |
| 1,232 | 64 | 3.7145 | 3.6830 | -0.85% |
| 4,096 | 8 | 4.6710 | 4.6255 | -0.97% |
| 4,096 | 64 | 4.4400 | 4.4150 | -0.56% |

The absolute saving is about 0.025--0.046 microseconds per signature. This is
smaller than the leaf's 58% change because challenge reduction is only a small
part of the complete verifier.

The authoritative release matrix is the exact pushed commit, three one-second
samples per cell:

| batch size | 200 bytes | 1,232 bytes | 4,096 bytes |
| ---: | ---: | ---: | ---: |
| 1 | 13.590 | 14.170 | 16.380 |
| 2 | 13.530 | 14.140 | 16.360 |
| 4 | 7.558 | 8.047 | 9.394 |
| 8 | 3.662 | 3.899 | 4.638 |
| 64 | 3.438 | 3.683 | 4.410 |

The n=1 and n=2 paths do not call the native x8 reducer. The n=4 path has only
four live lanes and sees a correspondingly small benefit. The speed policy is
deliberately Zen-5-only until the complete gate is repeated on Zen 4 and other
IFMA implementations; compile-time SDE coverage is a correctness result, not
a performance measurement.

## Files

- `environment.txt` — exact commit, CPU, Go version, and governor;
- `final-matrix.txt` — exact-commit public cold matrix;
- `exact-parent-abba.txt` — exact parent/final public A/B;
- `final-micro.txt` — portable versus native reducer microbenchmark;
- `final-tests.txt` — native correctness, policy, vet, and diff gates;
- `scalar-reduce-objdump.txt` — exact final binary's decoded instruction
  stream for the native reducer;
- `public-1232-abba.txt`, `public-200-4096-abba.txt`, and
  `tail-1232-controls.txt` — earlier development gates retained for audit
  chronology;
- `commands.txt` — reproducible command forms;
- `SHA256SUMS` — checksums of this bundle.
