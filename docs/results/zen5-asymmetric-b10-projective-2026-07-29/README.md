# Zen 5 merged fixed-base B10 schedule — 2026-07-29

This bundle records the native correctness and performance gate for
implementation commit `55f43623f5af8813549a202fd9fd2b31908a5cff` on an AMD
Ryzen 7 9700X (family 1Ah, Zen 5), Linux amd64, Go 1.26.4, one pinned physical
core, and `GOMAXPROCS=1`.

Every reported signature used an arbitrary cold public key. No per-key state
or warm table survived between calls. The fixed generator table is immutable,
process-shared state in both arms.

## Why the older result no longer applied

The retained merged-B10 experiment originally used a complete-coordinate
general-multiply doubler. That schedule predated the registered Zen 5 x8
loop's dedicated squaring kernel and intermediate-P2 representation, and the
complete verifier had regressed by about 1.1%.

The accepted candidate changes only the doubling implementation inside the
same merged schedule: every five-doubling block now uses the registered
dedicated-square `P3 -> P2 -> P2 -> P2 -> P2 -> P3` chain. The first four
results cannot be consumed by an addition because their Go type has no `T`
coordinate; `T` is restored at every A- or B-addition boundary.

The algebra remains one shared 250-doubling Horner chain:

- A uses 51 balanced radix-32 digits;
- B uses 26 balanced radix-1024 digits and a process-shared table of signed
  multiples 1 through 512;
- B therefore needs at most 26 additions and no independent B doubling chain;
  and
- there is no final full-point addition joining separate A and B terms.

The signed B table occupies exactly 122,880 bytes. It replaces the larger
separate radix-256 generator-comb evaluation only for complete x8 groups on
measured AMD family 1Ah CPUs. Zen 4, unknown IFMA CPUs, and x4 tails retain the
previous schedule.

## Controlled complete-verifier A/B

Values are medians of six two-second samples in microseconds per signature.
Lower is better. Every sample reported zero allocations.

| message bytes | width | separate radix-256 comb | merged B10 | change |
|---:|---:|---:|---:|---:|
| 200 | 8 | 3.925 | 3.670 | -6.5% |
| 200 | 64 | 3.704 | 3.450 | -6.9% |
| 1,232 | 8 | 4.169 | 3.911 | -6.2% |
| 1,232 | 64 | 3.974 | 3.695 | -7.0% |
| 4,096 | 8 | 4.907 | 4.662 | -5.0% |
| 4,096 | 64 | 4.720 | 4.448 | -5.8% |

The 1,232-byte target is therefore positive rather than traded for either the
shorter or longer message case.

## Registered public cold matrix

The exported `SetBackend("r51")` plus `VerifyBatchStrict` path was measured
with four one-second samples after CPU-policy promotion. Values are medians in
microseconds per signature. Every sample reported 0 B/op, 0 allocs/op, and
zero internal-fault fallbacks.

| batch size | 200 bytes | 1,232 bytes | 4,096 bytes |
|---:|---:|---:|---:|
| 1 | 13.410 | 14.220 | 16.405 |
| 2 | 13.450 | 14.225 | 16.375 |
| 4 | 7.519 | 8.069 | 9.423 |
| 8 | 3.754 | 3.999 | 4.740 |
| 64 | **3.526** | **3.770** | **4.513** |

Widths 1, 2, and 4 do not use the merged x8 schedule and serve as unaffected
controls.

## Correctness gates

- independent exact reconstruction of 2,257 scalar inputs from all 26 signed
  width-10 digits, including every bit boundary, `L-1`, non-canonical `L`,
  inactive lanes, and five active masks;
- poisoned-output reuse proving recoding clears stale digits;
- projective equality against the separate-comb equation on native IFMA;
- both supported acceptance profiles at widths 8, 16, and 64 with mixed
  byte-precheck and full-equation failures;
- registered dispatch against the reference predicate at widths 0, 1, 2, 3,
  4, 5, 7, 8, 9, 15, 16, 17, 32, 64, and 65, moving the invalid equation
  through every lane;
- zero allocations in the complete merged verifier;
- explicit Zen 5/Zen 4/no-IFMA/unmeasured-family policy tests; and
- full native `go test -count=1 ./...` plus `go vet ./...`.

The complete `go test -race ./ed25519 ./sha512mb` gate passed at follow-up
test-harness commit `c4f068f`. That commit changes no production code; it
skips four exact-zero-allocation assertions under race instrumentation, whose
own bookkeeping necessarily allocates 1–3 objects around the measured call.
The same assertions continue to execute and pass in ordinary builds.

## Files

- `environment.txt`: exact implementation SHA, toolchain, kernel, CPU, cache,
  and relevant ISA flags;
- `tests.txt`: full native and focused correctness output;
- `race.txt`: passing full race-detector output at test-only commit `c4f068f`;
- `complete-ab.txt`: controlled six-sample complete-verifier A/B;
- `public-cold.txt`: registered exported-API message-size matrix;
- `commands.txt`: reproducible commands without machine-specific paths; and
- `SHA256SUMS`: hashes for every other artifact in this directory.
