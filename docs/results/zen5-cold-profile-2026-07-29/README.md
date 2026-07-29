# Zen 5 cold-verification profile — 2026-07-29

This record profiles the exported forced-r51 `VerifyBatchStrict` path at
implementation commit `1972c5b` on an AMD Ryzen 7 9700X, Linux amd64, Go
1.26.4, the performance governor, one pinned physical core, and
`GOMAXPROCS=1`. Every signature used a distinct public key and a 1,232-byte
message. No per-key table survived between calls.

The run also corrected two misleading singleton observations:

- an approximately 32-us sample had another benchmark pinned to the same
  physical core and is invalid;
- a real approximately 5% regression came from production packed-table
  construction accidentally using the portable model normalizer. Commit
  `1972c5b` restores the native leaf and the approximately 15-us singleton.

## Public timings

| batch width | us/signature | signatures/s/core |
|---:|---:|---:|
| 1 | 14.93 | 66,997 |
| 8 | 4.648 | 215,146 |
| 64 | 4.452 | 224,628 |

These are profile-instrumented eight-second samples. The paired release gate
without sampling measured n=1 at 15.05--15.07 us/signature.

## CPU profile

### n=1

| leaf or phase | flat or cumulative share |
|---|---:|
| packed NAF evaluation | 69.72% cumulative |
| packed doubling | 51.06% cumulative |
| normalized x4 field multiply | 30.85% flat |
| fused packed final multiply | 27.99% flat |
| A/R simultaneous decode | 18.25% cumulative |
| packed cached addition | 15.55% cumulative |
| repeated x4 squaring | 10.97% flat |
| scalar SHA-512 AVX2 block | 6.46% flat |
| scalar NAF recoding | 1.15% flat |
| projective final comparison | 1.72% cumulative |

The public adapters are not a large hidden cost. At the same checkpoint and
message size, the exported default-strict entry measured about 15.03 us and
`VerifyStrict` about 14.90 us.

### n=8

| leaf or phase | flat or cumulative share |
|---|---:|
| variable-base x8 evaluation | 58.17% cumulative |
| normalized x8 field multiply | 24.30% flat |
| raw x8 field multiply | 22.04% flat |
| x8 doubling | 42.40% cumulative |
| projective-Niels addition | 12.95% cumulative |
| fixed-base comb | 10.30% cumulative |
| challenge hash and reduction | 9.09% cumulative |
| rolling x8 SHA-512 rounds | 7.40% flat |
| scalar recoding | 3.06% cumulative |
| pre-signed micro-AoS selector | 2.33% cumulative |

### n=64

| leaf or phase | flat or cumulative share |
|---|---:|
| variable-base x8 evaluation | 59.22% cumulative |
| normalized x8 field multiply | 26.72% flat |
| raw x8 field multiply | 21.87% flat |
| x8 doubling | 45.29% cumulative |
| projective-Niels addition | 12.65% cumulative |
| challenge hash and reduction | 11.10% cumulative |
| rolling x8 SHA-512 rounds | 9.42% flat |
| pre-signed table-entry store | 2.69% cumulative |
| pre-signed micro-AoS selector | 2.69% cumulative |
| scalar recoding | 2.42% cumulative |

## Hardware counters

Repeated `perf stat` samples gave the following qualitative result:

| width | sustained clock | IPC | front-end stalled cycles | branch misses | L1D misses |
|---:|---:|---:|---:|---:|---:|
| 1 | about 5.5 GHz | about 3.3 | about 2% | about 0.3% | negligible |
| 8 | about 5.4 GHz | about 4.0 | about 1% | about 0.1% | about 1.0% |
| 64 | about 5.4 GHz | about 4.0 | about 1% | about 0.1% | about 1.1% |

The full-width path is instruction-throughput bound. It is not materially
limited by cache misses, branch prediction, or front-end starvation. This is
consistent with the field-multiply leaves accounting for approximately half
of all sampled cycles and with earlier primitive measurements placing the x8
multiply close to Zen 5's IFMA throughput floor.

## SHA/IFMA execution-resource experiment

One sibling thread executed four independent x8 multiply-normalize chains
while the other executed the rolling x8 SHA-512 compressor:

| operation | isolated | simultaneous sibling | change |
|---|---:|---:|---:|
| x8 multiply-normalize | 5.706 ns/primitive | 5.725 ns/primitive | +0.3% |
| x8 SHA-512 compression | 240.6 ns/block group | 286.1 ns/block group | +18.9% |

This supports a real software-pipelining opportunity: the saturated IFMA
stream leaves resources that SHA can use with almost no IFMA slowdown. It does
not prove that SHA becomes free in one thread. Realizing the overlap requires
an explicitly interleaved schedule small enough for the out-of-order window;
two sequential Go calls cannot create that overlap. Treat the experiment as a
gate for a future n>=16 prototype, not as a measured verifier speedup.

## Tested candidate: pre-signed packed NAF tables

Profile sampling initially made packed cached-point negation look large enough
to justify storing both signs. Candidate `e29aa08` doubled the process-shared B
table and the per-call eight-entry A table, then selected the prepared sign
without online field negation. All focused correctness tests passed.

A paired ten-sample public n=1 gate measured:

| implementation | median ns/signature | change |
|---|---:|---:|
| `1972c5b` runtime negation | 15,062 | -- |
| `e29aa08` pre-signed tables | 15,014 | -0.32% |

Cold A-table sign construction gives back most of the evaluation saving, and
the sampled negation cost was partly a symbol-boundary artifact. Revert
`19b406c` therefore keeps the smaller table design. The candidate remains in
history as a regime-tagged result rather than being rebuilt or mistaken for a
5% opportunity later.

## Tested candidate: asymmetric fixed-B injection

The ordinary cold x8 path evaluates `[s]B` with a separate radix-256 comb,
evaluates `-[k]A` on a 250-doubling radix-32 chain, and adds the two resulting
points. The asymmetric experiment instead injects width-10 B digits into A's
existing chain. It needs 26 B additions, no separate B doubling phase, and no
final full-point addition. This changes neither cache warmth nor retained
per-key state; B is a process-shared constant in both designs.

### x4 regime record

The older prepared radix-64 x4 measurement seam showed a useful trend. These
are arithmetic-loop results, not complete public-verifier results and not
measurements of the registered Zen 5 x8 path:

| x4 fixed-B layout | median ns/signature | change from current x4 |
|---|---:|---:|
| current micro-AoS B6 projective | 6,028 | -- |
| dense affine B6 | 5,916 | -1.9% |
| dense affine B8 | 5,649 | -6.3% |
| dense affine B9 | 5,616 | -6.8% |
| dense affine B10 | 5,540 | -8.1% |

This result remains relevant to Zen 4, x4 tails, and future dispatch work. Its
mechanism is fewer B additions plus removal of the separate B doubling/final-
add phase. It must not be quoted as an x8 or complete-verifier improvement.

### x8 gate

The first x8 B10 core gate also looked positive:

| x8 arithmetic core | median ns/signature | change |
|---|---:|---:|
| separate radix-256 comb | 3,090 | -- |
| merged B10 fixed-block schedule | 2,983 | -3.4% |

The complete cold-verifier gate reversed the verdict:

| batch width | separate comb, us/signature | merged B10, us/signature | change |
|---:|---:|---:|---:|
| 8 | 4.348 | 4.401 | +1.2% |
| 64 | 4.127 | 4.173 | +1.1% |

An initial per-exponent prototype was substantially worse because it tested
the injection schedule with `%10` and `%5` in every doubling round. Commit
`9b052de` replaced that with a fixed 25-block schedule and recovered nearly
all of the loss, but did not cross the complete-path gate. The registered
path therefore remains the separate radix-256 comb. The zero-allocation,
test-only x8 experiment is retained with this regime tag so a future point-
kernel or microarchitecture change can remeasure it instead of rebuilding it.

Raw outputs:

- `narya-asymmetric-b-zen5.txt` — x4 B-width/layout sweep;
- `narya-asymmetric-b-niels-x8-blocks-core.txt` — isolated x8 core A/B;
- `narya-asymmetric-b-niels-x8-blocks-complete.txt` — complete x8 verifier A/B.

## Retested candidate: x8 runtime sign handling

The current cold x8 A table stores both public signs while it is built. The
alternative stores one sign, halves that table's payload, and swaps Y+X/Y-X
plus negates 2dT after every selected negative digit. Because the original
verdict predated the current x8 Niels loop, commit `0331de0` re-ran the
complete-path gate rather than trusting the stale result.

| batch width | pre-signed, us/signature | runtime sign, us/signature | runtime change |
|---:|---:|---:|---:|
| 8 | 4.326 | 4.441 | +2.7% |
| 64 | 4.119 | 4.268 | +3.6% |

Both paths were allocation-free and produced identical per-lane verdicts in
the focused differential. Pre-signing remains the correct cold x8 design: its
extra table-store work is cheaper than 51 rounds of online lane-wise sign
handling. Raw output is in `narya-x8-runtime-sign-complete.txt`.

## Commands

Representative commands, with repository-relative placeholders:

```sh
taskset -c 6 env GOMAXPROCS=1 go test -c -tags r51_release_bench \
  -o /tmp/narya-profile.test ./ed25519

taskset -c 6 env GOMAXPROCS=1 /tmp/narya-profile.test -test.run '^$' \
  -test.bench '^BenchmarkPublicR51VerifyBatchStrict$/msg=1232/n=8$' \
  -test.benchtime=10s -test.cpuprofile=/tmp/narya-cold-n8.pprof

perf stat -d -r 3 taskset -c 6 env GOMAXPROCS=1 \
  /tmp/narya-profile.test -test.run '^$' \
  -test.bench '^BenchmarkPublicR51VerifyBatchStrict$/msg=1232/n=64$' \
  -test.benchtime=8s -test.count=1
```
