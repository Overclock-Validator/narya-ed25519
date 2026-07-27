# Ed25519 cross-library comparison on Zen 4

[Documentation index](../README.md) · Performance

> **Historical record with a current follow-up.** The original comparison
> below is intentionally preserved at its named Narya commit. It predates the
> packed singleton, exact-tail dispatcher, and registration of forced backend
> `r51`. Use this section for current Narya capacity estimates; use the
> remainder to reproduce the earlier architecture decision.

## Current registered r51 dispatcher

Final pinned-core valid-signature medians for the registered, explicitly
forced public r51 dispatcher. Each entry is the median of ten three-second
samples through exported `SetBackend("r51")` and `VerifyBatchStrict`, with
`GOMAXPROCS=1`. Values are microseconds per signature.

| message bytes | batch | Narya r51 |
| ---: | ---: | ---: |
| 64 | 1 | 26.14 |
| 64 | 4 | 15.05 |
| 64 | 8 | 14.68 |
| 64 | 64 | 14.38 |
| 200 | 1 | 26.28 |
| 200 | 4 | 15.24 |
| 200 | 8 | 14.81 |
| 200 | 64 | 14.51 |
| 1232 | 1 | 27.12 |
| 1232 | 4 | 16.02 |
| 1232 | 8 | 15.58 |
| 1232 | 64 | 15.30 |

The same 200-byte Go benchmark binary compared the Narya public dispatcher,
the standard-library loop, and curve25519-voi. Each entry below is the median
of six two-second samples, in microseconds per signature. This Oasis-tagged
binary has a different code layout from the lean release benchmark above, so
only rows within this table are compared. The voi expanded row uses a public
key expanded before the timed loop, so it is a warm-key result; the cold row
performs that work for every verification.

| batch | Narya r51 cold | Go stdlib | voi cold strict | voi expanded strict |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 27.350 | 36.480 | 25.495 | 21.410 |
| 2 | 27.440 | 36.830 | 25.420 | 21.290 |
| 3 | 20.415 | 36.445 | 25.250 | 21.300 |
| 4 | 15.775 | 36.600 | 25.340 | 21.440 |
| 5 | 18.050 | 36.770 | 25.445 | 21.320 |
| 8 | 15.285 | 36.590 | 25.435 | 21.405 |
| 9 | 16.680 | 36.670 | 25.460 | 21.350 |
| 12 | 15.180 | 36.690 | 25.440 | 21.375 |
| 16 | 15.140 | 36.690 | 25.470 | 21.360 |
| 17 | 15.820 | 36.730 | 25.410 | 21.340 |
| 32 | 15.020 | 36.720 | 25.440 | 21.395 |
| 64 | 15.010 | 36.680 | 25.490 | 21.390 |

The result is deliberately width-specific: both voi modes remain faster for a
cold singleton, and Narya overtakes them at n=3. Narya beats the
standard-library loop at every measured width. Automatic Narya selection remains `generic`; these
rows require `SetBackend("r51")` or `OVERCLOCK_ED25519_BACKEND=r51`.

At 200 bytes, Narya's strict canonical-S precheck rejects without curve work
in 0.035/0.046/0.044 us per signature at n=1/8/64. A self-consistent signature
that fails only at the final equation costs 26.03/15.02/14.75 us/signature.
The same all-lanes comparison measured Go stdlib at 36.33/36.62/36.68,
curve25519-voi cold at 24.86/24.89/24.98, and voi expanded at
21.79/22.16/22.09 us/signature for the corresponding late failure.

## Historical comparison at Narya `64851dc`

This note records a pinned, single-core comparison on the AMD Ryzen 7 PRO
8700GE. It covers Narya, Go's `crypto/ed25519`, and Oasis `curve25519-voi`.

The Narya r51 rows are the forced, test-only two-x4/radix-64 batch-Q
candidate. Automatic production selection remains generic. The arithmetic
under test is Narya commit `64851dc`; the reusable Go benchmark was introduced
at `36f23a1` and subsequently extended with dense crossover widths.

## Method and semantics

- CPU: AMD Ryzen 7 PRO 8700GE (Zen 4), performance governor
- Go: 1.26.4
- one pinned physical core, `GOMAXPROCS=1`
- independent keys and messages unless stated otherwise
- benchmark setup, key expansion, and table construction excluded from timed
  verification; cold rows still pay all per-verification decoding and table
  work
- all valid Go rows allocate zero bytes in the timed path

Oasis is configured with the option set that matches Narya `DalekStrict`:
canonical S, permissively decodable A, canonical R, small-order A/R rejection,
the cofactorless equation, and hashing of the original bytes. Go stdlib has a
different acceptance predicate and is included only as a performance baseline
on honest canonical signatures.

Values below are microseconds per signature. Short repeated samples were
extremely stable, but these are engineering measurements rather than a release
gate.

## Cold, valid, 200-byte messages

`Narya cold choice` uses generic at `n=1` and forced r51 at every wider value.
The `Narya r51` singleton is shown separately because it exposes the cost of
running one live lane in an x4 kernel.

| batch | Narya cold choice | Narya r51 | Go stdlib | Oasis cold | Oasis expanded |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 38.75 | 60.06 | 36.78 | 25.56 | 21.39 |
| 4 | 16.19 | 16.19 | 36.64 | 25.47 | 21.29 |
| 8 | 15.75 | 15.75 | 36.63 | 25.40 | 21.23 |
| 16 | 15.51 | 15.51 | 36.66 | 25.45 | 21.30 |
| 17 | 17.98 | 17.98 | 36.66 | 25.41 | 21.27 |
| 32 | 15.52 | 15.52 | 36.71 | 25.48 | 21.33 |
| 64 | 15.48 | 15.48 | 36.68 | 25.47 | 21.32 |

At full x4 occupancy, Narya is 27.3% faster than Oasis expanded at `n=4` and
27.4% faster at `n=64`. The `n=17` row exposes a one-lane second chunk and is
correspondingly slower.

Dense widths make the dispatch crossover and tail cost explicit:

| batch | Narya r51 cold | Go stdlib | Oasis cold | Oasis expanded |
| ---: | ---: | ---: | ---: | ---: |
| 2 | 30.89 | 36.92 | 25.26 | 21.13 |
| 3 | 21.01 | 36.79 | 25.35 | 21.24 |
| 5 | 24.22 | 36.88 | 25.36 | 21.23 |
| 9 | 20.36 | 36.92 | 25.46 | 21.32 |
| 12 | 15.66 | 36.94 | 25.48 | 21.35 |

The current r51 kernel already beats Narya generic at `n=2`. It reaches the
roughly 21-us Oasis-expanded level at `n=3` and wins clearly once
an x4 group is full. The sharp `n=5/9/17` sawtooth is lane underfill, not an
arithmetic regression. A dispatcher that sends full x4 groups through r51
and handles a one-signature remainder with the scalar path should remove much
of it.

## Message length

The same conclusion holds at Solana-shaped message lengths:

| message bytes | Narya r51 n=8 | Narya r51 n=64 |
| ---: | ---: | ---: |
| 64 | 15.70 | 15.38 |
| 200 | 15.75 | 15.48 |
| 1232 | 16.54 | 16.22 |

The extra 1,168 message bytes add about 0.8 us/signature to Narya. Reusing one
message across every signer did not materially help: Narya r51 measured
15.75 us/signature for independent 200-byte messages at `n=8` and 15.79 for a
shared message.

## Cold, decoded, compact, and hot keys

This matrix excludes all preparation time from the timer. Narya's decoded-A
row is an arithmetic upper bound for a future small decoded-point cache; it
still builds the variable-base table during verification. Compact NAF uses
1,280 bytes/key. The existing hot comb uses 30,720 bytes/key.

| batch | Narya cold r51 | decoded-A r51 | compact NAF | hot comb | Oasis expanded |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 59.27 | 55.35 | 34.50 | 17.79 | 21.86 |
| 2 | 30.77 | 28.77 | 34.10 | 17.50 | 21.69 |
| 3 | 20.97 | 19.64 | 33.97 | 17.69 | 21.69 |
| 4 | 16.01 | 15.03 | 34.50 | 17.80 | 21.90 |
| 8 | 15.62 | 14.66 | 34.23 | 17.71 | 21.82 |
| 64 | 15.23 | 14.38 | 34.42 | 17.94 | 21.84 |

The important singleton result is positive: Narya's existing hot-comb path
at 17.79 us/signature is about 18.6% faster than Oasis expanded in this same
prepared-tier run. Its 30 KiB/key
footprint limits it to genuinely hot signers. Decoded-A saves only about
0.9--1.3 us/signature at useful r51 widths, so a broad decoded-point cache is
an incremental complement rather than the main speed source.

## Invalid signatures

The common Go harness processes every lane and records every verdict. An
all-invalid noncanonical-S fixture measures early rejection; an all-invalid
bad-message fixture passes parsing and measures full equation failure.

| case | batch | Narya r51 | Narya generic | Go stdlib | Oasis cold | Oasis expanded |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| noncanonical S | 1 | 0.116 | 3.39 | 3.36 | 2.86 | 0.0115 |
| noncanonical S | 8 | 0.0446 | 3.39 | 3.36 | 2.86 | 0.0103 |
| noncanonical S | 64 | 0.0439 | 3.39 | 3.36 | 2.86 | 0.0102 |
| bad message | 1 | 59.28 | 38.25 | 36.97 | 24.94 | 21.80 |
| bad message | 8 | 15.58 | 38.23 | 36.77 | 24.96 | 21.86 |
| bad message | 64 | 15.21 | 38.37 | 36.68 | 24.95 | 21.87 |

No implementation gets a shortcut when malformed traffic reaches the curve
equation.

## Decisions supported by this run

1. The sub-16-us claim is real for full r51 groups, not for a singleton. At
   200 bytes, cold r51 is 15.2--15.8 us/signature at useful widths; prepared A
   reaches 14.38 us/signature at `n=64`.
2. Keep Narya self-contained. Oasis is a useful independent predicate and
   performance oracle, but Narya already wins the target batched workload and
   its hot comb wins repeated-key singleton work.
3. The highest-value routing change is a hybrid tail dispatcher: generic for
   a cold singleton, r51 for `n>=2`, and scalar handling for a one-item
   remainder after full x4 groups.
4. Preserve both cache tiers conceptually: the large comb table for a bounded
   set of very hot signers, and a much smaller decoded-point tier only if real
   reuse-distance telemetry pays for it.
5. The remaining architectural gap is cold `n=1` (and, relative to C/expanded
   implementations, `n=2`). That is the right target for coordinate-parallel
   r51/r43 work; it is not evidence that the full-width r51 kernel is slow.
