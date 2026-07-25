# Ed25519 cross-library comparison on Zen 4

> **Historical record with a current follow-up.** The original comparison
> below is intentionally preserved at its named Narya and Firedancer commits.
> It predates the packed singleton, exact-tail dispatcher, and registration of
> forced backend `r51`. Use this section for current Narya capacity estimates;
> use the remainder to reproduce the earlier architecture decision.

## Current registered r51 dispatcher

Final pinned-core valid-signature medians for the registered, explicitly
forced r51 dispatcher core are compared with an independent native Firedancer
C harness.
Firedancer was built from commit
`3ed37488372b7e50bb03ca30477be48508ee7022` using `-O3 -march=znver4`; each
entry is the median of five approximately 20,000-signature runs (the harness
records the exact integer count). Narya values call the registered dispatcher's
private core with `GOMAXPROCS=1`; PR 1's separate exported-API release gate
must remain within 2%. Values are microseconds per signature. The harnesses are
independent, so these are engineering comparisons rather than paired
`benchstat` samples.

| message bytes | batch | Narya r51 | Firedancer |
| ---: | ---: | ---: | ---: |
| 64 | 1 | 25.80 | 20.913 |
| 64 | 4 | 15.24 | 20.980 |
| 64 | 8 | 14.75 | 20.922 |
| 64 | 64 | 14.55 | 20.900 |
| 200 | 1 | 26.26 | 20.961 |
| 200 | 4 | 15.32 | 20.957 |
| 200 | 8 | 14.99 | 20.977 |
| 200 | 64 | 14.66 | 20.983 |
| 1232 | 1 | 27.20 | 21.847 |
| 1232 | 4 | 16.05 | 21.971 |
| 1232 | 8 | 15.71 | 21.951 |
| 1232 | 64 | 15.40 | 21.928 |

The same 200-byte Go benchmark binary compared the Narya dispatcher core, the
standard-library loop, and curve25519-voi. Each entry below is the median of
six two-second samples, in microseconds per signature. The voi expanded row
uses a public key expanded before the timed loop, so it is a warm-key result;
the cold row performs that work for every verification.

| batch | Narya r51 cold | Go stdlib | voi cold strict | voi expanded strict |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 26.260 | 36.815 | 25.550 | 21.360 |
| 2 | 29.510 | 36.460 | 25.265 | 21.175 |
| 3 | 20.140 | 36.570 | 25.420 | 21.195 |
| 4 | 15.320 | 36.720 | 25.610 | 21.400 |
| 5 | 17.560 | 36.765 | 25.605 | 21.390 |
| 8 | 14.990 | 36.690 | 25.470 | 21.370 |
| 12 | 14.835 | 36.650 | 25.450 | 21.350 |
| 16 | 14.820 | 36.700 | 25.590 | 21.380 |
| 17 | 15.395 | 36.725 | 25.590 | 21.390 |
| 32 | 14.690 | 36.710 | 25.560 | 21.360 |
| 64 | 14.660 | 36.725 | 25.600 | 21.400 |

The result is deliberately width-specific: Firedancer remains faster for a
cold singleton, as do both voi modes. Narya overtakes both voi modes at n=3
and Firedancer when an x4 group is full. Narya beats the standard-library loop
at every measured width. Automatic Narya selection remains `generic`; these
rows require `SetBackend("r51")` or `OVERCLOCK_ED25519_BACKEND=r51`.

At 200 bytes, Narya's strict canonical-S precheck rejects without curve work
in about 0.035 us at n=1 and 0.041/0.040 us per signature at n=8/64. A
self-consistent signature that fails only at the final equation costs 27.44,
15.35, and 15.02 us/signature at n=1, n=8, and n=64. Firedancer's ordinary
serial loop costs 20.900, 21.007, and 20.991 us/signature for the corresponding
late failure. Firedancer's native batch API reports only the first error, so
its early-invalid timing is not an all-lane comparison and is intentionally
omitted.

## Historical comparison at Narya `64851dc`

This note records a pinned, single-core comparison on the AMD Ryzen 7 PRO
8700GE. It covers Narya, Go's `crypto/ed25519`, Oasis
`curve25519-voi`, and Firedancer's r43x6 Ed25519 implementation.

The Narya r51 rows are the forced, test-only two-x4/radix-64 batch-Q
candidate. Automatic production selection remains generic. The arithmetic
under test is Narya commit `64851dc`; the reusable Go benchmark was introduced
at `36f23a1` and subsequently extended with dense crossover widths. Firedancer
was built from commit `3ed37488372b7e50bb03ca30477be48508ee7022` with
`-O3 -march=znver4`.

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

Upstream Firedancer omits canonical-R enforcement. The standalone comparison
harness adds `low255(R) < p` before Firedancer verification; because
Firedancer already rejects small-order R, this also excludes the remaining
negative-zero anomaly and yields the Narya strict predicate. Firedancer's
native batch API accepts one shared message, returns only the first error, and
executes each verification serially. Widths above 16 are therefore chunked;
the ordinary distinct-message loop measures essentially the same speed.

Values below are microseconds per signature. Short repeated samples were
extremely stable, but these are engineering measurements rather than a release
gate.

## Cold, valid, 200-byte messages

`Narya cold choice` uses generic at `n=1` and forced r51 at every wider value.
The `Narya r51` singleton is shown separately because it exposes the cost of
running one live lane in an x4 kernel.

| batch | Narya cold choice | Narya r51 | Go stdlib | Oasis cold | Oasis expanded | Firedancer |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 38.75 | 60.06 | 36.78 | 25.56 | 21.39 | 20.85 |
| 4 | 16.19 | 16.19 | 36.64 | 25.47 | 21.29 | 20.98 |
| 8 | 15.75 | 15.75 | 36.63 | 25.40 | 21.23 | 20.97 |
| 16 | 15.51 | 15.51 | 36.66 | 25.45 | 21.30 | 21.00 |
| 17 | 17.98 | 17.98 | 36.66 | 25.41 | 21.27 | 21.01 |
| 32 | 15.52 | 15.52 | 36.71 | 25.48 | 21.33 | 20.99 |
| 64 | 15.48 | 15.48 | 36.68 | 25.47 | 21.32 | 21.01 |

At full x4 occupancy, Narya is 22.8% faster than Firedancer at `n=4`,
24.9% faster at `n=8`, and 26.3% faster at `n=64`. The `n=17` row exposes a
one-lane second chunk and is correspondingly slower.

Dense widths make the dispatch crossover and tail cost explicit:

| batch | Narya r51 cold | Go stdlib | Oasis cold | Oasis expanded |
| ---: | ---: | ---: | ---: | ---: |
| 2 | 30.89 | 36.92 | 25.26 | 21.13 |
| 3 | 21.01 | 36.79 | 25.35 | 21.24 |
| 5 | 24.22 | 36.88 | 25.36 | 21.23 |
| 9 | 20.36 | 36.92 | 25.46 | 21.32 |
| 12 | 15.66 | 36.94 | 25.48 | 21.35 |

The current r51 kernel already beats Narya generic at `n=2`. It reaches the
roughly 21-us Firedancer/Oasis-expanded level at `n=3` and wins clearly once
an x4 group is full. The sharp `n=5/9/17` sawtooth is lane underfill, not an
arithmetic regression. A dispatcher that sends full x4 groups through r51
and handles a one-signature remainder with the scalar path should remove much
of it.

## Message length

The same conclusion holds at Solana-shaped message lengths:

| message bytes | Narya r51 n=8 | Narya r51 n=64 | Firedancer n=8 | Firedancer n=64 |
| ---: | ---: | ---: | ---: | ---: |
| 64 | 15.70 | 15.38 | 20.82 | 20.88 |
| 200 | 15.75 | 15.48 | 20.97 | 21.01 |
| 1232 | 16.54 | 16.22 | 21.83 | 21.83 |

The extra 1,168 message bytes add about 0.8 us/signature to Narya. Reusing one
message across every signer did not materially help any implementation:
Narya r51 measured 15.75 us/signature for independent 200-byte messages at
`n=8` and 15.79 for a shared message. Firedancer's specialized shared-message
API likewise remained serial.

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
at 17.79 us/signature is about 14.7% faster than Firedancer's 20.85 and 18.6%
faster than Oasis expanded in this same prepared-tier run. Its 30 KiB/key
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

Firedancer's native first-error API makes its early-invalid number
non-comparable to the all-lanes contract. With the invalid signature placed
last, its full-equation failure remains approximately 20.9 us per attempted
signature. No implementation gets a shortcut when malformed traffic reaches
the curve equation.

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
