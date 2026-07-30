# Narya — Ed25519 verification

```
go get github.com/Overclock-Validator/narya-ed25519
```

Narya is a no-cgo Ed25519 verification library for Go built to make
consensus-exact verification fast. Its opt-in AVX-512 IFMA backend delivers
substantial cold-key speedups over Go's `crypto/ed25519` when independent
signatures can be processed together; see [Performance](#performance) for the
measured results, hardware, checkpoints, and limitations.

The speedup comes from wide-lane SIMD: Narya maps unrelated signatures onto
independent AVX-512 lanes, keeping a separate verification equation and verdict
for every input. It is aimed at replicated systems, high-throughput services,
archival verification, and any other application where two properties matter
at once: verification must be fast, and every implementation must agree on
exactly which byte strings are valid.

Narya provides explicit `DalekStrict` and Go-standard-library-compatible
profiles instead of treating "Ed25519 verification" as one universal
predicate. Its cold path handles arbitrary public keys without persistent
state. Its optional cache adds a decoded-key tier for broad recurrence and a
larger precomputed tier for genuinely hot keys. Batch APIs never replace
per-signature verification with a randomized aggregate equation: every input
still receives its own deterministic accept/reject result.

On supported AMD64 processors, the forced `r51` backend runs independent
signatures across AVX-512 IFMA lanes. Measured AMD CPUs use native x8 groups,
x4 tails, and a coordinate-packed singleton. Zen 5 additionally places two
complete verification equations in the independent low and high halves of one
ZMM register for strict two-signature tails. Portable callers retain the
pure-Go `generic` backend, and automatic backend selection remains
conservative.

> **Security status: experimental and unaudited.** Narya has extensive
> differential, vector, fuzz, range, aliasing, and hardware tests, but it has
> not received an independent cryptographic or assembly audit. Do not treat it
> as a drop-in production security boundary without your own review and
> validation. The software is provided **as is**, without warranty; the
> authors and contributors accept no liability for its use. See
> [LICENSE](LICENSE) for the governing terms.

Narya was one of the Three Elven Rings in Tolkien's legendarium. Known as the
Ring of Fire and carried by Gandalf, it had the power to inspire hope,
withstand the weariness of time, and kindle resistance against tyranny and
despair.

## Why this exists

**Ed25519 verification is not one predicate.** RFC 8032 leaves several choices
open, and production implementations resolve them differently:

| | cofactorless | small-order `A` | small-order `R` | non-canonical `A` | non-canonical `R` |
| --- | --- | --- | --- | --- | --- |
| Go `crypto/ed25519` | yes | accept | accept | accept | reject |
| `ed25519-dalek` `verify_strict` | yes | **reject** | **reject** | accept | reject |
| ZIP 215 | no (cofactored) | accept | accept | accept | **accept** |

Any two rows disagree on a nonempty, adversarially constructible set of inputs.
In a replicated or long-lived system, that difference can become a remotely
triggerable consistency failure: an attacker chooses an input in the symmetric
difference and two otherwise-correct implementations return different verdicts.

The subtlety that makes this worth a library: `verify_strict` is **not**
"strict about everything." It rejects non-canonical `R` but *accepts*
non-canonical `A`. Hand-rolling the predicate and getting that one case
backwards is a silent fork.

Narya makes the choice explicit, versioned, and differentially tested rather
than incidental.

## The contract

Verification enforces one of two versioned **profiles**, because the
consensus-correct acceptance predicate is itself versioned. An
accept/reject flip is a fork, so it is a deliberate choice, not an
implementation detail:

- **`DalekStrict`** (default, and the zero value) matches
  `ed25519-dalek` 2.x `verify_strict`. This is `crypto/ed25519.Verify` **plus**
  rejection of small-order public keys A and small-order signature
  points R. The standard library accepts those (it never decodes R); a
  verifying node that used it unmodified could be forked off the
  network by a crafted block, so this is the default.
- **`StdlibCompat`** is exactly `crypto/ed25519.Verify`, for
  differential testing and callers who explicitly want standard-library
  behavior.

Small-order rejection is a byte-level classifier over the seven low-255-bit
small-order `y` encodings, sign-bit-insensitive: fourteen byte strings, with
no point decode required.

For every input (non-canonical encodings, small-order points,
malformed signatures), every backend, cached or not, batched or single,
returns exactly what the active profile's predicate returns. This is
enforced by differential tests, the CCTV and Wycheproof corpora, a
cross-library differential against curve25519-voi, and fuzzing rather than
assumed; the 165 CCTV vectors where the two profiles differ are precisely the
small-order set, cross-checked against Firedancer's independent verdict.

Narya never uses random-coefficient aggregate verification: an ordinary
cofactored aggregate can accept adversarial signatures that cofactorless
per-signature verification rejects. A strict-compatible Monte Carlo hybrid can
first apply an exact per-item torsion-membership gate; it still returns one
probabilistic batch assertion rather than N independent, zero-error verdicts.
The proof boundary and the one justified point-halving experiment are recorded
in
[`docs/STRICT_AGGREGATE_BATCHING.md`](docs/STRICT_AGGREGATE_BATCHING.md).
Narya's public "Batch" APIs instead preserve an independent verdict for every
signature. The default `generic` backend processes signatures independently.
The explicitly selected `r51` backend hashes and decodes several independent
signatures in SIMD lanes while retaining a separate verdict for every input.
A future `ZIP215` profile may expose the cofactored predicate explicitly. It
will not silently change either existing profile.

The security meaning of these checks is subtler than a simple
"strict-versus-permissive" ordering. Brendel, Cremers, Jackson, and Zhao prove
strong unforgeability from the canonical-`S` check for their standardized
Ed25519 variant, while their additional malicious-key and message-binding
results rely on rejecting small-order elements. Narya's profiles are not
identical to the paper's named variants, so the precise correspondence and the
limits of what can be inferred are recorded in
[`docs/PROVABLE_SECURITY.md`](docs/PROVABLE_SECURITY.md).

### "Batch" means two different things

The word is overloaded, and the two meanings have different guarantees. This
is worth being precise about, because it explains both what `VerifyBatch` does
here and why Narya's throughput curve has a different shape from other
libraries'.

|  | **Lane-parallel** (what Narya does) | **Aggregate** (`VerifyBatch` in most libraries) |
| --- | --- | --- |
| equations evaluated | N, one per signature | **1**, all signatures combined |
| verdicts returned | N | **1** |
| identical to verifying one at a time? | **yes, bit for bit** | no |
| valid under a cofactorless predicate? | yes | ordinary form: **no**; gated hybrid: probabilistic |
| source of the speedup | filling SIMD lanes | fewer group operations |
| scaling | flattens at the lane count | keeps improving with N |

Lane-parallel batching is a *hardware* optimization. Eight independent
signatures occupy eight AVX-512 lanes, so one instruction stream performs
eight signatures' worth of field arithmetic, but each signature still gets
its own complete verification equation and its own answer. Nothing about the
mathematics changes; the machine is merely busier. That is why every verdict
is bit-for-bit what you would get from a loop, and why the curve flattens once
the lanes are full.

Aggregate batching is a *mathematical* optimization. It folds N signatures
into a single equation with random weights, replacing N double-scalar
multiplications with one multi-scalar multiplication. It is genuinely faster
where it applies, and it keeps getting faster as N grows. What it returns is
one probabilistic answer for the whole set. The ordinary construction is sound
for a cofactored predicate; applying it directly to a cofactorless predicate
lets individual torsion errors cancel. A hybrid can restore cofactorless
predicate compatibility by proving each residual torsion-free first, but that
per-item cost and the aggregate's nonzero soundness error remain.

That constraint is not Narya's opinion. `curve25519-voi` implements ordinary
aggregate batch verification and refuses to apply it to cofactorless entries,
returning false rather than a possibly-unsound accept
(`primitives/ed25519/batch_verify.go`). Under `DalekStrict`, Narya does not use
aggregate verification because its contract requires deterministic,
independent verdicts. The more expensive strict-compatible hybrid is retained
only as a documented research question.

**Choosing between them.** If one answer for the whole set is enough (you
reject an entire block on any failure, say), aggregate batching under a
cofactored predicate is likely the better tool, and Narya is not it. If you
need to know *which* input failed, or you must match a cofactorless predicate
exactly, aggregate batching cannot give you that at any speed, and
lane-parallel is what remains. Admission control is the clearest case: an
aggregate verdict over a batch of user-submitted transactions cannot tell you
which one to drop, and discarding the whole batch hands an attacker a very
cheap denial of service.

**Narya has no signing API, deliberately.** The mismatched private/public-key
signing-oracle failures catalogued by
[ed25519-unsafe-libs](https://github.com/MystenLabs/ed25519-unsafe-libs)
are therefore outside its API: Narya never accepts a caller-supplied
private/public key pair. Verification still has its own consensus and input
validation risks, which are addressed by the profile contract and differential
test corpus below. If signing is ever added, it must derive or validate the
public key from the secret as required by the
[RFC 8032 signing procedure](https://www.rfc-editor.org/rfc/rfc8032#section-5.1.6);
merely verifying the emitted signature is not a sufficient defense against the
mixed-order substitution described by the Mysten audit.

## API

```go
func Verify(pub *[32]byte, message, sig []byte) bool   // uses DefaultProfile()
func VerifyStrict(pub, message, sig []byte) bool       // always DalekStrict; byte-slice pub,
                                                       // drop-in for crypto/ed25519.Verify
func VerifyBatch(pubs []*[32]byte, msgs, sigs [][]byte, ok []bool) bool
func VerifyBatchStrict(pubs []*[32]byte, msgs, sigs [][]byte, ok []bool) bool

func Precompute(pub *[32]byte) (*PrecomputedKey, error)
func (k *PrecomputedKey) Verify(message, sig []byte) bool

type Cache struct{ MaxTableBytes int64 }               // 0 means DefaultMaxTableBytes (128 MiB)
func (c *Cache) Verify(pub *[32]byte, message, sig []byte) bool
func (c *Cache) VerifyStrict(pub *[32]byte, message, sig []byte) bool
func (c *Cache) VerifyBatch(pubs []*[32]byte, msgs, sigs [][]byte, ok []bool) bool
func (c *Cache) VerifyBatchStrict(pubs []*[32]byte, msgs, sigs [][]byte, ok []bool) bool
func (c *Cache) Stats() CacheStats

type Profile uint8
const (DalekStrict Profile = iota; StdlibCompat)
func SetDefaultProfile(p Profile)
func DefaultProfile() Profile

func ActiveBackend() string
func SetBackend(name string) error                     // must precede first verification
```

`VerifyBatch` writes per-signature verdicts into `ok` and panics if the slice
lengths differ. `Precompute` returns a non-nil error when `pub` does not decode.

## Packages and backends

- **`ed25519`** is the public API above. Exactly one backend is active per
  process, latched on first use. Resolution order: the name passed to
  `SetBackend`, then `OVERCLOCK_ED25519_BACKEND`, then the default.
- **`sha512mb`** is multi-buffer SHA-512.
- **`cmd/sigverifytracebench`** is offline exact-input schema-v3 replay for a
  measured stdlib/generic/generic-cache diagnostic. It never promotes the
  generic table result to the pending r51 production cache gate.

| backend | status | notes |
| --- | --- | --- |
| `generic` | **default** | Pure Go over the vendored `edwards25519` internals, with per-key fixed-base comb tables for recurring signers. |
| `stdlib` | available | Routes to `crypto/ed25519`. The rollback proof point. |
| `ifma` | opt-in, in development | AVX-512 IFMA point arithmetic after Firedancer's `r43x6` representation. Requires AVX512F/VL/DQ/BW/IFMA/VBMI, detected at runtime via `x/sys/cpu`, never via `GOAMD64`, since `x86-64-v4` does not imply IFMA. |
| `r51` | **registered, forced-only** | AMD lane-per-signature r51 backend. Strict singletons use paired A/R decode and a coordinate-packed projective finalizer. Zen 5 strict two-signature tails put one complete equation in each 256-bit half of a ZMM register; other measured CPUs call the packed singleton twice. Wider batches use a radix-32 A table, A-only decode, and cross-group batch encoding of Q. Measured AMD family 19h+ IFMA parts, including Zen 4 and Zen 5, use x8/ZMM for complete eight-signature groups and x4 curve arithmetic for the tail. Zen 5 injects width-10 generator digits into A's x8 doubling chain; Zen 4, unknown IFMA CPUs, and x4 tails retain the process-shared radix-256 generator comb. Zen 5 hashes four-to-seven-item cold tails through the x8 SHA/reduction path; Zen 4 and unknown IFMA CPUs retain x4 hashing. The x8 doubler uses the symmetry-aware raw-square schedule on both measured families; Zen 5 additionally keeps intermediate doubling results in a three-coordinate P2 type and computes extended T only at addition boundaries. From 16 signatures, Zen 5 also widens literal-Q batch encoding to x8; other measured widths retain x4. Its opt-in `Cache` first admits an exact-byte-bound decoded-A entry and promotes recurring valid strict keys to an immutable A6/r9 warm comb. Warm x4 groups are consumed in aligned pairs on the measured AMD set, except a final four-item tail, so a half-warm x8 group stays on the faster native-wide cold path. `StdlibCompat` singleton calls retain the generic literal-encoding path. This backend is never selected automatically. |

Selection is deliberately non-degrading. `ifma` requires AVX512F/VL/DQ/BW,
IFMA, and VBMI. `r51` requires that same IFMA feature set plus AVX2 for its
native x4 SHA-512 path. `SetBackend` performs the complete activation check
synchronously; an unknown or unsupported forced name returns an error there
and panics on the environment-variable path. A forced name represents explicit
operator intent and must not silently fall back.

`sha512mb`'s public `Lanes()` and `Sum512Batch` surface remains the portable
scalar implementation. Its AVX2 and AVX-512 kernels are hardware-gated behind
the `Experimental*` entry points; the forced `r51` backend calls the x8 native
entry for complete groups on measured AMD family 19h+ IFMA parts. Zen 5 also
uses x8 hashing for four-to-seven-item cold x4 curve tails; Zen 4, smaller
tails, and unknown IFMA CPUs retain x4 hashing. Automatic
backend selection never reaches either kernel.

**Unclaimed AVX2 path.** The x4 kernel gates on AVX2 alone, with no AVX-512
term. Since the point arithmetic in `r51` needs IFMA and cannot run without it,
an AVX2-only host falls to `generic`, which hashes through the scalar
`Sum512Batch` and so never reaches that kernel. Routing the default batch entry
through the native kernels would therefore speed up `generic` on any host with
AVX2, bounded by SHA-512's share of one verification. **Not wired, not
measured, and no AVX2-only machine has been benchmarked** — the size of the win
is an estimate, not a result.

The x8 fixed-three-segment entry recognizes full
groups of the exact `R[32] || A[32] || message` shapes at message sizes
64/200/1232, ingesting their first and final blocks without generic segmented
staging. Design details and historical measurements are kept in
[`docs/SHA512_MULTIBUFFER.md`](docs/SHA512_MULTIBUFFER.md).

## Performance

Narya's accelerated path is measured through the exported
`SetBackend("r51")`, `VerifyBatchStrict`, and `Cache.VerifyBatchStrict` APIs.
The release snapshot uses **cold Zen 5 measurements only** for its headline:
an AMD Ryzen 7 9700X, Go 1.26.4, one pinned physical core, the performance
governor, and `GOMAXPROCS=1`. Every single-core table below was rerun from
exact live-path implementation commit
`bbc6c2194438090b0c48ac9bd95eab6b92602d6f`; raw output, commands, host
details, and checksums are under
[`docs/results/zen5-packed-pair-whole-window-2026-07-29/`](docs/results/zen5-packed-pair-whole-window-2026-07-29/).
Every timed Narya row reported 0 B/op, 0 allocs/op, and zero internal-fault
fallbacks. Displayed single-core values are medians of three two-second
samples. The unchanged multicore table retains its separately identified
six-sample checkpoint.

**Units:** every numeric timing cell in the tables below is **microseconds per
signature (`µs/signature`, lower is better)**. These are per-signature costs,
not per-batch latencies.

### Cold verification across message sizes

**Ryzen 7 9700X · arbitrary keys with no retained key state · µs/signature,
lower is better**

| batch size | 200-byte message | 1,232-byte message | 4,096-byte message |
| ---: | ---: | ---: | ---: |
| 1 | 13.040 | 13.590 | 15.780 |
| 2 | 11.110 | 11.620 | 13.730 |
| 4 | 7.408 | 7.872 | 9.223 |
| 8 | 3.585 | 3.850 | 4.548 |
| 64 | **3.373** | **3.623** | **4.330** |

At 1,232 bytes, the n=8 and n=64 rows correspond to approximately 259,700 and
276,100 signatures/second/core. Batch width matters because n=1 uses the
coordinate-packed x4 verifier, Zen 5 n=2 fills both independent 256-bit halves
of a ZMM register, n=4 fills one x4 curve group and uses x8 hashing on Zen 5,
and n=8 or larger can fill native x8 groups. Zen 4 retains two independently
measured singleton calls for n=2.

### Warm-cache reference

**Ryzen 7 9700X · 1,232-byte messages · 64 promoted keys · µs/signature,
lower is better**

| batch size | cold µs/signature | warm µs/signature | warm speedup |
| ---: | ---: | ---: | ---: |
| 1 | 13.590 | 13.800 | 0.98x |
| 2 | 11.620 | 11.960 | 0.97x |
| 4 | 7.872 | **4.057** | **1.94x** |
| 8 | 3.850 | 3.819 | 1.01x |
| 64 | **3.623** | 3.655 | 0.99x |

The cache fixture promotes 64 keys and occupies 1,243,136 table bytes. The
cache deliberately bypasses prepared tables below n=4, so lookup overhead can
make the singleton row marginally slower. Its wider-batch result depends on
key population and locality; this small hot fixture is a reference, not a
universal hit-rate claim. Current cold x8 now approximately matches the
hot-fixture warm path at n=8 and exceeds it at n=64, so this cross-check is not
a claim that a cache hit necessarily helps every current width.

The warm path is also not unconditionally faster for every message size. The
complete measured matrix is:

**Ryzen 7 9700X · 64 promoted keys · µs/signature, lower is better**

| batch size | 200-byte message | 1,232-byte message | 4,096-byte message |
| ---: | ---: | ---: | ---: |
| 1 | 12.940 | 13.800 | 15.760 |
| 2 | 11.060 | 11.960 | 14.110 |
| 4 | 3.307 | 4.057 | 6.105 |
| 8 | 3.065 | 3.819 | 5.868 |
| 64 | **2.906** | **3.655** | **5.730** |

At 4,096 bytes, cold x8 is faster than the current warm x4-oriented path at
n=8 and n=64. The two paths schedule hashing differently, and hashing is a
larger fraction of a long-message warm verification. Cache population,
message size, and width must therefore be reported together.

These numbers describe the explicitly forced backend, not automatic dispatch;
the portable `generic` backend remains the default.

### Cross-library comparison

**Ryzen 7 9700X · 1,232-byte messages · µs/signature, lower is better**

The comparison below uses one binary, the same Zen 5 host, and 1,232-byte
messages. Every candidate runs
ordinary per-signature verification and returns one verdict per input; no
aggregate batch equation is used. Voi's expanded-key row excludes expansion
cost and is included as a warm-key reference.

| implementation | n=1 µs/sig | n=2 µs/sig | n=4 µs/sig | n=8 µs/sig | n=64 µs/sig |
| --- | ---: | ---: | ---: | ---: | ---: |
| Narya r51, cold strict | 13.860 | 12.200 | 7.851 | 3.789 | 3.601 |
| Go `crypto/ed25519` | 27.690 | 27.340 | 27.430 | 27.370 | 27.370 |
| curve25519-voi, cold strict | 21.980 | 21.690 | 21.780 | 21.770 | 21.890 |
| curve25519-voi, expanded key | 19.160 | 18.880 | 18.960 | 18.960 | 19.040 |

Within that comparison binary, Narya is 2.00x faster than Go at n=1, 2.24x at
n=2, 3.49x at n=4, 7.22x at n=8, and 7.60x at n=64. The comparison binary
includes the opt-in Voi dependency and has a different link layout from the
release binary, so use this table for library ratios and the cold table above
for Narya's release latency.

### Multicore scaling

**Ryzen 7 9700X · 1,232-byte messages · aggregate signatures/second, higher is
better**

These are aggregate **signatures per second** over 1,232-byte messages, not
individual request latency. Each row pins only distinct physical cores;
SMT siblings are excluded.

| physical cores | n=4 signatures/s | n=4 scaling | n=8 signatures/s | n=8 scaling |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 125,100 | 1.00x | 260,104 | 1.00x |
| 2 | 248,807 | 1.99x | 524,739 | 2.02x |
| 4 | 488,958 | 3.91x | 1,029,362 | 3.96x |
| 6 | 702,317 | 5.61x | 1,476,064 | 5.68x |
| 8 | 891,736 | 7.13x | 1,821,228 | 7.00x |

The eight-core rows correspond to aggregate throughput costs of 1.121
and 0.549 microseconds per signature. Each worker still verifies complete,
independent equations; this table measures concurrent callers, not aggregate
cryptographic batch verification. Raw output is in the earlier, unchanged
[`docs/results/zen5-final-review-2026-07-29/`](docs/results/zen5-final-review-2026-07-29/)
multicore checkpoint; it was not inferred from the newer serial run.

**Hardware scope: AMD only so far.** Every displayed timing above was captured
on an AMD Ryzen 7 9700X (Zen 5); historical bundles in `docs/results/` also
include a Ryzen 7 PRO 8700GE (Zen 4). Narya dispatches on the AVX512-IFMA
feature set rather than on
vendor, so the same kernels are expected to run on Intel Ice Lake Server and
newer, and CI exercises them under Intel SDE emulating Ice Lake Server. But
emulation establishes function, not speed: **no Intel silicon has been
benchmarked, and no server part of either vendor has.** Treat the numbers as
characterizing consumer Zen 5 and nothing else. Intel and EPYC
measurement is outstanding work, not a completed check.

Historical measurements and their exact environments remain in
[`docs/results/`](docs/results/); they are intentionally not stacked into the
current tables because code, CPU generation, and cache population materially
change the result. Current cold, warm, and cross-library outputs are in
[`docs/results/zen5-packed-pair-whole-window-2026-07-29/`](docs/results/zen5-packed-pair-whole-window-2026-07-29/).
The unchanged multicore output remains in
[`docs/results/zen5-final-review-2026-07-29/`](docs/results/zen5-final-review-2026-07-29/).

### Cold and warm verification

Cold and warm are two execution conditions with the same acceptance predicate,
not different security modes:

| path | public entry point | intended workload | trade-off |
| --- | --- | --- | --- |
| **cold** | `VerifyStrict` / `VerifyBatchStrict` | arbitrary, first-seen, or low-recurrence public keys | no persistent key state; decodes A and builds its small variable-base table for each verification |
| **warm** | `Cache.VerifyStrict` / `Cache.VerifyBatchStrict` | public keys that recur enough to repay preparation | exact-byte-bound decoded-A and precomputed-comb tiers reduce curve work in exchange for memory, lookup, and admission overhead |

Both paths hash the original public-key and signature bytes, retain independent
per-signature verdicts, and enforce the selected profile. Invalid inputs and
invalid equations never earn cache promotion. Warm results depend on the
number and recurrence of keys: a tiny permanently hot fixture can overstate
performance compared with a populated cache, so Narya reports cache population
alongside every release measurement.

The cache is opt-in. Raw `VerifyBatchStrict` remains cold and stateless, and
automatic backend selection remains `generic`.

### Running the benchmarks

The public cold/warm benchmark is isolated behind a build tag so it cannot
accidentally measure a private implementation seam:

```sh
taskset -c 2 env GOMAXPROCS=1 go test -tags r51_release_bench \
  -run '^$' \
  -bench '^BenchmarkPublicR51(VerifyBatchStrict|CacheVerifyBatchStrict)$/^msg=(200|1232|4096)$/^n=(1|2|4|8|64)$' \
  -benchmem -benchtime=2s -count=10 ./ed25519
```

The 1232-byte comparison table comes from the isolated Voi module:

```sh
taskset -c 2 env GOMAXPROCS=1 go test \
  -modfile=go.oasis.mod -tags oasis_compare -run '^$' \
  -bench '^BenchmarkEd25519CrossLibrary$/^mode=independent$/^impl=(narya-r51-dispatch|go-stdlib-loop|oasis-strict-cold-loop|oasis-strict-expanded-loop)$/^n=(1|2|4|8|64)$/^msg=1232$' \
  -benchmem -benchtime=2s -count=6 ./ed25519
```

The accelerated backends require AVX512-IFMA and must be selected explicitly
with `SetBackend("r51")` or `OVERCLOCK_ED25519_BACKEND=r51`. Unsupported
forced activation fails synchronously instead of silently measuring the
portable path.

For reproducible CPU measurements, pin a physical core, use the same Go
toolchain, record the CPU governor, and use repeated samples with
`benchstat`. Do not infer sustained frequency from an idle
`/proc/cpuinfo` sample; use hardware counters when cycle-level comparisons
matter.

## Verification

- All five plain Ed25519 known-answer vectors from
  [RFC 8032 section 7.1](https://www.rfc-editor.org/rfc/rfc8032#section-7.1),
  914 [CCTV](https://github.com/C2SP/CCTV) `ed25519vectors`, and 133
  [Project Wycheproof](https://github.com/C2SP/wycheproof) `eddsa_test`
  vectors, plus pinned Firedancer regression vectors and a generated edge-point
  corpus.
- Differential tests anchoring every backend, cached or not, batched or single,
  to `crypto/ed25519` and to the generic backend, per profile.
- A cross-library differential against
  [curve25519-voi](https://github.com/oasisprotocol/curve25519-voi/tree/1f23a7beb09a)
  version `v0.0.0-20230904125328-1f23a7beb09a`, configured to the equivalent
  strict option set. It is isolated from the library module graph in
  `go.oasis.mod`; run it with `make test-oasis`.
- Fuzz targets comparing backends three ways.

**Fuzz soak status: short rounds only.** The differential fuzzing run so far is
smoke-scale — roughly 4.6 million executions across about 25 minutes, split
between the r51 pipeline, the public verifier, and multi-buffer SHA-512, all
passing. The bar this project sets for enabling automatic SIMD dispatch is a
prolonged soak on the order of **10^9 executions**, and that has not been run.
The two facts are consistent rather than contradictory: automatic selection is
still `generic`, and `r51` is reachable only by explicit `SetBackend`. But the
soak is a precondition for changing that, not a formality already satisfied.
The runner and its evidence format are described in
[`docs/FUZZ_SOAK.md`](docs/FUZZ_SOAK.md).

**No external review of the assembly.** Everything above is self-consistency:
the vector kernels are checked against scalar models, the models against the
vector corpora, and the corpora against `crypto/ed25519`. That is a strong
structure and it is not the same thing as an independent audit. Roughly 4,500
lines of assembly have had no third-party review.

CI runs portable tests on `ubuntu-latest` and `macos-latest`, the isolated
Oasis differential on Linux, plus a pinned
[Intel SDE](https://www.intel.com/content/www/us/en/developer/articles/tool/software-development-emulator.html)
10.8 job that emulates Ice Lake Server and executes focused r51x5 IFMA,
native-SHA, and public forced-r51 differentials. Dedicated `sde_gate` tests
fail rather than skip when the emulated feature set is missing. SDE is
functional coverage only. Native release gates have run on the Ryzen 7 PRO
8700GE (Zen 4), while the displayed release-performance snapshots were taken
on the Ryzen 7 9700X (Zen 5); zero-allocation and differential gates are
required on the native hardware used for each release measurement. Automatic
backend selection remains `generic`.

## Status

Alpha. The `generic` backend, the profile contract, and the per-key comb cache
are functional and differential-tested. The `r51` throughput backend is
registered for explicit selection on supported hardware but remains outside
automatic dispatch. It uses native x8 groups, x4 tails, and packed strict
singletons on measured AMD family 19h+ IFMA processors; Zen 5 also has the
two-equation packed-ZMM n=2 path described above. Its opt-in two-tier Cache
and width-aware A6/r9 warm promotion are implemented and hardware-tested; the
traffic-specific admission and eviction policy remains integration work. The
`ifma` reference backend and alternate arithmetic experiments remain test-only
evidence. Performance work is frozen at this checkpoint while the supported
path receives safety review.

The radix-51 backend's analytic range evidence, exact test coverage, and
remaining machine-certificate boundary are summarized in
[`docs/R51_ARITHMETIC_ASSURANCE.md`](docs/R51_ARITHMETIC_ASSURANCE.md).
Proof-oriented artifacts are indexed separately in
[`docs/formal/README.md`](docs/formal/README.md); each artifact states whether
it is a Lean theorem, executable certificate, differential test, or native
hardware gate and names the remaining refinement boundary.
The exact supported/experimental boundary and pre-audit checklist are frozen in
[`docs/SAFETY_FREEZE_2026-07-29.md`](docs/SAFETY_FREEZE_2026-07-29.md).

### Outstanding before automatic dispatch

These are open, not pending paperwork. Each is described where it belongs above.

| item | state |
| --- | --- |
| 10^9-execution differential fuzz soak | not run; ~4.6M executions so far |
| Intel silicon benchmarks | not run; SDE gives function, not speed |
| Server-part benchmarks (EPYC, Xeon) | not run; consumer Zen 4/5 only |
| Independent review of the assembly | not done |
| Native SHA-512 under the default batch entry (helps AVX2-only hosts) | not wired, not measured |
| Traffic-specific cache admission and eviction policy | integration work |

Until these close, `generic` remains the automatic choice and `r51` remains
opt-in. Published `r51` figures describe an explicitly forced backend.

## AI-assisted development

Narya was developed with extensive assistance from OpenAI Codex and ChatGPT
Pro, together with Anthropic Claude. These systems contributed to code
exploration, profiling analysis, mathematical review, hypothesis generation,
test design, documentation, and implementation work, including assembly.

Humans selected the supported design and remain responsible for every change.
AI output was treated as an untrusted proposal: retained work had to pass
independent reference vectors, differential tests, range and aliasing checks,
native-hardware correctness gates, and repeated performance measurements. The
AI systems are development collaborators, not cryptographic auditors or
endorsers of the library.

## License

Apache-2.0. See [NOTICE](NOTICE) for the full attribution list.

**Vendored code.** `internal/edwards25519` derives from the Go standard
library's `crypto/internal/edwards25519` and from
[`filippo.io/edwards25519` v1.0.0](https://github.com/FiloSottile/edwards25519/tree/v1.0.0);
its `field` subpackage is synchronized to
[`filippo.io/edwards25519` v1.2.0](https://github.com/FiloSottile/edwards25519/tree/v1.2.0)
(BSD-3-Clause). The upstream LICENSE files and BSD headers are preserved.
Modified vendored files retain those headers and are enumerated in
[NOTICE](NOTICE); standalone Narya-authored files carry Apache-2.0 headers.

**Derived work.** The `r43x6` AVX-512 IFMA design and constants in
`internal/r43x6` follow
[Firedancer at `3ed37488372b7e50bb03ca30477be48508ee7022`](https://github.com/firedancer-io/firedancer/tree/3ed37488372b7e50bb03ca30477be48508ee7022),
Copyright 2022 Firedancer Contributors, Apache-2.0. Firedancer records that its
Ed25519 implementation was originally based on OpenSSL's circa-October-2022
implementation; the inherited notice and license text are carried in
[NOTICE](NOTICE).

**Prior work this library descends from.** The generic backend, the per-key
comb cache, and `internal/edwards25519/comb.go` originate in `pkg/ed25519fast`
in [Mithril](https://github.com/Overclock-Validator/mithril), authored by
palmer.

**Papers and design influences.** The sources below influenced different
parts of Narya; inclusion here does not mean their code was copied or that an
experimental idea is part of the supported backend.

| Source | Influence on Narya |
| --- | --- |
| [*ENG25519: Faster TLS 1.3 Handshake Using Optimized X25519 and Ed25519*](https://www.usenix.org/conference/usenixsecurity24/presentation/zhang-jipeng) (Zhang, Huang, Zhao, Chen, and Koç, USENIX Security 2024) | The strongest academic influence on the shipping r51 backend. It provided independent published evidence that five radix-2^51 limbs are a good fit for AVX-512 IFMA. Narya's lane-per-signature kernels and implementation are its own. |
| [*Taming the many EdDSAs*](https://eprint.iacr.org/2020/1244) | Shaped the acceptance-predicate analysis: canonical encodings, cofactored versus cofactorless equations, mixed-order behavior, and the edge-case corpus used to prove cross-implementation agreement. |
| [*The Provable Security of Ed25519: Theory and Practice*](https://eprint.iacr.org/2020/823) (Brendel, Cremers, Jackson, and Zhao, IEEE S&P 2021) | Supplies the formal security rationale for treating canonical scalar encodings, key-prefix hashing, and small-order rejection as distinct protocol choices. Narya does not claim that its profiles are identical to the paper's variants; the exact mapping and proof boundary are documented in [`docs/PROVABLE_SECURITY.md`](docs/PROVABLE_SECURITY.md). |
| [*Accelerating EdDSA Signature Verification with Faster Scalar Size Halving*](https://doi.org/10.46586/tches.v2025.i3.493-515) (ElSheikh, Keskinkurt Paksoy, Cenk, and Hasan, TCHES 2025) | Basis of Narya's test-only HEEA/scalar-halving track. Narya adds the modulo-8L relation and unit-multiplier requirement needed to preserve its cofactorless full-group equation; the published speedup is not treated as a prediction for Narya. |
| [*Optimized Lattice Basis Reduction in Dimension 2, and Fast Schnorr and EdDSA Signature Verification*](https://eprint.iacr.org/2020/454) (Pornin, 2020) | Earlier ABGLSV–Pornin lineage behind scalar-size-halving verification and Voi's cofactored fast path. It informed the research comparison, not the production `DalekStrict` backend. |
| [*Point-Halving and Subgroup Membership in Twisted Edwards Curves*](https://eprint.iacr.org/2022/1164) (Pornin, 2022) | Supplies the nonlinear prime-subgroup-membership method behind Narya's documented strict-compatible aggregate-batching research gate. No aggregate verifier or point-halving kernel is currently shipped. See [`docs/STRICT_AGGREGATE_BATCHING.md`](docs/STRICT_AGGREGATE_BATCHING.md). |
| [*High-speed high-security signatures*](https://ed25519.cr.yp.to/ed25519-20110926.pdf) and [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) | Foundational Ed25519 scheme, encoding, hashing, and known-answer vectors. Narya deliberately exposes explicit named verification predicates where real implementations resolve edge cases differently. |

The largest non-paper engineering influences are Firedancer's AVX-512
Ed25519 and SHA-512 work, curve25519-dalek and curve25519-voi's vectorized
Edwards implementations and predicate behavior, and BoringSSL's
square-root-ratio derivation. Eclipse Labs'
[*Breaking 10 Million TPS*](https://www.eclipselabs.io/blogs/breaking-10-million-tps)
was useful directional confirmation of the x8/radix-51 IFMA design space, but
is not treated as a formal result or performance claim. Exact code provenance,
pinned revisions, and license obligations are recorded in [NOTICE](NOTICE).

**Specifications and reference implementations.** The acceptance predicate is
that of [ed25519-dalek 2.2.0 at `8016d6d`](https://github.com/dalek-cryptography/curve25519-dalek/tree/8016d6d9b9cdbaa681f24147e0b9377cc8cef934/ed25519-dalek)
`verify_strict`, as reached by
[Agave audit snapshot `7e51da9`](https://github.com/anza-xyz/agave/tree/7e51da963aee49622a395f562386a6bd8ba0e717)
(Anza) through the `solana-signature` crate; Agave is the reference Narya's
verdict must match. The reserved `ZIP215` profile name is from Zcash's
[ZIP 215](https://zips.z.cash/zip-0215). `sha512mb` implements FIPS 180-4. The
square-root-ratio derivation used in `field/fe.go` and `internal/r43x6` follows
[BoringSSL commit `0fc57bef1821c163ac023a0aa96e4fb2a67c0d82`](https://boringssl.googlesource.com/boringssl/+/0fc57bef1821c163ac023a0aa96e4fb2a67c0d82).

**Test corpora.** The CCTV `ed25519vectors` corpus is redistributed under
BSD-3-Clause, Copyright 2019 Google LLC and Copyright 2022 Filippo Valsorda;
its license text is reproduced in full in [NOTICE](NOTICE) as that license
requires. Project Wycheproof vectors are redistributed under Apache-2.0,
Copyright Google LLC.

**Comparison and prior art.**
[curve25519-voi at `1f23a7beb09a`](https://github.com/oasisprotocol/curve25519-voi/tree/1f23a7beb09a)
(Oasis Protocol, BSD-3-Clause) serves as a cross-library differential oracle
and performance baseline. Narya does not use voi's shipped cofactored
ABGLSV–Pornin verification path for `DalekStrict`; multiplying the error point
by a non-injective cofactor can change that predicate. Narya's separate
torsion-safe modulo-8L HEEA work remains experimental.

voi is an opt-in test dependency only. The main `go.mod` retains only
`golang.org/x/sys`; `go.oasis.mod` pins the independent comparator used by
`make test-oasis` and the separately recorded comparison benchmarks.

voi is itself largely derived from
[curve25519-dalek 3.2.0 at `09a726c`](https://github.com/dalek-cryptography/curve25519-dalek/tree/09a726cc8c995a7565d80148536df21f1f287659), and
the vectorized Edwards backend that produces its uncached single-signature
timings is a Go port of dalek's AVX2 backend (Copyright isis agora lovecruft,
Henry de Valence, and Oasis Labs), selected whenever AVX2 is present. That intra-signature
orientation, one point's coordinates across vector lanes, is prior art that
Narya did not originate: dalek's AVX2 backend is a documented implementation,
and Firedancer's `r43x6` QUAD packing, which `internal/r43x6` credits, is the
same idea at AVX-512 width. Narya's experimental
coordinate-parallel work uses that orientation at radix 2^51. See
[NOTICE](NOTICE).
