# Narya — Ed25519 verification with an explicit acceptance predicate

Narya verifies Ed25519 signatures under an explicit, versioned acceptance
profile. It is built for workloads that verify at consensus scale: Solana block
replay and leader-mode transaction ingest, where a block can carry tens of
thousands of signatures and many of them come from a stable set of hot signers.

> Narya is Gandalf's ring — the Ring of Fire. The name nods to
> [Firedancer](https://github.com/firedancer-io/firedancer), whose
> AVX-512 `r43x6` design the `ifma` backend ports, and to
> [Mithril](https://github.com/Overclock-Validator/mithril), the Go
> Solana node this library was built for.

## Why this exists

**Ed25519 verification is not one predicate.** RFC 8032 leaves several choices
open, and production implementations resolve them differently:

| | cofactorless | small-order `A` | small-order `R` | non-canonical `A` | non-canonical `R` |
| --- | --- | --- | --- | --- | --- |
| Go `crypto/ed25519` | yes | accept | accept | accept | reject |
| `ed25519-dalek` `verify_strict` | yes | **reject** | **reject** | accept | reject |
| ZIP 215 | no (cofactored) | accept | accept | accept | **accept** |

Any two rows disagree on a nonempty, adversarially constructible set of inputs.
For a validating node that is a fork, and it is remotely triggerable — an
attacker picks an input in the symmetric difference. Solana is the maximal
case: Agave in Rust, Firedancer in C, and Mithril in Go must agree byte for
byte, on every input, indefinitely.

The subtlety that makes this worth a library: `verify_strict` is **not**
"strict about everything." It rejects non-canonical `R` but *accepts*
non-canonical `A`. Hand-rolling the predicate and getting that one case
backwards is a silent fork.

Narya makes the choice explicit, versioned, and differentially tested rather
than incidental.

## The contract

Verification enforces one of two versioned **profiles**, because the
consensus-correct acceptance predicate is itself versioned — an
accept/reject flip is a fork, so it is a deliberate choice, not an
implementation detail:

- **`DalekStrict`** (default, and the zero value) — current Solana mainnet
  transaction semantics: `ed25519-dalek` 2.x `verify_strict`, reached through
  the `solana-signature` crate. This is `crypto/ed25519.Verify` **plus**
  rejection of small-order public keys A and small-order signature
  points R. The standard library accepts those (it never decodes R); a
  verifying node that used it unmodified could be forked off the
  network by a crafted block, so this is the default.
- **`StdlibCompat`** — exactly `crypto/ed25519.Verify`, for
  differential testing and callers who explicitly want standard-library
  behavior.

Small-order rejection is a byte-level classifier over the seven low-255-bit
small-order `y` encodings, sign-bit-insensitive — fourteen byte strings, with
no point decode required.

For every input — non-canonical encodings, small-order points,
malformed signatures — every backend, cached or not, batched or single,
returns exactly what the active profile's predicate returns. This is
enforced by differential tests, the CCTV and Wycheproof corpora, a
cross-library differential against curve25519-voi, and fuzzing rather than
assumed; the 165 CCTV vectors where the two profiles differ are precisely the
small-order set, cross-checked against Firedancer's independent verdict.

Narya never uses random-coefficient (cofactored) batch verification:
its aggregate equation can accept adversarial signatures that
per-signature verification rejects. "Batch" preserves an independent verdict
for every signature. The default `generic` backend processes signatures
independently. The explicitly selected `r51` backend instead hashes and
decodes several independent signatures in SIMD lanes while retaining a
separate verdict for every input.
A future `ZIP215` profile will track Solana's proposed
[SIMD-0376 at `b13be70`](https://github.com/solana-foundation/solana-improvement-documents/blob/b13be70e7454144becbe9c474b296d737d72df98/proposals/0376-verify-strict.md)
loosening only after it is accepted and its feature gate activates on mainnet.
The existence of a ZIP-215 implementation is not itself an activation signal.

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

- **`ed25519`** — the public API above. Exactly one backend is active per
  process, latched on first use. Resolution order: the name passed to
  `SetBackend`, then `OVERCLOCK_ED25519_BACKEND`, then the default.
- **`sha512mb`** — multi-buffer SHA-512.
- **`cmd/sigverifytracebench`** — offline exact-input schema-v3 replay for a
  measured stdlib/generic/generic-cache diagnostic. It never promotes the
  generic table result to the pending r51 production cache gate.

| backend | status | notes |
| --- | --- | --- |
| `generic` | **default** | Pure Go over the vendored `edwards25519` internals, with per-key fixed-base comb tables for recurring signers. |
| `stdlib` | available | Routes to `crypto/ed25519`. The rollback proof point. |
| `ifma` | opt-in, in development | AVX-512 IFMA point arithmetic after Firedancer's `r43x6` representation. Requires AVX512F/VL/DQ/BW/IFMA/VBMI, detected at runtime via `x/sys/cpu` — never via `GOAMD64`, since `x86-64-v4` does not imply IFMA. |
| `r51` | **registered, forced-only** | AMD lane-per-signature r51 backend. Strict singletons and two-signature tails use paired A/R decode and a packed projective finalizer. Wider batches use a radix-32 A table, one process-shared radix-256 B comb, A-only decode, and cross-group batch encoding of Q. Zen 4 uses x4/YMM groups; AMD family 1Ah (Zen 5) uses x8/ZMM for complete eight-signature groups and x4 for the tail. Its opt-in `Cache` first admits an exact-byte-bound decoded-A entry and promotes recurring valid strict keys to an immutable A6/r9 warm comb. Zen 5 consumes warm x4 groups only in aligned pairs, except a final four-item tail, so a half-warm x8 group stays on the faster native-wide path. Zen 4 uses each complete warm x4 group independently. `StdlibCompat` singleton calls retain the generic literal-encoding path. This backend is never selected automatically. |

Selection is deliberately non-degrading. `ifma` requires AVX512F/VL/DQ/BW,
IFMA, and VBMI. `r51` requires that same IFMA feature set plus AVX2 for its
native x4 SHA-512 path. `SetBackend` performs the complete activation check
synchronously; an unknown or unsupported forced name returns an error there
and panics on the environment-variable path. A forced name represents explicit
operator intent and must not silently fall back.

`sha512mb`'s public `Lanes()` and `Sum512Batch` surface remains the portable
scalar implementation. Its AVX2 and AVX-512 kernels are hardware-gated behind
the `Experimental*` entry points; the forced `r51` backend calls the x4 native
entry on Zen 4 and the x8 native entry for complete Zen 5 groups. Automatic
backend selection never reaches either kernel.
The x8 fixed-three-segment entry recognizes full
groups of the exact `R[32] || A[32] || message` shapes at message sizes
64/200/1232, ingesting their first and final blocks without generic segmented
staging. On the Zen 4 release machine this hash-only path measured about
110.5 ns/message at 200 bytes and 390.3 ns/message at 1232 bytes. See
[`docs/SHA512_MULTIBUFFER.md`](docs/SHA512_MULTIBUFFER.md).

## Performance

The following results are from the exported `SetBackend("r51")` plus
`VerifyBatchStrict` API at implementation commit `2302d40`, on an AMD Ryzen 7
PRO 8700GE (Zen 4), one pinned core, `GOMAXPROCS=1`, valid signatures, and zero
allocations in the timed verification path. Each value is the median of ten
three-second samples in microseconds per signature. The backend was forced
explicitly and is not the automatic default. A paired diagnostic in the same
binary confirmed that the public wrapper was no more than 2% slower than the
private dispatcher core; code layout made some public rows slightly faster.

| message bytes | n=1 | n=4 | n=8 | n=64 |
| ---: | ---: | ---: | ---: | ---: |
| 64 | 26.14 | 15.05 | 14.68 | 14.38 |
| 200 | 26.28 | 15.24 | 14.81 | 14.51 |
| 1232 | 27.12 | 16.02 | 15.58 | 15.30 |

That table is the pinned PR-1 baseline. The current convergence branch promotes
the radix-32/comb256 cold core after ten-sample A/B gates showed 5.2--5.4% on
Zen 4 and 4.4--4.6% on Zen 5 at 1232 bytes. It also selects native x8 on Zen 5:
a short public-wrapper validation measured 22.50/12.76/8.55/8.27 us per
signature at n=1/4/8/64, versus 26.62/15.84/15.41/15.12 on Zen 4. These newer
rows are provisional until the full three-message release matrix is rerun;
their exact private/public deltas were below 2% and every row allocated zero.

The same 200-byte Go benchmark binary also measured the comparison libraries;
each value below is the median of six two-second samples.

| implementation | n=1 | n=4 | n=8 | n=64 |
| --- | ---: | ---: | ---: | ---: |
| Narya r51 public dispatcher, cold strict | 27.35 | 15.78 | 15.29 | 15.01 |
| Go `crypto/ed25519` loop | 36.48 | 36.60 | 36.59 | 36.68 |
| curve25519-voi, cold strict | 25.50 | 25.34 | 25.44 | 25.49 |
| curve25519-voi, pre-expanded key | 21.41 | 21.44 | 21.41 | 21.39 |

The comparison rows were measured in one Oasis-tagged binary; its different
code layout makes the Narya row about 3.5% slower than the lean release
benchmark above, so comparisons use only rows from that same executable. The
expanded-key row excludes key-expansion cost and is therefore a warm-key
comparison. Narya trails both voi rows at a cold singleton, but overtakes both
by n=3; the exact tail-width sweep is in the cross-library note. For additional
context, the same machine previously measured generic cold strict verification
at about 36.1 us/signature and the generic hot comb cache at about
16.3 us/signature. Those generic rows came from an earlier pinned run.

An independent native C harness linked against Firedancer commit
`3ed37488372b7e50bb03ca30477be48508ee7022` measured roughly
20.9/21.0/21.9 us per signature for 64/200/1232-byte messages, essentially
independent of batch width because that API verifies serially. Firedancer is
therefore still faster for a cold singleton, while forced r51 is faster for
full x4 groups. Exact rows and invalid-input caveats are recorded in
[`docs/CROSS_LIBRARY_ZEN4_2026-07-24.md`](docs/CROSS_LIBRARY_ZEN4_2026-07-24.md).

The registered r51 cold path remains arbitrary-key verification: its full SIMD
groups decode A and build the small variable-base table for every signature.
The opt-in `Cache.VerifyBatchStrict` path now has two exact-byte-bound tiers.
The first retains decoded A; a valid `DalekStrict` hit can then promote four
independent keys together to an immutable 19,424-byte entry containing the
A6/r9 warm comb. The original public-key bytes are still hashed, and strict
prechecks and final equality are unchanged. Invalid equations and inputs never
earn promotion. The first-tier threshold is eight successful sightings; group
promotion starts after eight valid hits and a stranded single key is flushed
only after 32 hits. These are conservative library defaults, not a production
traffic-policy recommendation.

At implementation commit `915fd6d`, the complete public/private Cache seam at
1232 bytes and n=64 measured, in microseconds per signature:

| CPU | raw cold | decoded/staging, 0% warm | 25% warm | 50% warm | 75% warm | 100% warm |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Ryzen 7 9700X (Zen 5) | 8.259 | 7.688 | 7.100 | 6.533 | 5.963 | 5.329 |
| Ryzen 7 PRO 8700GE (Zen 4) | 14.19 | 15.38 | 12.38 | 10.54 | 8.669 | 6.728 |

All timed rows allocated zero. Zen 5 benefits immediately from decoded A.
Zen 4 pays about 8% while admitted keys are only staging entries, then wins by
25% warm density; callers should therefore enable its Cache only for workloads
with demonstrated recurrence, such as validator-key repair or shred traffic,
not as an unconditional TPU-spam policy. The Cache is never used by raw
`VerifyBatchStrict`, and automatic backend selection remains `generic`.
HEEA remains a slower research oracle rather than a dispatch candidate. Exact
methodology and the complete n=4/8/64 matrix are in
[`docs/results/warm-comb-cache-2026-07-25/`](docs/results/warm-comb-cache-2026-07-25/).

Detailed commands, raw statistical samples, checksums, and caveats are recorded
in [`docs/results/zen4-8700ge-pr1-2026-07-25/`](docs/results/zen4-8700ge-pr1-2026-07-25/)
and summarized in
[`docs/ZEN4_8700GE_2026-07-24.md`](docs/ZEN4_8700GE_2026-07-24.md).
The reproducible standalone C driver is in
[`scripts/firedancer-compare`](scripts/firedancer-compare).

## Verification

- All five plain Ed25519 known-answer vectors from
  [RFC 8032 section 7.1](https://www.rfc-editor.org/rfc/rfc8032#section-7.1),
  914 [CCTV](https://github.com/C2SP/CCTV) `ed25519vectors`, and 133
  [Project Wycheproof](https://github.com/C2SP/wycheproof) `eddsa_test`
  vectors, plus pinned Firedancer regression vectors and a generated edge-point
  corpus.
- Differential tests anchoring every backend — cached or not, batched or single
  — to `crypto/ed25519` and to the generic backend, per profile.
- A cross-library differential against
  [curve25519-voi](https://github.com/oasisprotocol/curve25519-voi/tree/1f23a7beb09a)
  version `v0.0.0-20230904125328-1f23a7beb09a`, configured to the equivalent
  strict option set. It is isolated from the library module graph in
  `go.oasis.mod`; run it with `make test-oasis`.
- Fuzz targets comparing backends three ways.

CI runs portable tests on `ubuntu-latest` and `macos-latest`, the isolated
Oasis differential on Linux, plus a pinned
[Intel SDE](https://www.intel.com/content/www/us/en/developer/articles/tool/software-development-emulator.html)
10.8 job that emulates Ice Lake Server and executes focused r51x5 IFMA,
native-SHA, and public forced-r51 differentials. Dedicated `sde_gate` tests
fail rather than skip when the emulated feature set is missing. SDE is
functional coverage only; the Ryzen 7 PRO 8700GE remains the performance and
zero-allocation release authority. Automatic backend selection remains
`generic`.

## Status

Alpha. The `generic` backend, the profile contract, and the per-key comb cache
are functional and differential-tested. The `r51` throughput backend is
registered for explicit selection on supported hardware but remains outside
automatic dispatch. It uses the promoted two-x4 cold comb on Zen 4 and native
x8 groups plus x4 tails on AMD family 1Ah (Zen 5). Its opt-in two-tier Cache
and width-aware A6/r9 warm promotion are implemented and hardware-tested; the
traffic-specific admission and eviction policy remains integration work. The
`ifma` reference backend and alternate arithmetic experiments remain under
active development.

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
orientation — one point's coordinates across vector lanes — is prior art that
Narya did not originate: dalek's AVX2 backend is a documented implementation,
and Firedancer's `r43x6` QUAD packing, which `internal/r43x6` credits, is the
same idea at AVX-512 width. Narya's experimental
coordinate-parallel work uses that orientation at radix 2^51. See
[NOTICE](NOTICE).
