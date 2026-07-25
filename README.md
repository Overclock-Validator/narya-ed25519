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
for every signature and is the dispatch surface for future parallel hashing
and paired decoding. The currently selectable production backends still hash
and decode each item independently.
A future `ZIP215` profile will track Solana's proposed
[SIMD-0376](https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0376-verify-strict.md)
loosening only after it is accepted and its feature gate activates on mainnet.
The existence of a ZIP-215 implementation is not itself an activation signal.

**Narya has no signing API, deliberately.** It cannot be misused in the way
catalogued by
[ed25519-unsafe-libs](https://github.com/MystenLabs/ed25519-unsafe-libs),
because it never accepts a caller-supplied private/public key pair.

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
| `generic` | **default** | Pure Go over the vendored `edwards25519` internals, with per-key fixed-base comb tables for recurring signers. The only backend supporting precomputation. |
| `stdlib` | available | Routes to `crypto/ed25519`. The rollback proof point. |
| `ifma` | opt-in, in development | AVX-512 IFMA point arithmetic after Firedancer's `r43x6` representation. Requires AVX512F/VL/DQ/BW/IFMA/VBMI, detected at runtime via `x/sys/cpu` — never via `GOAMD64`, since `x86-64-v4` does not imply IFMA. |

Selection is deliberately non-degrading: an unknown backend name, or `ifma` on
a CPU without IFMA, is an error from `SetBackend` and a panic on the
environment-variable path. A forced name represents explicit operator intent
and must not silently fall back.

`sha512mb`'s AVX2 and AVX-512 kernels are present and tested but **not yet
wired into production dispatch** — `Lanes()` currently reports 1 and
`Sum512Batch` loops `crypto/sha512`. The vector kernels are reachable only
through the `Experimental*` entry points.

## Performance

Ryzen 7 PRO 8700GE (Zen 4), 200-byte messages, zero allocations in the timed
path. Numbers move with message size and batch width, so read these as shape
rather than as a single figure of merit.

| path | µs/signature | status |
| --- | ---: | --- |
| `crypto/ed25519` loop | ~36.6 | baseline |
| `generic`, cold key, `DalekStrict` | slower than stdlib | performs strictly more work |
| `generic`, hot key (comb cache) | ~24.6 | **shipping** |
| `r51` batch-Q, n=64 | ~15.5 | experimental; not reachable from a registered backend |

Two things this table says plainly:

1. **On a cold arbitrary key, `DalekStrict` is slower than the standard
   library**, because it performs the small-order checks the standard library
   omits. The shipping speed win is on recurring signers.
2. **The large speedups live in an experimental tier no registered backend can
   reach.** `internal/r51x5` is compiled and tested but has no backend adapter;
   `internal/heea8l` is not in the non-test build at all. Neither is part of the
   supported surface, and neither should be assumed in capacity planning.

## Verification

- 914 [CCTV](https://github.com/C2SP/CCTV) `ed25519vectors` and 133
  [Project Wycheproof](https://github.com/google/wycheproof) `eddsa_test`
  vectors, plus Firedancer regression vectors and a generated edge-point corpus.
- Differential tests anchoring every backend — cached or not, batched or single
  — to `crypto/ed25519` and to the generic backend, per profile.
- A cross-library differential against
  [curve25519-voi](https://github.com/oasisprotocol/curve25519-voi) configured
  to the equivalent strict option set.
- Fuzz targets comparing backends three ways.

**Known gap.** CI runs on `ubuntu-latest` and `macos-latest`, neither of which
has AVX512-IFMA. On those hosts the IFMA paths short-circuit on feature
detection, so a green run does **not** execute the SIMD kernels. An Intel SDE
job and an IFMA-capable runner are prerequisites for registering any SIMD tier
as a production backend.

## Status

Alpha. The `generic` backend, the profile contract, and the per-key comb cache
are functional and differential-tested. The `ifma` backend, the vectorized
`sha512mb` kernels, and the `r51` throughput tier are under active development
and are not selected by default.

## License

Apache-2.0. See [NOTICE](NOTICE) for the full attribution list.

**Vendored code.** `internal/edwards25519` and `internal/edwards25519/field`
derive from the Go standard library's `crypto/internal/edwards25519` and from
`filippo.io/edwards25519` v1.0.0 (BSD-3-Clause); the upstream LICENSE files are
preserved in those directories. Narya has **modified** files in that tree —
notably `field/fe.go` (square-root-ratio derivation) and `scalarmult.go`
(leading-zero skip) — and has added first-party files there. Narya-authored
files inside the vendored tree are Apache-2.0.

**Derived work.** The `r43x6` AVX-512 IFMA design and the constants in
`internal/r43x6` follow
[Firedancer](https://github.com/firedancer-io/firedancer), Copyright 2022
Firedancer Contributors, Apache-2.0. Firedancer's Ed25519 implementation is in
turn based on the OpenSSL project's Ed25519 implementation (Apache-2.0).

**Prior work this library descends from.** The generic backend, the per-key
comb cache, and `internal/edwards25519/comb.go` originate in `pkg/ed25519fast`
in [Mithril](https://github.com/Overclock-Validator/mithril), authored by
palmer.

**Specifications and reference implementations.** The acceptance predicate is
that of [ed25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek)
`verify_strict`, as reached by [Agave](https://github.com/anza-xyz/agave)
(Anza) through the `solana-signature` crate; Agave is the reference narya's
verdict must match. The reserved `ZIP215` profile name is from Zcash's
[ZIP 215](https://zips.z.cash/zip-0215). `sha512mb` implements FIPS 180-4. The
square-root-ratio derivation used in `field/fe.go` and `internal/r43x6` follows
[BoringSSL](https://boringssl.googlesource.com/boringssl/).

**Test corpora.** The CCTV `ed25519vectors` corpus is redistributed under
BSD-3-Clause, Copyright 2019 Google LLC and Copyright 2022 Filippo Valsorda;
its license text is reproduced in full in [NOTICE](NOTICE) as that license
requires. Project Wycheproof vectors are redistributed under Apache-2.0,
Copyright Google LLC.

**Comparison and prior art.**
[curve25519-voi](https://github.com/oasisprotocol/curve25519-voi) (Oasis
Protocol, BSD-3-Clause) serves as a cross-library differential oracle and
performance baseline. Narya does **not** implement its ABGLSV–Pornin cofactored
algorithm, which is incompatible with the strict predicate.

voi is itself largely derived from
[curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek), and
the vectorized Edwards backend that produces its uncached single-signature
timings is a Go port of dalek's AVX2 backend (Copyright isis agora lovecruft,
Henry de Valence, and Oasis Labs), selected whenever AVX2 is present. Narya's
own coordinate-parallel work reaches the same intra-signature orientation
independently, from Firedancer's `r43x6` and at radix 2^51 on AVX-512 IFMA. See
[NOTICE](NOTICE): credit for that architectural idea belongs to the dalek
authors, not to voi.
