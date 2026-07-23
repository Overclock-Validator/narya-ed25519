# Narya — fast Ed25519 verification for Go

Narya verifies Ed25519 signatures with acceptance behavior
**bit-identical to `crypto/ed25519.Verify`**, built for workloads that
verify at consensus scale: Solana block replay, where large blocks
carry tens of thousands of signatures and most of them come from a
stable set of hot signers.

> Narya is Gandalf's ring — the Ring of Fire. The name nods to
> [Firedancer](https://github.com/firedancer-io/firedancer), whose
> AVX-512 `r43x6` design the IFMA backend ports, and to
> [Mithril](https://github.com/Overclock-Validator/mithril), the Go
> Solana node this library was built for.

## Packages

- **`ed25519`** — drop-in verification (`Verify`, `Cache`,
  `Precompute`) with runtime-selected backends:
  - `generic` — pure Go over the vendored `crypto/ed25519` internals,
    with per-key fixed-base comb tables for recurring signers
    (~2× stdlib on hot keys);
  - `ifma` — AVX-512 IFMA point arithmetic after Firedancer's r43x6
    representation (amd64 with AVX512-IFMA, i.e. Intel Ice Lake or
    AMD Zen 4 and newer; in development);
  - `stdlib` — routes to `crypto/ed25519`, the rollback proof point.
- **`sha512mb`** — multi-buffer SHA-512: `Lanes()` messages hashed in
  parallel by an AVX-512 kernel (in development); degrades to
  `crypto/sha512` everywhere else.

## The contract

Verification enforces one of two versioned **profiles**, because the
consensus-correct acceptance predicate is itself versioned — an
accept/reject flip is a fork, so it is a deliberate choice, not an
implementation detail:

- **`DalekStrict`** (default) — current Solana mainnet transaction
  semantics: `ed25519-dalek` 2.x `verify_strict`, reached through the
  `solana-signature` crate. This is `crypto/ed25519.Verify` **plus**
  rejection of small-order public keys A and small-order signature
  points R. The standard library accepts those (it never decodes R); a
  verifying node that used it unmodified could be forked off the
  network by a crafted block, so this is the default.
- **`StdlibCompat`** — exactly `crypto/ed25519.Verify`, for
  differential testing and callers who explicitly want standard-library
  behavior.

For every input — non-canonical encodings, small-order points,
malformed signatures — every backend, cached or not, batched or single,
returns exactly what the active profile's predicate returns. This is
enforced by differential tests, the CCTV and Wycheproof corpora, and
fuzzing rather than assumed; the 165 CCTV vectors where the two profiles
differ are precisely the small-order set, cross-checked against
Firedancer's independent verdict.

Narya never uses random-coefficient (cofactored) batch verification:
its aggregate equation can accept adversarial signatures that
per-signature verification rejects. "Batch" here means amortized
hashing, paired decoding, and parallelism with per-signature verdicts.
A future `ZIP215` profile will track Solana's planned SIMD-0376
loosening once its feature gate activates on mainnet.

## Status

Alpha. The `generic` backend and per-key comb cache are functional and
differential-tested; `ifma` and the vectorized `sha512mb` kernel are
under active development.

## License

Apache-2.0. See [NOTICE](NOTICE) for attributions: vendored Go /
filippo.io edwards25519 code (BSD-3-Clause), and the Firedancer
lineage (Apache-2.0, itself building on OpenSSL) of the IFMA design.
