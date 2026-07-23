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

For every input — including non-canonical point encodings, small-order
points, and malformed signatures — every backend, cached or not,
returns exactly what `crypto/ed25519.Verify` returns. In consensus use
an accept/reject flip is a fork, so this equality is enforced by
differential tests, edge-case corpora, and fuzzing rather than assumed.
Notably this contract is *weaker* than RFC 8032 strictness and *not*
batch verification: random-coefficient batch equations (cofactored)
can accept adversarial signatures that per-signature verification
rejects, so Narya never uses them.

## Status

Alpha. The `generic` backend and per-key comb cache are functional and
differential-tested; `ifma` and the vectorized `sha512mb` kernel are
under active development.

## License

Apache-2.0. See [NOTICE](NOTICE) for attributions: vendored Go /
filippo.io edwards25519 code (BSD-3-Clause), and the Firedancer
lineage (Apache-2.0, itself building on OpenSSL) of the IFMA design.
