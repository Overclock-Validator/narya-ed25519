# Agave v4 Ed25519 oracles

This standalone Rust program pins the two Ed25519 verification dependency
paths present on Agave's `v4.0` branch:

- transaction verification: `solana-signature = 3.3.0`, resolving
  `ed25519-dalek = 2.2.0`;
- Ed25519 precompile verification: direct `ed25519-dalek = 1.0.1`.

It is a test tool only. It introduces no Rust, cgo, or dalek dependency into
the Go library. See [`docs/audits/AGAVE_V4_ORACLES.md`](../../docs/audits/AGAVE_V4_ORACLES.md)
for the pinned Agave commit and call paths.

Run the full differential from the repository root:

```sh
./scripts/check-agave-v4-oracles.sh
```

The script uses Rust 1.89.0, matching the Rust generation used by Agave v4.
Install it once with `rustup toolchain install 1.89.0 --profile minimal`.

The transaction verdict is required to match Narya `DalekStrict` for every
exported RFC 8032, CCTV, Wycheproof, torsion, canonicality, and scalar-boundary
case. The precompile verdict is reported independently because it is a
different Agave v4 dependency path and is not Narya's transaction contract.
