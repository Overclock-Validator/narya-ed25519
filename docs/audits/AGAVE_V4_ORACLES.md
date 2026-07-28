# Agave v4 Ed25519 compatibility oracles

## Scope

Narya targets Agave v4 transaction signature verification and the Alpenglow
integration branches that consume that predicate. It does not infer consensus
semantics from whichever `ed25519-dalek` release happens to be newest.

The pinned reference is Agave's `v4.0` branch at
[`v4.0.0-rc.0` / `8e3bcf0ccf43de6fe236a58f04b410f56e233ab4`](https://github.com/anza-xyz/agave/tree/8e3bcf0ccf43de6fe236a58f04b410f56e233ab4).
That lockfile contains two dalek majors for two different call paths:

| Agave v4 path | Public call | Resolved dependency | Narya role |
| --- | --- | --- | --- |
| transaction sigverify | `solana_signature::Signature::verify` | `solana-signature 3.3.0` → `ed25519-dalek 2.2.0` | `DalekStrict` consensus contract |
| Ed25519 precompile | `PublicKey::verify_strict` | direct `ed25519-dalek 1.0.1` | separate compatibility oracle |

The distinction is load-bearing. A lockfile search showing both `1.0.1` and
`2.2.0` does not identify which verifier a call site reaches. The dependency
edge and the call site must be recorded together.

## Alpenglow integration boundary

The Mithril Alpenglow branches are consumers, not a third cryptographic
specification. Their transaction, gossip, repair, and shred verification call
sites must eventually route to Narya `DalekStrict` when Narya is integrated.
Their feature-gated Ed25519 precompile remains a distinct surface and must be
checked against the v4 precompile oracle rather than assumed equivalent from
the profile name alone.

The branch snapshots inspected for this boundary were:

- `Overclock-Validator/mithril` `alpenglow-dev` at
  `705faabfe1104b103478c08f0ed8cd2f6d00f8c0`;
- `Overclock-Validator/mithril` `7layer/alpenglow-dev-consensus-integration`
  at `2596f3ae875cd5a897187985b0da5a164009acb2`.

No Mithril code is changed by the oracle harness.

## Executable evidence

[`contrib/agave-v4-oracle`](../../contrib/agave-v4-oracle) is a standalone
Rust program with exact dependency pins for both v4 paths. It is deliberately
outside the Go module and introduces no Rust, cgo, or dalek runtime dependency
into Narya.

[`scripts/check-agave-v4-oracles.sh`](../../scripts/check-agave-v4-oracles.sh)
does the following:

1. exports the committed RFC 8032, CCTV, and Wycheproof cases from the Go test
   package;
2. adds all fourteen small-order encodings as both `A` and `R`, every one-byte
   near mutation used by the classifier agreement test, all `p..p+18`
   non-canonical `y` encodings with both sign bits, and scalar boundaries;
3. evaluates the transaction path through `solana-signature 3.3.0`;
4. evaluates the precompile path through `ed25519-dalek 1.0.1`;
5. requires every transaction verdict to equal Narya's independent generic
   `DalekStrict` oracle and reports any precompile/transaction differences.

Run it with:

```sh
rustup toolchain install 1.89.0 --profile minimal
./scripts/check-agave-v4-oracles.sh
```

The first recorded run evaluated 2,954 cases with zero transaction/Narya
mismatches and zero precompile/transaction differences. This proves agreement
over the stated corpus, not universal equivalence of the two dalek majors.
Future dependency or predicate changes must rerun the harness and extend the
corpus when a new boundary is discovered.
