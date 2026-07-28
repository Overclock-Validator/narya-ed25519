# Agave v4 Ed25519 oracle differential — 2026-07-27

## Question

Does Narya `DalekStrict` agree with the exact Ed25519 transaction-verification
dependency stack on Agave's `v4.0` branch, and what does the branch's separate
dalek-1.0.1 precompile path do over the same boundary corpus?

## Pinned references

- Narya: `3f56e4f266d8874d615f720e0f4d62d32e64322f`
- Agave `v4.0`: `8e3bcf0ccf43de6fe236a58f04b410f56e233ab4`
  (`v4.0.0-rc.0`)
- transaction: `solana-signature 3.3.0` → `ed25519-dalek 2.2.0`
- precompile: direct `ed25519-dalek 1.0.1`

## Verdict

The cross-language run evaluated 2,954 RFC 8032, CCTV, Wycheproof, torsion,
non-canonical-field, near-mutation, and scalar-boundary inputs.

- Agave v4 transaction versus Narya `DalekStrict`: **0 mismatches**
- Agave v4 precompile versus transaction: **0 differences in this corpus**

The second result is corpus evidence, not a universal-equivalence claim about
the two dalek majors. The paths remain separately pinned and separately named.
