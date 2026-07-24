# Narya — review notes / PR description

> Consensus-exact, accelerated Ed25519 verification for a Go Solana node.
> Alpha. This branch is up for review; the AVX-512 kernels are staged but
> not yet landed (see TODO).

## Why

Mithril (a Go Solana verifying full node) is bottlenecked on Ed25519
transaction signature verification when replaying large blocks. The
verification is on the hot path of block replay, and it must be
**consensus-exact**: a single accept/reject that disagrees with mainnet is
a fork. Narya is a standalone library (no cgo) that provides that
verification with room for an AVX-512 fast path, so the acceleration work
lives outside the node and can be reviewed, fuzzed, and versioned on its
own.

## What this is

Two packages:

- **`ed25519`** — `Verify`, `VerifyStrict`, `VerifyBatch`, `Precompute`,
  and a `Cache` for per-key acceleration. Runtime-selected backends behind
  one API.
- **`sha512mb`** — multi-buffer SHA-512. Digests are bit-identical to
  `crypto/sha512`; the batch API exists so a vector kernel can hash
  `Lanes()` messages at once. Currently a scalar fallback (correct
  everywhere); the AVX-512 kernel is staged.

## Acceptance semantics (the load-bearing part)

Verification enforces a versioned **`Profile`**, because the
consensus-correct predicate is itself versioned:

- **`DalekStrict`** (default) — current Solana mainnet transaction
  semantics: `ed25519-dalek` 2.x `verify_strict`, reached through the
  `solana-signature` crate. This is `crypto/ed25519.Verify` **plus**
  rejection of small-order public keys A and small-order signature points
  R. The standard library accepts those (it never decodes R); a verifying
  node built on the stdlib alone could be forked off the network by a
  crafted block, which is why strict is the default.
- **`StdlibCompat`** — exactly `crypto/ed25519.Verify`, for differential
  testing and callers that explicitly want standard-library behavior.
- `VerifyStrict(pub, msg, sig []byte)` always enforces `DalekStrict`
  regardless of the mutable default — for consensus P2P call sites that
  must not depend on global state.

The small-order test decodes exactly as dalek does (permissive,
non-canonical accepted) and checks `[8]P == identity`, matching
`EdwardsPoint::is_small_order`. A future `ZIP215` profile is reserved for
Solana's staged SIMD-0376 loosening (cofactored), which will be a
slot-gated change on mainnet.

Narya never uses random-coefficient (cofactored) batch verification: its
aggregate equation can accept adversarial signatures that per-signature
verification rejects. "Batch" here means amortized hashing, paired
decoding, and parallelism with **per-signature** verdicts.

## Architecture

- **Backends**, one active per process (so a `Cache` never mixes table
  formats), selected at runtime — never inferred from `GOAMD64`:
  - `generic` — pure Go over the vendored `crypto/ed25519` internals
    (BSD; see `NOTICE`), with per-key fixed-base comb tables that remove
    the doubling chain for recurring signers. **Implemented.**
  - `ifma` — AVX-512 IFMA point arithmetic after Firedancer's `r43x6`
    representation. **Staged (TODO).** Target hardware is Zen 5+ (native
    512-bit datapath), so there is deliberately no Zen 4-specific or AVX2
    intermediate tier — dispatch is binary: IFMA vs the pure-Go fallback.
  - `stdlib` — routes to `crypto/ed25519`; the rollback proof point.
- No cgo anywhere. The AVX-512 kernels will be Go assembly
  (avo-generated), gated on `x/sys/cpu` feature detection, with the
  pure-Go path as the fallback for non-AVX-512 hosts (ARM dev machines,
  CI correctness).

## Status

| Piece | State |
|---|---|
| `generic` backend + comb cache | done |
| Profiles + `VerifyStrict` + small-order rejection | done |
| `VerifyBatch` pipeline (per-signature verdicts) | done (scalar hashing) |
| Differential test corpus (CCTV 914, Wycheproof 133, fuzz) | done |
| `sha512mb` 8-lane AVX-512 kernel | TODO |
| `ifma` r43x6 field/point kernels + backend | TODO |
| Per-key comb tables in IFMA layout | TODO |

## Testing

The invariant under test everywhere: for every input — non-canonical
encodings, small-order points, malformed signatures — every backend,
cached or not, batched or single, returns exactly what the active
profile's predicate returns. Enforced by:

- Differential tests vs `crypto/ed25519.Verify` (random + edge corpus),
  profile-aware.
- The CCTV (914) and Wycheproof (133) vector corpora, asserting agreement
  with the standard library — the 165 CCTV vectors where the profiles
  differ are exactly the small-order set, cross-checked against
  Firedancer's independent verdict.
- Fuzz targets (three-way: stdlib vs generic vs cached vs batch; sha512mb
  vs `crypto/sha512`).

## Reviewer focus

- The `DalekStrict` predicate equivalence to `verify_strict` (see
  `ed25519.go` / `profile.go`), and the argument that `stdlib_accept AND
  !smallOrder(A) AND !smallOrder(R)` is exactly `verify_strict` (dalek's
  "R must decode" clause is implied by the byte-compare).
- The one-active-backend invariant and `Cache` concurrency.
- That `VerifyStrict` can never be weakened by a global profile flip.

---

# TODO / follow-ups (for reviewers)

These are tracked here so they get separate eyes; several are Mithril-side
changes, not narya.

## 1. ed25519 precompile non-strict else-branch (Mithril) — consensus, get a second reviewer

**Separate consensus review requested.** During the sigverify audit we
found a latent consensus-divergence in Mithril's ed25519 precompile
(`pkg/sealevel/ed25519_program.go`), which branches on the
`Ed25519PrecompileVerifyStrict` feature (SIMD-0152).

- The **strict** branch (feature active = current mainnet) is **correct** —
  it matches dalek 1.0.1 `verify_strict` for all feasible inputs (0
  mismatches over the 768-vector "Taming the many EdDSAs" corpus; the only
  theoretical divergence requires solving a discrete log). **Do not
  change it.**
- The **non-strict else branch** (curve25519-voi default `Verify`) is used
  only when replaying slots before SIMD-0152 activation (mainnet slot
  308,880,000, ~Dec 2024). It **diverges** from Agave's actual
  pre-activation behavior (dalek 1.0.1 non-strict `verify()`): voi default
  is **cofactored** and **rejects small-order A**, whereas dalek `verify()`
  is **cofactorless** and **accepts small-order A** (238/768 corpus
  mismatches, both directions).
- **Reachability:** dead code for live forward-following (a node bootstraps
  from a recent post-activation snapshot, so the strict branch is always
  taken — **zero risk today**). But reachable for **historical replay** of
  pre-activation slots (a roadmapped archival feature; the explicit
  `--snapshot` path has no age/lower-bound guard). If a pre-activation
  mainnet block ever contained a small-order-A or cofactor-torsion
  precompile instruction, replaying it would flip the outcome → bank-hash
  mismatch. Whether such a block exists is an empirical unknown (needs an
  archival-ledger scan we haven't run).

**Proposed fix (staged, NOT applied — wants a consensus engineer's sign-off):**
change the else branch to `VerifyWithOptions` with the dalek-`verify()`
predicate:

```go
ed25519.VerifyOptions{
    AllowSmallOrderA:   true,
    AllowSmallOrderR:   true,
    AllowNonCanonicalA: true,
    AllowNonCanonicalR: false, // byte-compare inherently rejects non-canonical R
    CofactorlessVerify: true,
}
```

Confidence is high on the target predicate: dalek 1.0.1 non-strict
`verify()` is **exactly** `crypto/ed25519.Verify`, which is exactly narya's
`StdlibCompat` profile (already differentially tested over 1000+ vectors).
The fix should ship with a differential test (voi-with-these-options vs
`crypto/ed25519.Verify` over the corpus) **before** historical replay
ships. Alternative stopgap: hard-gate historical replay of pre-SIMD-0152
slots as unsupported until the fix lands.

## 2. Mithril P2P strict-verify fix (separate branch)

The gossip / shred / repair verification sites were on the standard
library (accepting the same small-order class mainnet rejects). Fixed on a
separate Mithril branch by routing all of them through `VerifyStrict`, with
tests including the rigorous repair-path divergence proof. That branch
depends on this library.

## 3. Replay transaction sigverify integration

Wire the batch verifier into Mithril's replay sigverify pool and the
turbine transaction-verifier seam. Not in this branch.

## 4. AVX-512 kernels

`sha512mb` 8-lane and the `ifma` r43x6 backend (Go assembly, Zen 5 target).
Each lands behind runtime dispatch with the pure-Go fallback, gated by a
differential-fuzz harness that runs all backends against each other and the
standard library.

## 5. Performance-roadmap note (Alpenglow)

The per-key comb cache assumes recurring signers. On Alpenglow, votes are
BLS certificates (a separate path), not Ed25519 transactions — so replay
sigverify sees non-vote user traffic with more diverse fee-payers, and the
comb cache's value drops from "headline" to "opportunistic." Multi-buffer
SHA-512 (recurrence-independent) and a from-scratch batch verifier become
the core wins. Benchmarks must use an Alpenglow-shaped block corpus
(diverse keys, larger messages), not replayed vote-heavy history.

## 6. Before merge

- Replace the local dev `replace` directive in the consuming module with a
  proper version pin/tag of this library.
- Name / collision check for the module path.
