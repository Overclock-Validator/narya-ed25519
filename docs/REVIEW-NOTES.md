# Narya — review notes / PR description

> Consensus-exact, accelerated Ed25519 verification for a Go Solana node.
> Alpha. This branch is up for review. The Zen 4/Zen 5 r51 composition is
> registered for explicit selection; automatic dispatch remains generic. Its
> opt-in Cache can promote recurring valid strict keys to the warm A6/r9 comb.
> The r43 reference and HEEA variants remain forced experiments.

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
  `crypto/sha512`. The public `Lanes`/`Sum512Batch` API remains scalar and
  portable; hardware-gated AVX2 x4 and AVX-512F x8 entry points are present.
  The explicitly forced r51 verifier consumes the x4 entry point internally.

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

The production strict pre-pass classifies the exact seven low-255-bit values
that the permissive decoder maps into the small torsion subgroup. Tests retain
permissive decode plus `[8]P == identity` as an independent mathematical
oracle. A future `ZIP215` profile is reserved for Solana's proposed
[SIMD-0376 at `b13be70`](https://github.com/solana-foundation/solana-improvement-documents/blob/b13be70e7454144becbe9c474b296d737d72df98/proposals/0376-verify-strict.md)
loosening (cofactored). The proposal currently has no assigned feature; any
accepted rollout must be slot-gated rather than inferred from library
availability.

Narya never uses random-coefficient (cofactored) batch verification: its
aggregate equation can accept adversarial signatures that per-signature
verification rejects. "Batch" is a per-signature-verdict dispatch surface.
The default generic backend processes items independently. The forced r51
backend uses lane-parallel hashing and decoding while retaining independent
verdicts.

## Architecture

- **Backends**, one active per process (so a `Cache` never mixes table
  formats), selected at runtime — never inferred from `GOAMD64`:
  - `generic` — pure Go over the vendored `crypto/ed25519` internals
    (BSD; see `NOTICE`), with per-key fixed-base comb tables that remove
    the doubling chain for recurring signers. **Implemented.**
  - `ifma` — a forced-only AVX-512 IFMA correctness backend after
    Firedancer's `r43x6` representation. The first field kernel and complete
    scalar reference verifier are implemented and have executed on Zen 4; its
    performance does not displace the selected r51 path. Automatic selection
    deliberately remains `generic`.
  - `r51` — a registered, forced-only five-limb lane-per-signature AMD
    backend. It uses a packed singleton, x4 batch-Q groups on Zen 4, and native
    x8 groups plus x4 tails on Zen 5. Its optional Cache promotes four recurring
    strict keys together to immutable warm A6/r9 tables while preserving the
    native SIMD width. Automatic selection remains generic. Alternate-radix
    configurations remain benchmark candidates. See
    `docs/R51_THROUGHPUT_BACKEND.md`.
  - `stdlib` — routes to `crypto/ed25519`; the rollback proof point.
- No cgo anywhere. The current AVX-512 primitives are Go assembly, gated on
  `x/sys/cpu` feature detection, with the
  pure-Go path as the fallback for non-AVX-512 hosts (ARM dev machines,
  CI correctness).

## Status

| Piece | State |
|---|---|
| `generic` backend + comb cache | done |
| Profiles + `VerifyStrict` + small-order rejection | done |
| `VerifyBatch` pipeline (per-signature verdicts) | done; forced r51 uses native x4 hashing |
| Differential test corpus (RFC 8032, CCTV 914, Wycheproof 133, Firedancer regressions, fuzz) | done |
| `sha512mb` AVX2 x4 / AVX-512F x8 kernels | hardware-tested; x4 consumed by forced r51, public hash dispatch remains scalar |
| forced-only `ifma` r43x6 reference backend | implemented and hardware-tested; not automatic |
| registered r51 cold backend | done for explicit Zen 4/Zen 5 selection; packed singleton plus width-specific batch-Q dispatcher |
| exact modulo-8L HEEA selector/QSM | research-only; ordinary r51 remains selected |
| r51 x8 plus radix-32/comb256 cold schedule | promoted inside forced `r51`; CPUID selects x8 on measured AMD family 19h+ IFMA parts, with x4 retained for tails and unknown CPUs |
| r51 variable-base tables | small cold table rebuilt per verification; opt-in Cache admits exact-byte-bound decoded A and promotes valid strict hits to a 19,424-byte A6/r9 warm entry on Zen 4 and Zen 5 |
| Exact Mithril trace cache timing | strict schema-v3 serialized generic-cache diagnostic implemented; representative artifact and backend-native r51/end-to-end gates pending |

The branch is an audit candidate, not a release tag. After review findings are
resolved and the reviewed commit is merged, that merge commit is the intended
`v0.1.0` tag target. Do not tag the mutable audit branch or infer release
authorization from a passing emulator job.

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

The registered r51 dispatcher's core is measured at all batch widths. PR 1's
external-package release benchmark forces it through `SetBackend("r51")` and
calls only exported `VerifyBatchStrict`; the public result must be no more than
2% slower than the core. On the Ryzen 7 PRO 8700GE it uses packed verification
at n=1/2 and x4 groups plus exact tails for wider batches. Future r43, x8,
warm-cache, and HEEA changes must beat the final registered public-dispatch
baseline rather than an older private-pipeline denominator.

`scripts/zen4-evaluate.py RESULT_DIR --decision-output decision-v1.json`
writes a mode-0600, versioned decision artifact inside the result bundle. The
artifact binds the benchmark configuration, exact source-tree manifest,
recorded/current Git HEAD when observable, and every consumed benchmark file
by SHA-256. It records the r43 decision, selected ordinary r51 batch
configuration, optional HEEA path, measurement authority, and individual
micro-gate results. The evaluator is intentionally incapable of authorizing
production: `production_promotable` is always `false`, and the artifact keeps
statistical significance, dense tails, Mithril replay, backend-native cache
trace evidence, and reviewed release-source authority explicitly pending.
Passing point-estimate microbenchmarks is therefore evidence for a later
release decision, never that decision itself.

## Reviewer focus

- The `DalekStrict` predicate equivalence to `verify_strict` (see
  `ed25519.go` / `profile.go`), and the argument that `stdlib_accept AND
  !smallOrder(A) AND !smallOrder(R)` is exactly `verify_strict` (dalek's
  "R must decode" clause is implied by the byte-compare).
- The independent canonical-R gate, original-byte challenge hash, and both
  projective cross-products in the packed singleton; the batch-Q path must
  remain equivalent to literal `Encode(Q) == original Rbytes`.
- Every IFMA input/range and alias contract, including atomic output on native
  errors and the generic recomputation plus `InternalFaultFallbacks` signal.
- Synchronous CPU activation: forced r51 requires the complete IFMA feature
  set and the AVX2 x4 SHA kernel, while an unsupported force fails rather than
  silently selecting another backend.
- The main module graph contains no Oasis dependency. The pinned voi oracle is
  reachable only with `go.oasis.mod` plus the `oasis_compare` test tag.
- The one-active-backend invariant and `Cache` concurrency.
- Cache promotion atomicity and byte accounting: only valid strict hits may
  promote; replacement entries are immutable; build failure preserves the
  decoded entry; Zen 5 must not fragment one native x8 group into half-warm
  x4 work.
- That `VerifyStrict` can never be weakened by a global profile flip.

## Saved convergence audit — 2026-07-25

Claude's static review of the 20 commits after `89cb0ea` is retained as a
review checkpoint. It was performed without a Ryzen hardware run. The findings
remain useful, but their disposition matters because the branch changed while
the review was being written:

| finding | disposition |
|---|---|
| SHA-512 x8 assembly clobbered the Go frame pointer through `BP` | fixed in `c033896` by using `R12`; cross-compiled linux/amd64 `go vet ./...` passes |
| native x8 SHA gate omitted AVX-512VL despite EVEX.256 loads | fixed in `c033896`; the gate now requires F, VL, and BW |
| an r51 `StdlibCompat` singleton/tail could pass a nil public key directly to the generic backend | fixed fail-closed in `c033896`, with direct tests for both profiles before hardware activation |
| `detectAMDZen4OrNewer` also matched family-19h Zen 3 | renamed to describe family 19h-or-newer and kept subordinate to the IFMA capability gate in `c033896` |
| one wide-IFMA predicate controlled x8 width, decoded-A, and warm-cache policy | split into independent policy predicates in `c033896` |
| promoted micro-AoS coverage lacked explicit random mixed-order and pure-torsion bases | added in `c033896`, including all eight pure torsion points |
| predicted micro-AoS out-of-bounds read | refuted: the exact 160-byte record uses five 32-byte loads at offsets 0, 32, 64, 96, and 128 |
| transpose, direct-output aliasing, formulas, and workspace reuse | independently traced and accepted by the static review |

The review's closing statement that runtime sign handling still consisted of a
40-iteration swap plus conditional negate became stale before handoff. Commit
`997d9b9` stores both signed Niels forms, removed that runtime negation, and
reduced the exported Zen 5 n=64/msg=1232 path from about 6.404 to 6.072
microseconds per signature. In the post-change profile the whole selector is
about 1.8% cumulative and its transpose about 1.1% flat. Selector-to-first-
multiply fusion is therefore preserved as a possible later experiment, not an
open release requirement; reopen it only if a new profile makes selection
material again or an exact prototype clears the complete-verifier keep gate.

Commit `ef7bdc7` added a private raw-singleton seam for the complete packed
strict verifier. It removed a redundant generic profile/interface traversal
from exported `VerifyStrict`; the Zen 4 public gate fell from about 19.60 to
17.46 microseconds at 1232 bytes and remained within 0.6% of batch-of-one at
200, 1232, and 4096 bytes. The follow-up default-profile route applies the
same seam only while `DefaultProfile() == DalekStrict`; `StdlibCompat` and all
non-r51 backends retain the shared predicate path. A deliberately forced
non-inlined helper was rejected because it recreated the old overhead.

This section is a regime-tagged record, not a claim that static review replaces
the required Zen 4/Zen 5 native tests.

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

Keep two distinct arithmetic tracks: r43x6 as a correctness/latency reference
and 5x51 transposed x4/x8 arithmetic for throughput. The latter has independent
scalar x4/x8 field and point models, real ZMM/YMM IFMA multiplication kernels,
composable u52 point operations, paired decompression, regular
radix-16/radix-32/radix-64 ordinary variable-base tables, exact signed DSM/QSM,
native x4/x8 SHA-512, and a complete forced verifier. Fixed IFMA table and
workspace storage is now physically specialized to 8/16/32 positive entries;
smaller radices neither retain nor clear radix-64 capacity. Radix 64 is measured
only for the ordinary DSM; HEEA retains radix 16/32. The selected packed
singleton plus radix-32/comb256 batch-Q composition is registered as forced
backend `r51`. Measured Zen 4 and Zen 5 parts use x8 for complete groups and
x4 for the tail. Alternative arithmetic and HEEA
configurations remain private. Automatic dispatch remains generic.

The optional HEEA handoff preserves arbitrary-width signed coefficients for
mixed-order A/R points and has an allocation-free modulo-8L selector. On the
M4 development host, profile-directed fixed-width improvements reduced the
selector from roughly 130--138 microseconds to 63--65 microseconds, but that is
still slower than a complete verification. It remains research-only until the
selector plus QSM clears the complete-verifier gate. Published results from
other verifiers adjust which candidates we benchmark; they do not establish
Narya's predicate or release performance.

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
