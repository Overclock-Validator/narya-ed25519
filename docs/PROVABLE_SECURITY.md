# What the Ed25519 security proofs do—and do not—say about Narya

The primary reference for this note is Brendel, Cremers, Jackson, and Zhao,
[*The Provable Security of Ed25519: Theory and Practice*][paper], IEEE
Symposium on Security and Privacy 2021. The authors' publication page and the
IACR ePrint record are linked below.

[paper]: https://dennis-jackson.uk/assets/pdfs/ed25519.pdf
[publication]: https://cispa.de/en/research/publications/53200-the-provable-security-of-ed25519-theory-and-practice
[eprint]: https://eprint.iacr.org/2020/823

This document records how that paper informs Narya's verification contract. It
is not a claim that the paper formally verifies this implementation.

## The paper's results

The paper separates security properties that are often blurred together:

- **EUF-CMA** prevents a forgery on a new message under an honestly generated
  target key.
- **SUF-CMA** additionally prevents a different valid signature for a message
  that was already signed.
- **S-UEO** prevents substitution of another public key for an honest signer's
  signature.
- **M-S-UEO** strengthens ownership against maliciously generated signers and
  keys.
- **MBS** says one signature cannot verify for two different messages, even
  under a maliciously generated public key.

In the random-oracle model, under the paper's stated discrete-log and
identification-protocol assumptions, it proves:

1. its `Ed25519-Original` variant is EUF-CMA secure but not SUF-CMA secure;
2. requiring the decoded scalar `S` to lie in `[0, L)` makes its
   `Ed25519-IETF` variant SUF-CMA secure;
3. Ed25519's inclusion of the public-key encoding in
   `H(R || A || M)` provides S-UEO key-substitution resistance; and
4. rejecting pure small-order public keys and signature points gives the
   paper's `Ed25519-LibS` variant the additional MBS and M-S-UEO properties.

The last two results concern malicious keys, a setting outside ordinary
EUF-CMA and SUF-CMA. Small-order rejection therefore has a different security
role from canonical `S`: it is not the step that creates SUF-CMA for honest
keys, but it rules out signatures whose validity becomes detached from the
message or uniquely owned key when malicious torsion inputs are admitted.

## The variants are not Narya profiles

The paper models a generic cofactored equation

```text
[8S]B = [8]R + [8H(R || A || M)]A
```

and states its security results for that more-permissive verifier so that they
also cover a cofactorless verifier that rejects additional inputs. Its named
variants are distinguished primarily by scalar, point-order, and encoding
checks.

Narya's current profiles both use the cofactorless equation. They intentionally
match deployed implementation predicates, not the paper's taxonomy:

| Property | Paper `Ed25519-IETF` | Paper `Ed25519-LibS` | Narya `StdlibCompat` | Narya `DalekStrict` |
| --- | --- | --- | --- | --- |
| Require `S < L` | yes | yes | yes | yes |
| Equation | cofactored in the proof model | cofactored in the proof model | cofactorless | cofactorless |
| Reject pure-small-order `A` and `R` | no | yes | no | yes |
| Canonical `R` bytes | not the defining check | yes | yes, by literal recomputation | yes |
| Canonical `A` bytes | not the defining check | yes | no | **no** |

The bold final entry is important. `DalekStrict` deliberately accepts a
non-canonical but decodable `A`, matching `ed25519-dalek` 2.x
`verify_strict`. It is therefore inaccurate to call `DalekStrict`
"Ed25519-LibS" or to cite the paper as a turnkey proof of the exact Narya
predicate. Establishing such a theorem would require a formal refinement that
models Narya's permissive `A` decoder, byte-level key prefixing, canonical `R`
rule, cofactorless equation, and mixed-order acceptance.

There is nevertheless a useful monotonicity observation: honest signatures
use canonical prime-subgroup points, and a cofactorless verifier accepts a
subset of the signatures accepted by the paper's cofactored equation. This
makes the paper strong evidence for the design choices, but it is not a
substitute for spelling out the exact implementation relation.

## Consequences for Narya

### Canonical `S` is load-bearing

Without `S < L`, replacing `S` by `S + mL` preserves the group equation and
immediately malleates a signature. Every Narya profile checks the exact scalar
boundary, and the shared preparation tests pin `L-1`, `L`, and `L+1`.

### Hash the original encodings

Ed25519 is key-prefixed: the challenge is

```text
k = SHA-512(original R bytes || original A bytes || message) mod L.
```

Narya accepts non-canonical `A` under both current profiles. Decoding and then
re-encoding `A` before hashing would therefore change the signature scheme and
discard the byte-level public-key prefix the paper's key-substitution argument
uses. The original `R` and `A` bytes are retained through every scalar and
SIMD preparation path, and segment-order tests make that invariant explicit.

### Small-order rejection is an independently meaningful rule

The paper gives a direct malicious-key counterexample when low-order elements
are admitted: choose a low-order public key and a signature satisfying
`[S]B = R`; the cofactored equation can then verify independently of the
message. Its MBS and M-S-UEO proofs exclude this by rejecting small-order
inputs.

`DalekStrict` performs exactly that pure-torsion classification over the
original compressed bytes, including every accepted non-canonical alias.
Mixed-order points are not pure small-order points and remain accepted, as the
profile requires. `StdlibCompat` intentionally does not inherit this rule.

### Cofactor handling is part of the predicate

Multiplying the verification equation by eight erases its torsion component.
It is not an arithmetic refactoring of cofactorless verification. This is why
Narya reserves a separate future `ZIP215` profile instead of changing an
existing profile, and why scalar-halving or aggregate transformations need a
full-group injectivity proof before they can serve `DalekStrict`.

### Batch APIs must preserve the same scheme

The paper proves properties of one signature's verification relation. Narya's
public batch APIs evaluate that relation independently per item and retain one
verdict per signature. A randomized aggregate equation is a different
construction with its own assumptions and failure semantics; it cannot inherit
the paper's theorems merely because its inputs are Ed25519 signatures. See
[`STRICT_AGGREGATE_BATCHING.md`](STRICT_AGGREGATE_BATCHING.md).

## Proof boundary

The paper does not establish any of the following for Narya:

- correctness of radix-51 or radix-43 field arithmetic;
- equality of the Go, IFMA, cached, and batch implementations;
- constant-time behavior, fault handling, range safety, or alias safety;
- security of random-coefficient aggregate verification;
- security outside its random-oracle and hardness assumptions; or
- end-to-end security of a protocol that uses Ed25519.

Those are separate obligations. Narya addresses implementation equivalence
with independent reference predicates, CCTV and Wycheproof vectors,
differential fuzzing, per-lane invalid tests, range/alias contracts, and native
hardware tests. It remains experimental and unaudited.

## Practical reading

The paper's most useful lesson for this repository is not that one verifier is
universally "more secure." It is that small changes to accepted encodings,
scalar bounds, cofactor handling, and public-key hashing change the formal
scheme and the properties available to a surrounding protocol. Narya therefore
names and tests complete predicates rather than exposing a collection of
independent "strictness" switches.

For provenance, use the [authors' copy][paper], the [CISPA publication
record][publication], or [IACR ePrint 2020/823][eprint].
