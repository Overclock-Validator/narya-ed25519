# What the Ed25519 security proofs do—and do not—say about Narya

This note relates Narya's exact `DalekStrict` acceptance predicate to two
primary references:

- Brendel, Cremers, Jackson, and Zhao,
  [*The Provable Security of Ed25519: Theory and Practice*][brendel], IEEE
  Symposium on Security and Privacy 2021; and
- Chalkias, Garillot, and Nikolaenko,
  [*Taming the many EdDSAs*][taming], SSR 2020.

[brendel]: https://eprint.iacr.org/2020/823
[taming]: https://eprint.iacr.org/2020/1244
[rfc8032]: https://www.rfc-editor.org/rfc/rfc8032
[dalek]: https://github.com/dalek-cryptography/curve25519-dalek/tree/8016d6d9b9cdbaa681f24147e0b9377cc8cef934/ed25519-dalek

This is a proof-oriented design record, not a cryptographic audit or a claim
that either paper formally verified this implementation. Sections explicitly
labelled **Narya refinement** are repository proof sketches that still need
independent formal review. They are recorded so the assumptions, algebra, and
remaining obligations are inspectable instead of living only in discussion.

## Executive result

`DalekStrict` does not exactly match a named variant in either paper. It is
closest to the corrected libsodium-style predicate, with one intentional
relaxation: a non-canonical but decodable public-key string `A_bytes` is
accepted, and those exact original bytes—not a canonical re-encoding—enter the
challenge hash.

Under the classical random-oracle model and byte-string public-key identity, that
relaxation does not introduce an evident weakness in EUF-CMA, SUF-CMA, S-UEO,
MBS, M-S-UEO, or SBS. The load-bearing conditions are:

1. decoding is deterministic;
2. `H(R_bytes || A_bytes || message)` receives the original fixed-width byte
   strings;
3. pure-small-order `A` is rejected, so decoded `A` has a nonzero prime-order
   component; and
4. the implementation realizes the documented predicate exactly.

For honest-key EUF-CMA and SUF-CMA, the result follows by restriction from the
published verifier: an honestly generated `A` is canonical and prime-order,
and a Narya-accepted equation is also accepted by the paper's cofactored
relation. The malicious-key binding claims require the byte-string refinement
below. They should not be presented as theorems quoted verbatim from either
paper.

No new verifier check follows from this analysis. In particular, silently
requiring canonical `A` would change the consensus predicate and is not
justified as a hardening of `DalekStrict`.

## Exact predicate

For a 32-byte public key `A_bytes`, a 64-byte signature `R_bytes || S_bytes`,
and a message, `DalekStrict` requires:

1. `A_bytes` decodes with the permissive decoder;
2. the integer encoded by `S_bytes` is less than the prime subgroup order
   `L`;
3. neither `A_bytes` nor `R_bytes` decodes to a pure-small-order point;
4. `k = SHA-512(R_bytes || A_bytes || message) mod L`, using the original
   bytes; and
5. `Encode([S]B - [k]A) == R_bytes`.

The final byte comparison is equivalent to the conjunction

```text
R_bytes is a canonical, decodable point encoding
and
[S]B = R + [k]A in the full Edwards25519 group.
```

The generic backend implements the byte comparison literally. The r51 backend
may instead establish canonical `R`, decode it, and compare the two affine
coordinates projectively. Differential tests make those forms one predicate.
This is the behavior of the pinned [ed25519-dalek 2.2.0 source][dalek] reached
by the Agave reference snapshot recorded in `README.md` and `NOTICE`.

The predicate deliberately accepts mixed-order `A` and `R`. It deliberately
accepts non-canonical, decodable `A_bytes`. Both choices are consensus
semantics, not parser accidents.

## Relation to the named variants

Brendel et al. package three variants: Original, IETF, and LibS. Their generic
formal verifier uses a cofactored equation; their variants are distinguished
by scalar and point-order checks. The LibS row requires `|A| >= L` and
`|R| >= L`, which admits mixed-order points. *Taming the many EdDSAs* later
corrects the mapping from that model to the real libsodium implementation:
libsodium checks only for pure small order rather than computing full point
orders, and its verification equation is cofactorless. The papers state that
the main security conclusions survive those corrections.

| Property | Paper `Ed25519-IETF` | Paper `Ed25519-LibS` | Narya `StdlibCompat` | Narya `DalekStrict` |
| --- | --- | --- | --- | --- |
| require `S < L` | yes | yes | yes | yes |
| equation | cofactored proof model | cofactored proof model | cofactorless | cofactorless |
| reject pure-small-order `A` and `R` | no | yes | no | yes |
| require canonical `R` | not defining | yes | yes, by byte comparison | yes, by byte comparison or equivalent |
| require canonical `A` | not defining | yes | no | **no** |
| accept mixed-order points | yes | yes (`|P| >= L`) | yes | **yes** |

Algorithm 2 in *Taming the many EdDSAs* also is not Narya's exact predicate: it
requires canonical `A`, uses a cofactored equation, and does not need to reject
small-order `R` for its binding theorem. Names such as “LibS” or “Algorithm 2”
must therefore not be used as shorthand for `DalekStrict`.

## Decoder and alias lemma

An Ed25519 compressed point contains a 255-bit little-endian `y` integer and
one sign bit for `x`. A canonical encoding requires `y < p` and requires the
sign bit to be zero when `x = 0`. The permissive decoder reduces the `y`
integer modulo `p` and accepts the redundant sign-one encoding of zero `x`.

The round-trip failures are therefore exactly:

```text
low255(bytes) >= p
or
decoded x == 0 and sign == 1.
```

For Edwards25519, `x = 0` in the curve equation implies `y^2 = 1`, so the only
such points are `(0, 1)` and `(0, -1)`. Both are pure small-order and are
already rejected by `DalekStrict`. Consequently, after the small-order gate,

```text
A_bytes is canonical  <=>  low255(A_bytes) < p.
```

This equivalence is a classification result, not a new production check. The
tests derive all fourteen accepted encodings of the eight small-order points,
compare the byte classifier with permissive-decode-plus-`[8]P == O`, exercise
every one-bit neighbor, and enumerate all nineteen possible unreduced `y`
aliases. See `ed25519/small_order_agreement_test.go` and
`ed25519/strict_primitives_test.go`.

### Narya refinement: aliases cannot share a signature cheaply

Suppose distinct byte strings `A_bytes != A'_bytes` decode to the same point
`A`, and the same `(R_bytes, S)` verifies for `(A_bytes, M)` and
`(A'_bytes, M')`. Then

```text
[S]B = R + [k]A
[S]B = R + [k']A
```

and subtraction gives `[k-k']A = O`. Because pure-small-order `A` was rejected,
its prime-order component is nonzero. Projection to that component gives
`k = k' mod L`; since both reduced challenges lie in `[0,L)`, they are equal.

The random-oracle inputs are distinct because `A_bytes != A'_bytes`, and the
two 32-byte prefixes have fixed lengths. A cross-alias success therefore
requires a collision *after reduction modulo `L`*. It need not be a raw
SHA-512 collision: two different 512-bit outputs separated by a nonzero
multiple of `L` also collide after reduction.

This is why hashing the original bytes is load-bearing. Re-encoding `A` before
hashing would merge the aliases into one challenge domain and define a
different signature scheme.

## Exact reduced-random-oracle probabilities

Let `N = 2^512`, write `N = qL + r` with `0 <= r < L`, and let
`K = X mod L` for uniform `X` in `[0,N)`. Exactly `r` residues have `q+1`
preimages and `L-r` residues have `q` preimages. Therefore the largest point
probability is

```text
mu_L = (q+1)/N
     = 1/L + (L-r)/(L*N),
```

and the collision probability for two independent, distinct oracle inputs is

```text
rho_L = [r(q+1)^2 + (L-r)q^2] / N^2
      = 1/L + r(L-r)/(L*N^2).
```

Both are approximately `1/L`, or about `2^-252`, with `rho_L <= mu_L`.
For `Q` distinct oracle inputs, a union bound gives at most
`choose(Q,2) * rho_L` for some reduced collision. Hitting one already fixed
target with `Q` fresh attempts is bounded by `Q * mu_L`.

The transcript encoding is injective. Its first 32 bytes are `R_bytes`, its
next 32 bytes are `A_bytes`, and all remaining bytes are the message. Two
different `(R_bytes,A_bytes,message)` tuples therefore cannot reach one oracle
input through a concatenation ambiguity.

### Narya refinement: adaptive weighted-collision lemma

Adaptive key selection is the main subtlety in the malicious-key bounds. List
the relevant *fresh* oracle inputs in the order first evaluated, including
transcripts evaluated lazily by final verification. Immediately before answer
`K_j` is sampled, the bytes of that input—and hence the deterministically
decoded public key's nonzero prime coefficient `a_j`—are already fixed. The
coefficient may depend arbitrarily on all earlier oracle answers, but it cannot
depend on `K_j` without changing `A_bytes` and creating another fresh input.

Define `Y_j = a_j*K_j mod L` for accepted public-key transcripts. Conditional
on the complete history before query `j`, collision with one earlier `Y_i`
requires exactly one target value:

```text
K_j = a_j^-1 * Y_i mod L.
```

That target has probability at most `mu_L`. Collision with any earlier
weighted value therefore costs at most `(j-1)*mu_L`, and summing the conditional
bounds gives

```text
Pr[some weighted collision among N fresh inputs]
    <= choose(N,2) * mu_L.
```

The argument does not require a reduction to know the discrete logarithm
`a_j`; it uses only its mathematical uniqueness and commitment before the
fresh answer. A candidate key selected after seeing an earlier challenge can
turn its own success condition into a chosen-target query, but every adjustment
of that key commits a new input before the corresponding challenge is known.

This also explains why `mu_L`, rather than the smaller ordinary-collision
parameter `rho_L`, is the safe quantity for adaptive M-S-UEO and SBS. The bound
is tight in its basic two-query form. Set `R=B` and `A_1=B`; after observing
`k_1`, use `A_2=[k_1]B`, target `k_2=1`, and set `S=1+k_1 mod L`. In the
`k_1=0` case use `A_2=B` and target `k_2=0`. With distinct messages, a hit
makes the same signature verify for both transcripts. The constructor still
must win one fresh event of probability `mu_L`.

This is a classical-ROM exposure argument. It is not a proof for quantum
superposition access to the random oracle.

## Full-group decomposition

The Edwards25519 group decomposes as `G_L x T_8`. Write

```text
A = aB + A_T
R = rB + R_T,
```

where `a,r` are modulo `L` and the torsion components are in `T_8`. The
cofactorless equation is equivalent to the simultaneous relations

```text
S = r + k*a mod L
R_T + [k]A_T = O.
```

The byte classifier's mathematical condition has a useful interpretation:

```text
[8]A != O  <=>  a != 0
[8]R != O  <=>  r != 0.
```

If `A_T` has order `d` dividing eight, the torsion relation depends only on
`k mod d`. More exactly, if `R` is pure torsion then its prime coefficient is
zero. For a prime-order public key (`A_T=O`), the torsion relation forces
`R_T=O`; the identity is the only pure-small-order `R` that can satisfy the
cofactorless equation. For a mixed-order key, a solution exists only when
`R_T` lies in the subgroup generated by `A_T`. Writing
`R_T=-[j]A_T` reduces the torsion relation to `k=j mod d`.

A malicious constructor who knows the prime coefficient `a` can select those
torsion components, find the desired residue in about `d` random-oracle trials
(at most eight), and set `S=k*a mod L`. That constructs a valid signature for
a deliberately chosen key; it is not an eight-trial forgery against an honest
key. In every two-transcript binding game, the surviving prime relation is
still `k=k'` or `k*a=k'*a' mod L`. The short torsion grind does not remove
that roughly 252-bit condition.

This decomposition also explains why multiplying a verification equation by
eight is not an arithmetic refactor of `DalekStrict`: it erases the second
relation. Every scalar-halving, HEEA, and aggregate transformation must remain
injective on the full `G_L x T_8` group or fall back to the ordinary equation.

## Security-property classification

Let `Q_H` count the adversary's distinct challenge-oracle queries. A verifier
may evaluate as many as two winning transcripts that the adversary did not
query, so set `N = Q_H+2` for the bounds below.

| Property | Key model | Status for Narya | Bound/status |
| --- | --- | --- | --- |
| EUF-CMA | honest target key | direct restriction of published result | no greater than Brendel Theorem 3 |
| SUF-CMA | honest target key | direct restriction of published result | no greater than the IETF EUF bound |
| S-UEO | honest target, malicious substitute | published result plus byte-string bookkeeping | published conservative form `2 Q_H mu_L` |
| MBS | malicious key | **Narya refinement** | `choose(Q_H+2,2) rho_L` proof sketch |
| M-S-UEO | two malicious keys | **Narya refinement** | `choose(Q_H+2,2) mu_L` proof sketch |
| SBS | malicious keys and messages | **Narya refinement** of *Taming* Theorem 1 | `choose(Q_H+2,2) mu_L` proof sketch |

### EUF-CMA and SUF-CMA

The target public key in these games is honestly generated, hence canonical,
prime-order, and nonidentity. A full-group Narya equation implies the paper's
cofactored equation, while Narya adds rejections. Every Narya-accepted honest-
key forgery is therefore also accepted by the paper's IETF verifier.

Brendel Theorem 3 supplies the EUF-CMA reduction under its identification-
protocol, programmable-random-oracle, and nonce-min-entropy assumptions.
Theorem 4 shows that the `S < L` rule removes response malleability and reduces
SUF-CMA to EUF-CMA. Accepting non-canonical public keys is irrelevant to these
two games because the honest target key is generated canonically and fixed.

### S-UEO

For honest `A = aB` and an accepted substitute `A' = a'B + A'_T`, both
`a` and `a'` are nonzero. Prime-order projection of one signature accepted by
both keys gives `k*a = k'*a' mod L`. Once one challenge is known, the other
must hit one particular scalar, costing at most `mu_L` per fresh oracle input.
Brendel Theorem 5 gives the conservative `2 Q_H mu_L` bound. An alias of the
same decoded point is the special case `a = a'`, which requires the reduced
collision `k = k'` described above.

### Narya refinement: MBS

If one byte-level key and signature verify for distinct messages `M != M'`,
subtraction gives `[k-k']A = O`. The nonzero prime-order component of `A`
forces `k = k'`. With at most `Q_H` adversarial queries and two final
verification evaluations, the direct collision bound is

```text
Adv_MBS <= choose(Q_H+2, 2) * rho_L.
```

The proof uses deterministic decoding, original-byte hashing, and rejection
of pure-small-order `A`. `R` cancels. It does not require canonical `A`,
canonical `R`, small-order-`R` rejection, or rejection of mixed-order points.
The simple counterexample without the `A` order check is `A=O`, `R=B`, `S=1`:
the same signature then verifies for every message.

### Narya refinement: M-S-UEO and SBS

If the same signature verifies for `(A_bytes,M)` and `(A'_bytes,M')`, write
the nonzero prime coefficients as `a` and `a'`. Prime-order projection gives

```text
k*a = k'*a' mod L.
```

For different points, fixing one challenge determines one target value for the
other. The second key may be selected as a function of that first challenge,
but its bytes and coefficient are committed before its own challenge is
sampled. Applying the adaptive weighted-collision lemma to the at most
`N=Q_H+2` relevant evaluations gives

```text
Adv_M-S-UEO <= choose(Q_H+2, 2) * mu_L
Adv_SBS     <= choose(Q_H+2, 2) * mu_L.
```

For aliases of the same decoded point, `a=a'`, so the relation reduces to the
ordinary collision `k=k'` on distinct byte-level inputs. Searching across the
same query budget is bounded more tightly by
`choose(Q_H+2,2)*rho_L`.

*Taming the many EdDSAs* Theorem 1 proves SBS for its Algorithm 2 after
rejecting small-order public keys and explicitly notes that small-order `R`
rejection is unnecessary. Narya's non-canonical-`A` acceptance is the part
requiring the byte-string refinement: key equality in the game must mean
equality of the original 32-byte public-key strings, and those strings must be
the ones hashed.

These are algebraically short arguments, but they are not a replacement for a
machine-checked game proof. Until independently reviewed, describe them as
proof sketches rather than established Narya theorems.

## What each check contributes

| Check | Principal role in this analysis |
| --- | --- |
| `S < L` | load-bearing for SUF-CMA; prevents `(R,S) -> (R,S+L)` malleability |
| reject pure-small-order `A` | load-bearing for malicious-key message/key binding |
| reject pure-small-order `R` | exact dalek/consensus predicate; not needed by the binding algebra |
| canonical `A` | not needed by these byte-identity sketches when original bytes are hashed |
| canonical `R` | exact predicate, signature-encoding uniqueness, and interoperability |
| reject mixed-order `A` or `R` | not required by the cited binding arguments; Narya accepts them |
| hash original `A_bytes` | load-bearing for ownership of byte-level key identities |
| cofactorless equation | preserves the torsion relation and is stricter than the cofactored equation on honest-key proofs |

This table is not permission to remove checks. `DalekStrict` is a consensus
contract. A check can be unnecessary for one theorem and still be mandatory
for compatibility, encoding uniqueness, or the selected acceptance predicate.

## Small-order `R` and almost-correctness

Consider a hypothetical predicate `DalekStrict-minus-R-order` that changes only
the pure-small-order-`R` rejection and keeps `S<L`, pure-small-order-`A`
rejection, canonical `R`, original-byte hashing, and the cofactorless equation.
Under the assumptions of the proof sketches above, the removed check is not
independently required for any of EUF-CMA, SUF-CMA, S-UEO, MBS, M-S-UEO, or
SBS:

- for an honest prime-order target key, a pure-small-order `R` satisfying the
  cofactorless equation must be the identity, and the remaining equation
  `S=k*a mod L` is still the prime-order forgery problem;
- in S-UEO, M-S-UEO, and SBS, the shared `R` cancels when the two verification
  equations are subtracted; and
- in MBS, the same cancellation leaves `[k-k']A=O`, so the nonzero prime
  coefficient of `A` forces a reduced-challenge collision.

This is a dependency result, not a proposal to remove the check. The accepted
byte set demonstrably changes. The smallest witness is

```text
A = B
R = O (canonical identity encoding)
k = H(R_bytes || A_bytes || message) mod L
S = k.
```

It satisfies `[S]B = O + [k]A` and is accepted by `StdlibCompat`, but current
`DalekStrict` rejects it. `TestSmallOrderRIsAProfileBoundary` constructs this
signature and pins the divergence. A mixed-order constructor can similarly
choose `A=B+A_T`, `R=-[j]A_T`, grind `k=j mod ord(A_T)`, and set `S=k`.
Neither witness is a forgery because the constructor deliberately knows the
key's prime scalar.

Pure-small-order `R` rejection remains an intentional part of the pinned
[ed25519-dalek predicate][dalek] and therefore of Narya's consensus contract.
The fact that a check is redundant for the named security games does not make
it redundant for compatibility.

There is a formal correctness caveat when this verifier is paired with literal
standard Ed25519 signing. The signer computes `r = H(prefix || M) mod L` and
`R = [r]B`. The only pure-small-order `R` an honest prime-subgroup signer can
produce is the identity, which occurs when `r = 0`. In the reduced random-
oracle model this has probability `mu_L` per fresh nonce-hash input, and Narya
rejects the resulting otherwise-consistent signature.

Thus literal signing plus `DalekStrict` has negligible correctness error rather
than perfect correctness:

```text
Pr[honest signature rejected because R=O] = mu_L.
```

A scheme definition that needs perfect correctness can specify retry on
`r = 0`; that changes signing and its distribution proof. Retrying also matters
for key safety: a signer that actually emits the nonce-zero signature exposes
its signing scalar whenever `k != 0`, because `S=k*a mod L` gives
`a=S*k^-1 mod L`. Verifier-side rejection prevents acceptance but cannot undo
that disclosure once the bytes have been released. Narya is a verifier and
does not silently impose a signing rule. The `R=O` probability statement is a
formal correctness caveat for the verifier; robust signers should independently
ensure that no nonce-zero signature is emitted.

## Protocol identity boundary

The alias result assumes that public-key identity is the exact original
32-byte string. A surrounding protocol that deduplicates by decoded point,
canonicalizes keys in one layer but not another, or derives an account identity
from a different representation needs a separate identity-semantics analysis.
The verifier alone cannot make those layers consistent.

This is the practical reason not to summarize the result as “non-canonical
keys are harmless.” The narrower statement is: under deterministic permissive
decoding, original-byte challenge hashing, pure-small-order rejection, and
byte-string key identity, accepting a decodable non-canonical `A` introduces
only the reduced-random-oracle collision branch described above.

## Proof and implementation boundary

Neither paper, nor the refinements in this note, proves:

- correctness of the radix-51 or radix-43 field arithmetic;
- equivalence of the Go, IFMA, cached, singleton, and batch implementations;
- range, carry, alias, fault-fallback, or CPU-dispatch safety;
- constant-time behavior;
- security of random-coefficient aggregate verification;
- security of concrete SHA-512 beyond the random-oracle heuristic; or
- end-to-end security of a protocol using Narya.

Narya addresses implementation equivalence with independent reference
predicates, RFC, CCTV, *Taming*, and Wycheproof vectors, differential fuzzing,
per-lane invalid tests, and explicit range/alias contracts. Those are evidence,
not an external audit.

## Remaining formal obligations

1. **Byte-string games.** State EUF/SUF/ownership games with a public key
   represented as `(A_bytes, Decode(A_bytes))` and equality defined on bytes.
2. **Decoder theorem.** Tie the alias classification to the exact permissive
   decoder with a small proof or exhaustive machine-checked boundary lemma.
3. **Reduction formalization.** Translate the adaptive exposure lemma and its
   `Q_H+2` lazy-verification accounting into the complete byte-string games,
   and have the reduction independently reviewed.
4. **Almost-correctness.** State the nonce-zero rejection whenever describing
   standard signing plus `DalekStrict` as a signature scheme.
5. **Protocol identity.** Specify how every consumer compares, stores, and
   canonicalizes public keys.
6. **Implementation proof.** Keep predicate equivalence separate from the
   field/group implementation audit.
7. **QROM scope.** Do not transfer the sequential classical-ROM lemma to
   quantum random-oracle queries without a separate proof and concrete bound.

The strongest defensible summary today is therefore:

> Narya directly inherits the honest-key EUF-CMA and SUF-CMA results by
> restriction. Its original-byte hashing and small-order-`A` rejection support
> concise byte-string refinements of the published S-UEO, MBS, M-S-UEO, and
> SBS arguments, with reduced-challenge collision probability approximately
> `2^-252`. Those refinements are documented proof sketches pending independent
> formal review, not a claim of a completed proof or audit.

For encoding and signing details, also consult [RFC 8032][rfc8032].
