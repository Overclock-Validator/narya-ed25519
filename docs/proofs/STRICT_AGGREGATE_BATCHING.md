# Strict aggregate batching: proof boundary and research gate

[Documentation index](../README.md) · Proofs and formal reasoning

> **Status:** proof and research note. Narya does not implement this aggregate
> verifier, and this document does not change the supported verification
> contract. `DalekStrict` continues to evaluate one complete equation and
> return one deterministic verdict per input.

This note records what is and is not possible when trying to combine
random-coefficient aggregate verification with Narya's cofactorless
`DalekStrict` predicate. The useful result is narrower than ordinary Ed25519
batch verification:

1. all existing strict byte, scalar, decoding, and small-order gates remain;
2. every signature pays an **exact** prime-subgroup-membership test on one
   derived point; and
3. only the remaining prime-order equations are combined probabilistically.

That hybrid can implement the same mathematical predicate with a conventional
soundness error such as `2^-128`. It is not bit-for-bit or zero-error
equivalent to independent verification. Consequently it does not currently
satisfy Narya's public batch contract.

## Definitions

Let the Edwards25519 group be

```text
G = G_L direct-sum G_8,
```

where `G_L` has prime order `L`, `G_8` has order 8, and the base point `B`
generates `G_L`. After the ordinary strict gates, define the residual

```text
E_i = R_i + [k_i]A_i - [s_i]B.
```

`k_i` is the canonical reduction of
`SHA-512(original-R-bytes || original-A-bytes || message)`. The original byte
strings matter: decoding and re-encoding either point before hashing would
change the predicate.

Independent strict verification accepts exactly when `E_i` is the identity,
in addition to its separate canonicality and small-order rules for `A_i` and
`R_i`.

## The exact torsion/prime decomposition

Write

```text
E_i = Q_i + T_i,  Q_i in G_L, T_i in G_8.
```

Because `L` is coprime to 8, multiplication by `L` is an automorphism on
`G_8`. Multiplication by 8 is likewise an automorphism on `G_L`. Therefore

```text
E_i = identity
iff ([L]E_i = identity and [8]E_i = identity).
```

The first condition says the residual has no torsion component. The second
says its prime-order component is zero.

The torsion condition has a useful simplification. Since `[L]B` is the
identity and the exponent of `G` is `8L`, let

```text
k8_i = k_i mod 8
P_i  = R_i + [k8_i]A_i.
```

Then

```text
[L]E_i
  = [L]R_i + [L*k_i]A_i
  = [L](R_i + [k8_i]A_i)
  = [L]P_i.
```

The middle equality follows because `k_i-k8_i` is divisible by 8, so the
difference is a multiple of the full-group exponent `8L`. Hence

```text
[L]E_i = identity  iff  P_i is in G_L.
```

This is the exact per-signature gate needed before aggregating a strict
equation. It does **not** replace the strict small-order tests: those are
separate acceptance rules and must still be applied to the original `A` and
`R` inputs.

Constructing `P_i` needs only two doublings to obtain `2A_i` and `4A_i`, plus
three additions selected by the low three bits of `k_i`. The expensive part is
the subgroup-membership predicate.

## A predicate-compatible Monte Carlo aggregate

Suppose every `P_i` has passed an exact subgroup-membership test. Every
`E_i` is then in `G_L`. Choose independent unpredictable `b`-bit coefficients
`z_i` only after the complete batch has been committed, with `2^b <= L`, and
test

```text
[8] (
    [-sum(z_i*s_i)]B
  + sum([z_i]R_i)
  + sum([(z_i*k_i) mod L]A_i)
) = identity.
```

The outer multiplication by 8 is load-bearing. Reducing `z_i*k_i` modulo `L`
is exact on the prime-order component of `A_i`, but it can change its torsion
component by a multiple of `[L]A_i`. Multiplication by 8 removes that scalar-
representation artifact. It is cheaper and simpler than carrying exact
variable-point coefficients modulo `8L` through a conventional MSM.

After that multiplication, the aggregate is equivalent to

```text
sum([z_i]E_i) = identity
```

inside the prime-order group. If a fixed committed batch contains a nonzero
residual `E_j`, then after conditioning on all other coefficients there is at
most one `z_j` in a `b`-bit domain that makes the sum zero. Thus

```text
Pr[an invalid fixed batch passes] <= 2^-b.
```

For `b=128`, this is the usual `2^-128` Monte Carlo bound. All valid batches
pass for every coefficient choice.

The theorem assumes fresh, independent coefficients unpredictable when the
batch is chosen. Transcript-derived deterministic coefficients instead need a
random-oracle/grinding argument; they are not information-theoretic random
coins. RNG failure, short reads, or coefficient reuse must fail closed.

## What the construction does not provide

This is not Narya's existing lane-parallel contract:

- a successful aggregate gives one assertion about the entire batch, not an
  independently computed verdict for each item;
- an invalid batch can pass with probability at most `2^-b`, rather than zero;
- a failed aggregate needs independent verification or recursive localization
  to identify invalid inputs; and
- an adversary can force the expensive failure/localization path, so a real
  design would require bounded chunks and explicit denial-of-service policy.

If the application requires literal equality with `N` independent verifier
executions for every run, this construction is unavailable regardless of its
speed.

## Linear torsion lower bound, with its scope stated precisely

The order-two subgroup gives a sharp warning against trying to omit the
per-item membership gate. Let `T2` be its nonidentity point. For arbitrary
bits `x_i`, choose nonzero scalars `a_i,r_i` and construct

```text
A_i = [a_i]B
R_i = [r_i]B - [x_i]T2
s_i = r_i + k_i*a_i mod L.
```

Canonical encodings of `A_i` and `R_i` pass the strict small-order gates,
because each has a nonzero prime-order component. Yet

```text
E_i = -[x_i]T2.
```

Thus strict-valid-looking inputs can realize every binary torsion-residual
vector.

For `q` fixed group-linear aggregate equations, only coefficient parity
survives on this subgroup. The tests define a linear map

```text
F_2^n -> F_2^q.
```

If `q<n`, its kernel contains a nonzero vector, so some invalid residual set
passes every equation. The same worst-case lower bound holds when later query
rows may depend on earlier identity-test results but not on nonlinear
inspection of the coordinates or encodings: along the all-zero response path,
fewer than `n` rows leave a nonzero vector consistent with that transcript.

For a fixed nonzero torsion vector and `q` independent uniformly random linear
tests, the pass probability is `2^-q`. A 128-bit scalar coefficient does not
provide 128 bits of torsion soundness: on the order-two subgroup it contributes
only its parity. One would need 128 independent torsion equations to obtain a
`2^-128` bound this way.

This is **not** an unconditional lower bound over all coordinate algorithms or
all functions of the input encodings. A verifier that extracts nonlinear
coordinate information is outside the group-linear model. Thomas Pornin's
point-halving membership test is exactly such an escape. Claims that no
sublinear nonlinear batch-membership algorithm can exist would require a
different proof and are not made here.

The analogous fixed-linear-map argument applies to exact aggregation of
arbitrary prime-order residuals: fewer than `n` equations have a nontrivial
kernel. Random coefficients trade zero error for a conventional cryptographic
soundness bound; they do not make the result literally identical to `n`
independent equations.

## Independent verdicts are a multi-output problem

For `n` signatures, let the prime-order residuals be

```text
D_i = [s_i]B - R_i - [k_i]A_i.
```

Any conventional deterministic group-linear construction producing `q`
aggregate points has a coefficient matrix `C` in `F_L^(q by n)`. If `q<n`,
`C` has a nonzero kernel vector `v`. Choosing `D_i=[v_i]B` makes every
aggregate the identity while at least one individual residual is nonidentity.
The prime subgroup alone supplies the counterexample, so torsion policy cannot
repair the lost dimension.

Consequently an exact checker based only on deterministic linear group
combinations needs at least `n` independent output dimensions to reproduce
`n` independent verdicts. With `q=n`, an invertible coefficient matrix is
only a change of basis: it does not collapse the curve computation to a
one-output MSM.

This is deliberately a statement about conventional group-linear algorithms,
not a universal lower bound for every coordinate program. A nonlinear
algorithm may inspect encodings or coordinates, and one group element has
enough cardinality to encode more than `n` Boolean results. No claim is made
that such an encoding is impossible; only that an ordinary deterministic MSM
does not provide it.

### The one common-base opportunity, and Narya's present gate

The products `[s_i]B` do share a base, so vector addition chains are a real
multi-output technique in the abstract. Pippenger's asymptotic estimate for
eight roughly 252-bit outputs is about 436 scalar group operations. That is a
useful research bound, but it is not the correct baseline for Narya's x8
backend.

Narya's promoted radix-256 comb evaluates all eight lanes with at most:

```text
32 x8 affine-Niels mixed-add calls + 8 x8 doubling calls.
```

Each call advances eight independent fixed-base products simultaneously. The
canonical Ed25519 scalar bound `s<L<2^253` also means Narya needs 32 radix-256
rounds, rather than the 33 additions required by a general table accepting
unreduced 255-bit scalars.

Even granting perfect eight-way packing, the cited 436-operation estimate has
a floor of `ceil(436/8)=55` vector group-operation slots. It would additionally
need batch-specific chain construction, cross-lane source placement, temporary
projective points, and generally more expensive projective additions. The
current comb needs only 40 vector point-operation calls and consumes affine
cached operands. Therefore that estimate does **not** justify an IFMA
prototype.

At the `afe5c65` gate, the Zen 5 radix-256 fixed-base group measured 5.1715 us
for eight signatures, or about 0.646 us/signature, while the complete
1232-byte cold verifier measured 4.673 us/signature. Deleting that fixed-base
term entirely would have capped the gain at roughly 14%; a realistic
fractional improvement was low-single-digit end to end. Later selector changes
altered the table layout, so these numbers are a same-commit ceiling rather
than a current microbenchmark. Reopen a multi-output-chain prototype only if a
finite eight-scalar schedule is supplied that beats the current 32 mixed adds
and 8 doublings after distinguishing affine from projective costs.

## Point-halving membership experiment

Pornin's subgroup test uses the fact that the image of multiplication by 8 is
exactly `G_L`:

```text
P in G_L  iff  P is divisible by 8 in G.
```

The published construction maps a projective Edwards point to related
Weierstrass models, attempts two successive halvings with square-root tests,
and replaces the third halving with a quadratic-residuosity test. Low-order
exceptional cases receive a corrective final check. The implementation is
division-free and reports roughly 40% of the cost of generic variable-base
scalar multiplication, or about twice the speed of its retained `[L]P`
reference chain. Those are upstream measurements, not Narya results.

Only one experiment is justified before building any aggregate MSM:

```text
P = R + [k mod 8]A
return point_halving_is_in_prime_subgroup(P)
```

It should be implemented as a forced, test-only x8 component with projective
inputs and fixed field-exponentiation chains. Measure all-valid inputs and
failures at every stage. Do not infer a Narya cost from the upstream ratio:
root extraction, Legendre evaluation, representation conversion, and lane
masking have different economics in Narya's radix-51 IFMA backend.

The component must first satisfy these differential gates:

1. agreement with the slow exact oracle `[L]P == identity` on random points;
2. every one of the eight torsion cosets, including all low-order exceptions;
3. random prime-order and mixed-order points;
4. `P=R+[k mod 8]A` vectors for every `k mod 8` value;
5. the order-two residual construction above at every lane and tail; and
6. zero allocations, fail-closed native errors, and unchanged outputs on
   inactive lanes.

No aggregate verifier should be built unless this isolated exact gate is fast
enough to leave a plausible end-to-end win.

## Sources and provenance

- Thomas Pornin, [“Point-Halving and Subgroup Membership in Twisted Edwards
  Curves”](https://eprint.iacr.org/2022/1164), 2022.
- Pornin's pinned `crrl` implementation at
  [`4cc7cbbe`](https://github.com/pornin/crrl/blob/4cc7cbbe8796ee8d459b815d81318603279879e4/src/ed25519.rs#L554-L790),
  including the point-halving implementation and retained `[L]P` reference.
- `curve25519-voi`'s pinned ordinary batch implementation at
  [`2ab5a27a`](https://github.com/oasisprotocol/curve25519-voi/blob/2ab5a27a1729946d0751b4fd3f8ced567c65664a/primitives/ed25519/batch_verify.go),
  which refuses cofactorless entries rather than applying its cofactored
  aggregate without an exact torsion gate.
- Henry de Valence,
  [“It's 255:19AM. Do you know what your validation criteria are?”](https://hdevalence.ca/blog/2020-10-04-its-25519am),
  for the scalar-reduction/cofactor distinction in Ed25519 predicates.
- Nicholas Pippenger,
  [“On the Evaluation of Powers and Monomials”](https://doi.org/10.1137/0209022),
  *SIAM Journal on Computing* 9(2), 1980, for the multi-output addition-chain
  framework. The asymptotic estimate is treated as a research bound, not as a
  finite eight-scalar implementation count.
- `curve25519-dalek`'s
  [basepoint-table documentation](https://docs.rs/curve25519-dalek/latest/curve25519_dalek/edwards/struct.EdwardsBasepointTableRadix128.html),
  for the published table-size/addition tradeoffs and the distinction between
  32 radix-256 additions for bounded scalars and the extra carry coefficient
  needed for general unreduced 255-bit scalars.

The hybrid decomposition and lower-bound discussion were prompted by an
external ChatGPT Pro research pass, then independently re-derived against the
group decomposition, Pornin paper, and pinned source above. The qualification
on input-dependent coefficients is deliberate: the fixed-map proof must not
be cited as an impossibility theorem for arbitrary nonlinear coordinate code.
