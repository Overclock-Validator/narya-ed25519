# Whole-window Edwards25519 synthesis: initial result

## Scope

This report studies a bounded arithmetic grammar for six Edwards25519
doublings followed by one Niels mixed addition in the r51/u52 IFMA model. It
is not a physical-CPU benchmark and does not establish literature novelty.

The grammar permits:

- conventional `S` and direct-XY `D` doubling formulas;
- raw or ready P2 boundaries between doublings;
- optional dead T reconstruction at intermediate boundaries;
- materialized or fused final-double-to-Niels transitions;
- affine or projective Niels tables;
- P2 or P3 output after the addition.

The search enumerated **40,960** concrete DAG configurations.

## Strongest candidate

Keep only `(X,Y,Z)` through the doubling chain. For the last doubling, retain
its carried completed coordinates `(E,F,G,H)` and form exact raw products:

```text
Xraw = E*F
Yraw = G*H
Zraw = F*G
Traw = E*H
```

Instead of carrying `Xraw` and `Yraw` separately and then carrying `Y-X` and
`Y+X`, form and carry the raw combinations directly:

```text
YmX = carry(Yraw + 535*p - Xraw)
YpX = carry(Yraw + Xraw)
T   = carry(Traw)
```

For an affine-Niels table, pass `Zraw` directly as Stage-2 `D`. The existing
Niels Stage-2 contract already accepts `D` as an exact raw product and computes
`2D±C` before its own carry pass.

The affine-Niels result is then emitted as ready P2, omitting the final `T`
because the next operation is another doubling.

## Metrics

| Candidate | S | M | carries | carry depth | nonlinear depth |
|---|---:|---:|---:|---:|---:|
| full-P3 baseline | 18 | 37 | 58 | 15 | 14 |
| P2 chain, materialized boundary | 18 | 31 | 52 | 15 | 14 |
| P2 chain, fused X/Y | 18 | 31 | 50 | 14 | 14 |
| P2 chain, fused X/Y and raw Z | 18 | 31 | 49 | 14 | 14 |
| mixed D+5S fused candidate | 23 | 26 | 54 | 14 | 14 |
| projective-Niels fused candidate | 18 | 32 | 50 | 14 | 14 |

Relative to the full-P3 baseline in this model, the all-direct fused candidate
removes:

- **6 field multiplications**;
- **9 value-normalization carries**;
- **1 serial carry layer**.

Its multiplication count is lower because `T` is contextually dead after each
of the first five doublings and after the final addition. The boundary fusion
itself does not reduce multiplication count; it removes three carries without
adding a multiplication.

## Closed forms

For `n` doublings, `d` direct-XY choices, a raw P2 boundary before every later
standard doubling, the fused affine-Niels/P2 schedule has:

```text
squarings       = 4n - d
multiplications = 3n + d + 7
carries         = 8n + 7 - d
carry depth     = 2n + 3 - 1[first doubling is D]
nonlinear depth = 2n + 2
```

If a boundary immediately before a later `S` doubling is materialized as ready
P2, add one carry layer for each such boundary. Materializing before `D` moves
the required coordinate carries but does not change carry depth.

For six all-direct doublings, this gives:

```text
18S + 31M, 49 carries, carry depth 14.
```

The search independently rebuilt and checked every relevant DAG for all
schedules and all 32 inter-doubling ready/raw masks.

## Contextual-T theorem

For `n` doublings followed by `a` additions, where the next operation is a
doubling:

```text
full P3 after every point operation:  n + a T products
contextual P2/P3 schedule:            a T products
saving:                               n T products
```

If `a=0`, no T is needed. If `a>0`, the final doubling creates T for the first
addition and each non-final addition creates T for the next one; the final
addition emits P2. Therefore the saving is exactly the radix width, independent
of how many additions occur in the round.

For all-direct doublings, the resulting 0/1/2-addition round metrics are:

| Table | additions | variant | S | M | carries | carry depth | T products |
|---|---:|---|---:|---:|---:|---:|---:|
| affine | 0 | contextual-P2-fused | 18 | 24 | 42 | 12 | 0 |
| affine | 0 | full-P3-materialized | 18 | 30 | 48 | 12 | 6 |
| projective | 0 | contextual-P2-fused | 18 | 24 | 42 | 12 | 0 |
| projective | 0 | full-P3-materialized | 18 | 30 | 48 | 12 | 6 |
| affine | 1 | contextual-P2-fused | 18 | 31 | 49 | 14 | 1 |
| affine | 1 | full-P3-materialized | 18 | 37 | 58 | 15 | 7 |
| projective | 1 | contextual-P2-fused | 18 | 32 | 50 | 14 | 1 |
| projective | 1 | full-P3-materialized | 18 | 38 | 58 | 15 | 7 |
| affine | 2 | contextual-P2-fused | 18 | 38 | 56 | 16 | 2 |
| affine | 2 | full-P3-materialized | 18 | 44 | 68 | 18 | 8 |
| projective | 2 | contextual-P2-fused | 18 | 40 | 58 | 16 | 2 |
| projective | 2 | full-P3-materialized | 18 | 46 | 68 | 18 | 8 |

The affine contextual/fused formulas are:

```text
squarings       = 3n
multiplications = 4n + 7a
carries         = 7n + 7a
carry depth     = 2n + 2a
T products      = a
```

For projective Niels, replace `7a` by `8a` in multiplications and carries.
The full-P3 materialized control uses `5n + 7a` affine multiplications,
`8n + 10a` carries, and carry depth `2n + 3a`.

## Range certificate for the fused boundary

The exact folded raw-product upper bounds are:

```text
[1202461100507921976, 959266720629915282, 716072340751908588, 472877960873901894, 229683580995895200]
```

The minimum whole-modulus bias for `Yraw-Xraw` is exactly:

```text
535 * p
```

Both `Yraw+Xraw` and the biased difference remain non-negative and below
`2^64`. One radix-51 carry/fold returns each to the u52 IFMA domain. `Traw`
likewise carries to u52. `Zraw` remains an exact raw-product value, satisfying
the provenance-sensitive input contract of Niels Stage 2.

Maximum carried exclusive bounds:

```text
Y-X: [2251799813697332, 2251799813686316, 2251799813686208, 2251799813686100, 2251799813685992]
Y+X: [2251799813689105, 2251799813686315, 2251799813686099, 2251799813685883, 2251799813685667]
T:   [2251799813687167, 2251799813685781, 2251799813685673, 2251799813685565, 2251799813685457]
```

## Verification performed

- Exact sparse-polynomial identity of the materialized and fused boundaries:
  `True`.
- Exact direct-XY rewrite identity: `True`.
- Valid-point differential checks across all 64 S/D schedules:
  `960`.
- Arbitrary-field fused/materialized checks, requiring no curve assumption:
  `2000`.
- Closed-form DAG checks: `2048`.
- Contextual-T theorem checks: `80`.
- Explicit generalized 0-to-3-add DAG checks: `64`.
- Valid-point 0/1/2-add checks across all S/D schedules: `2880`.
- Arbitrary-field two-add chain checks: `2000`.
- Mutation gates:
  - 534p subtraction bias rejected: `True`;
  - `Y-X` sign mutation rejected: `True`;
  - raw-Z extra-double mutation rejected: `True`;
  - omission of a needed T rejected: `True`.

The valid-point fixtures include the identity, order-2/order-4 torsion, and
mixed prime-order-plus-torsion points.

## Bounded lower bound

Within this grammar, carry depth 14 is optimal for six doublings plus an
affine-Niels add returning ready P2:

1. The first direct doubling needs one Stage-2 carry layer.
2. Each of the next five doublings needs one input-coordinate carry layer and
   one Stage-2 carry layer: ten more.
3. The final completed point needs one carry layer to create the u52
   `Y±X` and `T` multiplicands.
4. Niels Stage 2 needs one carry layer for its four outputs.
5. The ready P2 output needs one final carry layer.

Total: `1 + 10 + 1 + 1 + 1 = 14`.

The fused schedule attains every term of this lower bound. Beating it requires
leaving the current grammar, for example a multiply that legally consumes a
raw product, a different coordinate representation, or a wider multi-product
leaf with a separately proved range contract.

## Implementation shape

Use distinct types rather than an invalid/uninitialized `T` inside the current
extended point type:

```text
IFMAPointP2      = (X,Y,Z) u52
IFMACompleted    = (E,F,G,H) u52
IFMAPointP3      = (X,Y,Z,T) u52
```

Recommended leaves:

```text
doubleP2ToP2
lastDoubleP2ToCompleted
addCompletedAffineNielsToP2
addCompletedAffineNielsToP3   # only when another add follows
```

The four final-double products form a cycle over `E,F,G,H`. A destructive
schedule needs only one extra field-element slot, so the product phase has a
five-element storage lower bound/constructive schedule:

```text
P=E*F -> extra
R=F*G -> overwrite F
Q=G*H -> overwrite G
U=E*H -> overwrite E or H
```

The destructive product graph needs five field-element storage slots, but this
must not be confused with an all-register implementation. The current x8 raw
multiply schedule occupies Z0 through Z30, and the existing double and Niels
Stage-2 leaves occupy Z0 through Z26. Therefore a monolithic leaf cannot retain
all completed coordinates while reusing the present multiply body. The
apply-ready shape is workspace-resident and destructive: compute one raw
product at a time, overwrite dead completed slots, and use a small fused linear
and carry leaf at the boundary. An all-register version would require a new
streamed multiplication schedule and is a separate optimization problem.

## What is and is not new

Context-dependent P2/P3 conversion is established Edwards-scalar-multiplication
practice. The session-original bounded result is the exact r51/u52 accounting,
the raw `GH±EF` plus raw-Z fusion, and its carry-depth lower-bound match. A
literature search did not locate this exact fused IFMA boundary, but that is not
sufficient to claim global novelty.
