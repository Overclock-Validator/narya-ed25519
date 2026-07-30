# Narya whole-window P2/completed implementation plan

## Goal

Implement the proved six-doubling plus zero, one, or two mixed-add schedule
without changing the Ed25519 group result or the r51/u52 multiplicand contract.
The first implementation should optimize the arithmetic boundary, not attempt
a giant all-register loop.

## State types

Introduce distinct internal states so an absent T coordinate cannot be used by
mistake:

```go
type ifmaPointP2X4 struct { X, Y, Z IFMAElementX4 }
type ifmaPointP2X8 struct { X, Y, Z IFMAElementX8 }

// Stored in [E,F,G,H] order. Every limb is u52 after Stage 2.
type ifmaCompletedX4 [4]IFMAProductX4
type ifmaCompletedX8 [4]IFMAProductX8
```

The completed storage can reuse the existing Stage-2 workspace layout. Keep the
provenance distinction explicit: the same byte storage contains exact raw
products at Stage-2 entry and carried u52 E/F/G/H at exit.

## Required leaves

### Doubling

```text
ifmaPointDoubleP2ToP2WorkspaceStaticX4/X8
    direct-XY Stage 1
    existing double Stage 2
    compute only X=EF, Y=GH, Z=FG

ifmaPointDoubleP2ToCompletedWorkspaceStaticX4/X8
    direct-XY Stage 1
    existing double Stage 2
    stop with E,F,G,H

ifmaCompletedToP2X4/X8
    compute and normalize EF, GH, FG
```

The first five radix-64 doublings use P2-to-P2. The sixth uses
P2-to-completed. If no mixed addition executes in that round, convert the
completed state directly to P2.

### Completed-to-Niels boundary

Add a boundary workspace with five field-element slots. A destructive schedule
is possible because the raw multiply assembly loads both inputs before its
first output store:

```text
slot 4 = P = E*F              // extra slot
slot 1 = R = F*G              // overwrite dead F
slot 2 = Q = G*H              // overwrite dead G
slot 0 = U = E*H              // overwrite dead E
```

After this sequence the live values are P, Q, R, and U. The original H is dead.

Add a fused linear/carry leaf:

```text
YmX = carry(Q + 535*p - P)
YpX = carry(Q + P)
T   = carry(U)
```

For affine Niels, retain R as exact raw D. For projective Niels, normalize R and
multiply it by the cached Z.

Then compute raw Niels Stage-1 products:

```text
A = YmX * cached.YMinusX
B = YpX * cached.YPlusX
C = T   * cached.T2D
D = R                         // affine
D = carry(R) * cached.Z       // projective
```

Reuse the existing `ifmaNielsStage2X4/X8`, whose contract already permits D to
be an exact raw product in the affine case.

Provide two consumers:

```text
ifmaCompletedAddAffineNielsToCompletedX4/X8
    stop after Niels Stage 2

ifmaCompletedAddAffineNielsToP2X4/X8
    Niels Stage 2, then EF, GH, FG only
```

The same shape applies to projective Niels with its additional D multiply.

## Round control flow

Determine which terms execute before choosing the output state. This metadata
is public scalar metadata already used for table selection.

```text
six P2 doublings:
    P2 -> P2, repeated five times
    P2 -> Completed, once

executing terms = terms whose NonzeroMask intersects usable

0 executing terms:
    Completed -> P2

1 executing term:
    Completed + Niels -> P2

2 executing terms:
    Completed + Niels[0] -> Completed
    Completed + Niels[1] -> P2
```

Do not construct a P3 between the two additions. The second boundary computes
its required T as E*H directly from the first addition's completed output.

## Recommended integration order

1. Add P2 and completed types plus portable/model implementations.
2. Add P2-only doubling and completed-output doubling using existing raw
   multiply and Stage-2 leaves.
3. Add completed-to-projective-Niels transitions first. They avoid affine table
   construction changes and have a one-multiply arithmetic penalty relative to
   the optimum.
4. Add the affine3 x4 selector path already present in the repository and wire
   the existing affine-Niels table experiment into the x8 path.
5. Add the raw `GH-EF`, `GH+EF`, and raw-Z boundary leaf.
6. Benchmark zero-, one-, and two-add rounds independently, then benchmark the
   complete prepared DSM and complete verifier.

## Proof and mutation gates

Every implementation variant should pass:

- exact representation equality against the materialized P3 path when the same
  low-level carry schedule is intended;
- reduced group equality for random prime-order, identity, order-2, order-4,
  and mixed-order points;
- all active masks and signed-digit masks;
- aliasing tests for in-place accumulator use;
- range tests at the exact maximum raw-product vectors;
- mutation test changing 535p to 534p;
- mutation test replacing Q-P by Q+P;
- mutation test doubling raw Z before Niels Stage 2;
- mutation test omitting U=E*H when an addition executes;
- fail-closed tests for invalid scalar lanes;
- zero-allocation checks;
- native-independent model tests and native hardware differential tests.

## Register and workspace constraint

Do not assume the five-slot dependency result implies 25 ZMM registers can stay
live through multiplication. The current x8 raw multiplication body uses Z0
through Z30. Double and Niels Stage 2 use Z0 through Z26. Therefore the first
implementation should use a 1,600-byte five-element x8 workspace and a 800-byte
five-element x4 workspace, with one raw multiplication at a time and destructive
slot reuse.

A later assembly experiment may redesign multiplication to stream an operand or
spill selected limbs intentionally. That is an independent performance
hypothesis and must not be bundled into the arithmetic correctness patch.

## Arithmetic expectations for radix 64

For six all-direct doublings and affine Niels additions, returning ready P2:

| additions in round | optimized S | optimized M | optimized carries | carry depth | full-P3 M | full-P3 carries | full-P3 depth |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 0 | 18 | 24 | 42 | 12 | 30 | 48 | 12 |
| 1 | 18 | 31 | 49 | 14 | 37 | 58 | 15 |
| 2 | 18 | 38 | 56 | 16 | 44 | 68 | 18 |

Projective Niels adds one multiplication and one carry per executed addition.
These are arithmetic-DAG metrics, not cycle predictions.

## Admission rule

Promote only if the complete prepared DSM improves on both x4-tail and x8-wide
regimes without weakening any exactness gate. A selector-only or isolated-leaf
win is insufficient because the repository already records cases where a
projective-Niels selector improvement regressed the complete loop.
