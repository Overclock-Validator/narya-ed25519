# Radix-51 IFMA arithmetic assurance

This note records the proof obligations for Narya's five-limb radix-`2^51`
AVX-512 IFMA arithmetic, the obligations already backed by independent tests,
and the boundary that still requires a machine-linked certificate.

It is an audit map, not an audit certificate. Passing the tests named here does
not prove that every emitted instruction satisfies the contracts.

## Three separate obligations

For every arithmetic leaf, all three statements must hold:

1. **Field semantics:** the output represents the specified value modulo
   `p = 2^255 - 19`.
2. **Machine semantics:** no 64-bit addition, subtraction, shift, multiply, or
   IFMA accumulator loses an intended bit, and every `VPMADD52` source is
   strictly below `2^52`.
3. **Layout semantics:** registers, lanes, masks, aliases, and memory offsets
   refer to the intended signature, coordinate, and limb.

A field-congruent formula proves only the first statement. For example, an
unsigned underflow adds `2^64` to one radix-weighted coefficient; because `p`
is odd, that is not generally zero modulo `p`.

## Representation contracts

Let:

```text
B = 2^51
T = 2^52
W = 2^64
p = B^5 - 19
```

An `IFMAElementX4` or `IFMAElementX8` is five unsigned limb vectors. Each SIMD
lane is an independent field element. Any limb used as a `VPMADD52LUQ` or
`VPMADD52HUQ` source must be less than `T`, because IFMA consumes only its low
52 bits.

For non-negative, non-wrapped limbs, the unsigned carry/fold is:

```text
q_i = floor(x_i / B)
r_i = x_i - q_i*B

C(x)_0 = r_0 + 19*q_4
C(x)_i = r_i + q_(i-1),  i=1..4
```

Since a `uint64` limb has quotient at most `8191` when divided by `B`, one
application maps any genuine non-negative `uint64` input below `T`. This lemma
does not apply to a mathematically negative value stored in two's complement;
signed and unsigned folds are distinct contracts.

## Multiplication certificate

For two inputs with all limbs below `T`, the raw schoolbook product followed by
the `B^5 = 19 (mod p)` fold has strict per-limb upper bounds:

| limb | strict upper bound |
| --- | ---: |
| 0 | `267*T - 456` |
| 1 | `213*T - 366` |
| 2 | `159*T - 276` |
| 3 | `105*T - 186` |
| 4 | `51*T - 96` |

The live implementation in `internal/r51x5/ifma_amd64.s`:

- enumerates the complete 25-term schoolbook product;
- keeps IFMA low and high halves in separate zeroed accumulators;
- doubles the high-half contribution because the IFMA split is at bit 52 and
  the field radix is at bit 51;
- folds degrees 5 through 8 with the factor 19; and
- normalizes the resulting unsigned limbs before returning them as IFMA
  sources.

The independent evidence includes:

- `TestIFMAComposableAnalyticBounds` for the exact coefficient weights and
  inclusive maxima;
- `TestIFMAMaximumComposableMultiplyHardware` for maximum-u52 operands;
- `TestIFMAFusedMultiplyNormalizeDifferential` and
  `TestExperimentalIFMAMultiplyX8X4` against scalar field arithmetic;
- per-lane pattern tests; and
- exact `out == x`, `out == y`, and `out == x == y` alias tests.

These tests would detect many missing `2`, `19`, or cross-term factors. A final
certificate must still reconstruct the term matrix from the emitted machine
instructions instead of trusting the source macro expansion.

## Fused point stages

Narya's doubling stage uses the direct-`XY` form. Given raw products
`A=X^2`, `B=Y^2`, `C=Z^2`, and `E=XY`, the linear stage computes:

```text
E = 2*XY
G = B + 535*p - A
F = G + 1068*p - 2*C       // total margin: 1603*p
H = 1069*p - A - B
```

The constants `535`, `1069`, and `1603` are the minimal whole-modulus margins
derived from the exact raw-product bounds for one, two, and three negative raw
terms. `TestIFMADoubleStage2X8BoundariesAgainstIndependentOracle` checks the
stage against arbitrary-precision integer arithmetic; the analytic and
boundary tests separately prove no unsigned underflow, no 64-bit wrap, legal
post-carry outputs, and that lowering the required bias by one is not justified
by the interval proof.

The projective-Niels linear stage receives raw products `A`, `B`, `C`, and `D`
and computes:

```text
E = B + 535*p - A
F = 2*D + 535*p - C
G = 2*D + C
H = B + A
```

Its exact big-integer oracle, boundary vectors, x4/x8 comparisons, and
multiplicand-derived inputs exercise the same semantic and range obligations.

The formulas above describe the live sign convention. Algebraically equivalent
Edwards formulas may use different signs or intermediate names; a certificate
must bind itself to the actual implementation rather than substitute a
reference DAG.

## Completed-coordinate whole-window certificate

The test-only whole-window boundary stops the final doubling at carried
`(E,F,G,H)`, forms exact raw `[EF,GH,FG,EH]`, and carries `GH-EF` and `GH+EF`
directly. Its separate executable certificate proves the minimum `535*p`
subtraction bias, unsigned `uint64` safety, u52 outputs, and exact-product
provenance within the declared r51 grammar. The portable oracle, native leaf,
maximum-bound vector, mutations, and complete-loop verdict are documented in
[`formal/EDWARDS_WHOLE_WINDOW_RANGE_CERTIFICATE.md`](formal/EDWARDS_WHOLE_WINDOW_RANGE_CERTIFICATE.md).

That candidate remains unwired after a 0.53% prepared-loop gain. Its evidence
is still useful: it is a concrete example of a schedule-specific bound wider
than the common u61 contract and therefore of why native leaves must cite the
exact range proof they rely on. It does not close the source-to-machine
refinement gap below.

## Canonicalization boundary

Five radix-51 limbs cover `[0, 2^255)`, while the canonical field interval is
`[0, p)`. Therefore the complete non-canonical integer boundary is exactly:

```text
p, p+1, ..., p+18
```

`TestPermissiveEncodingAgainstBigAndEdwardsField` exhausts that interval and
requires permissive decoding of `p+j` to `j`. The canonical decoder test
requires rejection of every member while preserving the receiver on failure.
Canonical serialization and equality are additionally checked against both
`math/big` and the independent Edwards field implementation.

Field canonicality is not by itself point-encoding canonicality. Ed25519 also
has the sign-bit-one encoding of `x=0`; the strict point-preparation tests cover
that rule separately.

## Aliasing boundary

The typed internal API supports disjoint operands and exact whole-object
aliases. The assembly loads the required inputs before overwriting output, and
the tests exercise every documented exact-alias shape. Arbitrary partially
overlapping byte ranges are not an API contract and must not be introduced by
unsafe callers.

## What a machine-linked certificate must add

The remaining high-value hardening project is a small, independent checker over
the final object code or a mechanically equivalent instruction transcript. For
each supported arithmetic routine it should verify:

1. the complete product-term matrix, including low/high IFMA halves and every
   factor `2`, `19`, or `38`;
2. an exact interval transfer through each add, subtract, shift, IFMA, carry,
   and fold;
3. source-limb `<2^52` and accumulator `<2^64` obligations at every IFMA;
4. unsigned no-underflow and signed/unsigned carry selection;
5. register, lane, shuffle, mask, and memory-offset mappings;
6. supported alias patterns and load-before-store ordering; and
7. final congruence with the specified field expression.

The checker must use arbitrary-precision integers and remain independent of
the code generator and search heuristics. Deliberately deleting a fold,
changing a bias, swapping two lanes, or corrupting one product factor must make
the certificate fail. An SMT/bit-vector pass can then discharge the selected
schedule's exact 64-bit no-wrap and congruence obligations.

Until that exists, Narya's evidence is best described as analytic range proofs
plus independent exact and differential tests on the source and native
hardware—not as a mechanically verified assembly implementation.

## Primary specifications

- [RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)](https://www.rfc-editor.org/rfc/rfc8032)
- [Intel 64 and IA-32 Architectures Software Developer Manuals](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
