# Paired A/R decompression experiment

The strict cold path may decode `A` and `R` together, retain affine `R`, and
finish with two projective cross-products instead of encoding the computed
point. Zen 4 complete-verifier measurements admitted this mechanism for the
registered forced r51 strict singleton. Full x4 batch groups instead decode A
only and amortize canonical Q encoding across the batch; the broader paired
x4/x8 comparison remains experimental.

## Square-root-ratio primitive

Use the simplified Edwards25519 ratio formula:

```text
w = u * v
t = w^(2^252-3)
r = u * t
check = v * r^2
```

The usual `check == u`, `check == -u`, and `sqrt(-1)` correction logic is
unchanged. Relative to `(u*v^3)*(u*v^7)^(2^252-3)`, this saves two squarings
and three multiplications per decode. The generic field implementation uses
this formula and permanently differentially tests its complete output—not
just its validity bit—against the older construction over zero inputs,
square and nonsquare ratios, and all four quartic-character cases.

On an Apple M4 Pro, the isolated scalar primitive improved from a median of
about 3.65 microseconds to 3.50 microseconds (roughly 4.1%). This is a
development result, not the Zen 4 release measurement.

## Two roots still require two chains

`A` and `R` have independent radicands. A square root of their product does
not recover the individual roots or validity bits, and mixed intermediates in
a multiplication/squaring-only addition chain cannot contribute to either
independent pure power. `Decode2` therefore runs two `pow22523` chains.

Pairing is an instruction-scheduling optimization:

- interleave independent operations to expose instruction-level parallelism;
- use paired field macros or lane packing where the backend supports it;
- do not combine the radicands into one mathematical root computation.

With the simplified formula, the persistent outer state is `y`, `u`, and `v`
for each input—six field vectors total. The implementation must measure
out-of-line spilling, selective spilling/recomputation, and any custom
assembly calling convention rather than assuming a fixed spill layout.

The correctness-first scalar model is implemented as
`internal/r43x6.Decode2NoT`. It exposes one operation from each chain before
the corresponding operation from the other chain, returns full extended `A`
plus compact affine `R=(x,y)`, and reports independent A/R decode errors.
Malformed lengths use an uncommon path so fixed-width verification inputs do
not burden the paired schedule. The model allocates no heap memory.

On the Apple M4 Pro development host, the paired primitive was approximately
8% faster than two independent r43x6 decodes in a short three-sample run. The
complete r43x6 verification pipelines were roughly at parity and noisy across
message sizes, so this does not clear the dispatch gate; only the Zen 4 IFMA
pipeline measurement is authoritative.

The r51 throughput track has zero-allocation `Decode2NoTX4` and
`Decode2NoTX8` scheduling references with independent active/valid masks, full
extended A, and compact affine R. It now also has forced-only
`ExperimentalIFMADecode2NoTX4` and `ExperimentalIFMADecode2NoTX8` schedules.
The latter keep every exponentiation intermediate in the bounded u52
composable domain and alternate each A operation with the corresponding R
operation. They do not combine the two mathematical power chains.

The IFMA schedule has two explicit canonical boundaries:

1. reduce candidate roots and equality operands for root classification and
   encoded-sign selection; and
2. reduce `T=xA*yA` before committing the public reduced output buffers.

The public hardware APIs check the complete IFMA feature set before entering
the schedule, validate the imported u52 values once, and leave both output
buffers unchanged on every error. The exponentiation loop then uses the
private unchecked-input multiplier: the composable type invariant proves each
input remains below 2^52, while every raw product still undergoes carry/fold
normalization and output-range validation before reuse. The public standalone
composable multiply remains fully checked. The same decode schedule can use a
reduced lane multiplier in tests, so tails, aliases, invalid points, injected
failures, and x8-versus-two-x4 behavior run on machines that cannot execute
AVX-512. Both the model and callable hardware API are required to allocate zero
heap objects.

On the Apple M4 Pro, the older scalar-lane x8 reference took roughly 214--218
microseconds versus 206--209 microseconds for 16 independent scalar decodes;
two x4 references were similarly slower. That is a representation result, not
evidence about the new IFMA schedule. Its hardware benchmark compares the
interleaved power chains with both a paired outer schedule that serializes the
power chains and two complete independent decoders. It also compares one x8
group with two x4 groups, and retains a checked-every-multiply row to isolate
the cost of the removed u52 input scans. A skipped non-IFMA run is not a
performance result.

The general x4/x8 hardware comparison remains deliberately
correctness-first. Input unpacking, carry normalization, equality masks, and
final reduction remain Go code; active tails do not skip exponentiation work;
and no custom register or spill convention has been implemented. Complete
measurements must therefore include stack traffic and generated code as well
as elapsed time. The packed singleton's admitted schedule is narrower than
this general comparison.

## Strict pipeline invariants

```text
canonical S
seven-value small-order check on original A and R bytes
low255(R) < p (valid only after the small-order check)
Decode2NoT(A, R) -> full A, affine R=(x,y)
SHA-512(original R || original A || message)
Q = [S]B - [k]A
XQ == xR*ZQ and YQ == yR*ZQ
```

- Hash the original input bytes.
- Keep permissive, decodable noncanonical `A`.
- Require canonical `R` and reject pure-small-order `A` and `R`.
- Compare both coordinates modulo `p`.
- Accept mixed-order points according to the original cofactorless equation.
- Return independent decode-validity bits for `A` and `R`; never let one lane
  hide the other's failure.

The encoded-`Q` verifier remains the differential reference. The scalar
generic implementation also keeps encoded-`Q` in production: its separately
decoded-`R` complete pipeline was about 2% slower on the development machine.
The paired packed singleton cleared its complete-path gate and is used by the
forced r51 backend. Other paired SIMD shapes remain eligible only through a
complete-path improvement, not a decompression-only result.

The differential suite covers all edge-encoding pairs, wrong lengths,
negative zero in both positions, random decodable and non-decodable inputs,
exact raw roots for square and nonsquare ratios, CCTV/Wycheproof A/R inputs,
and self-consistent small-order identity aliases that prove the general
encoded-Q reference still needs a canonical-R gate. The strict path also
differentially tests its canonical predicate against re-encoding. A direct
equality-boundary discriminator now uses an accepted unreduced `y+p` encoding
whose decoded point is not small-order: projective equality accepts the point,
while canonical re-encoding differs from the original bytes.

A complete self-consistent signature with that rare kind of `R` is not known:
the discrete logarithms of the non-small-order points that have accepted
noncanonical encodings are unknown, so ordinary signing cannot construct one.
The C2SP corpus likewise constructs its `non_canonical_R` cases from torsion
aliases. If an independently constructed full signature becomes available it
should be added, but the existing full-signature torsion cases plus the
non-small-order equality-boundary test keep the two failure mechanisms
independently observable today.
