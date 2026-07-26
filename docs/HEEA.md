# Exact HEEA research track

HEEA is a parallel research track, not a production verifier. The published
artifact reports a 16.12% median improvement for individual Ed25519
verification relative to its ed25519-donna DSM baseline. That result justifies
an early prototype; it does not predict the gain over Narya's IFMA/SIMD
baseline or over the corrected full-group construction.

HEEA preserves one individual equation; it does not solve cancellation between
different signatures in an aggregate. The separate proof for a
strict-compatible Monte Carlo aggregate, including its mandatory exact
per-item torsion gate and nonzero soundness error, is in
[`STRICT_AGGREGATE_BATCHING.md`](STRICT_AGGREGATE_BATCHING.md).

The paper is Muhammad ElSheikh, İrem Keskinkurt Paksoy, Murat Cenk, and
M. Anwar Hasan, "Accelerating EdDSA Signature Verification with Faster Scalar
Size Halving," TCHES 2025(3), pp. 493–515,
[DOI 10.46586/tches.v2025.i3.493-515](https://doi.org/10.46586/tches.v2025.i3.493-515).
The implementation artifact is available from the
[IACR artifact archive](https://artifacts.iacr.org/tches/2025/a26/).
Anza's independently shipped cofactored implementation is recorded as a
comparison source in `NOTICE`; Narya's approximate-quotient experiment uses
its loop shape only behind a modulo-`8L` unit-multiplier gate.

## Full-group correction

Let

```text
E = [s]B - R - [k]A.
```

Narya's strict inputs may contain a torsion component even after rejecting
small-order `A` and `R`: mixed-order points are allowed. A relation modulo the
prime subgroup order `L` therefore cannot replace exact multipliers of `A` or
`R`.

The research selector instead uses the exponent of the full Edwards group:

```text
N = 8L
rho = epsilon * tau * k  (mod N), epsilon in {-1,+1}.
```

Then the transformed equation is exactly

```text
[tau*s]B - [tau]R - [epsilon*rho]A = [tau]E.
```

It has the same identity predicate precisely when multiplication by `tau` is
injective on the full group:

```text
gcd(tau, 8L) = 1.
```

For the configured short widths, nonzero odd `tau` is sufficient because its
absolute value is much smaller than `L`. The selector and selector-to-QSM
handoff nevertheless retain the complete unit check: oddness alone is not the
theorem, because the odd multiplier `tau=L` annihilates every prime-order
error. Candidate width overflow is an explicit baseline fallback, not a
truncated or reduced multiplier.

`internal/r43x6/heea_qsm_experiment_test.go` encodes both sides with exact
signed-integer double-and-add. It exercises mixed-order points and includes a
self-contained counterexample where an ordinary modulo-`L` transformation
accepts while the original cofactorless equation rejects.

## Basepoint split correction

The transformed basepoint coefficient does not need the same exact-integer
representation as the coefficients of `A` and `R`. Since `B` has order `L`,

```text
[tau*s]B = [(tau*s) mod L]B.
```

The r51x5 research path now reduces that coefficient canonically and splits it
at bit 128:

```text
ts = (tau*s) mod L
ts = lambda0 + 2^128*lambda1

[lambda0]B + [lambda1]([2^128]B) - [tau]R - [epsilon*rho]A.
```

`ExperimentalHEEABaseSplitEquationX4` and `X8` implement this four-base
schedule. The basepoint product uses fixed 512-bit multiplication plus the
independently differential-tested Barrett reducer shared with the scalar
reduction experiment. The admitted HEEA product is about 389 bits. A wider
research input is removed from the usable lane mask and must take the baseline
fallback; it is never truncated.

The `R` and `A` coefficients remain exact signed integers. Tests use
mixed-order points to demonstrate that replacing `-tau` or `-epsilon*rho`
with their modulo-`L` representatives changes the result, even though reducing
the basepoint coefficient is exact. Boundary tests cover bits 127 and 128,
every sign and epsilon combination, sparse masks, all x4/x8 tails, and direct
differential equality with the old exact roughly-389-bit equation.

The fixed basepoint product itself allocates nothing. The current scalar QSM
scaffold still allocates for arbitrary-width digit slices and builds tables on
each call, so its benchmark establishes the algorithmic critical-path change,
not production IFMA throughput. `[2^128]B` is prepared outside the timed path.
Run the comparison with:

```sh
go test -run '^$' -bench '^BenchmarkHEEAEquationBaseSplit$' \
  -benchmem -benchtime=3s -count=10 ./internal/r51x5
```

No base-split helper is connected to production dispatch.

## Composable IFMA base-split workspace

`ExperimentalIFMAHEEABaseSplitWorkspaceX4` and `X8` are forced/test-only
workspaces for the four-base equation above. They retain the `B` and
`[2^128]B` tables, rebuild cold `R` and `A` tables, and evaluate fixed-storage
radix-16 or radix-32 signed schedules with one shared doubling chain. One x8
group and two independent x4 groups use the same opaque coefficient record so
their masks and point results can be compared directly. No backend or
automatic dispatch can select either workspace.

The workspace uses concrete radix-specific arrays rather than four always-
32-entry tables. On a 64-bit Go target, the x8 physical workspace is 43,600
bytes for radix 16 and 84,560 bytes for radix 32, including four table
descriptors and fixed digit storage. Their active four-table coordinate
payloads are 40,960 and 81,920 bytes respectively. For comparison, retaining
the radix-64 capacity for the radix-32 schedule would make this workspace
166,480 bytes. Table builders overwrite only active entries and never clear
that larger reservation.

Coefficient preparation is deliberately an admission boundary. It accepts
only canonical `s`, exact magnitudes below `L`, `epsilon` in `{-1,+1}`, and a
nonzero odd `tau`; below `L`, those checks are equivalent to the complete unit
condition. Rejected active lanes are explicit baseline fallbacks. This local
defense against a malformed candidate does **not** make selector admission
atomic: a width-fallback selection can retain a unit diagnostic candidate.
The selector-to-QSM adapter must pass only `UseCandidate && NoFallback` lanes
within the selected width and carry all other original lanes to baseline
fallback. The trusted selector contract feeding that adapter is

```text
rho = epsilon*tau*k (mod 8L).
```

Independent selector tests verify that congruence for every admitted
candidate; the hot adapter does not recompute a wide-integer proof that the
deterministic selector has just established.

The paired decoder returns compact affine `R=(X,Y)`, while the QSM table needs
extended coordinates. `PrepareVariableBasesAffineR` performs the direct
handoff: admitted lanes get `Z=1` and `T=X*Y`; other lanes get a well-formed
identity solely for table construction. The complete decoder/precheck mask is
stored in the workspace and independently intersects `Evaluate`, so an invalid
lane cannot become usable if a caller forgets to reapply that mask. The one
composable multiplication needed to reconstruct `T` is included in the cold
affine-R benchmark path.

Portable model tests cover every x4/x8 reconstruction mask, exact signed A/R
semantics, split boundaries, mixed torsion, tails, and one-x8 versus two-x4
results. Hardware-gated tests repeat the affine reconstruction with the real
IFMA multiply, compare radix-16/radix-32 workspaces, and require zero
allocations. Run the target-machine comparison with:

```sh
go test -run '^$' -bench '^BenchmarkExperimentalIFMAHEEABaseSplit$' \
  -benchmem -benchtime=3s -count=10 ./internal/r51x5
```

The benchmark reports prepared QSM, full-point cold table construction,
compact-affine-R cold table construction, and coefficient-plus-cold variants.
The compact path therefore measures the `T=X*Y` handoff instead of treating a
full decoded `R` as free. It also reports active cold/retained table payload,
physical table bytes, and complete physical workspace bytes separately.

## Division-free fixed-width selector

`SelectShiftSubtract` is a second, deliberately weaker experimental selector.
Unlike `SelectFixed`, it does not preserve the globally best candidate from
all principal and nearby semiconvergent rows. It returns the first exact,
odd-`tau` row within the configured 128-, 132-, or 136-bit gate. Missing an
available short row is safe: the signature takes the ordinary verifier path.
The exact selector is used only as a test oracle and coverage comparator, not
as a hot-path fallback.

The two rows start as `(N,0)` and `(k,1)`. Each iteration updates the larger
remainder by the largest aligned power-of-two multiple of the smaller that
does not exceed it:

```text
(rLarge,tLarge) -= 2^d * (rSmall,tSmall).
```

The loop contains no general integer division. `d` comes from bit lengths and
one full-width comparison. The subtraction cancels the updated remainder's
leading bit, so the sum of the two remainder bit lengths strictly decreases;
at most 512 updates are possible.

The signed coefficients use five 64-bit magnitude limbs plus a sign. Their
range follows from a determinant invariant rather than empirical testing. The
row operations preserve

```text
abs(r0*t1 - r1*t0) = N.
```

After the initial row, positive remainders have opposite-sign coefficients,
so this is

```text
r0*abs(t1) + r1*abs(t0) = N.
```

Consequently every live coefficient and every shifted term used to construct
the next coefficient is at most `N=8L<2^256`. Four limbs are mathematically
sufficient; the fifth limb is retained as a checked overflow boundary. Tests
verify the determinant, exact row congruences, strict remainder shrinkage, and
that the fifth limb remains zero over deterministic random challenges.

Every admitted result is independently checked against `math/big` for

```text
rho = epsilon*tau*k (mod 8L),
tau != 0,
gcd(tau,8L) = 1,
max(bitlen(abs(rho)), bitlen(abs(tau))) <= gate.
```

Because an admitted `tau` is at most 136 bits, odd and nonzero also proves the
unit condition. The code still checks it directly. A product-group test
exercises mixed torsion explicitly and checks that a unit multiplier cannot
erase any nonzero order-eight error. A separate deterministic curve vector
sets `A=[a]B`, `R=[r]B+T2`, and `s=r+k*a`: strict verification rejects its
order-two error while the transformed equation with even `tau=2` accepts.

On a deterministic 8,192-challenge development corpus, the division-free and
exact selectors had these fallback counts:

| Gate | Division-free fallback | Exact-selector fallback |
| ---: | ---: | ---: |
| 128 | 1,184 (14.45%) | 868 (10.60%) |
| 132 | 6 (0.073%) | 6 (0.073%) |
| 136 | 0 | 0 |

This is a coverage snapshot, not a distribution claim. On the Apple M4 Pro,
an admitted 128-bit selection measured about 4.9--5.4 microseconds with zero
allocations, versus roughly 65 microseconds for `SelectFixed`; the explicit
pathological fallback measured about 5.5--5.7 microseconds. Ryzen measurements
were added on 2026-07-26: on a pinned Zen 5 Ryzen 7 9700X, ordinary admitted
selection measured about 7.12 microseconds at W128, 6.87 at W132, and 6.68 at
W136, with zero allocations. The concurrently measured strict singleton was
14.84 microseconds, so the current selector costs more than the plausible
saving from halving its approximately 255-doubling chain. The positive
two-chain ZMM arithmetic gate therefore does not make this selector a viable
complete singleton path. Future HEEA work must first supply a fundamentally
cheaper exact selector; extending the point layer alone cannot win. The
selector is connected only to the forced complete research verifier described
below; production backend dispatch is unchanged.

Run the selector benchmark and its dedicated fuzz target with:

```sh
go test -run '^$' -bench '^BenchmarkSelectShiftSubtract$' \
  -benchmem -benchtime=3s -count=10 ./internal/heea8l
go test -run '^$' -fuzz '^FuzzSelectShiftSubtract$' \
  -fuzztime=60s ./internal/heea8l
```

### Exact Lehmer follow-up

`SelectLehmer` retains principal-Euclid candidate semantics while batching
multiple quotient steps behind one full-width 2x2 matrix application. Its
production-shaped matrix helper computes all eight small-coefficient products
in a single limb pass and combines each signed pair directly; the former
four-`combine320` path remains a test oracle. The remaining exact row update
uses the same fused sign-and-magnitude rule and retains its compositional form
as a second randomized oracle.

On a Ryzen 7 PRO 8700GE, Go 1.26.4, one pinned core, the staged W128 medians
were 3.978 us for the four-combine selector, 3.647 us after the single limb
pass, 2.949 us after direct signed-pair combination, and 2.698 us after fusing
the exact coefficient step. The matrix helper itself moved from 415.4 to
327.35 and then 156.05 ns. Every row allocated zero bytes. Complete selector
outputs match the reference and exact principal-Euclid path over 60,000
deterministic challenges. Matrix and exact-step helpers each have an additional
100,000-case randomized signed/range differential.

This improves the reducer but does not promote HEEA: the selector alone costs
about 35% of the current 1232-byte, n=64 cold r51 verification on that CPU,
before the transformed curve equation or fallback. The valid gate remains a
complete exact verifier comparison, not a reducer microbenchmark. Evidence is
under `docs/results/zen4-heea-matrix-fusion-2026-07-26/`.

## Current implementation boundary

`internal/heea8l` provides the allocating `math/big` oracle and an exact
allocation-free `SelectFixed` implementation. The fixed selector preserves the
same candidate and fallback decisions over four 64-bit limbs, retains its
original restoring divider as a differential oracle, and uses a faster aligned
divider in the active research path. Profile-directed significant-limb
multiplication and parity-first row filtering reduced an admitted selection on
the M4 development machine from roughly 130--138 microseconds to 63--65
microseconds. An exact, fully verified eight-quotient lookahead matched all
oracles but was fractionally slower, so it remains unexported and the simpler
aligned path stays active. `SelectShiftSubtract` is materially cheaper by
accepting a measurable 128-bit coverage loss and making an ordinary-verifier
fallback explicit. Neither selector is production-ready. A fixed-storage
composable IFMA base-split workspace supplies the four-term QSM. A forced,
test-only complete verifier now connects the strict byte gates, paired decode,
native segmented SHA-512 over the original bytes, fixed scalar reduction, the
division-free selector, `tau*s mod L`, compact-affine `R` reconstruction, cold
`R/A` tables, the exact identity equation, and ordinary strict fallback.

The selector-to-QSM adapter admits a lane only when `UseCandidate` is true,
the fallback reason is `NoFallback`, the configured width holds, and `tau` is
a unit modulo `8L`. Only that admitted mask reaches coefficient preparation
and is independently retained by the variable-base workspace. Thus a
diagnostic candidate returned with `WidthExceeded` cannot enter the identity
test.

The non-IFMA scalar model executes the same selector and transformed equation
against complete valid, invalid, noncanonical-A, and mixed-order signatures.
Hardware-gated tests compare x8 and two-x4 at radix 16/32, rotate mixed-order
and selector-fallback cases through every lane, and distinguish valid fallback
from an S-mutated invalid fallback. The latter catches accidental acceptance
of an identity-filled fallback lane.

The complete forced pipeline does not call the scalar reference verifier for
a selector, coefficient-preparation, or QSM-evaluation miss. Those disjoint
lane masks are reunited and evaluated by a retained ordinary radix-32 r51 DSM
of the same shape as the candidate: one x8 group stays x8, and two x4 groups
stay two independently remapped x4 groups. It reuses decoded `A`, compact
affine `R`, canonical `s`, and the already-reduced `k`, so fallback does not
pay a second decode or hash. Its fixed-B table, cold-A table storage, scalar
digits, and verdict masks are all caller-owned; admitted and fallback complete
paths have zero per-call allocations on the hardware test target. The generic
strict verifier remains an independent test oracle rather than timed fallback
work.

This lane fallback is intentionally different from a kernel error. Any error
from paired decode, native SHA-512, IFMA table construction, transformed QSM,
or ordinary DSM is returned by the forced harness and clears the complete
output verdict slice. Likewise, an ordinary DSM that unexpectedly loses one
of its already-canonical scalar lanes is reported as an invariant error. No
generic backend retry is hidden in the benchmark; a production fail-safe
policy must be implemented and tested separately.

Run the complete comparison with:

```sh
go test -run '^$' -bench '^BenchmarkR51HEEACompletePipeline$' \
  -benchmem -benchtime=3s -count=10 ./ed25519

taskset -c 0-7 env GOMAXPROCS=8 go test -run '^$' \
  -bench '^BenchmarkR51HEEACompletePipelineParallel$' \
  -benchmem -benchtime=3s -count=10 ./ed25519
```

The timed HEEA boundary includes selector cost, the extra cold `R` table,
basepoint-product reduction, and the same-width radix-32 ordinary DSM for
fallback lanes. These costs are not amortized away by the x8 point kernel and
are why the paper's reported gain is not treated as a Narya prediction.

The parallel benchmark limits the release candidate to W132/radix-32 and
gives every worker a private mutable pipeline, ordinary-fallback workspace,
verdict buffer, and fallback counters. The fixture bytes are the only shared
inputs. Its n=8/64, 64/200/1232 matrix must be measured at the intended
production worker count alongside the ordinary r51 worker shortlist.

No coefficient multiplying `A` or `R` may pass through Narya's modulo-`L`
`Scalar` type. Basepoint coefficients may be reduced only where the proof and
API make the basepoint's prime order explicit.

## Admission gate

### 2026-07-25 target-hardware result

The complete W132/radix-32 experiment fails the performance gate decisively on
both production targets. A compact pinned-core screen used 1232-byte messages,
zero selector fallbacks, zero allocations, and the ordinary same-shape
radix-32 diagnostic as the baseline:

| CPU / shape | n | ordinary (us/sig) | HEEA (us/sig) | HEEA change |
|---|---:|---:|---:|---:|
| Ryzen 7 9700X / x8 | 8 | 9.973 | 15.89 | +59.3% |
| Ryzen 7 9700X / x8 | 64 | 10.05 | 15.94 | +58.6% |
| Ryzen 7 PRO 8700GE / two-x4 | 8 | 16.43 | 23.97 | +45.9% |
| Ryzen 7 PRO 8700GE / two-x4 | 64 | 16.53 | 24.14 | +46.0% |

Each value is the median of three 750 ms samples with `GOMAXPROCS=1` and
`taskset -c 2`, using Go 1.26.4 at implementation commit `778005e`. The current
registered ordinary path is faster than this diagnostic baseline, so expanding
the HEEA matrix cannot reverse the decision. HEEA remains useful proof and
differential-test evidence, but it is closed as a Zen 4/Zen 5 performance track
unless a materially different QSM construction changes the cost model.

HEEA stays experimental unless all of the following hold:

- the modulo-`8L` congruence and complete unit-`tau` checks are local to the
  selector/QSM handoff;
- width failure always runs the same-width ordinary r51 strict DSM;
- exact mixed-order, CCTV, Wycheproof, fuzz, and lane-mask tests have zero
  mismatches;
- one coherent x8 or two-x4 HEEA shape improves every serial and production-
  worker complete-verifier row by at least 5% on the target Ryzen, with no
  increase in either B/op or allocs/op, relative to the exact ordinary r51
  configuration
  selected by the worker shortlist (not a fixed same-path radix-32 row);
- the W132 adversarial matrix, with one fallback in each possible lane and
  all eight lanes falling back at 64/200/1232-byte messages, is no more than
  5% slower than that exact selected ordinary n=8 configuration and has no
  B/op or allocs/op increase;
- the ordinary DSM path remains available as rollback.

### Width-specific closure

The table above closes the present HEEA construction only for batch kernels
whose SIMD lanes are already occupied by independent signatures. It must not be
used to reject a different singleton construction on algorithm name alone.
The packed singleton currently places one point's four Edwards coordinates in
one YMM register and follows one shared NAF doubling chain. A native-width ZMM
version is useful only if the equation supplies two independent point chains,
placing four coordinates from each chain in the eight lanes. HEEA and separate
`[S]B`/`[k]A` evaluation can create that shape; their extra table/reducer costs
then occupy lanes that are idle in the current singleton rather than competing
with eight already-live signatures.

The minimum gate is an exact two-point-ZMM doubling A/B against
`quadPointDoubleHardwareUncheckedX4`. Do not mechanically retype the packed
point layer to x8, and do not transfer an x8 HEEA verdict to this singleton
experiment in either direction.

Randomized aggregate batch verification is a separate API and algorithmic
regime. A Straus/Pippenger MSM over a very large batch shares one doubling
chain across all signatures, so it attacks the same work that HEEA halves;
HEEA has little doubling-chain value inside such an aggregate. It remains
potentially relevant to small batches, tails, and per-signature paths.

That observation does not make aggregate verification part of Narya's current
contract. Narya promises an exact deterministic verdict for every input. A
failed aggregate does not identify its bad members, and recursive localization
must build and verify fresh random-coefficient sub-batches. An adversary can
choose and distribute the invalid entries, making that work depend on the
attacker-controlled failure count. Cofactored aggregate verification also
belongs to a different acceptance profile. No current HEEA or cold-path gate
uses aggregate-throughput projections as its baseline.
