# Modulo-8L HEEA sampling experiment

This package is research tooling. It is not imported by signature
verification and its `math/big` performance is not representative of a future
fixed-width implementation.

The fixed-width Lehmer checkpoint is also research-only. Its matrix update now
applies all eight small-coefficient products in one limb pass. On a Ryzen 7 PRO
8700GE, a same-binary comparison measured 3.647 microseconds per W128
selection versus 3.978 microseconds for the retained four-combine reference,
an 8.3% complete-selector improvement. The matrix application itself improved
from 415.4 to 327.35 nanoseconds. Both paths are allocation-free and return the
same exact principal-Euclid row. See
[`../../docs/results/zen4-heea-matrix-fusion-2026-07-26`](../../docs/results/zen4-heea-matrix-fusion-2026-07-26/README.md).

That is still too expensive for verifier integration: the selector alone is
about 47% of the current 1232-byte, n=64 cold r51 cost on this CPU, before any
transformed point work or fallback. A complete verifier gate remains mandatory.

## Strict-equation exactness contract

Let `N=8L`, where `L` is the prime subgroup order. If the selector returns
signed integers `c0,c1` satisfying

```text
c1 = c0*k (mod N), and gcd(c0,N) = 1,
```

then multiplication by `c0` is injective on the full Edwards25519 group and

```text
[c0*s]B = [c0]R + [c1]A  iff  [s]B = R + [k]A.
```

The configured 128/132/136-bit fast widths are below `L`, so the unit check
reduces to oddness for a correctly bounded candidate. The implementation
nevertheless retains the complete `gcd(c0,8L)=1` admission check. This guards
both failure modes: an even multiplier can erase torsion, while the odd
multiplier `c0=L` can erase a prime-order error.

The deterministic torsion discriminator used by the tests sets
`A=[a]B`, `R=[r]B+T2`, and `s=r+k*a`, where `T2` has order two. The strict
error is `-T2`, but multiplying the equation by any even `c0` erases it. This
is the first mandatory vector for any future HEEA implementation.

Run the deterministic, rejection-sampled experiment with:

```sh
go run ./internal/heea8l/cmd/sample -samples 1000000 -workers 12
```

Every sample is independently derived from its index under the domain
`heea8l-sample-v1`, so counts are reproducible and independent of worker
count. Timing is machine-dependent.

## 2026-07-24 result

The million-sample experiment ran on an Apple M4 Pro with Go on Darwin/arm64.
It took 4m08.878s with 12 workers. The candidate-width mean was 127.605905
bits.

| Gate | Admitted | Fallback | Coverage | Prior claimed coverage | Difference |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 128 | 888,299 | 111,701 | 88.829900% | 88.8533% | -0.023400 pp |
| 132 | 999,620 | 380 | 99.962000% | 99.9595% | +0.002500 pp |
| 136 | 999,998 | 2 | 99.999800% | 99.9997% | +0.000100 pp |

These differences are consistent with ordinary sampling variation. The prior
percentages are comparison values, not test expectations or correctness
requirements.

The observed width histogram was:

```text
119:      1
120:     23
121:     75
122:    326
123:  1,317
124:  4,664
125: 18,794
126: 75,972
127:304,337
128:482,790
129: 85,550
130: 19,642
131:  4,895
132:  1,234
133:    283
134:     73
135:     19
136:      3
137:      2
```

The adversarial challenge `k=(N-2)/10` selected a 252-bit candidate and
explicitly fell back at all configured gates, as required by the proven
`max(abs(rho),abs(tau)) >= N/12` lower bound.

## Allocation benchmark

Run:

```sh
go test ./internal/heea8l -run '^$' -bench BenchmarkSelect -benchmem -benchtime=2s
```

On the same machine, representative results were approximately:

| Path | Time | Bytes/op | Allocs/op |
| --- | ---: | ---: | ---: |
| admitted W=128 | 572-588 us | 698,915 | 14,422 |
| ordinary W=128 fallback | 546-548 us | 692,030 | 14,233 |
| pathological W=136 fallback | 13.8-14.4 us | 28,471 | 565 |

The unusually cheap pathological case has a short Euclidean quotient chain;
it does not make fallback inexpensive in a future verifier, where the
baseline verification still has to run.

## Fixed-width selector checkpoint

`SelectFixed` now reproduces the same deterministic candidate and fallback as
the `math/big` oracle while representing signed coefficients as four 64-bit
little-endian magnitude limbs plus an explicit sign. It validates canonical
`k < L`, searches modulo `8L`, retains an exact candidate on width fallback,
and admits only nonzero odd `tau` coprime to `8L`. It is still variable-time
research code and is not connected to verification or point multiplication.

The differential tests cover challenge boundaries, the pathological fallback,
2,048 deterministic random challenges at every configured width, and the
congruence

```text
rho = epsilon * tau * k (mod 8L).
```

They also compare fixed add, subtract, multiply, and divide against
`math/big`. The arbitrary-precision selector remains the independent oracle.

The initial fixed-width implementation deliberately used restoring bitwise
division. On the same Apple M4 Pro, a one-second allocation benchmark measured:

| Fixed-width path | Time | Bytes/op | Allocs/op |
| --- | ---: | ---: | ---: |
| admitted W=128 | ~332 us | 0 | 0 |
| ordinary W=128 fallback | ~327 us | 0 | 0 |
| pathological W=136 fallback | ~11 us | 0 | 0 |

That implementation was an exact representation and control-flow checkpoint,
not a usable verifier optimization.

## Aligned multi-limb division checkpoint

`SelectFixed` now uses exact bit-length-aligned multi-limb division. It shifts
the divisor's leading bit to the numerator's leading bit and consumes only the
necessary quotient bits; a one-limb divisor uses `bits.Div64`. This avoids the
subtle quotient-estimate correction cases of Knuth division while doing work
proportional to quotient width instead of unconditionally restoring all 256
input bits. The original 257-bit-remainder routine remains available only as
`divMod256BitwiseOracle`.

Differential tests cover:

- every divisor width from 1 through 256;
- powers of two, top-bit-plus-one, all-ones, and patterned divisors;
- values immediately around each divisor and twice each divisor;
- 4,096 deterministic random numerator/divisor pairs;
- complete fixed-selector outputs for all existing edge and random challenges.

Both quotient and remainder agree with the retained bitwise implementation and
`math/big`; complete candidates also agree with both the bitwise selector and
the arbitrary-precision selector.

On the Apple M4 Pro, a two-second benchmark measured:

| Operation | Aligned | Bitwise oracle | Speedup |
| --- | ---: | ---: | ---: |
| ordinary admitted W=128 selection | ~138 us | ~347 us | ~2.51x |
| representative small-quotient division | ~25.8 ns | ~870 ns | ~33.7x |
| one-limb wide-quotient division | ~9.8 ns | ~1,779 ns | ~181x |

All paths remained at zero bytes and zero allocations per operation. Ordinary
selection is nevertheless still several times slower than a complete generic
verification, so HEEA remains unfit for integration. Division is no longer the
dominant explanation for that cost. The next selector work should profile and
reduce intermediate-row construction, fixed multiplication, and candidate
comparison, or evaluate a rigorously equivalent Lehmer schedule that advances
multiple EEA rows. It must then be measured together with exact signed-integer
multi-scalar multiplication. No production HEEA path should be enabled on the
strength of selector microbenchmarks alone.

## Candidate-row profile and quotient lookahead

A five-second CPU profile of the aligned selector measured about 130 us per
selection before this pass. The dominant sampled edges were fixed
multiplication and candidate preparation; exact division was a minority. Two
exact row-level changes addressed the dominant work:

- `mul256` now visits only significant operand limbs;
- nearby-candidate parity is derived from the low bits of `t0-q*t1`, and the
  complete signed coefficient is constructed only once for retained rows.

The parity shortcut relies on an explicit EEA invariant: the initial
coefficient pair is `(0,1)`, and subsequent pairs are nonzero with opposite
signs. Consequently `t0-q*t1` is zero only for the initial `q=0` case, while
its parity is exactly `t0[0] XOR (q[0] AND t1[0])`. Complete differential tests
against both prior selectors guard this derivation.

The profile-directed changes reduced ordinary aligned selection to roughly
63-65 us on the Apple M4 Pro, about a 2x improvement, with zero allocations.

An internal Lehmer-style lookahead experiment derives up to eight quotient
proposals from equally shifted leading words. Every proposal is checked using
the full operands before use:

```text
q*r1 <= r0 < (q+1)*r1.
```

Any failed proposal discards the queue and falls back immediately to aligned
exact division. The experiment exactly matched aligned, bitwise, and
`math/big` selection over the pathological and boundary cases, exhaustive
reduced moduli, and an additional 8,192 deterministic full-size challenges.

It did not produce a meaningful speedup. Five repeated one-second runs were:

| Mode | Range | Median |
| --- | ---: | ---: |
| aligned | 63.57-64.99 us | 63.94 us |
| exact-verified lookahead | 63.89-64.35 us | 64.11 us |

The sub-percent difference is noise and slightly favors the simpler aligned
path at the median. `SelectFixed` therefore continues to use aligned division;
lookahead remains an unexported research comparison. Preserving every
principal and parity-aware intermediate row leaves too little quotient work
for batching to repay proposal generation and verification. A future batching
attempt should start only if the candidate policy changes with a fresh proof,
or if a platform profile materially differs. Exact signed-integer point
multiplication remains the larger missing HEEA component.

## Principal-row Euclidean selector checkpoint

`SelectEuclidPrincipal` tests whether restricting the hot selector to
principal Euclidean rows can replace the power-of-two shift/subtract walk. It
uses exact fixed-width division, exact signed coefficient updates, a 384-step
defensive cap that always falls back to ordinary verification, and the full
unit-multiplier admission check. A verified quotient-lookahead variant reuses
only proposals checked against the complete 256-bit operands.

This is a negative performance checkpoint under the measured regime, not a
production candidate. On Apple M4 Pro with Go on Darwin/arm64, five two-second
runs measured an admitted W128 input at approximately:

| Selector | Time | Allocation |
| --- | ---: | ---: |
| existing shift/subtract | 4.75-4.80 us | 0 |
| principal exact divider | 4.96-5.18 us | 0 |
| principal verified lookahead | 4.79-4.87 us | 0 |

On 8,192 independent deterministic challenges, W128 fallback counts were
1,387 for principal rows, 1,245 for shift/subtract, and 908 for the exhaustive
fixed-width oracle. At W132 they were 7, 7, and 5; all three admitted every
sample at W136.

The conclusion is specific: merely replacing single-bit cancellations with
ordinary Euclidean rows does not reach the required reducer budget and loses
some W128 coverage. Keep the code as a regime-tagged exact experiment, but do
not wire it into the HEEA verifier. A next attempt must amortize multiple exact
rows per wide update (for example a true half-GCD/Lehmer matrix or a proven
delayed-subtraction schedule), rather than changing only the row policy.

## Anza/TCHES approximate-quotient checkpoint

`SelectApproxQuotient` reproduces the control-flow shape of Algorithm 4,
`hEEA_approx_q`, from the TCHES 2025 paper. The implementation was
cross-checked against Anza's `solana-ed25519` 0.2.2
`curve25519_heea_vartime` routine. Narya does not copy its cofactored
admission rule: this experiment runs checked signed arithmetic modulo `8L`
and admits only a complete unit multiplier modulo `8L`.

The exactness result is positive. Deterministic edges, 4,096 random
challenges, signed-row determinant checks, and fuzzing preserve

```text
rho = tau*k (mod 8L),  gcd(tau,8L)=1.
```

The performance and coverage result is negative. On Apple M4 Pro with Go on
Darwin/arm64, three one-second samples over three challenges measured roughly:

| Width | Approximate quotient | Existing shift/subtract | Principal Euclid |
| --- | ---: | ---: | ---: |
| 128 | 6.52-7.51 us | 4.82-4.99 us | 5.84-6.08 us |
| 132 | 6.32-6.87 us | 4.75-5.07 us | 5.61-5.84 us |
| 136 | 6.10-6.14 us | 4.56-4.78 us | 5.42-6.00 us |

All rows allocated zero bytes. Over 8,192 independent challenges, W128
fallback counts were 1,410 for approximate quotient, 1,246 for the existing
shift/subtract selector, and 927 for the exhaustive fixed oracle; all three
admitted every W136 sample. Signed remainders and checked five-limb updates
cost more than Narya's positive-remainder walk without recovering coverage.
Keep the source as a regime-tagged exact comparison. Anza's reported verifier
gain is for a modulo-`L`, cofactor-cleared ZIP-215 equation and cannot promote
this stricter modulo-`8L` reducer.
