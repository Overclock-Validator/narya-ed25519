# Exact constrained HEEA selector

This note records the proof and executable evidence for Narya's constrained
modulo-`8L` HEEA candidate problem. It is a research result, not a production
backend contract. HEEA remains opt-in test code and ordinary strict
verification remains the fallback.

## Problem

Let `L` be the Ed25519 prime-subgroup order, `N=8L`, and `0 <= k < L` the
reduced challenge. Define

```text
Lambda_k = {(rho,tau) in Z^2 : rho = tau*k (mod N)}.
```

The transformed strict equation is exact only when multiplication by `tau`
is injective on the complete Edwards group. Therefore `gcd(tau,N)=1` is the
admission condition; oddness alone is not the general theorem because the odd
coefficient `tau=L` kills the prime-order component.

For a candidate width `W`, the optimization target is

```text
M(k) = min max(abs(rho),abs(tau))
       over (rho,tau) in Lambda_k with gcd(tau,N)=1.
```

The fast path exists exactly when `bitlen(M(k)) <= W`.

In the Ed25519 domain, `(k,1)` is always feasible and has norm below `L`.
Consequently a global optimum is also below `L`; once `tau` is odd it cannot
be a nonzero multiple of the prime `L`. The implementation still checks the
full GCD as a defensive assertion.

## Constant-candidate theorem

Take the basis `(N,0),(k,1)` and compute an exact two-dimensional
Gauss-reduced basis

```text
b1=(r1,t1), b2=(r2,t2)
```

with

```text
norm2(b1) <= norm2(b2)
2*abs(dot(b1,b2)) <= norm2(b1).
```

Write `b2*` for the component of `b2` perpendicular to `b1`. Gauss reduction
gives

```text
norm2(b2*) >= (sqrt(3)/2)*norm2(b1).
```

Every lattice vector is `v=x*b1+y*b2`, and

```text
normInf(v) >= norm2(v)/sqrt(2)
           >= abs(y)*norm2(b2*)/sqrt(2).
```

If `t1` is odd, `b1` is feasible. If `t1` is even, basis unimodularity makes
`t2` odd and `b2` is feasible. In either case every vector with `abs(y)>=2`
has infinity norm strictly larger than that feasible basis vector. Hence an
optimum has `y` in `{-1,0,1}`. Negation preserves both norm and oddness, so
the `y=-1` family duplicates `y=1`.

The only candidates left are:

- `b1`, when `t1` is odd; and
- `v(x)=x*b1+b2` for an integer `x` of the parity making its `tau` odd.

For the second family,

```text
f(x)=max(abs(r1*x+r2), abs(t1*x+t2))
```

is convex and piecewise linear. Its real breakpoints are only

```text
-r2/r1
-t2/t1
-(r2-t2)/(r1-t1)
-(r2+t2)/(r1+t1),
```

omitting zero denominators. A discrete minimum over all integers, or over one
integer parity class, occurs at the nearest allowed integer below or above one
of those breakpoints. Thus at most eight breakpoint neighbors plus `b1` need
evaluation. The oracle also evaluates `x=0` defensively; after deduplication it
checks no more than ten vectors.

This proves that enumeration itself can be exact and bounded. It does **not**
prove that a chosen short width exists for every challenge.

## Bounded algorithm and validation

The independent oracle is `SelectExactGauss` in
`internal/heea8l/exact_gauss.go`. It:

1. performs exact Gauss reduction with a defensive 512-step cap;
2. validates `abs(det(b1,b2)) == N`;
3. validates both lattice congruences;
4. validates the Gauss postconditions;
5. enumerates the constant candidate set using integer division only;
6. selects the global minimum under deterministic tie-breaking; and
7. rechecks oddness and `gcd(tau,N)=1` before admission.

A cap or invariant failure is a selector failure and must route to ordinary
verification. It is never a signature accept/reject result.

`SelectExactGauss` deliberately uses `math/big`, allocates, and is not called
by a verifier. A future hot selector needs fixed-width signed coordinates,
512-bit norms/dot products, checked exact rounding, and an independent
congruence validator. The proof does not justify truncating an intermediate
or reducing coefficients of `A` or `R` modulo `L`.

`SelectExactGaussFixed` is the corresponding allocation-free experiment. It
uses Lehmer-batched EEA rows until the exact Euclidean-norm crossover, replays
the one crossing batch as elementary quotient steps, performs the bounded
Gauss finish, and then runs the same breakpoint finalizer. Its 512-bit
arithmetic and signed rounding are differentially tested against `math/big`.
It also revalidates both reduced basis vectors, their determinant, and the
selected congruence. This is intentionally proof-shaped code, not a promoted
hot path.

## Executable evidence

The tests provide independent layers:

- exhaustive brute-force optimum comparison for `N=8l`, thirteen small prime
  values of `l`, and every `0 <= k < l`;
- comparison with the older parity-aware EEA oracle over 8,192 full Ed25519
  challenges and fixed edge cases;
- direct tests of signed floor/ceil and parity rounding;
- basis determinant, congruence, and reducedness checks; and
- the two exact 252-bit regression vectors below.

The comparison intentionally checks the exact infinity norm, not only whether
both selectors happen to fit one of the configured width gates.

Run it with:

```sh
go test ./internal/heea8l -run 'TestExactGauss|TestNearestAllowed' -count=1
```

The deterministic one-million-challenge experiment now uses this oracle:

```sh
go run ./internal/heea8l/cmd/sample -samples 1000000 -workers 12
```

For domain `heea8l-sample-v1`, it exactly reproduced the earlier independent
EEA oracle's width histogram:

| Gate | Admitted | Fallback | Coverage |
| ---: | ---: | ---: | ---: |
| 128 | 888,299 | 111,701 | 88.829900% |
| 132 | 999,620 | 380 | 99.962000% |
| 136 | 999,998 | 2 | 99.999800% |

These are deterministic experiment counts, not a closed-form probability
claim. The new `math/big` oracle measured about 42--44 microseconds per random
challenge on the development M4, versus about 535--555 microseconds for the
older exhaustive EEA oracle. Neither timing is a production-selector result.

### Fixed-width target result

At implementation commit `50ce0f6`, on the pinned Zen 4 Ryzen 7 PRO 8700GE
with Go 1.26.4 and `GOMAXPROCS=1`, five two-second W132 samples measured:

| Selector | Median | Range | Allocation |
| --- | ---: | ---: | ---: |
| Exact fixed Gauss/breakpoint | 18.488 us | 18.413--18.495 us | 0 B/op |
| Heuristic Lehmer principal-row | 1.833 us | 1.833--1.836 us | 0 B/op |

The exact selector is slower than an entire optimized Narya batch
verification before any transformed point arithmetic is charged. Even the
same fixed selector without its independent congruence validations remained
far outside the reducer budget on the development machine. Exact enumeration
therefore closes a correctness gap but fails the performance gate. It is not
connected to HEEA verification or backend dispatch.

Run the comparison with:

```sh
taskset -c 2 env GOMAXPROCS=1 go test ./internal/heea8l -run '^$' \
  -bench '^(BenchmarkSelectExactGaussFixed|BenchmarkSelectLehmer)$' \
  -benchmem -benchtime=2s -count=5
```

## Width fallback is intrinsic

Exact enumeration removes solver-induced misses, but a short candidate does
not exist for every `k`.

For

```text
k0=(N-2)/10,
```

the relation implies

```text
2*tau + 10*rho = odd*N.
```

Therefore `max(abs(rho),abs(tau)) >= ceil(N/12)`. The pair constructed in the
test reaches that bound, so the optimum is exactly `ceil(N/12)`, which has 252
bits.

For the simpler regression `k=L-1`, an exact optimum is

```text
tau=(L+5)/2, rho=(L-5)/2,
```

again 252 bits. Conversely, every `k<L` has a feasible pair below `2^252`, so
252 is the universal worst-case width.

At `W=132`, the deterministic experiment observed a 0.038% ordinary-fallback
tail. A signer controls the hashed message and nonce and can grind for this
tail, so an adversary can make fallback common even though it is rare for
uniform challenges. Production routing must therefore classify and compact
candidate and fallback lanes before curve arithmetic; one wide lane must not
force an otherwise-fast SIMD group through the ordinary equation.

The accurate description is:

> an exact opportunistic fast path with bounded ordinary fallback.

It is not a universally half-width verifier.

## Exact equation boundary

For an admitted pair,

```text
rho = tau*k (mod 8L), gcd(tau,8L)=1
```

implies

```text
[tau*s]B - [tau]R - [rho]A = [tau]([s]B-R-[k]A),
```

and the transformed point is the identity exactly when the original error is
the identity. Multipliers of `A` and `R` use exact signed-integer semantics.
Only `tau*s` may be reduced modulo `L`, because `B` has order `L`.

All non-arithmetic strict checks remain mandatory, including canonical `S`,
small-order rejection, permissive original-byte hashing of `A`, and the
canonical-`R` effect of the terminal encoded comparison.

The reduction machinery is informed by the dimension-two lattice-reduction
line used in Pornin's optimized verification work and by ElSheikh et al.'s
HEEA scalar-halving work. The odd-coset infinity-norm finalizer above is a
Narya-specific derivation for the cofactorless full-group equation; the
executable oracles, rather than provenance alone, are its acceptance evidence.
