# Zen 5 intermediate-P2 x8 doubling — 2026-07-29

This bundle records the native gate for implementation commit `d11db24` on an
AMD Ryzen 7 9700X (Zen 5), Linux amd64, Go 1.26.4, the performance governor,
one fixed physical core, and `GOMAXPROCS=1`. The exact implementation parent is
`30b5935`.

The radix-32 variable-base loop performs five consecutive point doublings
before each possible addition. The former schedule materialized complete
extended coordinates `(X,Y,Z,T)` after every doubling even though the next
doubling reads only `(X,Y,Z)`. The candidate uses a distinct P2 Go type with no
`T` field for the first four results and returns to complete P3 on the fifth.
An incomplete point therefore cannot be passed to an addition by construction.

All table values are microseconds per signature unless the unit is explicitly
`ns/op`. Lower is better.

## Component results

| component | complete P3 | intermediate P2 | change |
|---|---:|---:|---:|
| final-product leaf | 22.33 ns/op | 16.81 ns/op | -24.7% |
| variable-base evaluator | 19,107 ns/op | 18,766 ns/op | -1.78% |

Each median contains six one-second samples. The final-product leaf removes one
of four normalized field multiplications on four of every five doublings; the
complete evaluator also includes table preparation, recoding, selection,
addition, and the unchanged doubling stages.

## Balanced complete-verifier gate

The path order was P2/P3/P3/P2. Each median contains twelve one-second samples:

| batch | bytes | complete P3 | intermediate P2 | change |
|---:|---:|---:|---:|---:|
| 8 | 1,232 | 4.1205 | 4.0615 | -1.43% |
| 8 | 4,096 | 4.8630 | 4.7995 | -1.31% |
| 64 | 1,232 | 3.9060 | 3.8480 | -1.48% |
| 64 | 4,096 | 4.6580 | 4.5930 | -1.40% |

The initial all-size pass also improved 200-byte verification by about 1.2% at
n=8 and 1.4% at n=64. A discontinuity in its n=64/4,096 candidate samples was
not accepted; the balanced rerun above is the evidence for that row.

## Registered public cold matrix

The registered public API was rerun after promotion with ten two-second
samples. Medians are recorded in the repository README and raw output is
`public-cold.txt`. Every sample reported zero allocations and zero internal-
fault fallbacks.

## Correctness and refinement gates

- the three-product P2 assembly leaf versus the complete four-product leaf over
  10,000 exact-representation inputs, including zero and maximum u52 limbs;
- 2,048 five-doubling chains comparing P2 after every intermediate doubling
  and complete P3 bit-for-bit at the addition boundary;
- all 256 active masks and four negative-mask patterns through the complete
  variable-base evaluator;
- poisoned scratch, in-place P2 operation, zero-allocation component and
  complete-verifier gates;
- both supported acceptance profiles and counts 8/9/16/64/65 through the
  complete candidate pipeline;
- compile-time Go-to-assembly assertions for the 960-byte P2 size and the
  fixed Y/Z store offsets;
- explicit Zen 5/Zen 4/no-IFMA/unmeasured-family CPU-policy tests; and
- full local and native `go test -count=1 ./...`, plus local `go vet ./...`.

## Files

- `component.txt`: final-product and variable-base component A/B.
- `complete-all-sizes.txt`: initial n=8/n=64, 200/1,232/4,096-byte A/B.
- `complete-abba.txt`: balanced accepted complete-verifier gate.
- `public-cold.txt`: registered public cold matrix.
- `commands.txt`: reproducible commands without machine-specific paths.
- `SHA256SUMS`: hashes for every other artifact in this directory.
