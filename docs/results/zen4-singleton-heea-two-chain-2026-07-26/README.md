# Zen 4 singleton HEEA two-chain checkpoint

This checkpoint measures the test-only singleton HEEA construction added at
commit `f92e868`. It evaluates the exact modulo-`8L` transformed equation as
two coordinate-parallel point chains in one ZMM register. `R` and `A` odd-
multiple tables are also built together in the two ZMM halves. Production
dispatch is unchanged.

Environment:

- AMD Ryzen 7 PRO 8700GE (Zen 4)
- Linux/amd64, Go 1.26.4
- performance governor
- one pinned CPU, `GOMAXPROCS=1`
- 1-second benchmark samples, five repetitions
- 1232-byte messages, zero allocations

Command:

```sh
taskset -c 2 env GOMAXPROCS=1 go test -run '^$' \
  -bench '^BenchmarkExperimentalPackedHEEAStrictVerifierX8$' \
  -benchmem -benchtime=1s -count=5 ./internal/r51x5
```

Median results, in microseconds per signature:

| Input shape | Ordinary packed x4 | W128 HEEA | W132 HEEA | W136 HEEA |
| --- | ---: | ---: | ---: | ---: |
| admitted fixture | 17.831 | 23.191 (+30.1%) | 22.941 (+28.7%) | 23.875 (+33.9%) |
| deterministic 256-signature corpus | 18.780 | 24.654 (+31.3%) | 24.235 (+29.0%) | 25.016 (+33.2%) |

Corpus admission was 83.20% at W128, 99.61% at W132, and 100.0% at
W136. Fallbacks reuse the already-decoded ordinary packed path. The focused
native differential covers valid and equation-invalid signatures, exact
mixed-order signed coefficients, paired versus sequential table construction,
ordinary fallback, and zero allocations.

This is a negative Zen 4 result. It does **not** close the construction on
Zen 5: Zen 4 executes a ZMM IFMA operation through two 256-bit passes, whereas
the design exists specifically to fill Zen 5's native 512-bit datapath with
two independent singleton chains. A Zen 5 complete-verifier rerun is required
before deciding whether to retain only the proof experiment or pursue a
production singleton path.
