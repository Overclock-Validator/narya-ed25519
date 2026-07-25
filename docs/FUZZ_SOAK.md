# Zen 4 differential fuzz soak

The short fuzz rounds in `scripts/zen4-gate.sh` are smoke tests. They do not
constitute the prolonged generic and IFMA differential fuzzing required before
automatic SIMD dispatch or release sign-off. The r51 backend is registered for
explicit use, but remains outside automatic selection. Run the separate soak
on the Ryzen 7 PRO 8700GE after the ordinary and optional candidates compile
there:

```text
./scripts/zen4-fuzz-soak.sh ../narya-zen4-fuzz-run-001 2h 8 0-7
```

The duration is **per target**. The example therefore schedules roughly ten
hours of fuzzing, plus correctness setup, across:

1. the generic/profile/cache/batch differential verifier;
2. the forced complete r51 x4/x8 pipeline;
3. the exact modulo-`8L` HEEA selector;
4. fixed scalar reduction;
5. native multi-buffer SHA-512.

Choose a CPU set containing the physical cores intended for the soak; do not
blindly assume `0-7` is the desired topology. `NARYA_FUZZ_DURATION`,
`NARYA_FUZZ_WORKERS`, and `NARYA_FUZZ_CPUSET` provide equivalent defaults.

The runner requires Linux x86-64, AVX-512 IFMA, a fresh result directory
outside the worktree, and by default the exact 8700GE model. A non-release IFMA
host requires `NARYA_ZEN4_ALLOW_NON_RELEASE_CPU=1` and produces
`state=diagnostic-complete`, never release evidence. Required hardware tests
must execute without a skip before fuzzing begins.

The bundle starts as `state=incomplete`, hashes all tracked and untracked
nonignored source files before and after the run, records CPU/affinity/Go/Git
configuration, retains one log per target, and finishes with `SHA256SUMS` only
if every target passes and the source tree remains unchanged. A crash or
predicate mismatch leaves the bundle incomplete and `go test` preserves the
minimized failing input under the corresponding `testdata/fuzz` directory.
