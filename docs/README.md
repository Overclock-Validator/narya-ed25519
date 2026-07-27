# Narya documentation

The documentation is grouped by purpose so measured results, implementation
designs, and proof obligations are not mistaken for one another.

## Architecture and design

Implementation structure, algorithm choices, and experiment designs:

- [r51 throughput backend](architecture/R51_THROUGHPUT_BACKEND.md)
- [double-scalar multiplication experiments](architecture/DSM_EXPERIMENTS.md)
- [fixed-base comb](architecture/FIXED_BASE_COMB.md)
- [paired decompression](architecture/PAIRED_DECODE.md)
- [signature preparation](architecture/SIGPREP.md)
- [multi-buffer SHA-512](architecture/SHA512_MULTIBUFFER.md)
- [scalar reduction](architecture/SCALAR_REDUCTION.md)

## Proofs and formal reasoning

Mathematical claims, exact predicate boundaries, and arithmetic contracts:

- [radix-51 IFMA arithmetic assurance](proofs/R51_ARITHMETIC_ASSURANCE.md)
- [Ed25519 security-proof mapping](proofs/PROVABLE_SECURITY.md)
- [strict aggregate-batching boundary](proofs/STRICT_AGGREGATE_BATCHING.md)
- [HEEA research track](proofs/HEEA.md)
- [exact constrained HEEA selector](proofs/HEEA_EXACT_SELECTOR.md)
- [formalization backlog](proofs/FORMALIZATION_BACKLOG.md)

These notes distinguish proved identities from measured performance and from
open research assumptions. Source comments should link here when a range,
alias, or predicate invariant needs more explanation than belongs beside the
instruction sequence.

## Performance

Benchmark methodology, machine-specific reports, and optimization findings:

- [benchmarking methodology](performance/BENCHMARKING.md)
- [Zen 4 checkpoint](performance/ZEN4_8700GE_2026-07-24.md)
- [Zen 5 checkpoint](performance/ZEN5_9700X_2026-07-25.md)
- [performance findings](performance/PERF_FINDINGS_2026-07-25.md)
- [historical cross-library comparison](performance/CROSS_LIBRARY_ZEN4_2026-07-24.md)

Raw command output, environment captures, checksums, and dated A/B runs remain
under [`results/`](results/). Those artifacts are evidence, not supported API
documentation, and may describe older commits or experimental paths.

## Audits and validation

- [review notes](audits/REVIEW-NOTES.md)
- [differential fuzz soak](audits/FUZZ_SOAK.md)

## Reproducibility

Reproduction instructions live beside each dated result set and are indexed by
[`results/README.md`](results/README.md). New evidence directories should carry
the implementation commit, machine/OS/toolchain description, exact commands,
raw output, and a checksum manifest.
