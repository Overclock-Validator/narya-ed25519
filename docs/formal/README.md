# Formal and proof-oriented evidence

This directory separates mathematical and machine-checkable evidence from
performance records under `docs/results/` and design notes in `docs/`.

The evidence has different strengths. Each document must identify its proof
boundary rather than using "proved" as an undifferentiated label:

- **Lean theorem:** checked by the pinned Lean toolchain, within the definitions
  imported by the theorem;
- **executable certificate:** exact or arbitrary-precision enumeration checked
  by a deterministic program, within its declared grammar and transfer rules;
- **differential test:** agreement on a finite corpus or generated sample;
- **native assembly gate:** evidence that the compiled implementation agrees
  with its oracle on tested inputs and hardware;
- **audit:** independent review of the implementation and its proof harness.

None of the current evidence decodes the final x86-64 binary and proves that
every machine instruction refines a mathematical Ed25519 specification. The
assembly remains unaudited, and automatic SIMD dispatch therefore remains
disabled.

## Index

- [`EDWARDS_WHOLE_WINDOW_RANGE_CERTIFICATE.md`](EDWARDS_WHOLE_WINDOW_RANGE_CERTIFICATE.md)
  records the bounded whole-window search, its exact range certificate, the
  assembly mapping, mutation gates, and the native performance rejection.
- [`certificates/edwards_whole_window_range_certificate.json`](certificates/edwards_whole_window_range_certificate.json)
  is the compact range certificate consumed by human and test review.
- [`certificates/edwards_whole_window_verification.json`](certificates/edwards_whole_window_verification.json)
  records the symbolic, differential, closed-form, and mutation results.
- [`../../tools/formal/edwards_whole_window_search.py`](../../tools/formal/edwards_whole_window_search.py)
  deterministically regenerates those artifacts.

The broader radix-51 assurance map, including the remaining source-to-machine
refinement gap, is in [`../R51_ARITHMETIC_ASSURANCE.md`](../R51_ARITHMETIC_ASSURANCE.md).

