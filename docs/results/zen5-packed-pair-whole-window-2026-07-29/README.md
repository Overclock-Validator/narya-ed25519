# Zen 5 packed-pair and whole-window checkpoint

This directory pins the final single-core README tables and the last bounded
performance experiment before the safety freeze.

## Supported live-path result

Commit `bbc6c2194438090b0c48ac9bd95eab6b92602d6f` adds the Zen 5 strict n=2
dispatch: one complete coordinate-packed verification equation occupies each
256-bit half of a ZMM register. The halves do not exchange point or scalar
state, and verdict zero remains input zero. `cold-warm.txt` is the exported
public API matrix; `cross-library.txt` is the independent-equation comparison.
Every Narya row reported zero allocations and zero internal-fault fallbacks.

The direct paired-versus-two-singletons gate, seven two-second samples per row,
measured these medians:

| message bytes | two singletons µs/signature | packed pair µs/signature | change |
| ---: | ---: | ---: | ---: |
| 200 | 12.92 | 11.25 | -12.9% |
| 1,232 | 13.47 | 11.70 | -13.1% |
| 4,096 | 15.73 | 14.06 | -10.6% |

Public-wrapper values differ because they include dispatch and use an isolated
release benchmark binary. The README reports those public values rather than
substituting the direct gate.

## Last performance experiment

Commit `5d8a3e4049f565e807e4b8e130de1ae55c3c429b` implements the independently
certified completed-coordinate boundary described in
[`../../formal/EDWARDS_WHOLE_WINDOW_RANGE_CERTIFICATE.md`](../../formal/EDWARDS_WHOLE_WINDOW_RANGE_CERTIFICATE.md).
The nine-sample rerun at `72d7fc1` measured medians of 19.324 µs/x8 group for
the materialized boundary and 19.221 µs/x8 group for the candidate, a **0.53%**
prepared-loop improvement. Both rows were allocation-free.

That result is retained because sub-1% gains remain useful evidence, but it is
not dispatched. The limited complete-loop gain does not justify enlarging the
supported assembly surface immediately before audit.

## Safety gates

`validation.txt` records the full suite, race detector, AMD-policy build, and
vet run at the live-path benchmark commit. The later targeted native run at
`72d7fc1` additionally passed:

- the complete CCTV and Wycheproof corpora through the exact public n=2 route;
- per-lane valid/invalid mixtures and result-index preservation;
- injected native faults with generic recomputation and fault accounting;
- packed-pair zero-allocation and direct singleton differentials;
- whole-window maximum-bound, exact-representation, active-mask, randomized,
  and zero-allocation gates.

The broader final suite is rerun after documentation-only changes and recorded
separately before the audit handoff SHA.

