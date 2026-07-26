# Zen 4 normalized-multiply fold A/B

This result closes the current `VPMULLQ` versus shift/add question for the
normalized r51 x8 multiply on AMD family 19h. It is a complete public-verifier
measurement, not a primitive-only estimate.

The control is implementation commit
`c964b84dfae206ae939784e42e690579b2149324`, whose five multiplication-by-19
folds use AVX-512DQ `VPMULLQ`. The candidate applies exactly the assembly diff
from `d9ddf5305fd163db37edcb31f1cd0e89ffcf7451` to that control, replacing the
five folds with shift/add sequences. No other source differs.

Pinned Ryzen 7 PRO 8700GE results at 1,232 message bytes:

| batch | `VPMULLQ` median, us/signature | shift/add median, us/signature | shift/add regression |
|---:|---:|---:|---:|
| 8 | 7.889 | 8.166 | +3.5% |
| 64 | 7.674 | 7.965 | +3.8% |

Every timed row reported 0 B/op, 0 allocs/op, and zero internal fault
fallbacks. Two control n=64 samples show a frequency/scheduling excursion; the
median remains conservative and the other six samples cluster at
7.669--7.676 us/signature.

Verdict: retain `VPMULLQ` on the current Zen 4 x8 verifier. The older
port-pressure argument for shift/add does not survive a complete-pipeline A/B
after the later fusion and scheduling changes. Remeasure only after a material
multiply/point-loop rewrite or on another microarchitecture.

