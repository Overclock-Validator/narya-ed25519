# Decoded-A Cache Gate — 2026-07-25

This directory records the complete-cache decision for Narya's forced r51
backend. The candidate stores an immutable 192-byte record containing the exact
original public-key bytes and its permissively decoded Edwards point. A hit
skips only A decompression. Strict byte checks, the original challenge hash,
scalar multiplication, and final equality are unchanged.

The final policy is intentionally hardware-specific:

- AMD family 1Ah / Zen 5: enable the decoded-A Cache tier;
- Zen 4: report `supportsPrecomp() == false` and use the ordinary raw r51 path.

Automatic backend selection remains `generic` on both CPUs.

## Commits

- `9ca01ecee3eeb0c89edc2b6b5e762dd5f8a003cc`: zero-copy immutable entry and
  single-lookup/valid-miss-only admission implementation used for the complete
  positive and negative message-size A/B;
- `7983032`: hardware gate enabling the tier only on native-wide Zen 5;
- `df90de2`: final Zen 5 tests and hit-density benchmark;
- `9aeff61`: corrected Zen 4 public-raw Cache-bypass benchmark control.

## Result

Median microseconds per signature, `n=64`, one pinned core,
`GOMAXPROCS=1`, performance governor, three 750 ms samples:

| CPU | message | cold | 100% decoded hits | change |
| --- | ---: | ---: | ---: | ---: |
| Ryzen 7 9700X (Zen 5) | 64 | 7.985 | 7.205 | -9.8% |
| Ryzen 7 9700X (Zen 5) | 200 | 8.016 | 7.250 | -9.6% |
| Ryzen 7 9700X (Zen 5) | 1232 | 8.256 | 7.497 | -9.2% |
| Ryzen 7 PRO 8700GE (Zen 4) | 64 | 13.73 | 13.87 | +1.0% |
| Ryzen 7 PRO 8700GE (Zen 4) | 200 | 13.85 | 13.98 | +0.9% |
| Ryzen 7 PRO 8700GE (Zen 4) | 1232 | 14.61 | 14.73 | +0.8% |

The negative Zen 4 rows include lookup/admission and therefore decide the
public Cache gate; the arithmetic-only decoded-point seam remains available as
a differential oracle.

At 1232 bytes on Zen 5, the final density gate measured:

| batch | cold | 25% | 50% | 75% | 100% |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 8 | 8.579 | 8.516 | 8.514 | 8.506 | 7.856 |
| 17 | 9.249 | 9.187 | 9.190 | 9.187 | 8.570 |
| 64 | 8.286 | 8.019 | 7.873 | 7.729 | 7.582 |

Rows below 100% at `n=8/17` deliberately use the cold arithmetic path after
lookup: pre-gate measurements showed that mixed hit packing was slower there.
The supported prepared-path rule is all hits for chunks below 64 items, or at
least 25% hits for a complete 64-item chunk.

Every timed row reported zero allocations and zero native fault fallbacks.
The Zen 5 correctness run covered exact-key binding, both verification
profiles, widths through 65, invalid-equation non-admission, narrow admission,
and zero-allocation hits. The Zen 4 run pins the hardware gate and shows the
cache-specific tests skipping by design.

`zen4-bypass.txt` compares two differently laid-out Go wrapper closures that
both converge on the same raw method. As in the established public-wrapper
gate, code layout can move those rows by several percent in either direction;
use it to verify routing, zero allocations, and zero faults, not as a claim
that adding a wrapper accelerates arithmetic.

