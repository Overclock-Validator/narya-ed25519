# Zen 4 HEEA matrix-fusion gate — 2026-07-26

Implementation and benchmark commit: `69e83747b6c38b4c9721403459e79ff2b61ec488`.

This is research code. It is not imported by signature verification and has no
backend-dispatch path.

The benchmark compares the fused Lehmer matrix application with the retained
four-`combine320` reference in the same binary, on the same 512 canonical
challenges, using a Ryzen 7 PRO 8700GE, Go 1.26.4, one pinned core, the
performance governor, and `GOMAXPROCS=1`.

| boundary | fused median | reference median | change |
| --- | ---: | ---: | ---: |
| one reachable matrix application | 327.35 ns | 415.4 ns | -21.2% |
| complete W128 selector | 3.647 us | 3.978 us | -8.3% |

Every row reports 0 B/op and 0 allocs/op. The complete selector and reference
also return byte-identical candidates over 60,000 deterministic challenges at
W128/W132/W136; the fused matrix helper is separately compared with the
four-combine implementation over 100,000 randomized signed/range cases.

The earlier 8.0--8.3 us Lehmer result came from a slower host-throughput regime
and must not be used as the before side of this change. The same-binary
3.978-to-3.647 us comparison is the valid algorithmic delta.

This is a useful reducer improvement, but not an HEEA integration gate. The
selector alone is still about 47% of the current 1232-byte, n=64 cold r51 cost
on this CPU, before coefficient preparation, the extra point/table work, the
transformed point equation, or ordinary-path fallback. HEEA remains
experimental until a complete exact verifier beats the ordinary path.

No machine addresses, account names, or local filesystem paths are recorded in
this artifact.
