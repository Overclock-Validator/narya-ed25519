# Zen 4 HEEA matrix-fusion gate — 2026-07-26

Final implementation and benchmark commit:
`c964b84f80badb630bdd97c0fc385d9316282176`.

This is research code. It is not imported by signature verification and has no
backend-dispatch path.

The benchmark compares the fused Lehmer matrix application with the retained
four-`combine320` reference in the same binary, on the same 512 canonical
challenges, using a Ryzen 7 PRO 8700GE, Go 1.26.4, one pinned core, the
performance governor, and `GOMAXPROCS=1`.

The work landed in three independently tested steps:

| boundary / checkpoint | median | preceding median | change |
| --- | ---: | ---: | ---: |
| matrix: one limb pass (`69e8374`) | 327.35 ns | 415.4 ns reference | -21.2% |
| selector: one limb pass (`69e8374`) | 3.647 us | 3.978 us reference | -8.3% |
| matrix: direct signed-pair combine (`24c9c17`) | 156.05 ns | 327.35 ns | -52.3% |
| selector: direct signed-pair combine (`24c9c17`) | 2.949 us | 3.647 us | -19.1% |
| selector: fused exact coefficient step (`c964b84`) | 2.698 us | 2.949 us | -8.5% |

Every row reports 0 B/op and 0 allocs/op. The complete selector and reference
also return byte-identical candidates over 60,000 deterministic challenges at
W128/W132/W136; the fused matrix helper is separately compared with the
four-combine implementation over 100,000 randomized signed/range cases.

The earlier 8.0--8.3 us Lehmer result came from a slower host-throughput regime
and must not be used as the before side of this change. The same-binary
3.978-to-3.647 us comparison is the valid algorithmic delta.

This is a useful reducer improvement, but not an HEEA integration gate. The
selector alone is still about 35% of the current 1232-byte, n=64 cold r51 cost
on this CPU, before coefficient preparation, the extra point/table work, the
transformed point equation, or ordinary-path fallback. HEEA remains
experimental until a complete exact verifier beats the ordinary path.

No machine addresses, account names, or local filesystem paths are recorded in
this artifact.
