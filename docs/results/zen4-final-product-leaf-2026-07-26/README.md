# Zen 4 x8 final-product leaf experiment

Commit `6787cc5` expanded the existing normalized r51 x8 multiply four times
inside one assembly leaf for the Edwards output products
`(E*F, G*H, F*G, E*H)`. The candidate is representation-identical to four
calls of `ifmaMulNormalizedUncheckedX8`; it shares one Go/assembly transition
and one final `VZEROUPPER`.

Pinned Ryzen 7 PRO 8700GE, Go 1.26.4, one core, `GOMAXPROCS=1`:

| measurement | four calls / before | one leaf / after | change |
|---|---:|---:|---:|
| isolated four products | 50.42 ns | 50.06 ns | -0.7% |
| public strict, msg=1232, n=8 | 7.887 us/signature | 7.853 us/signature | -0.4% |
| public strict, msg=1232, n=64 | 7.683 us/signature | 7.661 us/signature | -0.3% |

All native exact-representation tests passed, the complete `internal/r51x5`
and `ed25519` suites passed, and every timed row reported 0 B/op, 0 allocs/op,
and zero internal-fault fallbacks.

Verdict: do not route production through the 3.2 KiB duplicated assembly leaf
for a sub-0.5% complete-verifier gain. The helper and exact differential remain
as a regime-tagged experiment; normal builds dead-strip the unreferenced leaf.
Remeasure after a material multiply ABI or scheduling change.

