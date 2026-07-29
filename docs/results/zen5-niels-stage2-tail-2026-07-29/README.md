# Zen 5 Niels Stage-2 tail continuation — neutral result

Regime: registered native-x8 cold verification on an AMD Ryzen 7 9700X,
1,232-byte messages, one pinned physical core, performance governor,
`GOMAXPROCS=1`, Go 1.26.4. The control includes doubling Stage-2 tail
continuation commit `f1de35e`.

The candidate applied the same bit-identical continuation that won on point
doubling to projective-Niels addition. Four raw products already tail-entered
Niels Stage 2. The candidate additionally tail-entered the existing final
products, removing the Stage-2 return/call and intervening `VZEROUPPER`.

Native exact-representation tests confirmed that the raw workspace, carried
`E/F/G/H`, final `X/Y/Z/T`, input preservation, alias behavior, and allocation
count were identical to the split sequence.

Eight alternating two-second phases measured the following medians in
microseconds/signature:

| width | split Stage2/final | tail continuation | change |
|---:|---:|---:|---:|
| 8 | 4.008 | 4.007 | about -0.03% |
| 64 | 3.778 | 3.775 | about -0.08% |

The sample ranges overlap completely, so this is not a measurable verifier
gain. The prototype was removed rather than adding assembly and ABI surface.
The useful negative result is that the continuation mechanism pays at the
roughly 255-doubling frequency but not at the roughly 51-addition frequency;
the raw-products-to-Niels-Stage-2 boundary was already fused before this test.
