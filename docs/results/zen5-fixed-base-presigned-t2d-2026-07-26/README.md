# Zen 5 fixed-base pre-signed 2dT gate

This directory records the fixed-base selector gate at implementation commit
`afe5c65aed425cd37a89d7ce4af3e2beff5c32b1` on an AMD Ryzen 7 9700X,
Go 1.26.4, one pinned physical core, the performance governor, and
`GOMAXPROCS=1`.

The process-shared radix-256 B table now retains the negative `2dT` coordinate
for each positive affine cached point. Public signed-digit selection still
chooses the same entry and swaps `Y+X` with `Y-X`; it selects the retained
negative coordinate instead of invoking field negation online. Table payload
increases from 245,760 to 327,680 bytes. This is one shared fixed-base cost,
not per-key state.

The exact parent baseline is in
`../zen5-fixed-base-affine-stage2-2026-07-26/fixed-base.after.txt` and
`../zen5-fixed-base-affine-stage2-2026-07-26/cold.txt`.

| measurement | parent median | candidate median | delta |
| --- | ---: | ---: | ---: |
| fixed-base x4 radix-256 group | 4,068 ns | 3,576.5 ns | -12.1% |
| fixed-base x8 radix-256 group | 6,247.5 ns | 5,171.5 ns | -17.2% |
| public cold n=4, msg=1232 | 9.274 µs/signature | 9.139 µs/signature | -1.5% |
| public cold n=8, msg=1232 | 4.995 µs/signature | 4.850 µs/signature | -2.9% |
| public cold n=64, msg=1232 | 4.794 µs/signature | 4.673 µs/signature | -2.5% |

All candidate rows report zero allocations and zero internal-fault fallbacks.
The complete native repository suite passed before admission. A direct test
checks every retained coordinate against an independently recomputed scalar
negation; the existing scalar/IFMA, torsion, active-mask, x4/x8, and
zero-allocation differentials remain unchanged.

- `fixed-base.after.txt`: ten one-second fixed-base kernel samples.
- `public.after.txt`: ten one-second public-API samples at n=4/8/64.
- `commands.txt`: exact benchmark commands.
- `environment.txt`: benchmark environment without machine access details.
- `SHA256SUMS`: checksums for all evidence files except itself.
