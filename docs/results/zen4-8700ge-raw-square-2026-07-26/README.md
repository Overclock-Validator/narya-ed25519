# Zen 4 raw-square dispatch checkpoint

This directory records the public benchmark snapshot and the two dispatch
decisions for implementation commit
`c31522d80c2410fec42e60e300c1750b0c087d6c`.

Environment:

- AMD Ryzen 7 PRO 8700GE (Zen 4), performance governor;
- Go 1.26.4, linux/amd64;
- one pinned physical core and `GOMAXPROCS=1` for serial measurements;
- six 750-millisecond samples per row;
- public Narya rows report zero allocations and zero internal-fault fallbacks.

The same-binary raw-square A/B retained the dedicated folded-u61 x8 schedule
at every measured point:

| message bytes | n | general square, us/sig | raw square, us/sig | change |
| ---: | ---: | ---: | ---: | ---: |
| 200 | 8 | 7.810 | 7.571 | -3.1% |
| 200 | 64 | 7.619 | 7.374 | -3.2% |
| 1232 | 8 | 8.074 | 7.838 | -2.9% |
| 1232 | 64 | 7.855 | 7.628 | -2.9% |
| 4096 | 8 | 8.918 | 8.689 | -2.6% |
| 4096 | 64 | 8.727 | 8.495 | -2.7% |

The half-full x8 gate remained decisively negative:

| message bytes | n | x4, us/sig | half-full x8, us/sig |
| ---: | ---: | ---: | ---: |
| 200 | 4 | 9.913 | 15.785 |
| 1232 | 4 | 10.680 | 16.750 |

Files:

- `public-cold.txt`: exported cold r51 matrix;
- `public-warm.txt`: exported 64-key promoted-cache matrix;
- `compare-1232.txt`: same-binary Narya, standard-library, and Oasis rows;
- `parallel.txt`: public Narya scaling at 1, 2, 4, and 8 physical cores;
- `raw-square-ab.txt`: same-binary general/raw-square decision gate;
- `partial-x8-n4.txt`: same-binary x4/half-full-x8 decision gate;
- `commands.txt`: exact benchmark and correctness commands;
- `environment.txt`: non-identifying build and CPU environment;
- `SHA256SUMS`: checksums for this evidence set.

The raw output contains occasional isolated first-sample frequency transitions.
Published tables use the median of six samples, so those transitions do not
select a dispatch policy.
