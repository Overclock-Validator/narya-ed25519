# Zen 5 final review benchmark

This directory pins the README performance tables to commit
`3f7b6885876520f2434e0a89248e106ed144985a`.

All rows were measured on one Ryzen 7 9700X host with Go 1.26.4. Serial
benchmarks used one pinned physical core and `GOMAXPROCS=1`. Multicore rows
used CPUs 0 through N-1, which are distinct physical cores on this host; SMT
siblings were not included. Every displayed result is the median of six
two-second samples.

`public-cold-warm.txt` contains the exported cold and 64-promoted-key cache
APIs at message sizes 200, 1,232, and 4,096 and widths 1, 2, 4, 8, and 64.
`cross-library.txt` contains the independent-equation 1,232-byte comparison.
`multicore.txt` contains n=4 and n=8 scaling across 1, 2, 4, 6, and 8 physical
cores. No aggregate signature equation is used anywhere in this bundle.

Every timed Narya row reported zero allocations and zero internal-fault
fallbacks. SDE and hardware correctness gates are separate from this
performance-only bundle.
