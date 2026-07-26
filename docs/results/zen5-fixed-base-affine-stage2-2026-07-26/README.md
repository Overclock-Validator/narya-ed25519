# Zen 5 fixed-base affine Stage-2 snapshot

This directory records the public benchmark snapshot used by the README after
the x4 and x8 fixed-base affine cached-add Stage-2 changes at implementation
commit `fd117ae8c80024931d296d3a8b8298380494dde5`.

The measurements used the exported forced-r51 APIs, a single pinned physical
core, `GOMAXPROCS=1`, Go 1.26.4, and the performance governor. Timing cells are
microseconds per signature. Every timed Narya row reported zero allocations
and zero internal-fault fallbacks.

- `cold.txt`: cold `VerifyBatchStrict`, ten one-second samples.
- `warm.txt`: 64-key promoted `Cache.VerifyBatchStrict`, ten one-second
  samples. The 64 immutable A6/r9 tables total 1,243,136 bytes.
- `compare-1232.txt`: Narya, Go standard library, and curve25519-voi at 1232
  message bytes, six one-second samples.
- `fixed-base.before.txt`: fixed-base comb kernel at parent commit `f80de02`,
  eight one-second samples.
- `fixed-base.after.txt`: fixed-base comb kernel at `fd117ae`, eight one-second
  samples.
- `commands.txt`: exact benchmark commands.
- `environment.txt`: benchmark environment without machine access details.
- `SHA256SUMS`: checksums for all evidence files except itself.

Median fixed-base group time moved from 4,935 to 4,068 ns for x4 (-17.6%)
and from 7,970 to 6,247.5 ns for x8 (-21.6%). The change is algebraically the
same in both widths: four raw products enter one linear Stage-2 carry layer,
then four normalized output products write directly to the accumulator.

The public benchmark and comparison were run in an isolated worktree at the
recorded implementation commit so concurrent source edits could not affect the
result. The repository path and machine access details are intentionally not
recorded.
