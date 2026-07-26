# Zen 4 current public benchmark snapshot — 2026-07-26

This directory contains the raw evidence for the README performance tables at
implementation commit `957212d`. Subsequent commit `3bd1c76` changes only
documentation.

## Conditions

- AMD Ryzen 7 PRO 8700GE, Linux amd64
- Go 1.26.4
- one pinned physical core, `GOMAXPROCS=1`
- performance governor
- valid DalekStrict signatures over distinct public keys
- six 750-millisecond samples per row
- every timed Narya row: 0 B/op, 0 allocs/op, and zero native fault fallbacks

The warm setup promotes 64 distinct keys before timing and reports 64 immutable
tables totaling 1,243,136 bytes. It exercises exported
`Cache.VerifyBatchStrict`, not a private prepared-table seam.

The host had exhibited a separate near-exact 2x throughput regime during
earlier work. This complete snapshot remained in one stable regime across all
three files. A simultaneous sustained-run sample placed the pinned core near
5.06 GHz; idle frequency readings were not used to interpret timings.

## Files

- `public-cold.txt`: exported cold 200/1232/4096 matrix
- `public-warm.txt`: exported 64-key promoted 200/1232/4096 matrix
- `compare-1232.txt`: same-binary Narya, Go standard library, and
  curve25519-voi comparison at 1232 bytes
- `commands.txt`: exact benchmark commands
- `environment.txt`: benchmark environment without machine access details
- `SHA256SUMS`: checksums for every evidence file except itself

Timing cells in the README are medians in microseconds per signature, not
per-batch latency.
