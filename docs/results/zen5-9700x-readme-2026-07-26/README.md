# Zen 5 public API benchmark snapshot — 2026-07-26

This directory is the raw evidence for the current README performance tables.
The measured implementation and benchmark harness are commit
`1f0bfbfdbf9740729fb974eda85415867e2b4d61`. Commit `f56f2b9` subsequently
made the same release benchmarks fail if `ActiveBackendStats` reports any
native fault fallback; it does not change a timed verification path.

## Conditions

- AMD Ryzen 7 9700X (Zen 5), logical CPU 2
- Go 1.26.4, Linux amd64
- `GOMAXPROCS=1`
- CPU scaling governor and energy-performance preference both `performance`
- valid DalekStrict signatures over distinct public keys
- ten one-second samples for the public cold and fully promoted warm matrices
- six one-second samples for the same-binary Narya/stdlib/Voi comparison
- every timed Narya row: 0 B/op and 0 allocs/op

The warm setup promotes all 64 fixture keys before timing. It reports 64 warm
tables and 1,243,136 table bytes. Thus these rows exercise the exported
`Cache.VerifyBatchStrict` API rather than a private prepared-table seam.

## Startup/interference rerun

The first cold run's 200-byte n=1 samples and first two n=2 samples ran at
almost exactly half their later throughput. The governor was already
`performance`, and the other widths were unaffected. Those anomalous tail rows
are retained in `public-cold.txt` rather than silently deleted. They were
rerun alone immediately after the other serial measurements; all ten rerun
samples were stable within 0.05%, and the README uses the medians from
`public-cold-200-tail-rerun.txt`. All other cold medians come from
`public-cold.txt`.

## Files

- `public-cold.txt` — raw cold 200/1232/4096 matrix
- `public-cold-200-tail-rerun.txt` — replacement n=1/n=2 200-byte samples
- `public-warm.txt` — raw fully promoted warm matrix
- `compare-1232.txt` — Narya, Go stdlib, and curve25519-voi at 1232 bytes
- `commands.txt` — exact measurement commands
- `environment.txt` — source and machine identity
- `SHA256SUMS` — checksums for every evidence file except itself

