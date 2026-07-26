# Zen 5 decoder square-chain README snapshot

This directory records the public benchmark snapshot used by the README after
the register-resident decoder square-chain change at implementation commit
`1ac9fde`.

The measurements used the exported forced-r51 APIs, a single pinned physical
core, `GOMAXPROCS=1`, Go 1.26.4, and the performance governor. Timing cells are
microseconds per signature. Every timed Narya row reported zero allocations
and zero internal-fault fallbacks.

- `public-cold.txt`: cold `VerifyBatchStrict`, ten one-second samples.
- `public-warm.txt`: 64-key promoted `Cache.VerifyBatchStrict`, ten one-second
  samples.
- `compare-1232.txt`: Narya, Go standard library, and curve25519-voi at 1232
  message bytes, six one-second samples.
- `commands.txt`: exact benchmark commands.
- `environment.txt`: benchmark environment without machine access details.
- `SHA256SUMS`: checksums for all evidence files except itself.

The benchmark source was detached only to isolate it from concurrent edits.
The recorded implementation commit identifies the code under measurement.
