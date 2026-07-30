# Zen 5 dedicated raw-square dispatch — 2026-07-29

This bundle records the native gate for implementation commit `daaa776` on an
AMD Ryzen 7 9700X (Zen 5), Linux amd64, Go 1.26.4, the performance governor,
one fixed physical core, and `GOMAXPROCS=1`. The exact implementation parent is
`45d4281`.

The implementation already contained a dedicated x8 squaring kernel whose raw
output is bit-identical to `ifmaMulRawX8(out, x, x)`. Dispatch enabled it on
AMD family 19h but retained an older negative result for family 1Ah. The
balanced same-binary rerun below was performed after the surrounding x8 point
kernel changed and now selects the dedicated schedule on both measured AMD
families. Unknown future families retain the general-multiply default.

All table values are microseconds per signature. Lower is better.

## Exact same-binary A/B

The path order was dedicated/general/general/dedicated to balance host drift.
Each median contains twelve one-second samples:

| batch size | general multiply | dedicated square | change |
|---:|---:|---:|---:|
| 8 | 4.1660 | 4.1135 | -1.26% |
| 64 | 3.9445 | 3.9010 | -1.10% |

Every sample reported zero allocations. The 1,232-byte result was the hard
promotion gate. `public-after.txt` also covers 200/1,232/4,096-byte messages
through the registered public API; it is retained as a zero-allocation and
fault-fallback check, not as the exact delta, because its n=64 samples contain
a visible run-level timing discontinuity.

## Correctness gates

- raw square versus general raw multiply exact-representation differentials;
- point-doubling differential, aliasing, poisoned-workspace, and
  zero-allocation tests;
- CCTV, Wycheproof, mixed valid/invalid, and both supported predicate profiles
  through the complete candidate pipeline;
- registered Zen 5 policy activation (`wide=true`, `raw-square=true`,
  `wide-hash-x4=true`, and projective-Niels x4 enabled);
- full native `go test -count=1 ./...`, `go vet ./...`, and local equivalents;
  and
- an explicit negative dispatch test for unmeasured future AMD families.

## Files

- `raw-square-abba.txt`: balanced same-binary candidate/control output.
- `public-after.txt`: registered public cold-verifier sanity matrix.
- `correctness.txt`: full native test and vet transcript.
- `SHA256SUMS`: hashes for every artifact in this directory.
