# Zen 4 x4 projective-Niels checkpoint

This directory records the promotion gate for the four-lane cold variable-base
table at implementation commit `8590b4f`. The candidate was introduced at
`0f11df6` and then enabled in the registered forced-r51 worker. Commit
`71b2dbd` subsequently tightened names and the private representation type
without changing arithmetic or dispatch.

Environment:

- AMD Ryzen 7 PRO 8700GE (Zen 4), performance governor;
- Go 1.26.4, linux/amd64;
- one pinned physical core and `GOMAXPROCS=1`;
- ten three-second samples for the direct 1232-byte A/B;
- six 750-millisecond samples for the exported cold/warm matrix.

The candidate stores `[1]A` through `[16]A` as projective-Niels
`(Y+X,Y-X,Z,2dT)` entries in the existing micro-AoS footprint. Every selected
digit then uses the already-range-tested x4 Niels Stage-2 leaf, reducing a
variable-base addition from ten field multiplications to eight. It changes no
recoding, doubling, fixed-base, hashing, finalization, or acceptance-predicate
logic.

At n=4 and 1232-byte messages, the same-binary complete-verifier gate measured:

| table/addition form | median `µs/signature` | allocations |
| --- | ---: | ---: |
| extended / full addition | 10.07 | 0 |
| projective Niels / mixed addition | 9.451 | 0 |

That is a 6.1% complete-verifier reduction. The direct corpus covered both
profiles, CCTV, Wycheproof, valid/invalid mixtures, mixed-order points, x4
tails, and zero-allocation gates. The full native repository suite passed.

Files:

- `niels-ab-1232.txt`: same-binary direct A/B;
- `public-cold-warm.txt`: exported forced-r51 cold/warm matrix after promotion;
- `compare-1232.txt`: same-binary Narya, standard-library, and Voi comparison;
- `parallel-p{1,2,4,8}.txt`: exported Narya concurrent-caller scaling;
- `full-tests.txt`: native `go test ./... -count=1` output;
- `commands.txt`: exact commands;
- `SHA256SUMS`: checksums for the evidence set.

**Regime tag:** this gain applies when evaluation uses an x4 cold A table,
not to complete x8 groups or the prepared warm-comb path. The former extended
table/evaluator remains as an internal differential and benchmark reference.
