# Zen 5 projective-Niels Stage-2 gate — 2026-07-26

This record compares parent commit `1029df8` with implementation commit
`72bdf65` on an AMD Ryzen 7 9700X, Linux amd64, Go 1.26.4, one pinned physical
core, the performance governor, and `GOMAXPROCS=1`.

The candidate changes only the linear middle stage of the x8
projective-Niels addition. A separate arbitrary-precision oracle validates its
whole-box bounds and exact carried representation. The complete native suite,
pre-signed selector differential, point-alias test, and zero-allocation gates
passed before measurement.

Commands, shown with repository-relative placeholders rather than machine
paths:

```sh
taskset -c 2 env GOMAXPROCS=1 go test -run '^$' \
  -bench '^BenchmarkIFMAProjectiveNielsAddReusedWorkspaceX8$/scaffold=reused-workspace$' \
  -benchmem -benchtime=1s -count=10 ./internal/r51x5

taskset -c 2 env GOMAXPROCS=1 go test -tags r51_release_bench -run '^$' \
  -bench '^BenchmarkPublicR51VerifyBatchStrict$/msg=1232/n=(8|64)$' \
  -benchmem -benchtime=1s -count=10 ./ed25519
```

Benchstat medians:

| measurement | before | after | change |
|---|---:|---:|---:|
| mixed addition | 78.45 ns | 65.37 ns | -16.67% |
| public n=8 | 5.698 us/signature | 5.604 us/signature | -1.64% |
| public n=64 | 5.374 us/signature | 5.249 us/signature | -2.34% |

All deltas have p=0.000 at n=10. Public rows report 0 B/op, 0 allocs/op, and
zero internal fault fallbacks.
