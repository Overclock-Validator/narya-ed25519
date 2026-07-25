# Cold two-x4 comb plus batch-Q gate — 2026-07-25

This directory records the first complete-verifier comparison of the registered
two-x4/radix-64/shared-table batch-Q core with the two-x4/radix-32/comb256
candidate wired by commit `832e751`.

Both paths decode only `A`, hash the original `R || A || message` bytes, compute
the exact cofactorless equation, and use the same cross-group literal batch-Q
finalizer. The arithmetic core is the only changed variable. Automatic backend
selection and the registered forced-r51 constructor were unchanged during this
gate.

Commands used on both hosts:

```text
taskset -c 2 env GOMAXPROCS=1 /usr/local/go/bin/go test ./ed25519 \
  -run '^$' \
  -bench '^BenchmarkR51IFMABatchQGate/decode=single-A/final=batch-Q/path=two-x4/radixA=64/n=(4|8|64)/msg=1232$' \
  -benchmem -benchtime=1s -count=10

taskset -c 2 env GOMAXPROCS=1 /usr/local/go/bin/go test ./ed25519 \
  -run '^$' \
  -bench '^BenchmarkR51IFMABatchQGate/decode=single-A/final=batch-Q/path=two-x4/radixA=32/fixedB=comb256/n=(4|8|64)/msg=1232$' \
  -benchmem -benchtime=1s -count=10
```

Native correctness was run before timing: strict and compat differential
corpora, CCTV, Wycheproof, Firedancer fuzz regressions, every selected lane/tail
mapping, and the candidate zero-allocation gate all passed on both CPUs.

The Zen 4 host reported the `performance` governor. The Zen 5 host reported
`powersave`; treat its absolute numbers as provisional. The candidate's paired
within-host delta was nevertheless stable.

Arithmetic means of the ten `ns/op` samples, divided by the signature count:

| CPU | n | radix64 shared (us/sig) | radix32 comb256 (us/sig) | change |
|---|---:|---:|---:|---:|
| Zen 4 8700GE | 4 | 16.108 | 15.265 | -5.23% |
| Zen 4 8700GE | 8 | 15.730 | 14.915 | -5.18% |
| Zen 4 8700GE | 64 | 15.423 | 14.597 | -5.35% |
| Zen 5 9700X | 4 | 13.528 | 12.907 | -4.59% |
| Zen 5 9700X | 8 | 13.119 | 12.537 | -4.44% |
| Zen 5 9700X | 64 | 12.766 | 12.185 | -4.55% |

Every timed row reported zero bytes and zero allocations per operation.
