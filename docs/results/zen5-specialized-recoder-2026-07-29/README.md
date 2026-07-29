# Zen 5 merged-B10 specialized recoder gate

This directory records the cold public-API gate for branch commit `1023e7e`
(`db0a239` is the implementation commit). The only implementation change routes
the merged-B10 x8 evaluator through the already-tested all-active, all-negated
radix-32 recoder specialization.

Environment:

- AMD Ryzen 7 9700X (Zen 5), performance governor
- Go 1.26.4
- one pinned physical core
- `GOMAXPROCS=1`
- exported `SetBackend("r51")` plus `VerifyBatchStrict`
- arbitrary valid keys; no retained per-key state

The long first matrix attempt was rejected because another host workload made
every timing approximately two times slower. After confirming normal speed
with a per-core sentinel, each message size was run as a short isolated phase.
`public-cold.txt` records the three samples and their medians. Every timed row
reported zero bytes, zero allocations, and zero internal-fault fallbacks.

The controlled prebuilt-binary ABBA at 1,232 bytes measured:

| width | baseline median (us/signature) | candidate median (us/signature) | change |
|---:|---:|---:|---:|
| 8 | 3.994 | 3.946 | -1.2% |
| 64 | 3.767 | 3.712 | -1.5% |

The selector-to-first-product experiment recorded in the main performance
findings was evaluated immediately before this gate. It was removed after its
exact leaf A/B lost by 23.5%; it is not part of this SHA.

