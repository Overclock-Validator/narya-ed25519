# Zen 5 HEEA selector gate

This directory records the allocation-free modulo-8L
`SelectShiftSubtract` benchmark used to decide whether to extend the positive
two-chain ZMM arithmetic gate into a complete singleton HEEA verifier.

Environment: AMD Ryzen 7 9700X, Go 1.26.4, performance governor, one pinned
physical core, `GOMAXPROCS=1`. Each row has ten three-second samples and zero
allocations.

Median selector costs:

| case | W128 ns/op | W132 ns/op | W136 ns/op |
| --- | ---: | ---: | ---: |
| ordinary admitted | 7,121.0 | 6,868.0 | 6,683.0 |
| long schedule | 13,574.5 | 6,027.5 | 5,902.5 |
| pathological fallback | 8,263.0 | 8,256.0 | 8,268.5 |

The concurrently measured post-fusion strict singleton was 14.84
µs/signature. Its profile assigned about 48% to doubling, so halving the
doubling chain can save only roughly 3.6 µs before extra tables, additions,
and term combination. The current 6.68--7.12 µs ordinary selector is therefore
a negative complete-verifier gate. Reopen HEEA performance work only with a
fundamentally cheaper exact selector; the modulo-8L correctness work and the
two-chain ZMM arithmetic remain valid foundations.

`selector.txt` is the raw benchmark output. `SHA256SUMS` covers this README and
the raw output.
