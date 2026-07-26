# Zen 5 two-chain ZMM doubling gate

Implementation commit: `d01b574`

This is a test-only architectural gate. It packs two independent Edwards point
chains as `[X,Y,T,Z,X,Y,T,Z]` in one ZMM register and applies the packed
doubling formula independently to both 256-bit halves. It does not alter a
public verifier or dispatch path.

Environment: AMD Ryzen 7 9700X, Go 1.26.4, performance governor, one pinned
physical core, `GOMAXPROCS=1`.

Median result:

- two independent packed-x4 doubles: 50.30 ns per two-chain operation;
- one packed two-chain ZMM double: 30.42 ns per two-chain operation;
- delta: -39.5% per pair, with two chains completed by each operation.

The ZMM result is also essentially equal to the 30.575 ns cost previously
measured for one packed-x4 double. This supports, but does not complete, a
future separate-term or singleton-HEEA verifier. Cached addition, table
selection, recoding, term combination, and complete-predicate validation remain
unmeasured in this orientation.

`double-gate.txt` contains ten three-second samples for each two-chain shape.
`tests.txt` records the complete native repository suite. Source tests compare
exact redundant representations against two independent x4 oracles over
random mixed-order and non-unit-projective chains and assert zero allocations.
