# Zen 4 ordinary two-chain ZMM scalar-loop gate

This directory records the complete prepared scalar-loop A/B for the
experimental two-chain packed-ZMM orientation. The candidate tree is based on
commit `a095390` and adds the cached-add layer and ordinary, equation-preserving
two-chain NAF loop reviewed in the same checkpoint.

Environment:

- AMD Ryzen 7 PRO 8700GE (Zen 4);
- Go 1.26.4, linux/amd64;
- one pinned core, `GOMAXPROCS=1`;
- five one-second samples per path;
- zero allocations in every timed row.

The shared packed-x4 loop measured 10.710–10.717 µs/op. The two-chain ZMM
loop measured 17.823–17.828 µs/op, an approximately 66% regression. This
excludes the candidate from Zen 4 dispatch. It does not close the candidate on
Zen 5, where the earlier native-512 component gate measured two packed chains
at essentially the cost of one.

`loop-gate.txt` SHA-256:

```text
d74820f4482ed8bca693dd7976c6e6673e5f91f0c9ceb75a1e8d7e4927d849e1
```
