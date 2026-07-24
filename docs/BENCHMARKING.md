# Benchmarking narya

The benchmarks are ordinary Go benchmarks, so they run **independently of
any consuming node** and put every implementation side by side in one run.
No Mithril, no ledger, no hardware setup — `go test -bench` anywhere.

## Run

```
make bench                 # full sweep, all packages
make bench-verify          # single-signature: stdlib vs narya (4 variants) x msg size
make bench-batch           # batch: stdlib loop vs narya pipeline x size x msg size
make bench-hash            # hashing: crypto/sha512 vs sha512mb
```

Or directly:

```
go test -run '^$' -bench BenchmarkVerify -benchtime 2s ./ed25519
```

## The four implementations, side by side

Every `BenchmarkVerify` row is the *same honest input*, so the sub-benchmark
names are the comparison:

| label | what it measures |
|---|---|
| `impl=stdlib` | `crypto/ed25519.Verify` — the baseline Mithril used |
| `impl=narya-compat` | narya `StdlibCompat` — **same predicate** as stdlib, narya's code path. `narya-compat − stdlib` = our wrapper overhead. |
| `impl=narya-strict` | narya `DalekStrict` — mainnet semantics. `narya-strict − narya-compat` = the small-order pre-pass cost. |
| `impl=narya-cached` | narya through a warm `Cache` (per-key comb table) — the recurring-signer path. |

So the numbers directly answer: what does mainnet-correct verification cost
vs the standard library, and how much comes from the strict pre-pass vs the
arithmetic vs the cache.

## A/B comparison across code versions (benchstat)

To measure the effect of an optimization (e.g. an IFMA backend, or fusing
the strict pre-pass):

```
make bench > before.txt
# ... make the change ...
make bench > after.txt
benchstat before.txt after.txt        # go install golang.org/x/perf/cmd/benchstat@latest
```

benchstat reports the delta with statistical significance across `-count`
runs (use `COUNT=6 make bench` for stable deltas).

## Which backend runs

`ActiveBackend()` selects `ifma` on a CPU with AVX-512+IFMA (Zen 4, Zen 5,
Intel Ice Lake+ server), else `generic`. On an arm64 dev machine only
`generic` and `stdlib` exist, so the IFMA numbers require an x86 Zen box —
the harness is otherwise identical, so the same `make bench` there produces
the IFMA comparison with no code change. `sha512mb` reports its lane count
in the benchmark name (`x1` scalar fallback, `x8` once the kernel lands).

## Reading the message-size sweep

Sizes are 64 / 200 / 1232 bytes (up to the Solana packet cap). Point math
is constant across sizes; hashing grows with size. So the spread between a
64-byte and a 1232-byte row is the hashing fraction — which is what
`sha512mb` targets, and which only becomes a large share of total time once
the point math is fast (i.e. after the IFMA backend). Bench `sha512mb`
directly to see hashing in isolation.

## Note on hardware

Committed numbers should say which CPU produced them. arm64 dev results are
indicative of *structure* (which path is faster, where time goes) but not
of production magnitude — the target is x86 Zen 4/Zen 5, where the IFMA
path exists and the double-pumped (Zen 4) vs native-512 (Zen 5) datapaths
differ. Always benchmark the real target before committing to a kernel.
