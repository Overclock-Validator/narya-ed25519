# Forced-r51 warm-comb Cache gate — 2026-07-25

This record separates complete Cache performance from the earlier prepared
warm arithmetic microbenchmark. The timed path enters the r51 backend's actual
cache-aware raw contract, performs lookup and width-aware dispatch, verifies
every signature independently, and writes caller-order verdicts.

## Source and machines

- implementation commit: `915fd6ddc7ec7683877c367cc113a9aefed268f3`
- Zen 4: AMD Ryzen 7 PRO 8700GE, Linux amd64
- Zen 5: AMD Ryzen 7 9700X, Linux amd64
- one pinned core (`taskset -c 2`), `GOMAXPROCS=1`
- performance governor
- valid DalekStrict signatures, message sizes 64/200/1232
- widths 4/8/64
- zero allocations in every timed row

The source used for the measurements predates only the follow-up regression
test that pins the already-measured native-width rule; it does not predate a
performance-path change.

## Command

```text
taskset -c 2 env GOMAXPROCS=1 go test -run '^$' \
  -bench '^BenchmarkR51CacheTierMatrix$' -benchmem \
  -benchtime=3s -count=10 ./ed25519
```

The benchmark setup uses the public/private Cache seam to perform real initial
admission and grouped promotion. It then freezes the remaining non-warm
candidates before starting the timer, so the requested 0/25/50/75/100% warm
density is stable for the complete sample.

## Maximum-message result

Microseconds per signature at message size 1232:

| CPU | n | raw cold | cache, 0% warm | 25% warm | 50% warm | 75% warm | 100% warm |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Zen 5 | 4 | 12.69 | 11.79 | — | — | — | 5.265 |
| Zen 5 | 8 | 8.538 | 7.967 | — | 7.969 | — | 5.304 |
| Zen 5 | 64 | 8.259 | 7.688 | 7.100 | 6.533 | 5.963 | 5.329 |
| Zen 4 | 4 | 14.87 | 16.11 | — | — | — | 6.61 |
| Zen 4 | 8 | 14.50 | 15.68 | — | 10.84 | — | 6.62 |
| Zen 4 | 64 | 14.19 | 15.38 | 12.38 | 10.54 | 8.669 | 6.728 |

At Zen 5 n=8, 50% warm intentionally equals the decoded result: consuming one
warm x4 would split a faster native x8 group into warm and cold x4 work. Zen 4
uses that warm x4 independently and benefits. This is the measured reason for
the width-aware dispatcher rule.

## Interpretation

- Zen 5's decoded first tier improves the complete path before comb promotion.
- Zen 4 retains decoded A only as promotion staging. Its 0%-warm Cache path is
  about 8% slower than raw cold, but 25%-warm n=64 is already about 13% faster.
- A6/r9 group construction measured 14.18 us/key on Zen 5 and 17.61 us/key on
  Zen 4. Against the n=64 decoded/staging-to-warm saving, the arithmetic
  break-even is about six additional uses on Zen 5 and about two on Zen 4.
  The library's threshold of eight valid hits is deliberately conservative;
  the solo threshold of 32 prices a full four-lane build for one stranded key.
- `Cache` remains opt-in. Raw `VerifyBatchStrict` is unchanged, and automatic
  backend selection remains `generic`.
- Invalid strict inputs and invalid equations never earn promotion. Promotion
  failure retains the decoded entry and is not retried.

The complete raw stdout was retained on the measurement hosts during the run
but is not checked into this directory. Therefore this file is a compact
measurement record, not a substitute for the PR-1 checksummed release bundle.
