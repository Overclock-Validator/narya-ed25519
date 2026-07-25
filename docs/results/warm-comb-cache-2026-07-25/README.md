# Forced-r51 warm-comb Cache gate — 2026-07-25

This record separates complete Cache performance from the earlier prepared
warm arithmetic microbenchmark. The timed path enters the r51 backend's actual
cache-aware raw contract, performs lookup and width-aware dispatch, verifies
every signature independently, and writes caller-order verdicts.

## Source and machines

- implementation commit: `f808b98f3d0abb0b6b7c36e49739fb8ad1a813b5`
- Zen 4: AMD Ryzen 7 PRO 8700GE, Linux amd64
- Zen 5: AMD Ryzen 7 9700X, Linux amd64
- one pinned core (`taskset -c 2`), `GOMAXPROCS=1`
- performance governor
- valid DalekStrict signatures, message sizes 64/200/1232
- widths 4/8/64
- zero allocations in every timed row

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
| Zen 5 | 4 | 12.70 | 11.75 | — | — | — | 5.328 |
| Zen 5 | 8 | 8.536 | 7.959 | — | 7.957 | — | 5.327 |
| Zen 5 | 64 | 8.253 | 7.651 | 7.078 | 6.522 | 5.979 | 5.376 |
| Zen 4 | 4 | 14.90 | 16.14 | — | — | — | 6.565 |
| Zen 4 | 8 | 14.45 | 15.68 | — | 10.82 | — | 6.568 |
| Zen 4 | 64 | 14.19 | 15.36 | 12.41 | 10.54 | 8.657 | 6.704 |

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

The complete raw stdout was retained on the measurement hosts during the run:

```text
12f18c286e08ecb0aac3945709531e8c556a27f4011f788da71c21ded2875990  narya-warm-f808b98-zen4.txt
27a49c22e3252e26494f43ab7481dff9d163cc70ac12b3d5809813ce3c85ce13  narya-warm-f808b98-zen5.txt
```

The raw logs are not checked into this compact directory, so the checksums
identify the retained host artifacts but do not substitute for the PR-1
checksummed release bundle.
