# Forced-r51 warm-comb Cache gate — 2026-07-25

This record separates complete Cache performance from the earlier prepared
warm arithmetic microbenchmark. The timed path enters the r51 backend's actual
cache-aware raw contract, performs lookup and width-aware dispatch, verifies
every signature independently, and writes caller-order verdicts.

## Source and machines

- implementation commit: `2f54a304560e9c2d16f214f2bb600d783fe44df8`
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
| Zen 5 | 8 | 8.525 | 8.040 | — | 8.037 | — | 4.803 |
| Zen 5 | 64 | 8.242 | 7.756 | 6.974 | 6.166 | 5.360 | 4.492 |
| Zen 4 | 8 | 14.80 | 15.75 | — | 10.79 | — | 5.998 |
| Zen 4 | 64 | 14.52 | 15.51 | 12.27 | 10.10 | 7.957 | 5.729 |

At Zen 5 n=8, 50% warm intentionally equals the decoded result: consuming one
warm x4 would split a faster native x8 group into warm and cold x4 work. Zen 4
uses that warm x4 independently and benefits. This is the measured reason for
the width-aware dispatcher rule.

The production warm adapter originally encoded each x4 group separately. Commit
`2f54a30` restores the experiment's cross-group finalizer: consecutive usable
warm groups retain their Q points and share one batch inversion across up to 64
signatures. A separate focused run measured fully warm n=64/msg=200 at
3.74 us/signature on Zen 5 and 4.76 on Zen 4; n=64/msg=1232 measured 4.50 and
5.71 respectively. Minor differences from the full matrix above are normal
between separate short benchmark processes.

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
501dedbe4796c71af975667dd3db8cb49ec89d6f3ddccb05daa46fe2659115c9  narya-warm-batched-2f54a30-zen4.txt
68287c05a2a3d5526f422480a15644819d7eb268184cc947eee6d7a33a86fa3c  narya-warm-batched-2f54a30-zen5.txt
```

The raw logs are not checked into this compact directory, so the checksums
identify the retained host artifacts but do not substitute for the PR-1
checksummed release bundle.
