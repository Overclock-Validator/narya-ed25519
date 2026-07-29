# Zen 5 packed-x4 multiplication-by-19 gate

This directory records the native hardware gate for commit
`985a3b8807918b00f35daba289067513b34423d9`. The change affects only the
packed-x4 cold tail used at batch widths one and two. Complete x4 and x8 groups
are useful unchanged controls.

`public-abba.txt` alternates the prior shift/add fold and the candidate
`VPMULLQ` fold in one isolated run. It was produced while the candidate was
still an exact source-level A/B; its `base` is commit `54d6430`, and its
`mul19` arm is the arithmetic later selected by `985a3b8` on AMD family 1Ah.

`public-cold-matrix.txt` is the exported-API matrix built directly from
`985a3b8`. `validation.txt` is the exact-commit full, race, forced-policy, and
vet gate. Every timed row reports zero allocations and zero internal fault
fallbacks.

## Commands

The benchmark host used one pinned physical core, the performance governor,
Go 1.26.4, and `GOMAXPROCS=1`:

```sh
taskset -c 6 env GOMAXPROCS=1 /usr/local/go/bin/go test \
  -tags r51_release_bench -run '^$' \
  -bench '^BenchmarkPublicR51VerifyBatchStrict$' \
  -benchmem -benchtime=1s -count=3 ./ed25519
```

The exact-commit validation gate was:

```sh
/usr/local/go/bin/go test ./... -count=1
/usr/local/go/bin/go test -race ./ed25519 ./sha512mb -count=1
/usr/local/go/bin/go test -tags narya_test_amd_policy \
  ./internal/cpufeat ./internal/r51x5 ./ed25519 -count=1
/usr/local/go/bin/go vet ./...
```

## Result

At 1,232 bytes the exact-commit medians are 13.90, 13.86, 7.983, 3.913,
and 3.712 microseconds per signature at n=1, 2, 4, 8, and 64. The alternating
A/B shows the intended approximately 2--3% n=1/n=2 improvement at all three
message sizes. The unaffected n=4/n=8/n=64 rows remain controls rather than
claimed gains from this change.
