# Zen 4 signature-preparation native gate — 2026-07-26

This record covers merge commit `142255e`, which merges the shared
`internal/sigprep` preparation stage into the cold r51 line. The performance
baseline is `02ede36`. The machine was an AMD Ryzen 7 PRO 8700GE, using Go
1.26.4, the performance governor, one pinned core, and `GOMAXPROCS=1`.

## Correctness gate

The complete native repository suite passed after the merge. Portable tests,
`go vet`, and race-selected `ed25519`, `internal/sigprep`, and `sha512mb`
packages also passed. The native public benchmark reported zero allocations
and zero internal-fault fallbacks.

This is the hardware gate that the original preparation-stage handoff required:
the development host for that extraction was arm64 and could not execute its
IFMA rewires.

## Performance result

Focused public `VerifyBatchStrict` runs used 1232-byte messages. In the stable
high-throughput regime the observed ranges were:

| width | `02ede36`, us/signature | `142255e`, us/signature | reading |
|---:|---:|---:|---|
| 8 | 8.092–8.100 | 8.099–8.102 | flat; bands differ by less than 0.1% |
| 64 | 7.897–7.920 | 7.901–7.927 | flat; bands overlap |

The n=1 and n=2 rows were slightly faster after the extraction and n=4 was
flat, but they are not presented as gains because they were within run drift.

## Host-state warning

A later six-sample repeat switched between approximately 8 and 16
microseconds per signature without a source or binary change. Both the
baseline and candidate exhibited the slower regime. That near-exact 2x split
is external host state, not a credible arithmetic effect, so samples from
different regimes must not be combined. Future comparisons on this host should
alternate candidates in short blocks and reject a run if its control row
changes regimes.

## Reproduction

```sh
go test -count=1 ./...
go vet ./...
go test -race ./ed25519 ./internal/sigprep ./sha512mb

taskset -c 2 env GOMAXPROCS=1 go test -tags r51_release_bench -run '^$' \
  -bench '^BenchmarkPublicR51VerifyBatchStrict$/^msg=1232$/^n=(8|64)$' \
  -benchmem -benchtime=750ms -count=6 ./ed25519
```

No machine addresses, account names, or local filesystem paths are recorded
here.
