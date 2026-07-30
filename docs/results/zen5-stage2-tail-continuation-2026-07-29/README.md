# Zen 5 cold profile and doubling Stage-2 continuation — 2026-07-29

This record profiles the exported forced-r51 cold verifier at `ce55a0b` and
measures a native-ZMM control-flow refinement on an AMD Ryzen 7 9700X, Linux
amd64, Go 1.26.4, the performance governor, physical core 6, and
`GOMAXPROCS=1`. Messages were 1,232 bytes for the profiles. Every signature
used a distinct public key and no per-key state survived between calls.

The candidate does not change a field formula or a representation boundary.
The standalone doubling Stage-2 leaf and two new continuations expand the
same source-level assembly body. After that body has stored the same carried
`E/F/G/H` vectors, the continuations tail-enter the existing P2 or P3
final-product leaf. This removes one return/call boundary and one intervening
`VZEROUPPER` per doubling.

## Fresh profile

Profile-instrumented public timings were 14.21, 4.098, and 3.897
microseconds/signature at n=1, n=8, and n=64 respectively. The n=1 path is a
separate packed-x4 implementation and is unaffected by this x8 candidate.

The current n=8 and n=64 profiles put the doubling boundary at the top:

| leaf or phase | n=8 flat/cumulative | n=64 flat/cumulative |
|---|---:|---:|
| P2 final products | 12.91% flat | 14.54% flat |
| P3 final products | 11.61% flat | 12.57% flat |
| dedicated raw square | 10.91% flat | 11.83% flat |
| doubling Stage 2 | 5.71% flat | 5.26% flat |
| variable-base evaluator | 56.66% cumulative | 58.83% cumulative |
| rolling x8 SHA-512 rounds | 6.91% flat | 7.64% flat |

These percentages do not imply that the final-product arithmetic is
removable. They identify the repeated Stage-2-to-final transition as a cheap
boundary to test. The field multiplications themselves remain unchanged.

## Exactness gate

The native differential runs 2,048 independent five-doubling chains. After
each doubling it asserts both:

- byte-identical carried `E/F/G/H` workspace state against the split
  Stage-2-plus-final sequence; and
- byte-identical P2 `X/Y/Z` or complete P3 `X/Y/Z/T` output.

The all-mask evaluator differential, poisoned-workspace test, in-place P2
test, zero-allocation gate, full repository test suite, and `go vet ./...`
also remain required. The non-amd64 implementation calls the same two
existing scalar operations sequentially and serves as the portable semantic
model.

## Paired 1,232-byte result

Eight alternating two-second phases produced the following medians. Values
are microseconds/signature; lower is better.

| width | split boundary | tail continuation | change |
|---:|---:|---:|---:|
| 8 | 4.094 | 4.014 | -2.0% |
| 64 | 3.866 | 3.813 | -1.4% |

Every candidate sample was faster than every control sample. All samples
reported zero allocations and zero internal-fault fallbacks.

## Message-size non-regression matrix

The shorter balanced A/B used two control and two candidate phases. Values
are medians in microseconds/signature.

| bytes | width | split boundary | tail continuation | change |
|---:|---:|---:|---:|---:|
| 200 | 8 | 3.859 | 3.752 | -2.8% |
| 200 | 64 | 3.632 | 3.534 | -2.7% |
| 1232 | 8 | 4.120 | 4.006 | -2.8% |
| 1232 | 64 | 3.887 | 3.779 | -2.8% |
| 4096 | 8 | 4.851 | 4.747 | -2.2% |
| 4096 | 64 | 4.611 | 4.525 | -1.9% |

The 1,232-byte cold gate is therefore positive; the longer-message result is
also positive rather than a trade against the target size.

## Commands

```sh
taskset -c 6 env GOMAXPROCS=1 /usr/local/go/bin/go test \
  -tags r51_release_bench -run '^$' \
  -bench '^BenchmarkPublicR51VerifyBatchStrict$/^msg=1232$/^n=8$' \
  -benchtime=8s -count=1 -cpuprofile=/tmp/narya-current-n8.pprof ./ed25519

taskset -c 6 env GOMAXPROCS=1 /usr/local/go/bin/go test \
  -tags r51_release_bench -run '^$' \
  -bench '^BenchmarkPublicR51VerifyBatchStrict$/^msg=(200|1232|4096)$/^n=(8|64)$' \
  -benchtime=1500ms -count=1 ./ed25519

taskset -c 6 env GOMAXPROCS=1 /usr/local/go/bin/go test -count=1 ./...
/usr/local/go/bin/go vet ./...
```

Raw public outputs and textual `pprof -top` reports are stored beside this
file. CPU profiling perturbs absolute timing, so release tables should use the
unprofiled paired measurements.
