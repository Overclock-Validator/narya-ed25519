# Experimental multi-buffer SHA-512

Narya contains forced, hardware-gated x4 and x8 SHA-512 prototypes. They do
not change `sha512mb.Lanes`, `sha512mb.Sum512Batch`, backend selection, or any
production verification path.

The experimental entry point is:

```go
ok := sha512mb.ExperimentalSum512Batch(out, segmentedMessages, width)
```

`width` is `ExperimentalWidthX4` or `ExperimentalWidthX8`. x4 requires AVX2;
x8 requires AVX-512F and AVX-512BW. An unavailable or unsupported width
returns `false` without changing `out`. A length mismatch still panics,
matching the package's ordinary batch contract.

Each input is a list of byte slices and is hashed as their exact
concatenation. The verifier can therefore pass the original `R`, original `A`,
and message without constructing a contiguous buffer. Empty segments,
arbitrary segment boundaries, SHA-512 padding boundaries, unequal lane
lengths, and final groups smaller than the selected width are supported.

The wrapper constructs and transposes one block per live lane. For x8, a
complete 128-byte block contained in one input segment is loaded and
transposed directly from that segment. Blocks crossing segment boundaries and
blocks containing SHA-512 padding use the byte-for-byte segmented fallback.
The fallback storage is cleared only for lanes that actually need it; full
direct groups do not clear a dummy 1 KiB matrix on every block.

The native compression function processes all physical lanes. A short final
group uses a shared zero-filled dummy block for lanes whose results are
ignored. When lanes have unequal numbers of blocks, a completed lane's digest
is written immediately after its final real/padding block; later dummy
compression in that physical lane cannot change the saved digest. There is
consequently no public validity bitmask: every logical input has exactly one
output and tail lanes beyond `len(msgs)` are unobservable.

The x4 compression schedule uses AVX2 YMM registers. The x8 schedule is a
true AVX-512 ZMM implementation, not a wrapper around two x4 calls. Its
production candidate retains the sixteen message words in ZMM registers and
updates them as a rolling ring; the original 80-word stack schedule remains an
independent differential and benchmark control. The rolling organization is
adapted from Firedancer's pinned AVX-512 batch SHA-512 data flow, as recorded
in [NOTICE](../NOTICE). Zen 4 executes 512-bit operations over 256-bit datapaths,
so neither width is selected without target measurements.

The x8 complete-hash path fuses direct pointer loads, byte swapping, 8x8
transposition, and rolling compression into one assembly boundary. The split
transpose and compression functions remain independent controls. Both entries
tail-jump into the same 80-round body, so there is only one production round
schedule. The first fused block also initializes the transposed SHA state,
avoiding a scalar 64-word initialization followed by vector reloads.

Correctness tests compare both the raw compression state and complete
segmented hashing against independent Go/`crypto/sha512` references. Coverage
includes batch sizes 0 through 17, every physical lane and tail position,
message sizes 0, 64, 200, and 1232 (plus padding/block edges), randomized
segments and lengths, and fuzzing. Allocation tests require zero allocations
for prebuilt input descriptors.

Run the target benchmark on a pinned core with `GOMAXPROCS=1`:

```text
go test -run '^$' -bench 'BenchmarkNativeX(4|8)$' -benchmem -count=10 -benchtime=3s ./sha512mb
```

`BenchmarkNativeX8` directly compares scalar-eight, two AVX2 x4 groups, and
one AVX-512F x8 group. Digest-to-scalar reduction remains separate until these
hash kernels pass their correctness and complete-verifier performance gates.

On the Ryzen 7 PRO 8700GE, a pinned `GOMAXPROCS=1` development measurement of
the fixed `R || A || message` entry point after the rolling schedule, native
transpose/compression fusion, first-block state initialization, and
direct-block ingestion gave:

| message bytes | scalar Go | native x8 | speedup |
|---:|---:|---:|---:|
| 200 | about 402 ns/message | 139.6--139.7 ns/message | about 2.88x |
| 1232 | about 1,348 ns/message | 428.5--429.6 ns/message | about 3.14x |

These are hash-only figures, not complete signature-verification numbers. The
long-message result is especially relevant to Solana's 1232-byte transaction
ceiling. Automatic SHA or verifier dispatch remains unchanged while B1 is an
experimental branch.

`BenchmarkNativeTails` compares the scalar dispatcher, native x4, and native
x8 for every naturally available count from 1 through 17. The scalar row is
present even on non-x86 development hosts; native rows appear only when their
runtime feature gate passes. The Zen 4 gate records this sweep so scalar
hashing can remain selected for underfilled tails where it wins.
