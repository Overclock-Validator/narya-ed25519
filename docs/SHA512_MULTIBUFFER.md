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

The wrapper constructs and transposes one block per live lane. The native
compression function processes all physical lanes. A short final group uses
zero-filled dummy lanes whose results are ignored. When lanes have unequal
numbers of blocks, a completed lane's digest is written immediately after its
final real/padding block; later dummy compression in that physical lane cannot
change the saved digest. There is consequently no public validity bitmask:
every logical input has exactly one output and tail lanes beyond `len(msgs)`
are unobservable.

The x4 compression schedule uses AVX2 YMM registers. The x8 schedule is a
true AVX-512 ZMM implementation, not a wrapper around two x4 calls. Its
production candidate retains the sixteen message words in ZMM registers and
updates them as a rolling ring; the original 80-word stack schedule remains an
independent differential and benchmark control. The rolling organization is
adapted from Firedancer's pinned AVX-512 batch SHA-512 data flow, as recorded
in [NOTICE](../NOTICE). Zen 4 executes 512-bit operations over 256-bit datapaths,
so neither width is selected without target measurements.

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

`BenchmarkNativeTails` compares the scalar dispatcher, native x4, and native
x8 for every naturally available count from 1 through 17. The scalar row is
present even on non-x86 development hosts; native rows appear only when their
runtime feature gate passes. The Zen 4 gate records this sweep so scalar
hashing can remain selected for underfilled tails where it wins.
