# Standalone Firedancer C comparison

This harness measures Firedancer's native C Ed25519 implementation directly.
It is compiled inside a pinned Firedancer checkout and links the unmodified
Firedancer `ballet` objects; it does not use cgo and is not a Narya runtime
dependency.

The comparison is pinned to Firedancer commit
[`3ed37488372b7e50bb03ca30477be48508ee7022`](https://github.com/firedancer-io/firedancer/tree/3ed37488372b7e50bb03ca30477be48508ee7022).
The driver adds the missing `low255(R) < p` gate before calling Firedancer.
Together with Firedancer's small-order rejection, that makes valid and invalid
inputs comparable to Narya's `DalekStrict` profile. The independent Narya
differential corpus remains the predicate oracle; this program is a native
performance harness, not a replacement for those tests.

## Command line

```text
fd_ed25519_compare [target-signatures [message-bytes [width]]]
```

The default target is 50,000 signatures. Omitting the optional filters runs
the original matrix:

- message sizes: 64, 200, and 1232 bytes;
- widths: 1, 2, 3, 4, 5, 8, 12, 16, 17, 32, and 64.

For the Solana-sized singleton workload used by the Zen 5 comparison, pass
`100000 1232 1`. The program reports a shared-message control and
`fd-strict-distinct`, the primary row that calls `fd_ed25519_verify` for
independent messages, keys, and signatures. Fixtures are prepared before the
timed region.

## Build on a Zen 5 Linux host

The following commands use GCC 15 and Firedancer's Zen 5 machine definition.
Set the first two paths to the local Narya and Firedancer checkouts.

```sh
NARYA_CHECKOUT=/path/to/narya-ed25519
FIREDANCER_CHECKOUT=/path/to/firedancer

git clone --recurse-submodules https://github.com/firedancer-io/firedancer.git "$FIREDANCER_CHECKOUT"
cd "$FIREDANCER_CHECKOUT"
git checkout 3ed37488372b7e50bb03ca30477be48508ee7022
git submodule update --init --recursive
./deps.sh fetch

make -j4 MACHINE=linux_gcc_zen5 CC=gcc-15 LD=gcc-15 test_ed25519

gcc-15 -I. -isystem ./opt/include \
  -isystem src/third_party/s2n-bignum/include \
  -isystem src/third_party/zstd/lib -isystem src/third_party/lz4/lib \
  -DFD_USING_GCC=1 -DFD_HAS_OPTIMIZATION=1 -D_XOPEN_SOURCE=700 \
  -DFD_HAS_HOSTED=1 -DFD_HAS_THREADS=1 -DFD_HAS_ATOMIC=1 \
  -DFD_HAS_INT128=1 -DFD_HAS_DOUBLE=1 -DFD_HAS_ALLOCA=1 \
  -DFD_HAS_X86=1 -DFD_HAS_SSE=1 -DFD_HAS_AVX=1 \
  -DFD_HAS_SHANI=1 -DFD_HAS_AESNI=1 -DFD_HAS_AVX512=1 \
  -DFD_HAS_GFNI=1 -DFD_HAS_S2NBIGNUM=1 \
  -DFD_BUILD_INFO='"build/linux/gcc/zen5/info"' \
  -std=c17 -O3 -march=znver5 -mtune=znver5 -mfpmath=sse \
  -ffast-math -fno-associative-math -fno-reciprocal-math \
  -fwrapv -fno-omit-frame-pointer -pthread \
  -c "$NARYA_CHECKOUT/scripts/firedancer-compare/fd_ed25519_compare.c" \
  -o /tmp/fd_ed25519_compare.o

gcc-15 -Lbuild/linux/gcc/zen5/lib \
  /tmp/fd_ed25519_compare.o -lfd_ballet -lfd_util \
  -lm -ldl -lrt -pthread -o /tmp/fd_ed25519_compare
```

If `./deps.sh fetch` reports a nonessential third-party fetch problem, try the
narrow `test_ed25519` build before installing validator-wide dependencies.
This harness only needs the freshly built `libfd_ballet.a` and
`libfd_util.a`.

Run Firedancer's pinned correctness target successfully before recording
performance results. Do not compare results from a dirty Firedancer checkout.

## Run 1232-byte singleton measurements

First inspect the topology and select physical cores from the same socket.
Do not select SMT siblings.

```sh
lscpu -e=CPU,CORE,SOCKET,ONLINE
```

For a six-sample one-core run on logical CPU 0:

```sh
mkdir -p firedancer-bench-output
for sample in 1 2 3 4 5 6; do
  taskset -c 0 /tmp/fd_ed25519_compare 100000 1232 1 \
    > "firedancer-bench-output/one-core-${sample}.txt"
done
```

For a six-sample four-core run on physical cores represented by logical CPUs
0, 1, 2, and 3:

```sh
for sample in 1 2 3 4 5 6; do
  for cpu in 0 1 2 3; do
    taskset -c "$cpu" /tmp/fd_ed25519_compare 100000 1232 1 \
      > "firedancer-bench-output/four-core-${sample}-cpu-${cpu}.txt" &
  done
  wait
done
```

Use the median of the six `fd-strict-distinct` one-core rows. Convert each
`ns/sig` value to signatures/second with `1e9 / ns_per_sig`.

For each four-core sample, convert each process's `fd-strict-distinct` row
separately and sum the four signatures/second values. Report the median of
those six aggregate rates. Signatures/second/core is the aggregate divided by
four; scaling is the aggregate divided by the one-core rate.

Record the CPU model, compiler version, Firedancer commit, selected logical
CPUs, governor, raw output, and SHA-256 hashes of the harness, executable,
`libfd_ballet.a`, and `libfd_util.a` with the result.
