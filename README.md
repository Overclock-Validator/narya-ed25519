# Narya — Ed25519 verification

```
go get github.com/Overclock-Validator/narya-ed25519
```

Narya is a pure-Go Ed25519 verifier that makes its acceptance rule explicit and
versioned, preserves an independent verdict for every signature, and uses
wide-lane SIMD to turn a queue of unrelated signatures into useful parallel
work. It is aimed at replicated systems, high-throughput services, archival
verification, and any other application where two properties matter at once:
verification must be fast, and every implementation must agree on exactly
which byte strings are valid.

Narya provides explicit `DalekStrict` and Go-standard-library-compatible
profiles instead of treating "Ed25519 verification" as one universal
predicate. Its cold path handles arbitrary public keys without persistent
state. Its optional cache adds a decoded-key tier for broad recurrence and a
larger precomputed tier for genuinely hot keys. Batch APIs never replace
per-signature verification with a randomized aggregate equation: every input
still receives its own deterministic accept/reject result.

On supported AMD64 processors, the forced `r51` backend runs independent
signatures across AVX-512 IFMA lanes, with native x8 groups and x4 tails on
measured AMD CPUs. Portable callers retain the pure-Go `generic` backend, and
automatic backend selection remains conservative.

> **Security status: experimental and unaudited.** Narya has extensive
> differential, vector, fuzz, range, aliasing, and hardware tests, but it has
> not received an independent cryptographic or assembly audit. Do not treat it
> as a drop-in production security boundary without your own review and
> validation. The software is provided **as is**, without warranty; the
> authors and contributors accept no liability for its use. See
> [LICENSE](LICENSE) for the governing terms.

The name comes from Narya, the Ring of Fire.

## Why this exists

**Ed25519 verification is not one predicate.** RFC 8032 leaves several choices
open, and production implementations resolve them differently:

| | cofactorless | small-order `A` | small-order `R` | non-canonical `A` | non-canonical `R` |
| --- | --- | --- | --- | --- | --- |
| Go `crypto/ed25519` | yes | accept | accept | accept | reject |
| `ed25519-dalek` `verify_strict` | yes | **reject** | **reject** | accept | reject |
| ZIP 215 | no (cofactored) | accept | accept | accept | **accept** |

Any two rows disagree on a nonempty, adversarially constructible set of inputs.
In a replicated or long-lived system, that difference can become a remotely
triggerable consistency failure: an attacker chooses an input in the symmetric
difference and two otherwise-correct implementations return different verdicts.

The subtlety that makes this worth a library: `verify_strict` is **not**
"strict about everything." It rejects non-canonical `R` but *accepts*
non-canonical `A`. Hand-rolling the predicate and getting that one case
backwards is a silent fork.

Narya makes the choice explicit, versioned, and differentially tested rather
than incidental.

## The contract

Verification enforces one of two versioned **profiles**, because the
consensus-correct acceptance predicate is itself versioned — an
accept/reject flip is a fork, so it is a deliberate choice, not an
implementation detail:

- **`DalekStrict`** (default, and the zero value) — matches
  `ed25519-dalek` 2.x `verify_strict`. This is `crypto/ed25519.Verify` **plus**
  rejection of small-order public keys A and small-order signature
  points R. The standard library accepts those (it never decodes R); a
  verifying node that used it unmodified could be forked off the
  network by a crafted block, so this is the default.
- **`StdlibCompat`** — exactly `crypto/ed25519.Verify`, for
  differential testing and callers who explicitly want standard-library
  behavior.

Small-order rejection is a byte-level classifier over the seven low-255-bit
small-order `y` encodings, sign-bit-insensitive — fourteen byte strings, with
no point decode required.

For every input — non-canonical encodings, small-order points,
malformed signatures — every backend, cached or not, batched or single,
returns exactly what the active profile's predicate returns. This is
enforced by differential tests, the CCTV and Wycheproof corpora, a
cross-library differential against curve25519-voi, and fuzzing rather than
assumed; the 165 CCTV vectors where the two profiles differ are precisely the
small-order set, cross-checked against Firedancer's independent verdict.

Narya never uses random-coefficient (cofactored) batch verification:
its aggregate equation can accept adversarial signatures that
per-signature verification rejects. "Batch" preserves an independent verdict
for every signature. The default `generic` backend processes signatures
independently. The explicitly selected `r51` backend instead hashes and
decodes several independent signatures in SIMD lanes while retaining a
separate verdict for every input.
A future `ZIP215` profile may expose the cofactored predicate explicitly. It
will not silently change either existing profile.

**Narya has no signing API, deliberately.** The mismatched private/public-key
signing-oracle failures catalogued by
[ed25519-unsafe-libs](https://github.com/MystenLabs/ed25519-unsafe-libs)
are therefore outside its API: Narya never accepts a caller-supplied
private/public key pair. Verification still has its own consensus and input
validation risks, which are addressed by the profile contract and differential
test corpus below. If signing is ever added, it must derive or validate the
public key from the secret as required by the
[RFC 8032 signing procedure](https://www.rfc-editor.org/rfc/rfc8032#section-5.1.6);
merely verifying the emitted signature is not a sufficient defense against the
mixed-order substitution described by the Mysten audit.

## API

```go
func Verify(pub *[32]byte, message, sig []byte) bool   // uses DefaultProfile()
func VerifyStrict(pub, message, sig []byte) bool       // always DalekStrict; byte-slice pub,
                                                       // drop-in for crypto/ed25519.Verify
func VerifyBatch(pubs []*[32]byte, msgs, sigs [][]byte, ok []bool) bool
func VerifyBatchStrict(pubs []*[32]byte, msgs, sigs [][]byte, ok []bool) bool

func Precompute(pub *[32]byte) (*PrecomputedKey, error)
func (k *PrecomputedKey) Verify(message, sig []byte) bool

type Cache struct{ MaxTableBytes int64 }               // 0 means DefaultMaxTableBytes (128 MiB)
func (c *Cache) Verify(pub *[32]byte, message, sig []byte) bool
func (c *Cache) VerifyStrict(pub *[32]byte, message, sig []byte) bool
func (c *Cache) VerifyBatch(pubs []*[32]byte, msgs, sigs [][]byte, ok []bool) bool
func (c *Cache) VerifyBatchStrict(pubs []*[32]byte, msgs, sigs [][]byte, ok []bool) bool
func (c *Cache) Stats() CacheStats

type Profile uint8
const (DalekStrict Profile = iota; StdlibCompat)
func SetDefaultProfile(p Profile)
func DefaultProfile() Profile

func ActiveBackend() string
func SetBackend(name string) error                     // must precede first verification
```

`VerifyBatch` writes per-signature verdicts into `ok` and panics if the slice
lengths differ. `Precompute` returns a non-nil error when `pub` does not decode.

## Packages and backends

- **`ed25519`** — the public API above. Exactly one backend is active per
  process, latched on first use. Resolution order: the name passed to
  `SetBackend`, then `OVERCLOCK_ED25519_BACKEND`, then the default.
- **`sha512mb`** — multi-buffer SHA-512.
- **`cmd/sigverifytracebench`** — offline exact-input schema-v3 replay for a
  measured stdlib/generic/generic-cache diagnostic. It never promotes the
  generic table result to the pending r51 production cache gate.

| backend | status | notes |
| --- | --- | --- |
| `generic` | **default** | Pure Go over the vendored `edwards25519` internals, with per-key fixed-base comb tables for recurring signers. |
| `stdlib` | available | Routes to `crypto/ed25519`. The rollback proof point. |
| `ifma` | opt-in, in development | AVX-512 IFMA point arithmetic after Firedancer's `r43x6` representation. Requires AVX512F/VL/DQ/BW/IFMA/VBMI, detected at runtime via `x/sys/cpu` — never via `GOAMD64`, since `x86-64-v4` does not imply IFMA. |
| `r51` | **registered, forced-only** | AMD lane-per-signature r51 backend. Strict singletons and two-signature tails use paired A/R decode and a packed projective finalizer. Wider batches use a radix-32 A table, one process-shared radix-256 B comb, A-only decode, and cross-group batch encoding of Q. Measured AMD family 19h+ IFMA parts, including Zen 4 and Zen 5, use x8/ZMM for complete eight-signature groups and x4 for the tail; unknown IFMA CPUs retain the reviewed x4 default. Its opt-in `Cache` first admits an exact-byte-bound decoded-A entry and promotes recurring valid strict keys to an immutable A6/r9 warm comb. Warm x4 groups are consumed in aligned pairs on the measured AMD set, except a final four-item tail, so a half-warm x8 group stays on the faster native-wide cold path. `StdlibCompat` singleton calls retain the generic literal-encoding path. This backend is never selected automatically. |

Selection is deliberately non-degrading. `ifma` requires AVX512F/VL/DQ/BW,
IFMA, and VBMI. `r51` requires that same IFMA feature set plus AVX2 for its
native x4 SHA-512 path. `SetBackend` performs the complete activation check
synchronously; an unknown or unsupported forced name returns an error there
and panics on the environment-variable path. A forced name represents explicit
operator intent and must not silently fall back.

`sha512mb`'s public `Lanes()` and `Sum512Batch` surface remains the portable
scalar implementation. Its AVX2 and AVX-512 kernels are hardware-gated behind
the `Experimental*` entry points; the forced `r51` backend calls the x8 native
entry for complete groups on measured AMD family 19h+ IFMA parts and retains
x4 for tails and unknown IFMA CPUs. Automatic
backend selection never reaches either kernel.
The x8 fixed-three-segment entry recognizes full
groups of the exact `R[32] || A[32] || message` shapes at message sizes
64/200/1232, ingesting their first and final blocks without generic segmented
staging. Design details and historical measurements are kept in
[`docs/SHA512_MULTIBUFFER.md`](docs/SHA512_MULTIBUFFER.md).

## Performance

Narya's accelerated path is measured through the exported
`SetBackend("r51")`, `VerifyBatchStrict`, and `Cache.VerifyBatchStrict` APIs.
The latest snapshot is from implementation commit `fd117ae` on an AMD Ryzen 7
9700X (Zen 5), Go 1.26.4, one pinned core, the performance governor, and
`GOMAXPROCS=1`. Values are median microseconds per signature from ten repeated
one-second samples. Every timed Narya row reports 0 B/op and 0 allocs/op.

**Units:** every numeric timing cell in the next three tables is
**microseconds per signature (`µs/signature`, lower is better)**. The multicore
table is labeled separately in **signatures per second (`signatures/s`, higher
is better)**.

**Cold — arbitrary keys, no retained key state (`µs/signature`)**

| message bytes | n=1 µs/sig | n=2 µs/sig | n=4 µs/sig | n=8 µs/sig | n=64 µs/sig |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 200 | 14.320 | 14.270 | 8.261 | 4.743 | 4.554 |
| 1232 | 14.890 | 14.880 | 9.274 | 4.995 | 4.794 |
| 4096 | 16.995 | 17.030 | 12.065 | 5.705 | 5.531 |

**Warm — 64 distinct keys promoted before timing (`µs/signature`)**

| message bytes | n=1 µs/sig | n=2 µs/sig | n=4 µs/sig | n=8 µs/sig | n=64 µs/sig |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 200 | 14.300 | 14.230 | 3.418 | 3.182 | 3.020 |
| 1232 | 14.980 | 14.900 | 4.179 | 3.940 | 3.776 |
| 4096 | 17.030 | 17.040 | 6.230 | 5.998 | 5.825 |

These numbers describe the explicitly forced backend, not automatic dispatch;
the portable `generic` backend remains the default. Batch width matters because
r51 maps independent signatures onto SIMD lanes: n=1 and n=2 use dedicated tail
paths, n=4 fills one x4 group, and n=8 or larger can use native x8 groups. The
cache deliberately bypasses its prepared tables for n<4, so the cold and warm
singleton/pair rows are effectively the same path.

At 4096 bytes, the current warm x4 schedule is slower than native x8 cold at
n=8 and n=64 in this run. The crossover is retained rather than presenting
cache hits as universally faster; the cache remains a clear win at n>=4 for
200- and 1232-byte messages. Dispatch should therefore account for message
size as well as cache state and batch width.

The comparison below uses the same 1232-byte fixture shape and executable for
every row. Values are medians of six one-second samples in `µs/signature`
(lower is better). Voi's expanded-key row excludes expansion cost and is
included as a warm-key reference.

| implementation | n=1 µs/sig | n=2 µs/sig | n=4 µs/sig | n=8 µs/sig | n=64 µs/sig |
| --- | ---: | ---: | ---: | ---: | ---: |
| Narya r51, cold strict | 15.010 | 14.795 | 9.414 | 5.038 | 4.865 |
| Go `crypto/ed25519` | 27.605 | 27.140 | 27.310 | 27.385 | 27.445 |
| curve25519-voi, cold strict | 21.750 | 21.560 | 21.750 | 21.830 | 21.900 |
| curve25519-voi, expanded key | 18.940 | 18.740 | 18.930 | 19.000 | 19.070 |

The public cold path also scales across independent callers. At commit
`ac8c1ab`, six one-second samples per point over 1232-byte messages produced:

| physical cores | n=4 signatures/s | n=4 scaling | n=8 signatures/s | n=8 scaling |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 99,120 | 1.00x | 175,633 | 1.00x |
| 2 | 196,862 | 1.99x | 352,288 | 2.01x |
| 4 | 386,848 | 3.90x | 688,638 | 3.92x |
| 6 | 560,078 | 5.65x | 978,018 | 5.57x |
| 8 | 705,648 | 7.12x | 1,216,888 | 6.93x |

The eight-core n=4 and n=8 rows correspond to aggregate throughput costs of
1.417 and 0.822 microseconds per signature; they are not individual-request
latencies. Every parallel row reports 0 B/op, 0 allocs/op, and zero internal
fault fallbacks. CPUs 0--7 were verified as eight distinct physical cores;
their SMT siblings 8--15 were excluded.

Historical measurements and their exact environments remain in
[`docs/results/`](docs/results/); they are intentionally not stacked into this
table because code, CPU generation, and cache population materially change the
result. Raw output, exact commands, environment details, and checksums for the
current snapshot are in
[`docs/results/zen5-fixed-base-affine-stage2-2026-07-26/`](docs/results/zen5-fixed-base-affine-stage2-2026-07-26/).
The multicore evidence is in
[`docs/results/zen5-9700x-parallel-2026-07-26/`](docs/results/zen5-9700x-parallel-2026-07-26/).

### Cold and warm verification

Cold and warm are two execution conditions with the same acceptance predicate,
not different security modes:

| path | public entry point | intended workload | trade-off |
| --- | --- | --- | --- |
| **cold** | `VerifyStrict` / `VerifyBatchStrict` | arbitrary, first-seen, or low-recurrence public keys | no persistent key state; decodes A and builds its small variable-base table for each verification |
| **warm** | `Cache.VerifyStrict` / `Cache.VerifyBatchStrict` | public keys that recur enough to repay preparation | exact-byte-bound decoded-A and precomputed-comb tiers reduce curve work in exchange for memory, lookup, and admission overhead |

Both paths hash the original public-key and signature bytes, retain independent
per-signature verdicts, and enforce the selected profile. Invalid inputs and
invalid equations never earn cache promotion. Warm results depend on the
number and recurrence of keys: a tiny permanently hot fixture can overstate
performance compared with a populated cache, so Narya reports cache population
alongside every release measurement.

The cache is opt-in. Raw `VerifyBatchStrict` remains cold and stateless, and
automatic backend selection remains `generic`.

### Running the benchmarks

The public cold/warm benchmark is isolated behind a build tag so it cannot
accidentally measure a private implementation seam:

```sh
taskset -c 2 env GOMAXPROCS=1 go test -tags r51_release_bench \
  -run '^$' \
  -bench '^BenchmarkPublicR51(VerifyBatchStrict|CacheVerifyBatchStrict)$' \
  -benchmem -benchtime=1s -count=10 ./ed25519
```

The 1232-byte comparison table comes from the isolated Voi module:

```sh
taskset -c 2 env GOMAXPROCS=1 go test \
  -modfile=go.oasis.mod -tags oasis_compare -run '^$' \
  -bench '^BenchmarkEd25519CrossLibrary$/^mode=independent$/^impl=(narya-r51-dispatch|go-stdlib-loop|oasis-strict-cold-loop|oasis-strict-expanded-loop)$/^n=(1|2|4|8|64)$/^msg=1232$' \
  -benchmem -benchtime=1s -count=6 ./ed25519
```

The accelerated backends require AVX512-IFMA and must be selected explicitly
with `SetBackend("r51")` or `OVERCLOCK_ED25519_BACKEND=r51`. Unsupported
forced activation fails synchronously instead of silently measuring the
portable path.

For reproducible CPU measurements, pin a physical core, use the same Go
toolchain, record the CPU governor, and use repeated samples with
`benchstat`. Do not infer sustained frequency from an idle
`/proc/cpuinfo` sample; use hardware counters when cycle-level comparisons
matter.

## Verification

- All five plain Ed25519 known-answer vectors from
  [RFC 8032 section 7.1](https://www.rfc-editor.org/rfc/rfc8032#section-7.1),
  914 [CCTV](https://github.com/C2SP/CCTV) `ed25519vectors`, and 133
  [Project Wycheproof](https://github.com/C2SP/wycheproof) `eddsa_test`
  vectors, plus pinned Firedancer regression vectors and a generated edge-point
  corpus.
- Differential tests anchoring every backend — cached or not, batched or single
  — to `crypto/ed25519` and to the generic backend, per profile.
- A cross-library differential against
  [curve25519-voi](https://github.com/oasisprotocol/curve25519-voi/tree/1f23a7beb09a)
  version `v0.0.0-20230904125328-1f23a7beb09a`, configured to the equivalent
  strict option set. It is isolated from the library module graph in
  `go.oasis.mod`; run it with `make test-oasis`.
- Fuzz targets comparing backends three ways.

CI runs portable tests on `ubuntu-latest` and `macos-latest`, the isolated
Oasis differential on Linux, plus a pinned
[Intel SDE](https://www.intel.com/content/www/us/en/developer/articles/tool/software-development-emulator.html)
10.8 job that emulates Ice Lake Server and executes focused r51x5 IFMA,
native-SHA, and public forced-r51 differentials. Dedicated `sde_gate` tests
fail rather than skip when the emulated feature set is missing. SDE is
functional coverage only; the Ryzen 7 PRO 8700GE remains the performance and
zero-allocation release authority. Automatic backend selection remains
`generic`.

## Status

Alpha. The `generic` backend, the profile contract, and the per-key comb cache
are functional and differential-tested. The `r51` throughput backend is
registered for explicit selection on supported hardware but remains outside
automatic dispatch. It uses native x8 groups plus x4 tails on measured AMD
family 19h+ IFMA processors. Its opt-in two-tier Cache
and width-aware A6/r9 warm promotion are implemented and hardware-tested; the
traffic-specific admission and eviction policy remains integration work. The
`ifma` reference backend and alternate arithmetic experiments remain under
active development.

## License

Apache-2.0. See [NOTICE](NOTICE) for the full attribution list.

**Vendored code.** `internal/edwards25519` derives from the Go standard
library's `crypto/internal/edwards25519` and from
[`filippo.io/edwards25519` v1.0.0](https://github.com/FiloSottile/edwards25519/tree/v1.0.0);
its `field` subpackage is synchronized to
[`filippo.io/edwards25519` v1.2.0](https://github.com/FiloSottile/edwards25519/tree/v1.2.0)
(BSD-3-Clause). The upstream LICENSE files and BSD headers are preserved.
Modified vendored files retain those headers and are enumerated in
[NOTICE](NOTICE); standalone Narya-authored files carry Apache-2.0 headers.

**Derived work.** The `r43x6` AVX-512 IFMA design and constants in
`internal/r43x6` follow
[Firedancer at `3ed37488372b7e50bb03ca30477be48508ee7022`](https://github.com/firedancer-io/firedancer/tree/3ed37488372b7e50bb03ca30477be48508ee7022),
Copyright 2022 Firedancer Contributors, Apache-2.0. Firedancer records that its
Ed25519 implementation was originally based on OpenSSL's circa-October-2022
implementation; the inherited notice and license text are carried in
[NOTICE](NOTICE).

**Prior work this library descends from.** The generic backend, the per-key
comb cache, and `internal/edwards25519/comb.go` originate in `pkg/ed25519fast`
in [Mithril](https://github.com/Overclock-Validator/mithril), authored by
palmer.

**Specifications and reference implementations.** The acceptance predicate is
that of [ed25519-dalek 2.2.0 at `8016d6d`](https://github.com/dalek-cryptography/curve25519-dalek/tree/8016d6d9b9cdbaa681f24147e0b9377cc8cef934/ed25519-dalek)
`verify_strict`, as reached by
[Agave audit snapshot `7e51da9`](https://github.com/anza-xyz/agave/tree/7e51da963aee49622a395f562386a6bd8ba0e717)
(Anza) through the `solana-signature` crate; Agave is the reference Narya's
verdict must match. The reserved `ZIP215` profile name is from Zcash's
[ZIP 215](https://zips.z.cash/zip-0215). `sha512mb` implements FIPS 180-4. The
square-root-ratio derivation used in `field/fe.go` and `internal/r43x6` follows
[BoringSSL commit `0fc57bef1821c163ac023a0aa96e4fb2a67c0d82`](https://boringssl.googlesource.com/boringssl/+/0fc57bef1821c163ac023a0aa96e4fb2a67c0d82).

**Test corpora.** The CCTV `ed25519vectors` corpus is redistributed under
BSD-3-Clause, Copyright 2019 Google LLC and Copyright 2022 Filippo Valsorda;
its license text is reproduced in full in [NOTICE](NOTICE) as that license
requires. Project Wycheproof vectors are redistributed under Apache-2.0,
Copyright Google LLC.

**Comparison and prior art.**
[curve25519-voi at `1f23a7beb09a`](https://github.com/oasisprotocol/curve25519-voi/tree/1f23a7beb09a)
(Oasis Protocol, BSD-3-Clause) serves as a cross-library differential oracle
and performance baseline. Narya does not use voi's shipped cofactored
ABGLSV–Pornin verification path for `DalekStrict`; multiplying the error point
by a non-injective cofactor can change that predicate. Narya's separate
torsion-safe modulo-8L HEEA work remains experimental.

voi is an opt-in test dependency only. The main `go.mod` retains only
`golang.org/x/sys`; `go.oasis.mod` pins the independent comparator used by
`make test-oasis` and the separately recorded comparison benchmarks.

voi is itself largely derived from
[curve25519-dalek 3.2.0 at `09a726c`](https://github.com/dalek-cryptography/curve25519-dalek/tree/09a726cc8c995a7565d80148536df21f1f287659), and
the vectorized Edwards backend that produces its uncached single-signature
timings is a Go port of dalek's AVX2 backend (Copyright isis agora lovecruft,
Henry de Valence, and Oasis Labs), selected whenever AVX2 is present. That intra-signature
orientation — one point's coordinates across vector lanes — is prior art that
Narya did not originate: dalek's AVX2 backend is a documented implementation,
and Firedancer's `r43x6` QUAD packing, which `internal/r43x6` credits, is the
same idea at AVX-512 width. Narya's experimental
coordinate-parallel work uses that orientation at radix 2^51. See
[NOTICE](NOTICE).
