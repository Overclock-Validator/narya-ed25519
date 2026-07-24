# Benchmarking narya

The benchmarks are ordinary Go benchmarks, so they run **independently of
any consuming node** and put every implementation side by side in one run.
No Mithril, no ledger, no hardware setup — `go test -bench` anywhere.

## Run

```
make bench                 # full sweep, all packages
make bench-verify          # single-signature: stdlib vs narya (4 variants) x msg size
make bench-batch           # batch: lane fill, cache-hit, invalid-mix and lane-position sweeps
make bench-hash            # hashing: crypto/sha512 vs sha512mb
make bench-r51             # experimental x4/x8 field, point, DSM and QSM rows
make bench-r51-pipeline    # release shortlist: complete x8/two-x4 + baselines
make bench-r51-pipeline-full # full forced complete candidate Cartesian matrix
make bench-heea            # exact modulo-8L selector rows
make bench-heea-pipeline   # exact HEEA full verifier vs ordinary r51 DSM
```

Or directly:

```
go test -run '^$' -bench BenchmarkVerify -benchtime 2s ./ed25519
```

## The four implementations, side by side

Every `BenchmarkVerify` row is the *same honest input*, so the sub-benchmark
names are the comparison:

| label | what it measures |
|---|---|
| `impl=stdlib` | `crypto/ed25519.Verify` — the baseline Mithril used |
| `impl=narya-compat` | narya `StdlibCompat` — **same predicate** as stdlib, narya's code path. `narya-compat − stdlib` = our wrapper overhead. |
| `impl=narya-strict` | narya `DalekStrict` — mainnet semantics. `narya-strict − narya-compat` = the small-order pre-pass cost. |
| `impl=narya-cached` | narya through a warm `Cache` (per-key comb table) — the recurring-signer path. |

So the numbers directly answer: what does mainnet-correct verification cost
vs the standard library, and how much comes from the strict pre-pass vs the
arithmetic vs the cache.

## A/B comparison across code versions (benchstat)

To measure the effect of an optimization (e.g. an IFMA backend, or fusing
the strict pre-pass):

```
make bench > before.txt
# ... make the change ...
make bench > after.txt
benchstat before.txt after.txt        # go install golang.org/x/perf/cmd/benchstat@latest
```

benchstat reports the delta with statistical significance across `-count`
runs (use `COUNT=6 make bench` for stable deltas).

## Which backend runs

During development, `ActiveBackend()` keeps the empty/automatic choice on
`generic`. An experimental IFMA backend must be forced with
`OVERCLOCK_ED25519_BACKEND=ifma` (or `SetBackend("ifma")`) on a CPU with
AVX-512+IFMA. Automatic selection stays disabled until the Zen 4 correctness
and performance gates pass. On an arm64 dev machine only `generic` and
`stdlib` can execute, so IFMA measurements require an x86 Zen box.
`sha512mb` reports its lane count in the benchmark name (`x1` scalar fallback,
plus forced-only native `x4` and `x8` rows on supported hardware).

The first IFMA backend is a correctness reference: field multiply/square use
the audited assembly kernel, while point multiplication still uses the
straightforward width-5 variable-base and width-8 basepoint schedules. It has
no cache table or lane-parallel DSM yet. Every field operation still pays an
atomic enable check plus loose-range validation and canonicalization around
the assembly call. Those are intentionally measured correctness-reference
costs, not the expected cost of the final range-tracked loose-limb kernel. Run
its hardware-gated benchmarks directly when measuring that stage:

```
taskset -c 2 env GOMAXPROCS=1 go test -run '^$' \
  -bench '^BenchmarkIFMABackend(Verify|Batch)$' \
  -benchmem -benchtime=3s -count=10 ./ed25519
```

On a CPU without the complete IFMA feature gate these benchmarks skip before
any assembly instruction executes. A skip is not a performance result.

The complete forced r51 candidate is separate from the registered r43
backend. It composes strict/compat byte preparation, paired IFMA `A/R`
decompression, native multi-buffer SHA-512 over the original bytes, canonical
challenge reduction, cold variable-base table construction, exact signed DSM,
and the profile-specific final equation. It exposes true x8, x4, and two-x4
paths at arbitrary-A radix 16, 32, and 64, plus shared scalar-stored B-comb
widths 16/32/256 with a one-table arbitrary-A workspace, without changing
production dispatch. Radix 64 is an ordinary-verifier candidate only: its
43-round loop trades fewer doublings for a 32-point table, so only the complete
cold-path benchmark can justify its larger build and cache footprint.

The complete kernel is compiled from the private normal source file
`ed25519/backend_r51experiment.go`; the benchmark does not use a separate
`_test.go` implementation. Only its raw-dispatch adapter and harness live in
test source. The normal artifact deliberately has no backend registration,
public entry point, or automatic/explicit selector name, so this promotion
boundary changes what can be reviewed and linked into tests, not production
behavior.

The r51 IFMA table benchmarks distinguish three quantities that must not be
conflated: active coordinate payload, concrete table size, and complete
workspace size. `BenchmarkIFMATableFootprint` reports the latter two with
`unsafe.Sizeof` for each radix-16/32/64 specialization on any architecture.
The ordinary DSM and HEEA component rows repeat those metrics beside the timed
paths. Builders no longer clear a maximum radix-64 table before constructing a
smaller table, so the active-payload metric also describes the point entries
written by cold construction (excluding small metadata writes). Run the
complete-path comparison with:

```text
taskset -c 2 env GOMAXPROCS=1 go test -run '^$' \
  -bench '^BenchmarkR51IFMAPipeline$' -benchmem \
  -benchtime=3s -count=10 ./ed25519
```

Candidate rows enter through the same private dispatcher used by the public
`VerifyBatchStrict` API. An optional raw-slice backend interface performs the
length check and then hands the caller-owned slices directly to a native batch
pipeline, avoiding an otherwise artificial `[]batchItem` allocation/copy.
Generic baselines retain their existing item path, and cache batches retain it
because each item must carry a key lookup result. Tests require the raw public
shape to allocate zero bytes and require cache-shaped calls not to bypass
their item metadata.

Paired decompression has its own complete-path admission comparator:

```text
taskset -c 2 env GOMAXPROCS=1 go test -run '^$' \
  -bench '^BenchmarkR51IFMAPairedGate$' -benchmem \
  -benchtime=3s -count=10 ./ed25519
```

It holds radix-32 cold-A DSM, shared B, strict byte preparation, original-byte
hashing, reduction, and all batch boundaries constant. The control row is a
true single-point IFMA decode of A followed by canonical `Q` encoding and an
`Rbytes` comparison; it neither decodes R nor performs projective equality.
The candidate row decodes A/R together and compares Q with decoded affine R
using both cross-products. Rows are named:

```text
BenchmarkR51IFMAPairedGate/stage=cold-A/path={two-x4,x8}/decode=single-A/final=encoded-Q/radixA=32/fixedB=shared/n={1,8,64}/msg={64,200,1232}
BenchmarkR51IFMAPairedGate/stage=cold-A/path={two-x4,x8}/decode=paired-AR/final=projective/radixA=32/fixedB=shared/n={1,8,64}/msg={64,200,1232}
```

Only the complete paired row may pass the paired-decode gate, and only when it
improves the corresponding control by at least 2%. A decompression-only win is
diagnostic because the avoided final inversion/encoding is part of the same
trade. Both modes remain private, forced, and unregistered.

The benchmark deliberately contains the full counts 1--17/32/64 and all six
message sizes, as well as same-harness stdlib and generic-strict baselines. An
unfiltered ten-by-three-second run is therefore very large; use benchmark-name
filters to narrow `path=`, `radixA=`, `fixedB=`, `n=`, or `msg=`. The
timed `stage=cold-A` rows exclude reusable fixed-base `B` preparation but
include every per-batch operation, including the cold `A` table. They are the
dispatch comparison; isolated field, decode, SHA, and DSM rows are diagnostic.

`BenchmarkR51IFMAPipelineParallel` repeats the complete release-candidate
matrix under real Go-worker concurrency: x8 and two-x4 with shared-B radix
16/32/64, plus radix-32 with comb16/32/256, at n=8/64 and
64/200/1232-byte messages. These are twelve actual complete-verifier
configurations. Primitive comb rows and incomplete component combinations are
not promoted into this matrix. The standalone x4 benchmark remains diagnostic:
for n<=4 the two-x4 verifier already executes only its first x4 half, while
adding `path=x4` as a release row would create a duplicate measurement and an
unplanned top-level dispatch choice. SHA/tail selection stays informational.
`GOMAXPROCS` is the modeled verifier-worker count. Every worker gets its own
pipeline, backend adapter, verdict slice, and mutable IFMA workspaces before
timing starts. Workers share only the immutable input fixture and the
process-wide read-only comb table. This makes cache/table pressure visible
without adding a lock to the verifier or changing production dispatch:

```text
taskset -c 0-7 env GOMAXPROCS=8 go test -run '^$' \
  -bench '^BenchmarkR51IFMAPipelineParallel$' \
  -benchmem -benchtime=3s -count=10 ./ed25519
```

The same worker harness also records a concurrent stdlib loop at n=8/64. The
selected ordinary r51 configuration must be at least 15% faster than that
concurrent baseline in every release row, without increasing either B/op or
allocs/op, in addition to staying within 1% of its identical serial r51 path.
A release run requires at least two workers; `GOMAXPROCS=1` is a diagnostic
serial execution, not production cache-pressure evidence.

Two companion forced benchmarks keep invalid traffic in the same complete
candidate boundary:

```text
go test -run '^$' -bench '^BenchmarkR51IFMAPipelineInvalidMix$' \
  -benchmem -benchtime=3s -count=10 ./ed25519
go test -run '^$' -bench '^BenchmarkR51IFMAPipelineInvalidLane$' \
  -benchmem -benchtime=3s -count=10 ./ed25519
```

The first distinguishes cheap strict-precheck rejection from a full-equation
failure at 0/25/50/75/100% invalid ratios for n=8/17. The second moves one
full-equation failure through every lane at the 8/9/16/17 boundaries. Both
compare true x8 with two x4 groups; all allocations and verdict remapping stay
inside the timed call.

The exact modulo-`8L` HEEA experiment has a separate complete boundary:

```text
go test -run '^$' -bench '^BenchmarkR51HEEACompletePipeline$' \
  -benchmem -benchtime=3s -count=10 ./ed25519

taskset -c 0-7 env GOMAXPROCS=8 go test -run '^$' \
  -bench '^BenchmarkR51HEEACompletePipelineParallel$' \
  -benchmem -benchtime=3s -count=10 ./ed25519
```

Each HEEA row includes strict prechecks, paired decode, native segmented
SHA-512, scalar reduction, one allocation-free selector call per live
signature, `tau*s mod L`, cold `R` and `A` table construction, the signed
four-term QSM, the identity mask, and any ordinary strict fallback. It compares
widths 128/132/136, radix 16/32, and true x8/two-x4 against the ordinary r51
pipeline in the same harness. Reported selector and ordinary-fallback rates
must be interpreted with the time; a shorter QSM that loses to selection or
the second cold table is not a win.

The parallel benchmark is deliberately narrower: it measures only the
reviewed W132/radix-32 x8 and two-x4 candidates at n=8/64 and 64/200/1232-byte
messages. Each worker owns its mutable HEEA pipeline, ordinary-fallback
workspace, counters, and verdict buffer. It shares only immutable fixtures.
The release evaluator compares these rows, and the corresponding serial HEEA
rows, with the exact ordinary r51 configuration selected by the production-
worker shortlist. A fixed same-path radix-32 row is not a valid promotion
baseline after radix-64 or a fixed-B comb has won ordinary selection.

`BenchmarkR51HEEACompletePipelineFallback` exercises the actual W132/radix-32
release candidate. For each x8 and two-x4 shape and each release message size,
it moves one selector miss through all eight lane positions and then forces all
eight lanes to miss. The retained radix-32 ordinary DSM reuses the initial
decode and hash; the independent generic verifier is an oracle, not benchmarked
fallback work. The release evaluator compares every n=8 fallback row with the
exact ordinary r51 configuration selected by the worker shortlist. Any row
slower by more than 5%, or any B/op or allocs/op increase, rejects that HEEA
shape. This is fail-closed because valid inputs can steer selector fallback.
All complete rows report selector, preparation, evaluation, and ordinary
fallback rates. The first three are disjoint sources and their sum must equal
the ordinary rate. Kernel errors abort and fail closed rather than silently
entering a different backend.
HEEA remains test-only unless one coherent SIMD shape beats the selected
ordinary r51 configuration by at least 5% in every serial and production-
worker release row, clears the adversarial fallback gate above, has no
allocation increase, and has zero predicate mismatches.

## Reading the message-size sweep

The complete sweep is 64 / 176 / 200 / 512 / 1024 / 1232 bytes. The
64 / 200 / 1232 rows remain the release-gate set; 176 and 512 expose
intermediate SHA-512 block regimes, and 1024 makes published large-message
throughput results easier to compare without pretending their workload or
acceptance predicate is equivalent to Narya's. Point math is constant across
sizes while hashing grows, so the spread between a 64-byte and a 1232-byte
row is the hashing fraction. Bench `sha512mb` directly to isolate it.

## Reading the batch sweeps

`BenchmarkVerifyBatch` retains the headline `impl=.../n=.../msg=...`
rows and now covers every size from 1 through 17, then 32 and 64. The dense
range makes the x8 boundaries at 8/9 and 16/17 visible rather than comparing
only full batches.

The companion batch benchmarks isolate workload shape:

| benchmark | dimension |
|---|---|
| `BenchmarkVerifyBatchCacheMix` | stable 0 / 10 / 25 / 50 / 75 / 90 / 100% precomputed-key hits; misses are prevented from becoming hits during a long run |
| `BenchmarkVerifyBatchValidity` | 0 / 25 / 50 / 75 / 100% invalid items, distributed over four phases and several rejection depths |
| `BenchmarkVerifyBatchInvalidLane` | one full-equation failure at every lane for n=8/9/16/17 |

`BenchmarkStrictPointPrechecks` compares the seven-value classifier and the
ordered canonical-R predicate with their decode/cofactor and re-encode
specifications. It is diagnostic only; the complete `BenchmarkVerify` delta is
the strict-precheck release gate.

`BenchmarkStrictPrecheckCompletePipeline` provides a more controlled
before/after diagnostic around the same uncached generic verifier. Its
`legacy-decode-cofactor` mode permissively decodes A and R and calls
`IsSmallOrder`; `seven-value` uses the production byte pre-pass. Both modes
also emit `profile=compat` controls, where the structurally shared wrapper
skips strict rejection, at the 64/200/1232 release message sizes. These rows
isolate the pre-pass replacement without changing production dispatch. The
Zen 4 evaluator requires at least a 3% complete strict-verifier gain at every
release message size, no allocation increase, and no more than a 1% regression
in the compat control.

`BenchmarkUnaffectedCompatCompletePipeline` is the broader portable-path
control. The harness is intentionally standalone and uses only public APIs
that exist in both the current tree and commit
`05bf37ca843842f54109581755d587dc552e7aa8`, the reviewed pre-plan baseline.
The Zen 4 driver archives that exact commit into a temporary directory, copies
the identical harness into it, and compiles both source trees with the same Go
toolchain and `OVERCLOCK_ED25519_BACKEND=generic`. It compares complete
StdlibCompat single verification at n=1 and batch verification at n=8/64 for
64/200/1232-byte messages. Unlike an in-tree replica, the baseline retains its
own verifier, Edwards arithmetic, SHA implementation, and entry-point
plumbing. `unaffected-compat-source.txt` records the full baseline revision,
current HEAD, and harness blob. Both benchmark binaries are built once, outside
the timed work. The driver then collects ten one-count runs on the same pinned
core, alternating which revision runs first on every repetition to reduce
thermal and fixed-order drift. Every current row must stay within 1% of its
same-harness baseline row without increasing allocations. This median
point-estimate guard still requires a `benchstat` significance review before
release; alternation does not turn a noisy host into a controlled experiment.

Quarter mixtures process four independent batches per benchmark loop, so every
measured loop has the labeled ratio even for `n=1`. To run one slice directly:

```
go test -run '^$' -bench 'BenchmarkVerifyBatchCacheMix/.*/n=9/' -benchtime 2s ./ed25519
go test -run '^$' -bench 'BenchmarkVerifyBatchInvalidLane/.*/n=17/' -benchtime 2s ./ed25519
```

## Note on hardware

Committed numbers should say which CPU produced them. arm64 dev results are
indicative of *structure* (which path is faster, where time goes) but not
of production magnitude — the target is x86 Zen 4/Zen 5, where the IFMA
path exists and the double-pumped (Zen 4) vs native-512 (Zen 5) datapaths
differ. Always benchmark the real target before committing to a kernel.

## Zen 4 release protocol

The Ryzen 7 PRO 8700GE is the first release authority. Primitive and
single-signature measurements should use one pinned core and one Go worker;
throughput measurements should also be repeated with Mithril's intended
worker count. Record at least ten samples of three seconds each:

The checked-in gate driver first runs the complete and hardware-only
correctness suites, focused vet and race runs, and the frozen-revision
unaffected-path comparison. It fails if a required IFMA/native test skips, and
then writes the generic and final-r51 fuzz logs, release shortlist,
single-signature, strict-precheck, paired-decode, SHA-tail, primitive,
selector, complete HEEA, fallback, invalid-traffic, and hardware-counter
results into a caller-selected directory. `vet-focused.txt` and
`race-focused.txt` cover `ed25519`, `internal/r51x5`, `internal/heea8l`, and
`sha512mb`:

```text
./scripts/zen4-gate.sh 2
```

The default result path is the adjacent absolute directory
`../narya-zen4-results`. The release driver requires its complete result path
to be outside the Narya worktree and requires that path not to exist. This
keeps generated logs out of the tracked-plus-untracked source manifest and
prevents stale files from an earlier run entering the bundle. Choose a fresh
outside-worktree path for each run. A failed run remains visibly incomplete;
a passing 8700GE release bundle has `state=complete`, matching start/end source manifests and
a verified top-level `SHA256SUMS` (including the profiler subtree). Both gate
scripts use a restrictive umask so this private source and profiling evidence
is readable only by the user that ran the command.

The gate uses half of the online logical CPUs as its default verifier-worker
count (and requires at least two) and CPUs `0..workers-1` as a simple default
cpuset. Inspect `lscpu` and
override both values when that range does not select the intended physical
cores or when Mithril uses a different worker count. Positional arguments and
equivalent environment variables are supported:

```text
./scripts/zen4-gate.sh 2 ../narya-zen4-results-run-002 8 0-7
NARYA_ZEN4_WORKERS=8 NARYA_ZEN4_CPUSET=0-7 \
  ./scripts/zen4-gate.sh 2 ../narya-zen4-results-run-003
```

The resolved values are stored in `benchmark-config.txt`; concurrent shortlist
candidate results are stored in `pipeline-workers.txt` and concurrent stdlib
controls in `pipeline-worker-baselines.txt`. The evaluator consumes
those results to choose one coherent production-worker candidate across n=8,
n=64, and all three release message sizes. A worker candidate is eligible only
if that same configuration independently clears the serial 15% batch gate and
the 2% optional-variant gate at both counts. It must also beat concurrent
stdlib by at least 15% in every row and may not regress by more than 1%
wall-ns/op versus the identical single-worker complete path. This
is point-estimate scaling and cache-pressure evidence, not a replacement for
`benchstat` or Mithril trace replay.

It intentionally leaves production dispatch unchanged. Inspect the hardware
correctness log before interpreting any benchmark. The final
`gate-summary.txt` requires exactly ten samples for every expected row, rejects
missing and unexpected rows, and uses the median timing plus the maximum
observed `B/op` and `allocs/op`. A missing memory column is a malformed row. It
fails when the mandatory 10% cold-single or 15%
n=8/64 microbenchmark thresholds are not met, when the strict precheck misses
its 3% complete-path threshold, when the compat control regresses by more than
1%, when any general portable StdlibCompat row regresses by more than 1%
against the frozen source baseline, when neither SIMD shape clears the
paired-decode 2% gate, or when a chosen candidate increases allocations. Only
SIMD shapes admitted by the paired gate enter ordinary r51 selection. A single
implementation must clear every release message size for the single gate, and
each batch width selects one coherent configuration across message sizes.

Radix 16/64 and fixed-B comb16/32/256 are optional variants. Each is compared
only with the same SIMD path's complete radix-32/shared-B verifier and becomes
eligible only if it improves every release message size by at least 2% without
an allocation increase. This prevents isolated DSM/comb measurements from
being treated as complete-verifier evidence. The evaluator prefers one x8
group when an otherwise identical two-x4 configuration is no more than 2%
faster throughout the compared workloads. It applies the same coherent-path
rule to the reviewed W132/radix-32 HEEA release candidate, but HEEA is compared
with the already-selected ordinary production-worker configuration in both
serial and worker matrices. One x8 or two-x4 HEEA shape must clear every row by
at least 5% without increasing allocations; a win over only its same-path
radix-32 reference cannot promote it. The evaluator reports scalar/x4/x8 SHA
tail winners separately. Other HEEA widths/radices remain diagnostic until
explicitly admitted into the release matrix. This automatic point-estimate check does not replace
`benchstat` significance review or the still-required 5% Mithril wall-time
replay gate.

The runner also writes `micro-gate-decision.json`. This versioned artifact
binds the selected r43 single-call and r51 batch candidates to the exact source
manifest, benchmark configuration, Git revision, and input evidence hashes.
It is deliberately not a release authorization: `production_promotable` is
always false, with dense-tail confidence, Mithril replay, backend-native cache
trace evidence, and reviewed release-source authority left pending. Feed this
artifact to the separate dense-tail gate only after the micro-gate succeeds:

```text
./scripts/zen4-dense-tail-gate.sh \
  --result-dir ../narya-zen4-dense-run-001 \
  --core 2 \
  --selection-json ../narya-zen4-results-run-003/micro-gate-decision.json
```

That follow-on builds the test binary once and alternates stdlib/candidate
order for ten paired three-second rounds at every batch size 1--17, 32, and
64. Its conservative paired-confidence result requires at least 15% at n=8
and n=64. Other widths explicitly retain stdlib whenever the selected r51
candidate is not confidently faster across all release message sizes.

The final profiling phase requires Linux `perf` permission and, by default, an
exact CPU model containing `AMD Ryzen 7 PRO 8700GE`. Another AVX-512 IFMA host
is not release authority. It can execute the harness only with
`NARYA_ZEN4_ALLOW_NON_RELEASE_CPU=1`, and its `machine.txt` is permanently
marked `measurement_authority=diagnostic-only`. The top-level gate uses
`state=diagnostic-micro-gate-incomplete` while running and
`state=diagnostic-micro-gate-complete` after checksumming; an override can
never emit the release-authoritative `state=micro-gate-complete`.

The profiler refuses an existing result directory. A partial release run retains
`state=micro-gate-incomplete`; a successful 8700GE release run has
`state=micro-gate-complete` plus a verified
`SHA256SUMS` over every artifact. When the result directory is inside the
worktree, its exact repo-relative path is excluded from source capture. The
full release gate is stricter and accepts only an outside-worktree path.

Before building, `source-manifest.tsv` hashes the path, type, mode, size and
contents of every tracked and untracked nonignored working-tree file. This is
necessary because much of the experimental backend may not yet be committed;
a commit hash or `git diff` alone would be ambiguous. `source-provenance.txt`
also records the commit, branch, dirty flag, status digest and binary-diff
digest. The same source manifest is regenerated after profiling and the run
fails if it changed. Binary SHA-256 values and `go version -m` output bind the
result back to the built executables. `go-env-allowlist.json` records only
`GOOS`, `GOARCH`, `GOVERSION`, `GOROOT`, `GOAMD64`, `CGO_ENABLED`,
`GOEXPERIMENT`, `GOFLAGS`, `GOTOOLCHAIN`, `GOMOD`, and `GOWORK`; unrestricted
`go env -json` is intentionally not captured because proxy/auth configuration
can contain private endpoints or credentials.

The profiler records the exact CPU model and topology, pinning probe, kernel,
Go/perf/binutils versions, governor, scaling driver, min/max controls,
turbo/boost state and available AMD P-state controls. Governor/turbo controls
are sampled before and after and any change fails the run. Current frequency
and load are snapshots only; effective frequency evidence comes from PMU
`cycles / task-clock`, with `cycles / ref-cycles` retained alongside it.

It builds the actual `ed25519` and `r51x5` test binaries and retains their
sizes, filtered symbol sizes, and disassembly. PMU collection runs three
separate passes per benchmark so the requested events fit the Zen 4 counters:

- core: task-clock, cycles, reference cycles, instructions and branch events;
- cache: generic cache and L1 data-load events;
- L2: Zen 4 `l2_cache_req_stat.dc_access_in_l2` data accesses and
  `l2_cache_req_stat.ls_rd_blk_c` request misses.

Every required event is probed first. Every probe and measured pass must return
one numeric count, numeric runtime, and at least 99% scheduled time; unsupported,
uncounted, duplicate, nonnumeric, or materially multiplexed counters fail the
run. `perf-metrics-*.txt` derives IPC, effective GHz, reference-cycle ratio,
branch/cache/L1 miss rates and the L2 data-request miss rate from counters
collected in the same pass. A permission failure is likewise a failed release
measurement. Each exact benchmark filter must yield one row per `perf`
repetition. Run it independently when iterating on one kernel:

```text
./scripts/zen4-profile.sh 2 ../narya-zen4-profile-run-001
```

```text
taskset -c 2 env GOMAXPROCS=1 go test -run '^$' \
  -bench 'BenchmarkVerify$' -benchmem -benchtime=3s -count=10 ./ed25519 \
  > zen4-verify.txt

taskset -c 2 env GOMAXPROCS=1 go test -run '^$' \
  -bench 'BenchmarkVerifyBatch' -benchmem -benchtime=3s -count=10 ./ed25519 \
  > zen4-batch.txt

benchstat zen4-before.txt zen4-after.txt
```

Use the same core, governor, Go toolchain, backend setting, and machine load
for both sides of an A/B result. A forced IFMA run must set
`OVERCLOCK_ED25519_BACKEND=ifma`; a skipped IFMA hardware test is a failed
measurement setup, not a passing result.

For a representative fixed benchmark, collect hardware counters separately
from the statistical timing run:

```text
taskset -c 2 perf stat -r 10 \
  -e cycles,instructions,branches,branch-misses,cache-references,cache-misses,L1-dcache-load-misses \
  env GOMAXPROCS=1 OVERCLOCK_ED25519_BACKEND=ifma \
  go test -run '^$' -bench 'BenchmarkVerify/impl=narya-strict/msg=200$' \
  -benchtime=3s -count=1 ./ed25519
```

Also retain `-benchmem`, the benchmark binary size, and disassembly of each
candidate kernel. `*-static-stack-spill.tsv` deterministically reports the
first immediate downward RSP adjustment and counts SP-relative data/address
instructions, including vector-memory candidates, for every matched symbol.
It is explicitly **static generated-code evidence**: SP-relative operands can
be arguments or locals, do not prove execution frequency, and are not a
runtime stack-traffic measurement. Runtime spill/stack claims still require
appropriate sampling/PMU evidence. For x4/x8 table experiments, include L1/L2
behavior and effective frequency; an arithmetic win that loses to table lookup
pressure does not pass the complete-verifier gate.

## Exact Mithril trace cache diagnostic

`cmd/sigverifytracebench` consumes an exact `mithril-sigverify-v3` JSONL
export without importing Mithril into Narya or adding Narya to Mithril. Its
parser mirrors the authoritative `mithril/pkg/sigverifytrace` parser:
noncanonical hex/base64, schema drift, invalid bounded-ring suffixes, invalid
sources, and inconsistent dispatch/lane metadata are errors.

The command replays retained verification records in recorded attempt/begin
order through `crypto/ed25519.Verify`, uncached `narya.VerifyStrict`, and
`Cache.VerifyStrict`. The cache is empty at the start of every complete trace
pass, so sighting, admission, table-build, and budget costs are included.
Parsing, semantic preflight, inter-sample garbage collection, and the
`runtime.MemStats` reads sit outside the timed region. Reported allocation
deltas are process-wide and noisier than `testing.B` counters. SIMD batching is
disabled to isolate the current generic key-cache effect.

On the Zen 4 measurement host, pin externally and record both attestations:

```text
taskset -c 2 go run ./cmd/sigverifytracebench \
  -input mithril-sigverify-v3.jsonl \
  -output generic-cache-evidence.json \
  -representative \
  -pinned-core-attested
```

Release-quality defaults are ten rotating-order samples and at least three
seconds per variant per sample. Diagnostic qualification additionally requires
10,000 retained records, `GOMAXPROCS=1`, no truncated prefix or unknown
completion, exact agreement between recorded outcomes and all three paths, and
an actual generic cache-table hit. A predicate mismatch aborts before timing.
The artifact includes the input SHA-256, Go/build VCS provenance when
available, raw time/allocation samples, medians/maxima, and a paired-by-round
bootstrap lower 95% speedup bound. Existing evidence is never overwritten and
the input cannot be the output path.

This remains a **generic-cache diagnostic**, not the production cache release
gate. Generic Edwards tables differ from the selected r51 table representation,
x8 packing, and gather path, while synchronous replay cannot reconstruct
overlapping completion timing, queueing, worker contention, or Mithril wall
time. The JSON therefore leaves `production_r51_cache_gate.status` at
`pending_backend_native_cache` even if the generic diagnostic's lower bound is
above 2%. Production admission still needs the selected backend's real cache
path and a representative end-to-end Mithril A/B gain of at least 2%.
