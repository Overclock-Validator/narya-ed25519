#!/bin/sh
set -eu

export LC_ALL=C
umask 077

fail() {
	echo "zen4-gate: $*" >&2
	exit 1
}

for tool in git python3 taskset sha256sum find sort xargs cmp awk getconf; do
	command -v "$tool" >/dev/null 2>&1 || fail "$tool is required"
done

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
repo_root=$(git -C "$script_dir/.." rev-parse --show-toplevel) || \
	fail "script is not inside a Git worktree"
repo_root=$(CDPATH= cd -- "$repo_root" && pwd -P)
default_result_dir=$(python3 -c 'import os, sys; print(os.path.realpath(sys.argv[1]))' \
	"$repo_root/../narya-zen4-results")

core=${1:-2}
result_dir_arg=${2:-$default_result_dir}
result_dir=$(python3 -c 'import os, sys; print(os.path.realpath(os.path.abspath(sys.argv[1])))' \
	"$result_dir_arg")

[ "$result_dir" != "/" ] || fail "refusing to use / as the result directory"
[ "$result_dir" != "$repo_root" ] || fail "refusing to use the worktree root as the result directory"
case "$result_dir/" in
	"$repo_root"/*)
		fail "release result directory must be outside the Narya worktree so generated outputs cannot contaminate source provenance"
		;;
esac
if [ -e "$result_dir" ] || [ -L "$result_dir" ]; then
	fail "result directory already exists; choose a new path so stale artifacts cannot enter the release bundle: $result_dir"
fi

cd "$repo_root"

if [ "$(uname -s)" != "Linux" ] || [ "$(uname -m)" != "x86_64" ]; then
	fail "Linux x86_64 is required"
fi
if ! grep -qw avx512ifma /proc/cpuinfo; then
	fail "CPU flags do not contain avx512ifma"
fi
case "${NARYA_ZEN4_ALLOW_NON_RELEASE_CPU:-0}" in
	0|1) ;;
	*) fail "NARYA_ZEN4_ALLOW_NON_RELEASE_CPU must be 0 or 1" ;;
esac
cpu_model=$(awk -F: '/^model name[[:space:]]*:/{sub(/^[[:space:]]+/, "", $2); print $2; exit}' /proc/cpuinfo)
[ -n "$cpu_model" ] || fail "could not determine exact CPU model from /proc/cpuinfo"
normalized_cpu_model=$(printf '%s\n' "$cpu_model" | awk '{$1=$1; print}')
case "$normalized_cpu_model" in
	*"AMD Ryzen 7 PRO 8700GE"*) release_cpu_match=true ;;
	*)
		release_cpu_match=false
		if [ "${NARYA_ZEN4_ALLOW_NON_RELEASE_CPU:-0}" != 1 ]; then
			fail "release gate requires an AMD Ryzen 7 PRO 8700GE; use NARYA_ZEN4_ALLOW_NON_RELEASE_CPU=1 only for diagnostics"
		fi
		;;
esac
run_incomplete_state=micro-gate-incomplete
run_complete_state=micro-gate-complete
if [ "$release_cpu_match" != true ]; then
	run_incomplete_state=diagnostic-micro-gate-incomplete
	run_complete_state=diagnostic-micro-gate-complete
fi

online_cpu_count=$(getconf _NPROCESSORS_ONLN 2>/dev/null) || \
	fail "could not determine the number of online CPUs"
case $online_cpu_count in
	''|*[!0-9]*) fail "online CPU count is not a positive integer: $online_cpu_count" ;;
esac
[ "$online_cpu_count" -ge 1 ] || fail "online CPU count must be positive"
default_workers=$((online_cpu_count / 2))
if [ "$default_workers" -lt 2 ]; then
	default_workers=2
fi
worker_count=${3:-${NARYA_ZEN4_WORKERS:-$default_workers}}
case $worker_count in
	''|*[!0-9]*)
		echo "zen4-gate: verifier worker count must be a positive integer" >&2
		exit 1
		;;
esac
if [ "$worker_count" -lt 2 ]; then
	echo "zen4-gate: verifier worker count must be at least two for production cache-pressure evidence" >&2
	exit 1
fi
default_worker_cpuset=0
if [ "$worker_count" -gt 1 ]; then
	default_worker_cpuset="0-$((worker_count - 1))"
fi
worker_cpuset=${4:-${NARYA_ZEN4_CPUSET:-$default_worker_cpuset}}
process_allowed_cpus=$(awk '/^Cpus_allowed_list:/{print $2; exit}' /proc/self/status)
[ -n "$process_allowed_cpus" ] || fail "could not determine the process-allowed CPU list"
if ! topology_record=$(python3 ./scripts/zen4-topology.py \
	--primitive-core "$core" \
	--worker-cpuset "$worker_cpuset" \
	--workers "$worker_count" \
	--allowed-cpuset "$process_allowed_cpus"); then
	fail "primitive core or verifier worker topology is not authoritative"
fi
if ! taskset -c "$core" true >/dev/null 2>&1; then
	echo "zen4-gate: primitive benchmark core '$core' is not available" >&2
	exit 1
fi
if ! taskset -c "$worker_cpuset" true >/dev/null 2>&1; then
	echo "zen4-gate: verifier worker cpuset '$worker_cpuset' is not available" >&2
	exit 1
fi

mkdir -p "$result_dir"
gate_started_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
printf 'state=%s\nstarted_utc=%s\n' \
	"$run_incomplete_state" "$gate_started_utc" >"$result_dir/run-status.txt"
printf '%s\n' "$topology_record" >"$result_dir/cpu-topology.txt"
python3 ./scripts/zen4-source-manifest.py \
	--repo "$repo_root" --output "$result_dir/source-manifest-start.tsv"

unaffected_baseline_revision=05bf37ca843842f54109581755d587dc552e7aa8
unaffected_harness=scripts/unaffectedbench/unaffected_compat_test.go
if ! grep -q "const unaffectedBaselineRevision = \"$unaffected_baseline_revision\"" "$unaffected_harness"; then
	echo "zen4-gate: unaffected benchmark harness/revision mismatch" >&2
	exit 1
fi
if ! git cat-file -e "$unaffected_baseline_revision^{commit}"; then
	echo "zen4-gate: missing unaffected baseline commit $unaffected_baseline_revision" >&2
	exit 1
fi
unaffected_baseline_dir=$(mktemp -d "${TMPDIR:-/tmp}/narya-unaffected.XXXXXX")
cleanup_unaffected_baseline() {
	rm -rf -- "$unaffected_baseline_dir"
}
trap cleanup_unaffected_baseline EXIT
trap 'exit 1' HUP INT TERM
git archive --format=tar --output="$unaffected_baseline_dir/narya.tar" "$unaffected_baseline_revision"
tar -xf "$unaffected_baseline_dir/narya.tar" -C "$unaffected_baseline_dir"
mkdir -p "$unaffected_baseline_dir/scripts/unaffectedbench"
cp "$unaffected_harness" "$unaffected_baseline_dir/scripts/unaffectedbench/unaffected_compat_test.go"

{
	echo "baseline_revision=$unaffected_baseline_revision"
	echo "current_head=$(git rev-parse HEAD)"
	echo "harness_blob=$(git hash-object "$unaffected_harness")"
} >"$result_dir/unaffected-compat-source.txt"

{
	echo "cpu_model=$cpu_model"
	echo "release_cpu_match=$release_cpu_match"
	echo "non_release_cpu_override=${NARYA_ZEN4_ALLOW_NON_RELEASE_CPU:-0}"
	echo "primitive_core=$core"
	echo "online_cpu_count=$online_cpu_count"
	echo "verifier_workers=$worker_count"
	echo "verifier_cpuset=$worker_cpuset"
	echo "worker_topology_artifact=cpu-topology.txt"
	printf '%s\n' "$topology_record"
} >"$result_dir/benchmark-config.txt"

go test ./... >"$result_dir/correctness-all.txt"

{
	echo "packages=./ed25519 ./internal/r51x5 ./internal/heea8l ./sha512mb"
	go vet ./ed25519 ./internal/r51x5 ./internal/heea8l ./sha512mb
	echo "status=pass"
} >"$result_dir/vet-focused.txt" 2>&1

{
	echo "cpuset=$worker_cpuset"
	echo "gomaxprocs=$worker_count"
	echo "packages=./ed25519 ./internal/r51x5 ./internal/heea8l ./sha512mb"
	taskset -c "$worker_cpuset" env GOMAXPROCS="$worker_count" go test \
		-race -count=1 ./ed25519 ./internal/r51x5 ./internal/heea8l ./sha512mb
	echo "status=pass"
} >"$result_dir/race-focused.txt" 2>&1

taskset -c "$core" env GOMAXPROCS=1 go test -v \
	-run 'Test(R51IFMA|R51HEEA|ExperimentalIFMA.*(Hardware|Matches|Preserves|ZeroAllocations)|Native(X4|X8).*(Differential|Allocations))' \
	./ed25519 ./internal/r51x5 ./sha512mb >"$result_dir/correctness-hardware.txt"

if grep -q -- '--- SKIP:' "$result_dir/correctness-hardware.txt"; then
	echo "zen4-gate: a required hardware test skipped; see $result_dir/correctness-hardware.txt" >&2
	exit 1
fi

taskset -c "$core" env GOMAXPROCS=1 go test -run '^$' \
	-fuzz '^FuzzVerifyDifferential$' -fuzztime=60s \
	./ed25519 >"$result_dir/fuzz-generic.txt"

taskset -c "$core" env GOMAXPROCS=1 go test -run '^$' \
	-fuzz '^FuzzR51IFMAPipelineDifferential$' -fuzztime=60s \
	./ed25519 >"$result_dir/fuzz-r51.txt"

taskset -c "$core" env GOMAXPROCS=1 go test -run '^$' \
	-fuzz '^FuzzSelectShiftSubtract$' -fuzztime=60s \
	./internal/heea8l >"$result_dir/fuzz-heea-selector.txt"

taskset -c "$core" env GOMAXPROCS=1 go test -run '^$' \
	-fuzz '^FuzzExperimentalUniformScalarReduction$' -fuzztime=60s \
	./internal/r51x5 >"$result_dir/fuzz-scalar-reduction.txt"

taskset -c "$core" env GOMAXPROCS=1 go test -run '^$' \
	-fuzz '^FuzzSum512Differential$' -fuzztime=60s \
	./sha512mb >"$result_dir/fuzz-sha512.txt"

taskset -c "$core" env GOMAXPROCS=1 go test -run '^$' \
	-bench 'BenchmarkR51IFMAPipeline/stage=cold-A/path=(stdlib|generic-strict)/n=(1|4|8|9|17|64)/msg=(64|200|1232)' \
	-benchmem -benchtime=3s -count=10 ./ed25519 >"$result_dir/pipeline-baselines.txt"

taskset -c "$core" env GOMAXPROCS=1 go test -run '^$' \
	-bench 'BenchmarkR51IFMAPipeline/stage=cold-A/path=(two-x4|x8)/radixA=(16|32|64)/fixedB=(shared|comb16|comb32|comb256)/n=(1|4|8|9|17|64)/msg=(64|200|1232)' \
	-benchmem -benchtime=3s -count=10 ./ed25519 >"$result_dir/pipeline-candidates.txt"

taskset -c "$worker_cpuset" env GOMAXPROCS="$worker_count" go test -run '^$' \
	-bench '^BenchmarkR51IFMAPipelineParallel/workers=[0-9]+/stage=cold-A/path=stdlib/n=(8|64)/msg=(64|200|1232)$' \
	-benchmem -benchtime=3s -count=10 ./ed25519 >"$result_dir/pipeline-worker-baselines.txt"
worker_baseline_rows=$(grep -c '^BenchmarkR51IFMAPipelineParallel/' "$result_dir/pipeline-worker-baselines.txt" || true)
expected_worker_baseline_rows=$((2 * 3 * 10))
if [ "$worker_baseline_rows" -ne "$expected_worker_baseline_rows" ]; then
	echo "zen4-gate: concurrent stdlib baseline produced $worker_baseline_rows rows; expected $expected_worker_baseline_rows" >&2
	exit 1
fi

taskset -c "$worker_cpuset" env GOMAXPROCS="$worker_count" go test -run '^$' \
	-bench '^BenchmarkR51IFMAPipelineParallel/workers=[0-9]+/stage=cold-A/path=(two-x4|x8)/radixA=(16|32|64)/fixedB=(shared|comb16|comb32|comb256)/n=(8|64)/msg=(64|200|1232)$' \
	-benchmem -benchtime=3s -count=10 ./ed25519 >"$result_dir/pipeline-workers.txt"
worker_rows=$(grep -c '^BenchmarkR51IFMAPipelineParallel/' "$result_dir/pipeline-workers.txt" || true)
expected_worker_rows=$((12 * 2 * 3 * 10))
if [ "$worker_rows" -ne "$expected_worker_rows" ]; then
	echo "zen4-gate: worker shortlist produced $worker_rows rows; expected $expected_worker_rows" >&2
	exit 1
fi

taskset -c "$core" env GOMAXPROCS=1 go test -run '^$' \
	-bench 'BenchmarkVerify/impl=stdlib/msg=(64|200|1232)' \
	-benchmem -benchtime=3s -count=10 ./ed25519 >"$result_dir/single-baseline.txt"

taskset -c "$core" env GOMAXPROCS=1 go test -run '^$' \
	-bench 'BenchmarkIFMABackendVerify/profile=strict/msg=(64|200|1232)' \
	-benchmem -benchtime=3s -count=10 ./ed25519 >"$result_dir/single-ifma.txt"

taskset -c "$core" env GOMAXPROCS=1 go test -run '^$' \
	-bench '^BenchmarkStrictPrecheckCompletePipeline$' \
	-benchmem -benchtime=3s -count=10 ./ed25519 >"$result_dir/strict-precheck.txt"

unaffected_current_binary="$unaffected_baseline_dir/unaffected-current.test"
unaffected_baseline_binary="$unaffected_baseline_dir/unaffected-baseline.test"
go test -c -o "$unaffected_current_binary" ./scripts/unaffectedbench
(
	cd "$unaffected_baseline_dir"
	go test -c -o "$unaffected_baseline_binary" ./scripts/unaffectedbench
)

unaffected_current_output="$result_dir/unaffected-compat-current.txt"
unaffected_baseline_output="$result_dir/unaffected-compat-baseline.txt"
: >"$unaffected_current_output"
: >"$unaffected_baseline_output"
run_unaffected_compat() {
	unaffected_binary=$1
	unaffected_output=$2
	taskset -c "$core" env GOMAXPROCS=1 OVERCLOCK_ED25519_BACKEND=generic \
		"$unaffected_binary" -test.run '^$' \
		-test.bench '^BenchmarkUnaffectedCompatCompletePipeline$' \
		-test.benchmem -test.benchtime=3s -test.count=1 \
		>>"$unaffected_output"
}
unaffected_iteration=1
while [ "$unaffected_iteration" -le 10 ]; do
	if [ $((unaffected_iteration % 2)) -eq 1 ]; then
		run_unaffected_compat "$unaffected_current_binary" "$unaffected_current_output"
		run_unaffected_compat "$unaffected_baseline_binary" "$unaffected_baseline_output"
	else
		run_unaffected_compat "$unaffected_baseline_binary" "$unaffected_baseline_output"
		run_unaffected_compat "$unaffected_current_binary" "$unaffected_current_output"
	fi
	unaffected_iteration=$((unaffected_iteration + 1))
done

taskset -c "$core" env GOMAXPROCS=1 go test -run '^$' \
	-bench '^BenchmarkR51IFMAPairedGate$' \
	-benchmem -benchtime=3s -count=10 ./ed25519 >"$result_dir/paired-gate.txt"

taskset -c "$core" env GOMAXPROCS=1 go test -run '^$' \
	-bench '^BenchmarkNativeTails$' \
	-benchmem -benchtime=3s -count=10 ./sha512mb >"$result_dir/sha-tails.txt"

taskset -c "$core" env GOMAXPROCS=1 go test -run '^$' \
	-bench '^BenchmarkExperimental(IFMADecode2NoT|IFMAHEEABaseSplit|UniformScalarReduction|FixedBaseCombCompleteDSMTradeoffX8)$' \
	-benchmem -benchtime=3s -count=10 ./internal/r51x5 >"$result_dir/primitives.txt"

taskset -c "$core" env GOMAXPROCS=1 go test -run '^$' \
	-bench '^BenchmarkIFMATableFootprint$' \
	-benchtime=1x -count=1 ./internal/r51x5 >"$result_dir/table-footprint.txt"

taskset -c "$core" env GOMAXPROCS=1 go test -run '^$' \
	-bench '^BenchmarkSelectShiftSubtract$' \
	-benchmem -benchtime=3s -count=10 ./internal/heea8l >"$result_dir/heea-selector.txt"

taskset -c "$core" env GOMAXPROCS=1 go test -run '^$' \
	-bench '^BenchmarkR51HEEACompletePipeline/stage=cold-AR/mode=heea/path=(two-x4|x8)/W132/radix=32/n=(8|64)/msg=(64|200|1232)$' \
	-benchmem -benchtime=3s -count=10 ./ed25519 >"$result_dir/heea-complete.txt"
heea_serial_rows=$(grep -c '^BenchmarkR51HEEACompletePipeline/' "$result_dir/heea-complete.txt" || true)
expected_heea_rows=$((2 * 2 * 3 * 10))
if [ "$heea_serial_rows" -ne "$expected_heea_rows" ]; then
	echo "zen4-gate: serial HEEA candidate produced $heea_serial_rows rows; expected $expected_heea_rows" >&2
	exit 1
fi

taskset -c "$worker_cpuset" env GOMAXPROCS="$worker_count" go test -run '^$' \
	-bench '^BenchmarkR51HEEACompletePipelineParallel/workers=[0-9]+/stage=cold-AR/mode=heea/path=(two-x4|x8)/W132/radix=32/n=(8|64)/msg=(64|200|1232)$' \
	-benchmem -benchtime=3s -count=10 ./ed25519 >"$result_dir/heea-workers.txt"
heea_worker_rows=$(grep -c '^BenchmarkR51HEEACompletePipelineParallel/' "$result_dir/heea-workers.txt" || true)
if [ "$heea_worker_rows" -ne "$expected_heea_rows" ]; then
	echo "zen4-gate: worker HEEA candidate produced $heea_worker_rows rows; expected $expected_heea_rows" >&2
	exit 1
fi

taskset -c "$core" env GOMAXPROCS=1 go test -run '^$' \
	-bench '^BenchmarkR51HEEACompletePipelineFallback/path=(two-x4|x8)/W132/radix=32/n=8/msg=(64|200|1232)/pattern=(lane-[0-7]|all)$' \
	-benchmem -benchtime=3s -count=10 ./ed25519 >"$result_dir/heea-fallback.txt"
heea_fallback_rows=$(grep -c '^BenchmarkR51HEEACompletePipelineFallback/' "$result_dir/heea-fallback.txt" || true)
expected_heea_fallback_rows=$((2 * 3 * 9 * 10))
if [ "$heea_fallback_rows" -ne "$expected_heea_fallback_rows" ]; then
	echo "zen4-gate: W132 fallback matrix produced $heea_fallback_rows rows; expected $expected_heea_fallback_rows" >&2
	exit 1
fi

taskset -c "$core" env GOMAXPROCS=1 go test -run '^$' \
	-bench '^BenchmarkR51IFMAPipelineInvalid(Mix|Lane)$' \
	-benchmem -benchtime=1s -count=3 ./ed25519 >"$result_dir/pipeline-invalid.txt"

if ! python3 ./scripts/zen4-evaluate.py "$result_dir" \
	--decision-output micro-gate-decision.json >"$result_dir/gate-summary.txt"; then
	cat "$result_dir/gate-summary.txt" >&2
	echo "zen4-gate: mandatory numerical gate failed" >&2
	exit 1
fi
cat "$result_dir/gate-summary.txt"

./scripts/zen4-profile.sh "$core" "$result_dir/profile"

python3 ./scripts/zen4-source-manifest.py \
	--repo "$repo_root" --output "$result_dir/source-manifest-end.tsv"
if ! cmp -s "$result_dir/source-manifest-start.tsv" "$result_dir/source-manifest-end.tsv"; then
	fail "source tree changed while the release gate was running"
fi

gate_completed_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
printf 'state=%s\nstarted_utc=%s\ncompleted_utc=%s\n' \
	"$run_complete_state" "$gate_started_utc" "$gate_completed_utc" >"$result_dir/run-status.txt"
(
	cd "$result_dir"
	find . -type f ! -name SHA256SUMS ! -name SHA256SUMS.partial -print0 |
		LC_ALL=C sort -z |
		xargs -0 sha256sum >SHA256SUMS.partial
	mv SHA256SUMS.partial SHA256SUMS
	sha256sum -c SHA256SUMS >/dev/null
)

echo "zen4-gate: $run_complete_state, checksummed results written to $result_dir"
