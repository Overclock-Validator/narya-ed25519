#!/bin/sh
set -eu

export LC_ALL=C
umask 077

fail() {
	echo "zen4-fuzz-soak: $*" >&2
	exit 1
}

for tool in git go python3 taskset sha256sum find sort xargs cmp; do
	command -v "$tool" >/dev/null 2>&1 || fail "$tool is required"
done

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
repo_root=$(git -C "$script_dir/.." rev-parse --show-toplevel) || \
	fail "script is not inside a Git worktree"
repo_root=$(CDPATH= cd -- "$repo_root" && pwd -P)
default_result_dir=$(python3 -c 'import os, sys; print(os.path.realpath(sys.argv[1]))' \
	"$repo_root/../narya-zen4-fuzz-results")

result_dir_arg=${1:-$default_result_dir}
duration=${2:-${NARYA_FUZZ_DURATION:-2h}}

online_cpus=$(getconf _NPROCESSORS_ONLN 2>/dev/null || true)
case "$online_cpus" in
	''|*[!0-9]*) online_cpus=1 ;;
esac
default_workers=$((online_cpus / 2))
if [ "$default_workers" -lt 1 ]; then
	default_workers=1
fi
workers=${3:-${NARYA_FUZZ_WORKERS:-$default_workers}}
case "$workers" in
	''|*[!0-9]*) fail "workers must be a positive integer" ;;
esac
[ "$workers" -ge 1 ] || fail "workers must be at least one"

default_cpuset=0
if [ "$workers" -gt 1 ]; then
	default_cpuset="0-$((workers - 1))"
fi
cpuset=${4:-${NARYA_FUZZ_CPUSET:-$default_cpuset}}

result_dir=$(python3 -c 'import os, sys; print(os.path.realpath(os.path.abspath(sys.argv[1])))' \
	"$result_dir_arg")
[ "$result_dir" != "/" ] || fail "refusing to use / as the result directory"
[ "$result_dir" != "$repo_root" ] || fail "refusing to use the worktree root as the result directory"
case "$result_dir/" in
	"$repo_root"/*)
		fail "result directory must be outside the Narya worktree so fuzz artifacts cannot contaminate source provenance"
		;;
esac
if [ -e "$result_dir" ] || [ -L "$result_dir" ]; then
	fail "result directory already exists; choose a new path: $result_dir"
fi

if [ "$(uname -s)" != "Linux" ] || [ "$(uname -m)" != "x86_64" ]; then
	fail "Linux x86_64 is required"
fi
grep -qw avx512ifma /proc/cpuinfo || fail "CPU flags do not contain avx512ifma"
taskset -c "$cpuset" true >/dev/null 2>&1 || fail "CPU set '$cpuset' is unavailable"

case "${NARYA_ZEN4_ALLOW_NON_RELEASE_CPU:-0}" in
	0|1) ;;
	*) fail "NARYA_ZEN4_ALLOW_NON_RELEASE_CPU must be 0 or 1" ;;
esac
cpu_model=$(awk -F: '/^model name[[:space:]]*:/{sub(/^[[:space:]]+/, "", $2); print $2; exit}' /proc/cpuinfo)
[ -n "$cpu_model" ] || fail "could not determine CPU model"
case "$cpu_model" in
	*"AMD Ryzen 7 PRO 8700GE"*) release_cpu_match=true ;;
	*)
		release_cpu_match=false
		if [ "${NARYA_ZEN4_ALLOW_NON_RELEASE_CPU:-0}" != 1 ]; then
			fail "release soak requires an AMD Ryzen 7 PRO 8700GE; set NARYA_ZEN4_ALLOW_NON_RELEASE_CPU=1 only for diagnostics"
		fi
		;;
esac

mkdir -p "$result_dir"
started_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
printf 'state=incomplete\nstarted_utc=%s\n' "$started_utc" >"$result_dir/run-status.txt"

cd "$repo_root"
python3 "$script_dir/zen4-source-manifest.py" \
	--repo "$repo_root" --output "$result_dir/source-manifest-start.tsv"
{
	printf 'cpu_model=%s\n' "$cpu_model"
	printf 'release_cpu_match=%s\n' "$release_cpu_match"
	printf 'non_release_cpu_override=%s\n' "${NARYA_ZEN4_ALLOW_NON_RELEASE_CPU:-0}"
	printf 'workers=%s\n' "$workers"
	printf 'cpuset=%s\n' "$cpuset"
	printf 'duration_per_target=%s\n' "$duration"
	printf 'target_count=5\n'
	printf 'git_commit=%s\n' "$(git rev-parse HEAD)"
	printf 'git_branch=%s\n' "$(git symbolic-ref --quiet --short HEAD || printf '%s' detached)"
	go version
	uname -a
	taskset -c "$cpuset" sh -c "awk '/^Cpus_allowed_list:/{print \"observed_cpuset=\" \$2}' /proc/self/status"
} >"$result_dir/config.txt"

env GOMAXPROCS="$workers" go test -count=1 ./... >"$result_dir/correctness-all.txt"
taskset -c "$cpuset" env GOMAXPROCS="$workers" go test -v \
	-run 'Test(R51IFMA|R51HEEA|ExperimentalIFMA.*(Hardware|Matches|Preserves|ZeroAllocations)|Native(X4|X8).*(Differential|Allocations))' \
	./ed25519 ./internal/r51x5 ./sha512mb >"$result_dir/correctness-hardware.txt"
if grep -q -- '--- SKIP:' "$result_dir/correctness-hardware.txt"; then
	fail "a required hardware test skipped; see $result_dir/correctness-hardware.txt"
fi

run_fuzz() {
	label=$1
	package=$2
	target=$3
	log="$result_dir/fuzz-$label.txt"
	{
		printf 'package=%s\n' "$package"
		printf 'target=%s\n' "$target"
		printf 'duration=%s\n' "$duration"
		printf 'workers=%s\n' "$workers"
		printf 'cpuset=%s\n' "$cpuset"
	} >"$log"
	taskset -c "$cpuset" env GOMAXPROCS="$workers" go test \
		-run '^$' -fuzz "^$target\$" -fuzztime="$duration" \
		-parallel="$workers" -timeout=0 "$package" >>"$log" 2>&1
}

run_fuzz generic-verify ./ed25519 FuzzVerifyDifferential
run_fuzz r51-pipeline ./ed25519 FuzzR51IFMAPipelineDifferential
run_fuzz heea-selector ./internal/heea8l FuzzSelectShiftSubtract
run_fuzz scalar-reduction ./internal/r51x5 FuzzExperimentalUniformScalarReduction
run_fuzz sha512 ./sha512mb FuzzSum512Differential

python3 "$script_dir/zen4-source-manifest.py" \
	--repo "$repo_root" --output "$result_dir/source-manifest-end.tsv"
if ! cmp -s "$result_dir/source-manifest-start.tsv" "$result_dir/source-manifest-end.tsv"; then
	fail "source tree changed during the fuzz soak"
fi

completed_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
if [ "$release_cpu_match" = true ]; then
	state=complete
else
	state=diagnostic-complete
fi
printf 'state=%s\nstarted_utc=%s\ncompleted_utc=%s\n' \
	"$state" "$started_utc" "$completed_utc" >"$result_dir/run-status.txt"
(
	cd "$result_dir"
	find . -type f ! -name SHA256SUMS ! -name SHA256SUMS.partial -print0 |
		LC_ALL=C sort -z |
		xargs -0 sha256sum >SHA256SUMS.partial
	mv SHA256SUMS.partial SHA256SUMS
	sha256sum -c SHA256SUMS >/dev/null
)

echo "zen4-fuzz-soak: $state, checksummed results written to $result_dir"
