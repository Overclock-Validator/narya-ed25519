#!/bin/sh
set -eu

export LC_ALL=C
umask 077

fail() {
	echo "zen4-dense-tail-gate: $*" >&2
	exit 1
}

usage() {
	cat >&2 <<'EOF'
usage:
  zen4-dense-tail-gate.sh --result-dir DIR [--core CPU] --selection-json FILE
  zen4-dense-tail-gate.sh --result-dir DIR [--core CPU] \
      --path two-x4|x8 --radix-a 16|32|64 \
      --fixed-b shared|comb16|comb32|comb256

The result directory must not exist. Release measurements require Linux,
AVX-512 IFMA, and an AMD Ryzen 7 PRO 8700GE. Set
NARYA_ZEN4_ALLOW_NON_RELEASE_CPU=1 only to make a diagnostic artifact.
EOF
	exit 2
}

result_dir_arg=
core=2
selection_json=
selected_path=
selected_radix=
selected_fixed=
while [ "$#" -gt 0 ]; do
	case $1 in
	--result-dir)
		[ "$#" -ge 2 ] || usage
		result_dir_arg=$2
		shift 2
		;;
	--core)
		[ "$#" -ge 2 ] || usage
		core=$2
		shift 2
		;;
	--selection-json)
		[ "$#" -ge 2 ] || usage
		selection_json=$2
		shift 2
		;;
	--path)
		[ "$#" -ge 2 ] || usage
		selected_path=$2
		shift 2
		;;
	--radix-a)
		[ "$#" -ge 2 ] || usage
		selected_radix=$2
		shift 2
		;;
	--fixed-b)
		[ "$#" -ge 2 ] || usage
		selected_fixed=$2
		shift 2
		;;
	-h|--help) usage ;;
	*) fail "unknown argument: $1" ;;
	esac
done

[ -n "$result_dir_arg" ] || usage
case $core in
''|*[!0-9]*) fail "--core must be one nonnegative CPU number" ;;
esac
if [ -n "$selection_json" ]; then
	[ -z "$selected_path$selected_radix$selected_fixed" ] || \
		fail "do not combine --selection-json with explicit config flags"
else
	[ -n "$selected_path" ] && [ -n "$selected_radix" ] && [ -n "$selected_fixed" ] || usage
fi

for tool in git go python3 taskset sha256sum find sort xargs cmp awk grep date cp sed mv mkdir uname env; do
	command -v "$tool" >/dev/null 2>&1 || fail "$tool is required"
done

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
repo_root=$(git -C "$script_dir/.." rev-parse --show-toplevel) || \
	fail "script is not inside a Git worktree"
repo_root=$(CDPATH= cd -- "$repo_root" && pwd -P)
result_dir=$(python3 -c 'import os, sys; print(os.path.realpath(os.path.abspath(sys.argv[1])))' \
	"$result_dir_arg")
if [ -n "$selection_json" ]; then
	selection_json=$(python3 -c 'import os, sys; print(os.path.realpath(os.path.abspath(sys.argv[1])))' \
		"$selection_json")
fi

[ "$result_dir" != "/" ] || fail "refusing to use / as the result directory"
[ "$result_dir" != "$repo_root" ] || fail "refusing to use the worktree root as the result directory"
case "$result_dir/" in
"$repo_root"/*)
	fail "result directory must be outside the Narya worktree"
	;;
esac
if [ -e "$result_dir" ] || [ -L "$result_dir" ]; then
	fail "result directory already exists; refusing to mix or overwrite evidence: $result_dir"
fi

cd "$repo_root"
[ "$(uname -s)" = Linux ] || fail "Linux is required"
[ "$(uname -m)" = x86_64 ] || fail "x86_64 is required"
grep -qw avx512ifma /proc/cpuinfo || fail "CPU flags do not contain avx512ifma"
case ${NARYA_ZEN4_ALLOW_NON_RELEASE_CPU:-0} in
0|1) ;;
*) fail "NARYA_ZEN4_ALLOW_NON_RELEASE_CPU must be 0 or 1" ;;
esac
cpu_model=$(awk -F: '/^model name[[:space:]]*:/{sub(/^[[:space:]]+/, "", $2); print $2; exit}' /proc/cpuinfo)
[ -n "$cpu_model" ] || fail "could not determine exact CPU model"
normalized_cpu_model=$(printf '%s\n' "$cpu_model" | awk '{$1=$1; print}')
case "$normalized_cpu_model" in
*"AMD Ryzen 7 PRO 8700GE"*) release_cpu_match=true ;;
*)
	release_cpu_match=false
	[ "${NARYA_ZEN4_ALLOW_NON_RELEASE_CPU:-0}" = 1 ] || \
		fail "release gate requires an AMD Ryzen 7 PRO 8700GE"
	;;
esac
taskset -c "$core" true >/dev/null 2>&1 || fail "CPU core $core is unavailable"

mkdir -p "$result_dir"
run_state=incomplete
[ "$release_cpu_match" = true ] || run_state=diagnostic-incomplete
printf 'state=%s\nstarted_utc=%s\n' "$run_state" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
	>"$result_dir/run-status.txt"

python3 "$script_dir/zen4-source-manifest.py" \
	--repo "$repo_root" --output "$result_dir/source-manifest-start.tsv"

if [ -n "$selection_json" ]; then
	[ -f "$selection_json" ] || fail "selection JSON is not a regular file: $selection_json"
	cp -- "$selection_json" "$result_dir/selection-input.json"
	python3 "$script_dir/zen4-dense-tail-evaluate.py" selection \
		--selection-json "$result_dir/selection-input.json" \
		--output "$result_dir/selection.normalized.json"
else
	python3 "$script_dir/zen4-dense-tail-evaluate.py" selection \
		--path "$selected_path" --radix-a "$selected_radix" \
		--fixed-b "$selected_fixed" \
		--output "$result_dir/selection.normalized.json"
fi

selected_path=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["selected"]["path"])' \
	"$result_dir/selection.normalized.json")
selected_radix=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["selected"]["radix_a"])' \
	"$result_dir/selection.normalized.json")
selected_fixed=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["selected"]["fixed_b"])' \
	"$result_dir/selection.normalized.json")
selected_label="path=$selected_path/radixA=$selected_radix/fixedB=$selected_fixed"

test_binary="$result_dir/ed25519.test"
go test -c -o "$test_binary" ./ed25519
"$test_binary" -test.list '^BenchmarkR51IFMAPipeline$' \
	>"$result_dir/benchmark-list.txt"
[ "$(grep -c '^BenchmarkR51IFMAPipeline$' "$result_dir/benchmark-list.txt" || true)" -eq 1 ] || \
	fail "compiled test binary does not expose BenchmarkR51IFMAPipeline"

python3 "$script_dir/zen4-source-manifest.py" \
	--repo "$repo_root" --output "$result_dir/source-manifest-built.tsv"
cmp -s "$result_dir/source-manifest-start.tsv" "$result_dir/source-manifest-built.tsv" || \
	fail "source tree changed while building the benchmark binary"

test_binary_sha256=$(sha256sum "$test_binary" | awk '{print $1}')
source_tree_sha256=$(sed -n 's/^source_tree_sha256=//p' "$result_dir/source-manifest-start.tsv")
selection_sha256=$(sha256sum "$result_dir/selection.normalized.json" | awk '{print $1}')
case $source_tree_sha256 in
*[!0-9a-f]*|'') fail "source manifest tree SHA-256 is not lowercase hexadecimal" ;;
????????????????????????????????????????????????????????????????) ;;
*) fail "source manifest lacks a valid tree SHA-256" ;;
esac
case "$test_binary_sha256$selection_sha256" in
*[!0-9a-f]*) fail "artifact SHA-256 is not lowercase hexadecimal" ;;
esac
[ "${#test_binary_sha256}" -eq 64 ] && [ "${#selection_sha256}" -eq 64 ] || \
	fail "artifact SHA-256 has the wrong length"
{
	echo "cpu_model=$cpu_model"
	echo "release_cpu_match=$release_cpu_match"
	echo "non_release_cpu_override=${NARYA_ZEN4_ALLOW_NON_RELEASE_CPU:-0}"
	echo "primitive_core=$core"
	echo "gomaxprocs=1"
	echo "rounds=10"
	echo "benchtime=3s"
	echo "test_binary_sha256=$test_binary_sha256"
	echo "source_tree_sha256=$source_tree_sha256"
	echo "selection_sha256=$selection_sha256"
	echo "git_head=$(git rev-parse HEAD)"
	echo "go_version=$(go version)"
} >"$result_dir/benchmark-config.txt"

counts='(1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|32|64)'
messages='(64|200|1232)'
baseline_regex="^BenchmarkR51IFMAPipeline/stage=cold-A/path=stdlib/n=$counts/msg=$messages$"
candidate_regex="^BenchmarkR51IFMAPipeline/stage=cold-A/path=$selected_path/radixA=$selected_radix/fixedB=$selected_fixed/n=$counts/msg=$messages$"

run_role() {
	role=$1
	round=$2
	order=$3
	case $role in
	baseline) benchmark_regex=$baseline_regex ;;
	candidate) benchmark_regex=$candidate_regex ;;
	*) fail "internal invalid role: $role" ;;
	esac
	output="$result_dir/round-$round-$role.txt"
	[ ! -e "$output" ] && [ ! -L "$output" ] || fail "refusing to overwrite $output"
	measurement_sequence=$((measurement_sequence + 1))
	printf '# narya_dense_tail_sample_v1 role=%s round=%s sequence=%s order=%s config=%s\n' \
		"$role" "${round#0}" "$measurement_sequence" "$order" "$selected_label" >"$output"
	taskset -c "$core" env GOMAXPROCS=1 "$test_binary" \
		-test.run '^$' -test.bench "$benchmark_regex" \
		-test.benchtime 3s -test.count 1 -test.benchmem >>"$output"
}

measurement_sequence=0
round=1
while [ "$round" -le 10 ]; do
	round_padded=$(printf '%02d' "$round")
	if [ $((round % 2)) -eq 1 ]; then
		order=baseline-candidate
		run_role baseline "$round_padded" "$order"
		run_role candidate "$round_padded" "$order"
	else
		order=candidate-baseline
		run_role candidate "$round_padded" "$order"
		run_role baseline "$round_padded" "$order"
	fi
	round=$((round + 1))
done

measured_binary_sha256=$(sha256sum "$test_binary" | awk '{print $1}')
[ "$measured_binary_sha256" = "$test_binary_sha256" ] || \
	fail "benchmark test binary changed during measurement"

decision_output="$result_dir/tail-decision.json"
python3 "$script_dir/zen4-dense-tail-evaluate.py" evaluate "$result_dir" \
	--output "$decision_output"

python3 "$script_dir/zen4-source-manifest.py" \
	--repo "$repo_root" --output "$result_dir/source-manifest-end.tsv"
cmp -s "$result_dir/source-manifest-start.tsv" "$result_dir/source-manifest-end.tsv" || \
	fail "source tree changed during the dense-tail gate"

finish_state=tail-gate-complete
[ "$release_cpu_match" = true ] || finish_state=diagnostic-tail-gate-complete
printf 'state=%s\nstarted_utc=%s\nfinished_utc=%s\n' \
	"$finish_state" \
	"$(sed -n 's/^started_utc=//p' "$result_dir/run-status.txt")" \
	"$(date -u '+%Y-%m-%dT%H:%M:%SZ')" >"$result_dir/run-status.complete"
mv "$result_dir/run-status.complete" "$result_dir/run-status.txt"

(
	cd "$result_dir"
	find . -type f ! -name SHA256SUMS -print0 | sort -z | \
		xargs -0 sha256sum >SHA256SUMS
)
echo "zen4-dense-tail-gate: complete: $result_dir"
