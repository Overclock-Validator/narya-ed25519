#!/bin/sh
set -eu

export LC_ALL=C
umask 077

fail() {
	echo "zen4-profile: $*" >&2
	exit 1
}

core=${1:-2}
result_dir_arg=${2:-zen4-profile}

case "$core" in
	''|*[!0-9]*) fail "benchmark core must be one non-negative CPU number" ;;
esac
[ -n "$result_dir_arg" ] || fail "result directory must not be empty"

for tool in taskset perf go git sha256sum python3 nm objdump awk grep sed sort find xargs cmp; do
	command -v "$tool" >/dev/null 2>&1 || fail "$tool is required"
done

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
repo_root=$(git -C "$script_dir/.." rev-parse --show-toplevel) || \
	fail "script is not inside a Git worktree"
repo_root=$(CDPATH= cd -- "$repo_root" && pwd -P)
result_dir=$(python3 -c 'import os, sys; print(os.path.realpath(os.path.abspath(sys.argv[1])))' "$result_dir_arg")

[ "$result_dir" != "/" ] || fail "refusing to use / as the result directory"
[ "$result_dir" != "$repo_root" ] || fail "refusing to use the repository root as the result directory"
if [ -e "$result_dir" ] || [ -L "$result_dir" ]; then
	fail "result directory already exists; use a new path so stale artifacts cannot mix with this run: $result_dir"
fi

artifact_prefix=
case "$result_dir/" in
	"$repo_root"/*)
		artifact_relative=${result_dir#"$repo_root"/}
		artifact_prefix=$artifact_relative
		if git -C "$repo_root" ls-files -- "$artifact_prefix" | grep . >/dev/null 2>&1; then
			fail "result directory is under tracked source '$artifact_prefix'; choose an artifact-only path"
		fi
		;;
esac

if [ "$(uname -s)" != "Linux" ] || [ "$(uname -m)" != "x86_64" ]; then
	fail "Linux x86_64 is required"
fi
grep -qw avx512ifma /proc/cpuinfo || \
	fail "CPU flags do not contain avx512ifma"
taskset -c "$core" true >/dev/null 2>&1 || \
	fail "benchmark core '$core' is not available"

case "${NARYA_ZEN4_ALLOW_NON_RELEASE_CPU:-0}" in
	0|1) ;;
	*) fail "NARYA_ZEN4_ALLOW_NON_RELEASE_CPU must be 0 or 1" ;;
esac
cpu_model=$(awk -F: '/^model name[[:space:]]*:/{sub(/^[[:space:]]+/, "", $2); print $2; exit}' /proc/cpuinfo)
[ -n "$cpu_model" ] || fail "could not determine exact CPU model from /proc/cpuinfo"
normalized_cpu_model=$(printf '%s\n' "$cpu_model" | awk '{$1=$1; print}')
release_cpu_pattern='AMD Ryzen 7 PRO 8700GE'
case "$normalized_cpu_model" in
	*"$release_cpu_pattern"*) release_cpu_match=true ;;
	*) release_cpu_match=false ;;
esac
if [ "$release_cpu_match" != true ] && [ "${NARYA_ZEN4_ALLOW_NON_RELEASE_CPU:-0}" != 1 ]; then
	fail "release profiling requires an AMD Ryzen 7 PRO 8700GE; set NARYA_ZEN4_ALLOW_NON_RELEASE_CPU=1 only for diagnostic runs"
fi
run_incomplete_state=incomplete
run_complete_state=complete
if [ "$release_cpu_match" != true ]; then
	run_incomplete_state=diagnostic-incomplete
	run_complete_state=diagnostic-complete
fi

cpu_root="/sys/devices/system/cpu/cpu$core"
[ -r "$cpu_root/cpufreq/scaling_governor" ] || \
	fail "cannot record scaling governor for CPU $core"
[ -r "$cpu_root/cpufreq/scaling_driver" ] || \
	fail "cannot record scaling driver for CPU $core"
if [ ! -r /sys/devices/system/cpu/cpufreq/boost ] && \
	[ ! -r /sys/devices/system/cpu/intel_pstate/no_turbo ]; then
	fail "cannot determine whether turbo/boost is enabled"
fi

mkdir -p "$result_dir"
started_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
printf 'state=%s\nstarted_utc=%s\n' \
	"$run_incomplete_state" "$started_utc" >"$result_dir/run-status.txt"

cd "$repo_root"

source_manifest_args=""
if [ -n "$artifact_prefix" ]; then
	source_manifest_args=$artifact_prefix
fi
if [ -n "$source_manifest_args" ]; then
	python3 "$script_dir/zen4-source-manifest.py" \
		--repo "$repo_root" \
		--exclude-prefix "$source_manifest_args" \
		--output "$result_dir/source-manifest.tsv"
	git status --porcelain=v1 --untracked-files=all -- . \
		":(exclude)$artifact_prefix" >"$result_dir/git-status.txt"
	git diff --binary --no-ext-diff --no-color HEAD -- . \
		":(exclude)$artifact_prefix" >"$result_dir/git-diff.binary.patch"
else
	python3 "$script_dir/zen4-source-manifest.py" \
		--repo "$repo_root" \
		--output "$result_dir/source-manifest.tsv"
	git status --porcelain=v1 --untracked-files=all >"$result_dir/git-status.txt"
	git diff --binary --no-ext-diff --no-color HEAD >"$result_dir/git-diff.binary.patch"
fi

source_tree_sha256=$(sed -n 's/^source_tree_sha256=//p' "$result_dir/source-manifest.tsv")
case "$source_tree_sha256" in
	????????????????????????????????????????????????????????????????)
		case "$source_tree_sha256" in
			*[!0-9a-f]*) fail "source manifest SHA-256 is not lowercase hexadecimal" ;;
		esac
		;;
	*) fail "source manifest did not produce one SHA-256 digest" ;;
esac
git_commit=$(git rev-parse HEAD)
git_branch=$(git symbolic-ref --quiet --short HEAD || printf '%s' detached)
git_status_sha256=$(sha256sum "$result_dir/git-status.txt" | awk '{print $1}')
git_diff_sha256=$(sha256sum "$result_dir/git-diff.binary.patch" | awk '{print $1}')
if [ -s "$result_dir/git-status.txt" ]; then
	git_dirty=true
else
	git_dirty=false
fi
{
	printf 'git_commit=%s\n' "$git_commit"
	printf 'git_branch=%s\n' "$git_branch"
	printf 'git_dirty=%s\n' "$git_dirty"
	printf 'git_status_sha256=%s\n' "$git_status_sha256"
	printf 'git_diff_sha256=%s\n' "$git_diff_sha256"
	printf 'source_tree_sha256=%s\n' "$source_tree_sha256"
	printf 'source_manifest_scope=tracked+untracked-nonignored-working-tree-files\n'
	if [ -n "$artifact_prefix" ]; then
		printf 'source_manifest_excluded_artifact_prefix=%s\n' "$artifact_prefix"
	else
		printf 'source_manifest_excluded_artifact_prefix=outside-repository\n'
	fi
	git show -s --format='git_commit_timestamp=%cI%ngit_commit_subject=%s' HEAD
} >"$result_dir/source-provenance.txt"

{
	printf 'cpu_model=%s\n' "$cpu_model"
	printf 'release_cpu_pattern=%s\n' "$release_cpu_pattern"
	printf 'release_cpu_match=%s\n' "$release_cpu_match"
	printf 'non_release_cpu_override=%s\n' "${NARYA_ZEN4_ALLOW_NON_RELEASE_CPU:-0}"
	if [ "$release_cpu_match" = true ]; then
		printf 'measurement_authority=release\n'
	else
		printf 'measurement_authority=diagnostic-only\n'
	fi
	printf 'profile_core=%s\n' "$core"
	uname -a
	if command -v lscpu >/dev/null 2>&1; then
		lscpu
	fi
} >"$result_dir/machine.txt"

cpu_control_snapshot() {
	output=$1
	{
		printf 'profile_core=%s\n' "$core"
		printf 'online_cpus=%s\n' "$(cat /sys/devices/system/cpu/online)"
		printf 'scaling_driver=%s\n' "$(cat "$cpu_root/cpufreq/scaling_driver")"
		printf 'scaling_governor=%s\n' "$(cat "$cpu_root/cpufreq/scaling_governor")"
		for name in scaling_min_freq scaling_max_freq cpuinfo_min_freq cpuinfo_max_freq energy_performance_preference; do
			if [ -r "$cpu_root/cpufreq/$name" ]; then
				printf '%s=%s\n' "$name" "$(cat "$cpu_root/cpufreq/$name")"
			fi
		done
		if [ -r /sys/devices/system/cpu/cpufreq/boost ]; then
			printf 'cpufreq_boost=%s\n' "$(cat /sys/devices/system/cpu/cpufreq/boost)"
		fi
		if [ -r /sys/devices/system/cpu/intel_pstate/no_turbo ]; then
			printf 'intel_pstate_no_turbo=%s\n' "$(cat /sys/devices/system/cpu/intel_pstate/no_turbo)"
		fi
		if [ -r /sys/devices/system/cpu/amd_pstate/status ]; then
			printf 'amd_pstate_status=%s\n' "$(cat /sys/devices/system/cpu/amd_pstate/status)"
		fi
	} >"$output"
}

cpu_dynamic_snapshot() {
	output=$1
	{
		printf 'captured_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
		if [ -r "$cpu_root/cpufreq/scaling_cur_freq" ]; then
			printf 'scaling_cur_freq_khz=%s\n' "$(cat "$cpu_root/cpufreq/scaling_cur_freq")"
		fi
		printf 'loadavg=%s\n' "$(cat /proc/loadavg)"
	} >"$output"
}

cpu_control_snapshot "$result_dir/cpu-control-before.txt"
cpu_dynamic_snapshot "$result_dir/cpu-dynamic-before.txt"
{
	printf 'script_process_affinity='
	taskset -pc $$
	printf 'pinned_probe='
	taskset -c "$core" sh -c "awk '/^Cpus_allowed_list:/{print \$2}' /proc/self/status"
	for name in physical_package_id core_id thread_siblings_list core_siblings_list; do
		if [ -r "$cpu_root/topology/$name" ]; then
			printf '%s=%s\n' "$name" "$(cat "$cpu_root/topology/$name")"
		fi
	done
} >"$result_dir/pinning.txt"
pinned_probe=$(taskset -c "$core" sh -c "awk '/^Cpus_allowed_list:/{print \$2}' /proc/self/status")
[ "$pinned_probe" = "$core" ] || \
	fail "taskset probe ran with affinity '$pinned_probe', expected '$core'"

go version >"$result_dir/go-version.txt"
go env -json \
	GOOS GOARCH GOVERSION GOROOT GOAMD64 CGO_ENABLED GOEXPERIMENT GOFLAGS \
	GOTOOLCHAIN GOMOD GOWORK >"$result_dir/go-env-allowlist.json"
{
	perf --version
	nm --version | sed -n '1p'
	objdump --version | sed -n '1p'
	python3 --version
} >"$result_dir/tool-versions.txt"
perf list >"$result_dir/perf-list.txt"

ed25519_binary="$result_dir/ed25519-profile.test"
r51_binary="$result_dir/r51x5-profile.test"
env GOMAXPROCS=1 go test -c -o "$ed25519_binary" ./ed25519
env GOMAXPROCS=1 go test -c -o "$r51_binary" ./internal/r51x5

{
	sha256sum "$ed25519_binary"
	sha256sum "$r51_binary"
	wc -c "$ed25519_binary"
	wc -c "$r51_binary"
} >"$result_dir/binary-size-and-sha256.txt"
{
	go version -m "$ed25519_binary"
	go version -m "$r51_binary"
} >"$result_dir/binary-build-info.txt"

nm -S --size-sort "$ed25519_binary" >"$result_dir/ed25519-nm-all.txt"
nm -S --size-sort "$r51_binary" >"$result_dir/r51x5-nm-all.txt"

python3 "$script_dir/zen4-static-report.py" \
	--binary "$ed25519_binary" \
	--pattern '(r51x5|R51|r51|IFMA|ifma|HEEA|heea)' \
	--symbols-out "$result_dir/ed25519-symbol-sizes.txt" \
	--disassembly-out "$result_dir/ed25519-disassembly.txt" \
	--summary-out "$result_dir/ed25519-static-stack-spill.tsv"
python3 "$script_dir/zen4-static-report.py" \
	--binary "$r51_binary" \
	--pattern 'r51x5.*(IFMA|ifma|DSM|Decode|Mul|Square)' \
	--symbols-out "$result_dir/r51x5-symbol-sizes.txt" \
	--disassembly-out "$result_dir/r51x5-disassembly.txt" \
	--summary-out "$result_dir/r51x5-static-stack-spill.tsv"

for output in \
	"$result_dir/ed25519-symbol-sizes.txt" \
	"$result_dir/r51x5-symbol-sizes.txt" \
	"$result_dir/ed25519-disassembly.txt" \
	"$result_dir/r51x5-disassembly.txt" \
	"$result_dir/ed25519-static-stack-spill.tsv" \
	"$result_dir/r51x5-static-stack-spill.tsv"; do
	[ -s "$output" ] || fail "expected static-code output is empty: $output"
done

core_events='task-clock cycles ref-cycles instructions branches branch-misses'
cache_events='task-clock cycles cache-references cache-misses L1-dcache-loads L1-dcache-load-misses'
# Linux's Zen 4 vendor table names these event-0x64 masks: data accesses
# (0xf8) and data-request misses (0x08). The access mask includes misses, so
# misses/accesses is the intended data-request L2 miss rate.
l2_events='task-clock cycles l2_cache_req_stat.dc_access_in_l2 l2_cache_req_stat.ls_rd_blk_c'
required_events="$core_events $cache_events $l2_events"
# Preserve first occurrence order while removing task-clock/cycles duplicates.
required_events=$(printf '%s\n' $required_events | awk '!seen[$0]++' | awk 'BEGIN { first=1 } { if (!first) printf " "; printf "%s", $0; first=0 } END { print "" }')
printf '%s\n' $required_events >"$result_dir/perf-events-required.txt"

perf_record() {
	file=$1
	event=$2
	awk -F ';' -v required_event="$event" '
		function trim(value) {
			gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
			return value
		}
		{
			name = trim($3)
			if (name != required_event) next
			matches++
			value = trim($1)
			unit = trim($2)
		}
		END {
			if (matches != 1) exit 2
			if (value !~ /^[0-9]+([.][0-9]+)?$/) exit 3
			runtime = trim($4)
			running = trim($5)
			if (runtime !~ /^[0-9]+([.][0-9]+)?$/ || runtime + 0 <= 0) exit 4
			if (running !~ /^[0-9]+([.][0-9]+)?$/ || running + 0 < 99) exit 5
			print value "\t" unit "\t" runtime "\t" running
		}
	' "$file"
}

: >"$result_dir/perf-event-support.tsv"
printf 'event\tprobe_value\tunit\truntime\trunning_percent\n' >"$result_dir/perf-event-support.tsv"
: >"$result_dir/perf-event-probes.txt"
for event in $required_events; do
	probe_name=$(printf '%s' "$event" | sed 's/[^A-Za-z0-9]/_/g')
	probe_file="$result_dir/perf-probe-$probe_name.csv"
	if ! perf stat --no-big-num -x ';' -o "$probe_file" -e "$event" -- \
		taskset -c "$core" env GOMAXPROCS=1 "$ed25519_binary" -test.run '^$'; then
		fail "perf cannot count required event '$event' (unsupported or permission denied)"
	fi
	if ! record=$(perf_record "$probe_file" "$event"); then
		fail "perf returned an unsupported, uncounted, duplicate, or nonnumeric '$event' probe"
	fi
	printf '%s\t%s\n' "$event" "$record" >>"$result_dir/perf-event-support.tsv"
	{
		printf '[%s]\n' "$event"
		cat "$probe_file"
	} >>"$result_dir/perf-event-probes.txt"
done

profile_repetitions=5

write_perf_metrics() {
	core_file=$1
	cache_file=$2
	l2_file=$3
	output=$4
	task_record=$(perf_record "$core_file" task-clock) || return 1
	cycles_record=$(perf_record "$core_file" cycles) || return 1
	ref_record=$(perf_record "$core_file" ref-cycles) || return 1
	instructions_record=$(perf_record "$core_file" instructions) || return 1
	branches_record=$(perf_record "$core_file" branches) || return 1
	branch_misses_record=$(perf_record "$core_file" branch-misses) || return 1
	cache_refs_record=$(perf_record "$cache_file" cache-references) || return 1
	cache_misses_record=$(perf_record "$cache_file" cache-misses) || return 1
	l1_loads_record=$(perf_record "$cache_file" L1-dcache-loads) || return 1
	l1_misses_record=$(perf_record "$cache_file" L1-dcache-load-misses) || return 1
	l2_access_record=$(perf_record "$l2_file" l2_cache_req_stat.dc_access_in_l2) || return 1
	l2_misses_record=$(perf_record "$l2_file" l2_cache_req_stat.ls_rd_blk_c) || return 1

	task_value=$(printf '%s' "$task_record" | awk '{print $1}')
	task_unit=$(printf '%s' "$task_record" | awk '{print $2}')
	cycles_value=$(printf '%s' "$cycles_record" | awk '{print $1}')
	ref_value=$(printf '%s' "$ref_record" | awk '{print $1}')
	instructions_value=$(printf '%s' "$instructions_record" | awk '{print $1}')
	branches_value=$(printf '%s' "$branches_record" | awk '{print $1}')
	branch_misses_value=$(printf '%s' "$branch_misses_record" | awk '{print $1}')
	cache_refs_value=$(printf '%s' "$cache_refs_record" | awk '{print $1}')
	cache_misses_value=$(printf '%s' "$cache_misses_record" | awk '{print $1}')
	l1_loads_value=$(printf '%s' "$l1_loads_record" | awk '{print $1}')
	l1_misses_value=$(printf '%s' "$l1_misses_record" | awk '{print $1}')
	l2_access_value=$(printf '%s' "$l2_access_record" | awk '{print $1}')
	l2_misses_value=$(printf '%s' "$l2_misses_record" | awk '{print $1}')
	[ "$task_unit" = msec ] || return 1

	awk \
		-v task_ms="$task_value" \
		-v cycles="$cycles_value" \
		-v ref_cycles="$ref_value" \
		-v instructions="$instructions_value" \
		-v branches="$branches_value" \
		-v branch_misses="$branch_misses_value" \
		-v cache_refs="$cache_refs_value" \
		-v cache_misses="$cache_misses_value" \
		-v l1_loads="$l1_loads_value" \
		-v l1_misses="$l1_misses_value" \
		-v l2_accesses="$l2_access_value" \
		-v l2_misses="$l2_misses_value" '
		BEGIN {
			if (task_ms <= 0 || cycles <= 0 || ref_cycles <= 0 || instructions <= 0 ||
			    branches <= 0 || cache_refs <= 0 || l1_loads <= 0 || l2_accesses <= 0) exit 2
			print "# Runtime PMU evidence aggregated by perf stat; each ratio uses counters from one non-multiplexed pass."
			printf "effective_ghz_from_cycles_per_task_clock=%.6f\n", cycles / (task_ms * 1000000)
			printf "cycles_per_ref_cycle=%.6f\n", cycles / ref_cycles
			printf "instructions_per_cycle=%.6f\n", instructions / cycles
			printf "branch_miss_percent=%.6f\n", 100 * branch_misses / branches
			printf "cache_miss_percent=%.6f\n", 100 * cache_misses / cache_refs
			printf "l1d_load_miss_percent=%.6f\n", 100 * l1_misses / l1_loads
			printf "l2_data_request_miss_percent=%.6f\n", 100 * l2_misses / l2_accesses
		}
	' >"$output"
}

profile_perf_set() {
	set_name=$1
	label=$2
	binary=$3
	benchmark=$4
	set_events=$5
	if [ "$set_name" = core ]; then
		benchmark_output="$result_dir/benchmark-$label.txt"
	else
		benchmark_output="$result_dir/benchmark-$set_name-$label.txt"
	fi
	perf_output="$result_dir/perf-$set_name-$label.csv"
	event_csv=$(printf '%s' "$set_events" | sed 's/ /,/g')
	if ! perf stat --no-big-num -x ';' -r "$profile_repetitions" \
		-o "$perf_output" -e "$event_csv" -- \
		taskset -c "$core" env GOMAXPROCS=1 "$binary" \
		-test.run '^$' -test.bench "$benchmark" -test.benchmem \
		-test.benchtime=2s -test.count=1 >"$benchmark_output"; then
		fail "perf $set_name pass failed for '$label'"
	fi
	benchmark_rows=$(grep -c '^Benchmark' "$benchmark_output" || true)
	if [ "$benchmark_rows" -ne "$profile_repetitions" ]; then
		fail "'$label' $set_name pass produced $benchmark_rows benchmark rows; expected $profile_repetitions"
	fi
	for event in $set_events; do
		if ! perf_record "$perf_output" "$event" >/dev/null; then
			fail "'$label' $set_name pass has an unsupported, uncounted, duplicate, nonnumeric, or <99%-scheduled '$event' counter"
		fi
	done
}

profile_benchmark() {
	label=$1
	binary=$2
	benchmark=$3
	profile_perf_set core "$label" "$binary" "$benchmark" "$core_events"
	profile_perf_set cache "$label" "$binary" "$benchmark" "$cache_events"
	profile_perf_set l2 "$label" "$binary" "$benchmark" "$l2_events"
	if ! write_perf_metrics \
		"$result_dir/perf-core-$label.csv" \
		"$result_dir/perf-cache-$label.csv" \
		"$result_dir/perf-l2-$label.csv" \
		"$result_dir/perf-metrics-$label.txt"; then
		fail "could not derive runtime counter ratios for '$label'"
	fi
}

profile_benchmark r43-single "$ed25519_binary" \
	'^BenchmarkIFMABackendVerify/profile=strict/msg=200$'
for path in x8 two-x4; do
	for radix in 16 32 64; do
		profile_benchmark "$path-radix$radix" "$ed25519_binary" \
			"^BenchmarkR51IFMAPipeline/stage=cold-A/path=$path/radixA=$radix/fixedB=shared/n=8/msg=200$"
	done
	for comb in 16 32 256; do
		profile_benchmark "$path-comb$comb" "$ed25519_binary" \
			"^BenchmarkR51IFMAPipeline/stage=cold-A/path=$path/radixA=32/fixedB=comb$comb/n=8/msg=200$"
	done
done
profile_benchmark x8-heea-w132 "$ed25519_binary" \
	'^BenchmarkR51HEEACompletePipeline/stage=cold-AR/mode=heea/path=x8/W132/radix=32/n=8/msg=200$'
profile_benchmark two-x4-heea-w132 "$ed25519_binary" \
	'^BenchmarkR51HEEACompletePipeline/stage=cold-AR/mode=heea/path=two-x4/W132/radix=32/n=8/msg=200$'

cpu_control_snapshot "$result_dir/cpu-control-after.txt"
cpu_dynamic_snapshot "$result_dir/cpu-dynamic-after.txt"
if ! cmp -s "$result_dir/cpu-control-before.txt" "$result_dir/cpu-control-after.txt"; then
	fail "CPU governor/turbo/control state changed during profiling"
fi

if [ -n "$source_manifest_args" ]; then
	python3 "$script_dir/zen4-source-manifest.py" \
		--repo "$repo_root" \
		--exclude-prefix "$source_manifest_args" \
		--output "$result_dir/source-manifest-after.tsv"
else
	python3 "$script_dir/zen4-source-manifest.py" \
		--repo "$repo_root" \
		--output "$result_dir/source-manifest-after.tsv"
fi
if ! cmp -s "$result_dir/source-manifest.tsv" "$result_dir/source-manifest-after.tsv"; then
	fail "source tree changed while binaries or profiles were being produced"
fi

completed_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
printf 'state=%s\nstarted_utc=%s\ncompleted_utc=%s\n' \
	"$run_complete_state" "$started_utc" "$completed_utc" >"$result_dir/run-status.txt"
(
	cd "$result_dir"
	find . -type f ! -name SHA256SUMS ! -name SHA256SUMS.partial -print0 |
		LC_ALL=C sort -z |
		xargs -0 sha256sum >SHA256SUMS.partial
	mv SHA256SUMS.partial SHA256SUMS
	sha256sum -c SHA256SUMS >/dev/null
)

echo "zen4-profile: $run_complete_state, checksummed results written to $result_dir"
