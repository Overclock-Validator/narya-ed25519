#!/usr/bin/env bash
set -euo pipefail

# Intel SDE runtime varies sharply across GitHub-hosted runners. A focused test
# process that normally completes in seconds has run roughly 30 times slower,
# and one run consumed the entire 45-minute job. Go's -test.timeout is measured
# inside the emulated process and did not bound that failure mode, so enforce a
# host-side wall-clock limit and retry only timeout-shaped exits once.

: "${SDE64:?SDE64 must name the pinned Intel SDE executable}"

attempt_timeout=${SDE_TEST_TIMEOUT:-2m}
max_attempts=${SDE_TEST_ATTEMPTS:-2}
status=1

for ((attempt = 1; attempt <= max_attempts; attempt++)); do
	set +e
	timeout --signal=TERM --kill-after=15s "$attempt_timeout" \
		"$SDE64" -icx -- "$@"
	status=$?
	set -e

	if ((status == 0)); then
		exit 0
	fi
	case "$status" in
	124 | 137 | 143)
		echo "::warning::Intel SDE timed out after ${attempt_timeout} (attempt ${attempt}/${max_attempts})" >&2
		;;
	*)
		# Arithmetic/test failures are deterministic evidence. Do not hide them
		# behind a retry intended only for anomalously slow emulator runs.
		exit "$status"
		;;
	esac
done

exit "$status"
