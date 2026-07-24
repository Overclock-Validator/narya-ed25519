#!/usr/bin/env python3
"""Evaluate Narya's numerical Zen 4 complete-verifier release gates.

The gate driver records ten samples for every required row.  This evaluator
rejects incomplete or over-broad matrices, compares one realizable
configuration across every release message size, and treats both B/op and
allocs/op as release metrics rather than discarding ``-benchmem`` columns.

HEEA remains optional.  Its admission result cannot make the ordinary backend
pass or fail.  Statistical significance and Mithril wall time remain separate
release requirements.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
import re
import statistics
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Hashable, Mapping, Sequence, TypeVar


NUMBER = r"[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?"
ROW = re.compile(
    rf"^(Benchmark\S+)\s+\d+\s+({NUMBER})\s+ns/op(?P<metrics>.*)$"
)
ALLOCS = re.compile(rf"(?:^|\s)({NUMBER})\s+allocs/op(?:\s|$)")
BYTES = re.compile(rf"(?:^|\s)({NUMBER})\s+B/op(?:\s|$)")
CPU_SUFFIX = re.compile(r"-\d+$")

EXPECTED_SAMPLES = 10
MESSAGES = (64, 200, 1232)
PIPELINE_COUNTS = (1, 4, 8, 9, 17, 64)
RELEASE_BATCH_COUNTS = (8, 64)
PATHS = ("two-x4", "x8")
OPTIONAL_GAIN = 0.02
X8_SIMPLICITY_TIE = 0.02
WORKER_REGRESSION_LIMIT = 0.01
HEEA_GAIN = 0.05
HEEA_FALLBACK_REGRESSION_LIMIT = 0.05
HEEA_FALLBACK_PATTERNS = tuple(
    [f"lane-{lane}" for lane in range(8)] + ["all"]
)
STRICT_PRECHECK_GAIN = 0.03
COMPAT_REGRESSION_LIMIT = 0.01
PAIRED_PIPELINE_GAIN = 0.02
UNAFFECTED_REGRESSION_LIMIT = 0.01
UNAFFECTED_BASELINE_REVISION = "05bf37ca843842f54109581755d587dc552e7aa8"
EPSILON = 1e-12
DECISION_SCHEMA_VERSION = 1
DECISION_KIND = "narya.zen4.microbenchmark-decision"
PENDING_PRODUCTION_BLOCKERS = (
    "statistical_significance",
    "dense_tail_matrix",
    "mithril_trace_replay",
    "backend_native_cache_trace",
    "source_release_authority",
)
DECISION_EVIDENCE_FILES = (
    "benchmark-config.txt",
    "source-manifest-start.tsv",
    "unaffected-compat-source.txt",
    "pipeline-baselines.txt",
    "pipeline-candidates.txt",
    "pipeline-workers.txt",
    "pipeline-worker-baselines.txt",
    "single-baseline.txt",
    "single-ifma.txt",
    "strict-precheck.txt",
    "unaffected-compat-baseline.txt",
    "unaffected-compat-current.txt",
    "paired-gate.txt",
    "heea-complete.txt",
    "heea-workers.txt",
    "heea-fallback.txt",
    "sha-tails.txt",
)


@dataclass(frozen=True, order=True)
class Configuration:
    path: str
    radix: int
    fixed_base: str

    @property
    def label(self) -> str:
        return (
            f"path={self.path}/radixA={self.radix}/"
            f"fixedB={self.fixed_base}"
        )

    @property
    def proper_baseline(self) -> "Configuration":
        # Every optional arbitrary-A window and every split fixed-B comb is a
        # complete-pipeline alternative to the same SIMD path's shared-
        # doubling radix-32 implementation.
        return Configuration(self.path, 32, "shared")

    @property
    def optional(self) -> bool:
        return self != self.proper_baseline


ORDINARY_R51_CONFIGS = tuple(
    Configuration(path, radix, "shared")
    for path in PATHS
    for radix in (16, 32, 64)
) + tuple(
    Configuration(path, 32, fixed_base)
    for path in PATHS
    for fixed_base in ("comb16", "comb32", "comb256")
)


@dataclass(frozen=True)
class Sample:
    nanoseconds: float
    bytes_per_op: float | None
    allocations: float | None


@dataclass(frozen=True)
class Stats:
    nanoseconds: float
    # Use maxima, rather than medians, so sporadic allocation bytes or counts
    # cannot disappear behind nine zero-allocation samples.
    bytes_per_op: float
    allocations: float


@dataclass(frozen=True)
class EvaluationOutcome:
    mandatory_micro_gates_passed: bool
    decision: dict[str, Any]


Rows = dict[str, list[Sample]]
Workload = Hashable
T = TypeVar("T", bound=Hashable)


class GateError(RuntimeError):
    pass


def parse_lines(lines: Sequence[str]) -> Rows:
    rows: Rows = {}
    for line in lines:
        match = ROW.match(line.strip())
        if match is None:
            continue
        name = CPU_SUFFIX.sub("", match.group(1))
        byte_match = BYTES.search(match.group("metrics"))
        bytes_per_op = (
            float(byte_match.group(1)) if byte_match is not None else None
        )
        allocation_match = ALLOCS.search(match.group("metrics"))
        allocations = (
            float(allocation_match.group(1))
            if allocation_match is not None
            else None
        )
        rows.setdefault(name, []).append(
            Sample(float(match.group(2)), bytes_per_op, allocations)
        )
    return rows


def load(result_dir: Path, name: str) -> Rows:
    path = result_dir / name
    if not path.is_file():
        raise GateError(f"missing benchmark output: {path}")
    return parse_lines(path.read_text(encoding="utf-8").splitlines())


def stats(
    rows: Rows, name: str, expected_samples: int = EXPECTED_SAMPLES
) -> Stats:
    samples = rows.get(name)
    if samples is None:
        raise GateError(f"missing benchmark row: {name}")
    if len(samples) != expected_samples:
        raise GateError(
            f"benchmark row {name} has {len(samples)} samples; "
            f"expected exactly {expected_samples}"
        )
    if any(sample.bytes_per_op is None for sample in samples):
        raise GateError(f"benchmark row lacks B/op: {name}")
    if any(sample.allocations is None for sample in samples):
        raise GateError(f"benchmark row lacks allocs/op: {name}")
    return Stats(
        statistics.median(sample.nanoseconds for sample in samples),
        max(float(sample.bytes_per_op) for sample in samples),
        max(float(sample.allocations) for sample in samples),
    )


def require_exact_rows(
    rows: Rows,
    expected_names: Sequence[str],
    source: str,
    expected_samples: int = EXPECTED_SAMPLES,
) -> dict[str, Stats]:
    expected = set(expected_names)
    actual = set(rows)
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    if missing or unexpected:
        details: list[str] = []
        if missing:
            details.append(f"missing={missing[:3]}" + ("..." if len(missing) > 3 else ""))
        if unexpected:
            details.append(
                f"unexpected={unexpected[:3]}" + ("..." if len(unexpected) > 3 else "")
            )
        raise GateError(f"{source} benchmark matrix mismatch: {'; '.join(details)}")
    return {
        name: stats(rows, name, expected_samples)
        for name in expected_names
    }


def read_key_values(path: Path, description: str) -> dict[str, str]:
    if not path.is_file():
        raise GateError(f"missing {description}: {path}")
    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise GateError(f"cannot read {description}: {path}: {error}") from error
    if not lines:
        raise GateError(f"empty {description}: {path}")
    for line_number, line in enumerate(lines, 1):
        key, separator, value = line.partition("=")
        if not separator or not key or not value:
            raise GateError(
                f"malformed {description} line {line_number}: {line!r}"
            )
        if key in values:
            raise GateError(f"duplicate {description} key: {key}")
        values[key] = value
    return values


def read_benchmark_config(result_dir: Path) -> dict[str, str]:
    values = read_key_values(
        result_dir / "benchmark-config.txt", "benchmark configuration"
    )
    required = {
        "cpu_model",
        "release_cpu_match",
        "non_release_cpu_override",
        "primitive_core",
        "online_cpus",
        "verifier_workers",
        "verifier_cpuset",
    }
    missing = sorted(required - set(values))
    if missing:
        raise GateError(
            "benchmark-config.txt lacks required provenance keys: "
            + ", ".join(missing)
        )
    if values["release_cpu_match"] not in ("true", "false"):
        raise GateError("benchmark-config.txt has invalid release_cpu_match")
    if values["non_release_cpu_override"] not in ("0", "1"):
        raise GateError(
            "benchmark-config.txt has invalid non_release_cpu_override"
        )
    if (
        values["release_cpu_match"] == "false"
        and values["non_release_cpu_override"] != "1"
    ):
        raise GateError(
            "non-release CPU evidence must explicitly record its override"
        )
    for key in ("online_cpus", "verifier_workers"):
        try:
            number = int(values[key])
        except ValueError as error:
            raise GateError(
                f"benchmark-config.txt lacks a valid {key}"
            ) from error
        if number <= 0:
            raise GateError(f"benchmark-config.txt has non-positive {key}")
    if not values["cpu_model"].strip():
        raise GateError("benchmark-config.txt has an empty cpu_model")
    if not values["primitive_core"].strip() or not values[
        "verifier_cpuset"
    ].strip():
        raise GateError("benchmark-config.txt has an empty CPU binding")
    return values


def read_worker_count(result_dir: Path) -> int:
    values = read_benchmark_config(result_dir)
    try:
        count = int(values["verifier_workers"])
    except ValueError as error:
        raise GateError("benchmark-config.txt lacks a valid verifier_workers") from error
    if count < 2:
        raise GateError(
            "verifier_workers must be at least 2 for production cache-pressure evidence"
        )
    return count


def improvement(baseline: float, candidate: float) -> float:
    if baseline <= 0:
        raise GateError(f"non-positive benchmark baseline: {baseline}")
    return 1.0 - candidate / baseline


def allocations_do_not_increase(baseline: Stats, candidate: Stats) -> bool:
    return (
        candidate.bytes_per_op <= baseline.bytes_per_op + EPSILON
        and candidate.allocations <= baseline.allocations + EPSILON
    )


def allocation_metrics(value: Stats) -> str:
    return f"bytes={value.bytes_per_op:g} B/op, allocs={value.allocations:g}"


def stats_record(value: Stats) -> dict[str, float]:
    return {
        "median_ns_per_op": value.nanoseconds,
        "max_bytes_per_op": value.bytes_per_op,
        "max_allocs_per_op": value.allocations,
    }


def evaluate_r43_cold_single_policy(
    public_stdlib: Mapping[int, Stats],
    r43_values: Mapping[int, Stats],
) -> tuple[bool, list[dict[str, Any]]]:
    """Evaluate the only cold-single API candidate against its own surface.

    The r43 backend is measured through the single-call public API and is
    therefore compared only with the public stdlib single-call benchmark.
    r51's n=1 batch-pipeline numbers are deliberately absent from this API:
    their relative gain has a different denominator and cannot select or
    replace the cold-single implementation.
    """
    if set(public_stdlib) != set(MESSAGES) or set(r43_values) != set(MESSAGES):
        raise GateError("cold-single r43 policy has an incoherent message matrix")
    rows: list[dict[str, Any]] = []
    passed = True
    for message in MESSAGES:
        baseline = public_stdlib[message]
        candidate = r43_values[message]
        gain = improvement(baseline.nanoseconds, candidate.nanoseconds)
        allocation_ok = allocations_do_not_increase(baseline, candidate)
        row_passed = gain + EPSILON >= 0.10 and allocation_ok
        passed = passed and row_passed
        rows.append(
            {
                "message_bytes": message,
                "gain": gain,
                "allocation_gate_passed": allocation_ok,
                "passed": row_passed,
                "baseline": stats_record(baseline),
                "candidate": stats_record(candidate),
            }
        )
    return passed, rows


def select_cold_single_candidate(
    public_stdlib: Mapping[int, Stats],
    r43_values: Mapping[int, Stats],
) -> tuple[str, bool, list[dict[str, Any]]]:
    """Return the coherent single-call candidate and its independent gate."""
    passed, rows = evaluate_r43_cold_single_policy(public_stdlib, r43_values)
    return "r43", passed, rows


def unaffected_path_passes(baseline: Stats, candidate: Stats) -> bool:
    return (
        improvement(baseline.nanoseconds, candidate.nanoseconds) + EPSILON
        >= -UNAFFECTED_REGRESSION_LIMIT
        and allocations_do_not_increase(baseline, candidate)
    )


def unaffected_name(count: int, message: int) -> str:
    shape = "single" if count == 1 else "batch"
    return (
        "BenchmarkUnaffectedCompatCompletePipeline/"
        f"shape={shape}/n={count}/msg={message}"
    )


def require_unaffected_source(result_dir: Path) -> dict[str, str]:
    values = read_key_values(
        result_dir / "unaffected-compat-source.txt",
        "unaffected-path source record",
    )
    if set(values) != {"baseline_revision", "current_head", "harness_blob"}:
        raise GateError(
            "unaffected-compat-source.txt must contain exactly baseline_revision, "
            "current_head, and harness_blob"
        )
    if values.get("baseline_revision") != UNAFFECTED_BASELINE_REVISION:
        raise GateError(
            "unaffected-path baseline revision is missing or does not match "
            f"{UNAFFECTED_BASELINE_REVISION}"
        )
    for key in ("current_head", "harness_blob"):
        if re.fullmatch(r"[0-9a-f]{40}", values.get(key, "")) is None:
            raise GateError(f"unaffected-compat-source.txt lacks a valid {key}")
    return values


def sha256_file(path: Path) -> str:
    if not path.is_file():
        raise GateError(f"missing decision evidence file: {path}")
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
    except OSError as error:
        raise GateError(f"cannot hash decision evidence {path}: {error}") from error
    return digest.hexdigest()


def source_tree_digest(
    records: Sequence[tuple[bytes, str, int, int, str]]
) -> str:
    digest = hashlib.sha256()
    for source_path, kind, mode, size, content_digest in records:
        for field in (
            source_path,
            kind.encode("ascii"),
            f"{mode:o}".encode("ascii"),
            str(size).encode("ascii"),
            content_digest.encode("ascii"),
        ):
            digest.update(len(field).to_bytes(8, "big"))
            digest.update(field)
    return digest.hexdigest()


def read_source_manifest(result_dir: Path) -> dict[str, Any]:
    path = result_dir / "source-manifest-start.tsv"
    if not path.is_file():
        raise GateError(f"missing source manifest: {path}")
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise GateError(f"cannot read source manifest: {path}: {error}") from error
    if len(lines) < 4:
        raise GateError("source-manifest-start.tsv is incomplete")
    tree_prefix = "source_tree_sha256="
    count_prefix = "source_entry_count="
    if not lines[0].startswith(tree_prefix):
        raise GateError("source manifest lacks source_tree_sha256 header")
    tree_digest = lines[0][len(tree_prefix):]
    if re.fullmatch(r"[0-9a-f]{64}", tree_digest) is None:
        raise GateError("source manifest has an invalid source_tree_sha256")
    if not lines[1].startswith(count_prefix):
        raise GateError("source manifest lacks source_entry_count header")
    try:
        entry_count = int(lines[1][len(count_prefix):])
    except ValueError as error:
        raise GateError("source manifest has an invalid source_entry_count") from error
    if entry_count <= 0 or entry_count != len(lines) - 3:
        raise GateError(
            "source manifest entry count does not match its records"
        )
    if lines[2] != (
        "path_json\ttype\tmode_octal\tsize_bytes\tcontent_sha256"
    ):
        raise GateError("source manifest has an invalid record header")
    records: list[tuple[bytes, str, int, int, str]] = []
    for line_number, line in enumerate(lines[3:], 4):
        fields = line.split("\t")
        if len(fields) != 5:
            raise GateError(
                f"source manifest record {line_number} has the wrong field count"
            )
        try:
            path_value = json.loads(fields[0])
            mode = int(fields[2], 8)
            size = int(fields[3])
        except (json.JSONDecodeError, ValueError) as error:
            raise GateError(
                f"source manifest record {line_number} is malformed"
            ) from error
        if not isinstance(path_value, str) or not path_value or size < 0:
            raise GateError(
                f"source manifest record {line_number} has invalid values"
            )
        if fields[1] not in ("file", "symlink", "missing"):
            raise GateError(
                f"source manifest record {line_number} has invalid type"
            )
        if re.fullmatch(r"[0-9a-f]{64}", fields[4]) is None:
            raise GateError(
                f"source manifest record {line_number} has invalid digest"
            )
        try:
            source_path = os.fsencode(path_value)
        except UnicodeError as error:
            raise GateError(
                f"source manifest record {line_number} has invalid path"
            ) from error
        records.append((source_path, fields[1], mode, size, fields[4]))
    if source_tree_digest(records) != tree_digest:
        raise GateError("source manifest tree digest does not match its records")
    return {
        "file": path.name,
        "file_sha256": sha256_file(path),
        "source_tree_sha256": tree_digest,
        "source_entry_count": entry_count,
    }


def observed_git_head() -> str | None:
    repo = Path(__file__).resolve().parent.parent
    try:
        completed = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except OSError:
        return None
    if completed.returncode != 0:
        return None
    head = completed.stdout.strip()
    return head if re.fullmatch(r"[0-9a-f]{40}", head) else None


def read_decision_provenance(
    result_dir: Path,
) -> tuple[dict[str, Any], dict[str, str]]:
    config = read_benchmark_config(result_dir)
    source_manifest = read_source_manifest(result_dir)
    source_record = require_unaffected_source(result_dir)
    observed_head = observed_git_head()
    if observed_head is not None and observed_head != source_record["current_head"]:
        raise GateError(
            "current Git HEAD does not match the benchmark source record"
        )
    evidence = {
        name: sha256_file(result_dir / name)
        for name in DECISION_EVIDENCE_FILES
    }
    provenance: dict[str, Any] = {
        "benchmark_config": {
            "file": "benchmark-config.txt",
            "file_sha256": evidence["benchmark-config.txt"],
            "values": dict(sorted(config.items())),
        },
        "source_manifest": source_manifest,
        "recorded_git_head": source_record["current_head"],
        "observed_git_head": observed_head,
        "unaffected_baseline_revision": source_record["baseline_revision"],
        "unaffected_harness_blob": source_record["harness_blob"],
        "evidence_file_sha256": evidence,
    }
    return provenance, config


def require_evidence_unchanged(
    result_dir: Path, provenance: Mapping[str, Any]
) -> None:
    expected = provenance.get("evidence_file_sha256")
    if not isinstance(expected, dict) or set(expected) != set(
        DECISION_EVIDENCE_FILES
    ):
        raise GateError("decision provenance has an incoherent evidence set")
    for name in DECISION_EVIDENCE_FILES:
        if sha256_file(result_dir / name) != expected[name]:
            raise GateError(
                f"decision evidence changed during evaluation: {name}"
            )


def pipeline_name(configuration: Configuration, count: int, message: int) -> str:
    return (
        "BenchmarkR51IFMAPipeline/stage=cold-A/"
        f"{configuration.label}/n={count}/msg={message}"
    )


def worker_name(
    worker_count: int, configuration: Configuration, count: int, message: int
) -> str:
    return (
        "BenchmarkR51IFMAPipelineParallel/"
        f"workers={worker_count}/stage=cold-A/{configuration.label}/"
        f"n={count}/msg={message}"
    )


def worker_stdlib_name(worker_count: int, count: int, message: int) -> str:
    return (
        "BenchmarkR51IFMAPipelineParallel/"
        f"workers={worker_count}/stage=cold-A/path=stdlib/"
        f"n={count}/msg={message}"
    )


def heea_name(path: str, count: int, message: int) -> str:
    return (
        "BenchmarkR51HEEACompletePipeline/stage=cold-AR/"
        f"mode=heea/path={path}/W132/radix=32/n={count}/msg={message}"
    )


def heea_worker_name(
    worker_count: int, path: str, count: int, message: int
) -> str:
    return (
        "BenchmarkR51HEEACompletePipelineParallel/"
        f"workers={worker_count}/stage=cold-AR/mode=heea/path={path}/"
        f"W132/radix=32/n={count}/msg={message}"
    )


def heea_fallback_name(path: str, message: int, pattern: str) -> str:
    return (
        "BenchmarkR51HEEACompletePipelineFallback/"
        f"path={path}/W132/radix=32/n=8/msg={message}/pattern={pattern}"
    )


def matrix_for_count(
    rows: Mapping[str, Stats], count: int
) -> dict[Configuration, dict[int, Stats]]:
    return {
        configuration: {
            message: rows[pipeline_name(configuration, count, message)]
            for message in MESSAGES
        }
        for configuration in ORDINARY_R51_CONFIGS
    }


def worker_matrix(
    rows: Mapping[str, Stats], worker_count: int
) -> dict[Configuration, dict[tuple[int, int], Stats]]:
    return {
        configuration: {
            (count, message): rows[
                worker_name(worker_count, configuration, count, message)
            ]
            for count in RELEASE_BATCH_COUNTS
            for message in MESSAGES
        }
        for configuration in ORDINARY_R51_CONFIGS
    }


def admit_complete_variants(
    matrix: Mapping[Configuration, Mapping[Workload, Stats]],
    outer_baselines: Mapping[Workload, Stats] | None,
) -> tuple[dict[Configuration, Mapping[Workload, Stats]], dict[Configuration, str]]:
    """Admit optional complete-pipeline variants against the proper baseline.

    Radix 16/64 and comb16/32/256 are not allowed to win a release selection
    merely because they are present.  They must improve the same path's
    radix-32 shared-B complete verifier by at least 2% at every release
    workload, without increasing B/op or allocs/op. The radix-32 shared-B paths
    remain the non-optional reference candidates.
    """
    admitted: dict[Configuration, Mapping[Workload, Stats]] = {}
    reasons: dict[Configuration, str] = {}
    workloads = set(next(iter(matrix.values())).keys())
    if any(set(values) != workloads for values in matrix.values()):
        raise GateError("incoherent ordinary candidate workload matrix")
    if outer_baselines is not None and set(outer_baselines) != workloads:
        raise GateError("incoherent outer-baseline workload matrix")

    for configuration, values in matrix.items():
        proper = matrix[configuration.proper_baseline]
        allocation_ok = all(
            allocations_do_not_increase(proper[workload], values[workload])
            and (
                outer_baselines is None
                or allocations_do_not_increase(
                    outer_baselines[workload], values[workload]
                )
            )
            for workload in workloads
        )
        if not allocation_ok:
            reasons[configuration] = "allocation increase"
            continue
        if not configuration.optional:
            admitted[configuration] = values
            reasons[configuration] = "reference"
            continue
        worst_gain = min(
            improvement(
                proper[workload].nanoseconds,
                values[workload].nanoseconds,
            )
            for workload in workloads
        )
        if worst_gain + EPSILON < OPTIONAL_GAIN:
            reasons[configuration] = (
                f"worst complete-path gain {worst_gain:.2%} < 2%"
            )
            continue
        admitted[configuration] = values
        reasons[configuration] = f"admitted; worst gain {worst_gain:.2%}"

    if not admitted:
        raise GateError("no allocation-safe ordinary complete verifier remains")
    return admitted, reasons


def prefer_simple_x8(
    selected: Configuration,
    candidates: Mapping[Configuration, Mapping[Workload, Stats]],
) -> Configuration:
    """Prefer one x8 group when two-x4 is within the plan's 2% tie band."""
    if selected.path != "two-x4":
        return selected
    x8 = Configuration("x8", selected.radix, selected.fixed_base)
    if x8 not in candidates:
        return selected
    two_values = candidates[selected]
    x8_values = candidates[x8]
    if set(two_values) != set(x8_values):
        raise GateError(f"incoherent x8/two-x4 workload matrix for {selected.label}")
    if all(
        x8_values[workload].nanoseconds
        <= two_values[workload].nanoseconds * (1.0 + X8_SIMPLICITY_TIE)
        for workload in two_values
    ):
        return x8
    return selected


def choose_against_baseline(
    candidates: Mapping[Configuration, Mapping[Workload, Stats]],
    baselines: Mapping[Workload, Stats],
) -> Configuration:
    workloads = set(baselines)
    if any(set(values) != workloads for values in candidates.values()):
        raise GateError("incoherent release workload matrix")

    def score(configuration: Configuration) -> tuple[float, int, str]:
        values = candidates[configuration]
        worst_gain = min(
            improvement(
                baselines[workload].nanoseconds,
                values[workload].nanoseconds,
            )
            for workload in workloads
        )
        return worst_gain, int(configuration.path == "x8"), configuration.label

    selected = max(candidates, key=score)
    return prefer_simple_x8(selected, candidates)


def choose_minimax(
    candidates: Mapping[Configuration, Mapping[Workload, Stats]],
) -> Configuration:
    workloads = set(next(iter(candidates.values())))
    if any(set(values) != workloads for values in candidates.values()):
        raise GateError("incoherent worker workload matrix")

    def score(configuration: Configuration) -> tuple[float, int, str]:
        worst_ratio = max(
            candidates[configuration][workload].nanoseconds
            / min(
                values[workload].nanoseconds
                for values in candidates.values()
            )
            for workload in workloads
        )
        return worst_ratio, int(configuration.path != "x8"), configuration.label

    selected = min(candidates, key=score)
    return prefer_simple_x8(selected, candidates)


def serial_worker_eligible_configurations(
    matrices: Mapping[int, Mapping[Configuration, Mapping[int, Stats]]],
    baselines: Mapping[int, Mapping[int, Stats]],
    admitted: Mapping[int, Mapping[Configuration, Mapping[int, Stats]]],
) -> set[Configuration]:
    """Return configs that independently clear every serial batch release row."""
    configurations = set(ORDINARY_R51_CONFIGS)
    if set(matrices) != set(RELEASE_BATCH_COUNTS):
        raise GateError("serial worker-eligibility matrix has wrong batch counts")
    if set(baselines) != set(RELEASE_BATCH_COUNTS):
        raise GateError("serial worker baselines have wrong batch counts")
    if set(admitted) != set(RELEASE_BATCH_COUNTS):
        raise GateError("serial admissions have wrong batch counts")
    return {
        configuration
        for configuration in configurations
        if all(
            configuration in admitted[count]
            and all(
                improvement(
                    baselines[count][message].nanoseconds,
                    matrices[count][configuration][message].nanoseconds,
                )
                + EPSILON
                >= 0.15
                and allocations_do_not_increase(
                    baselines[count][message],
                    matrices[count][configuration][message],
                )
                for message in MESSAGES
            )
            for count in RELEASE_BATCH_COUNTS
        )
    }


def production_worker_candidate_passes(
    concurrent_stdlib: Mapping[Workload, Stats],
    identical_serial: Mapping[Workload, Stats],
    candidate: Mapping[Workload, Stats],
) -> bool:
    """Require worker throughput and no material concurrent regression."""
    workloads = set(concurrent_stdlib)
    if set(identical_serial) != workloads or set(candidate) != workloads:
        raise GateError("incoherent production-worker comparison matrix")
    return all(
        improvement(
            concurrent_stdlib[workload].nanoseconds,
            candidate[workload].nanoseconds,
        )
        + EPSILON
        >= 0.15
        and improvement(
            identical_serial[workload].nanoseconds,
            candidate[workload].nanoseconds,
        )
        + EPSILON
        >= -WORKER_REGRESSION_LIMIT
        and allocations_do_not_increase(
            concurrent_stdlib[workload], candidate[workload]
        )
        and allocations_do_not_increase(
            identical_serial[workload], candidate[workload]
        )
        for workload in workloads
    )


def admit_heea_paths(
    serial_candidates: Mapping[str, Mapping[tuple[int, int], Stats]],
    worker_candidates: Mapping[str, Mapping[tuple[int, int], Stats]],
    fallback_candidates: Mapping[str, Mapping[tuple[int, str], Stats]],
    selected_serial_ordinary: Mapping[tuple[int, int], Stats],
    selected_worker_ordinary: Mapping[tuple[int, int], Stats],
) -> tuple[
    dict[str, dict[tuple[str, int, int], Stats]],
    dict[str, str],
]:
    """Admit one HEEA path against the selected ordinary configuration.

    HEEA is not entitled to use a fixed radix-32 same-path comparator after
    ordinary selection has found a faster radix, comb, or SIMD shape. A path
    is eligible only when that same HEEA shape clears every serial *and*
    production-worker row against the exact selected ordinary configuration.
    It must also avoid a greater than 5% regression or any allocation growth
    when an attacker places a W132 selector fallback in any lane, or all lanes,
    of an eight-signature group.
    """
    expected_workloads = {
        (count, message)
        for count in RELEASE_BATCH_COUNTS
        for message in MESSAGES
    }
    expected_fallback_workloads = {
        (message, pattern)
        for message in MESSAGES
        for pattern in HEEA_FALLBACK_PATTERNS
    }
    if set(serial_candidates) != set(PATHS):
        raise GateError("HEEA serial matrix has wrong SIMD paths")
    if set(worker_candidates) != set(PATHS):
        raise GateError("HEEA worker matrix has wrong SIMD paths")
    if set(fallback_candidates) != set(PATHS):
        raise GateError("HEEA fallback matrix has wrong SIMD paths")
    if set(selected_serial_ordinary) != expected_workloads:
        raise GateError("selected ordinary serial HEEA baseline is incoherent")
    if set(selected_worker_ordinary) != expected_workloads:
        raise GateError("selected ordinary worker HEEA baseline is incoherent")
    if any(
        set(values) != expected_workloads
        for values in (*serial_candidates.values(), *worker_candidates.values())
    ):
        raise GateError("HEEA candidate workload matrix is incoherent")
    if any(
        set(values) != expected_fallback_workloads
        for values in fallback_candidates.values()
    ):
        raise GateError("HEEA fallback workload matrix is incoherent")

    admitted: dict[str, dict[tuple[str, int, int], Stats]] = {}
    reasons: dict[str, str] = {}
    for path in PATHS:
        serial_worst = min(
            improvement(
                selected_serial_ordinary[workload].nanoseconds,
                serial_candidates[path][workload].nanoseconds,
            )
            for workload in expected_workloads
        )
        worker_worst = min(
            improvement(
                selected_worker_ordinary[workload].nanoseconds,
                worker_candidates[path][workload].nanoseconds,
            )
            for workload in expected_workloads
        )
        serial_allocations_ok = all(
            allocations_do_not_increase(
                selected_serial_ordinary[workload],
                serial_candidates[path][workload],
            )
            for workload in expected_workloads
        )
        worker_allocations_ok = all(
            allocations_do_not_increase(
                selected_worker_ordinary[workload],
                worker_candidates[path][workload],
            )
            for workload in expected_workloads
        )
        fallback_worst = min(
            improvement(
                selected_serial_ordinary[(8, message)].nanoseconds,
                fallback_candidates[path][(message, pattern)].nanoseconds,
            )
            for message, pattern in expected_fallback_workloads
        )
        fallback_allocations_ok = all(
            allocations_do_not_increase(
                selected_serial_ordinary[(8, message)],
                fallback_candidates[path][(message, pattern)],
            )
            for message, pattern in expected_fallback_workloads
        )
        if not serial_allocations_ok or not worker_allocations_ok:
            failed = []
            if not serial_allocations_ok:
                failed.append("serial")
            if not worker_allocations_ok:
                failed.append("worker")
            reasons[path] = f"allocation increase in {'+'.join(failed)} matrix"
            continue
        if serial_worst + EPSILON < HEEA_GAIN:
            reasons[path] = (
                f"worst serial gain {serial_worst:.2%} < {HEEA_GAIN:.0%}"
            )
            continue
        if worker_worst + EPSILON < HEEA_GAIN:
            reasons[path] = (
                f"worst worker gain {worker_worst:.2%} < {HEEA_GAIN:.0%}"
            )
            continue
        if not fallback_allocations_ok:
            reasons[path] = "allocation increase in adversarial fallback matrix"
            continue
        if fallback_worst + EPSILON < -HEEA_FALLBACK_REGRESSION_LIMIT:
            reasons[path] = (
                f"worst adversarial fallback change {fallback_worst:.2%} "
                f"< -{HEEA_FALLBACK_REGRESSION_LIMIT:.0%}"
            )
            continue
        admitted[path] = {
            **{
                ("serial", count, message): value
                for (count, message), value in serial_candidates[path].items()
            },
            **{
                ("worker", count, message): value
                for (count, message), value in worker_candidates[path].items()
            },
        }
        reasons[path] = (
            f"admitted; worst serial gain {serial_worst:.2%}, "
            f"worker gain {worker_worst:.2%}, "
            f"fallback change {fallback_worst:.2%}"
        )
    return admitted, reasons


def print_variant_admission(
    reasons: Mapping[Configuration, str], indent: str = "  "
) -> None:
    for configuration in ORDINARY_R51_CONFIGS:
        if configuration.optional:
            print(f"{indent}{configuration.label}: {reasons[configuration]}")


def expected_pipeline_names() -> tuple[list[str], list[str]]:
    baseline_names = [
        (
            "BenchmarkR51IFMAPipeline/stage=cold-A/"
            f"path={path}/n={count}/msg={message}"
        )
        for path in ("stdlib", "generic-strict")
        for count in PIPELINE_COUNTS
        for message in MESSAGES
    ]
    candidate_names = [
        pipeline_name(configuration, count, message)
        for configuration in ORDINARY_R51_CONFIGS
        for count in PIPELINE_COUNTS
        for message in MESSAGES
    ]
    return baseline_names, candidate_names


def evaluate(result_dir: Path) -> EvaluationOutcome:
    try:
        result_dir = result_dir.resolve(strict=True)
    except OSError as error:
        raise GateError(f"invalid result directory: {result_dir}: {error}") from error
    if not result_dir.is_dir():
        raise GateError(f"result path is not a directory: {result_dir}")
    provenance, benchmark_config = read_decision_provenance(result_dir)
    worker_count = int(benchmark_config["verifier_workers"])
    baseline_names, candidate_names = expected_pipeline_names()
    pipeline_baselines = require_exact_rows(
        load(result_dir, "pipeline-baselines.txt"),
        baseline_names,
        "pipeline-baselines.txt",
    )
    pipeline_candidates = require_exact_rows(
        load(result_dir, "pipeline-candidates.txt"),
        candidate_names,
        "pipeline-candidates.txt",
    )
    worker_names = [
        worker_name(worker_count, configuration, count, message)
        for configuration in ORDINARY_R51_CONFIGS
        for count in RELEASE_BATCH_COUNTS
        for message in MESSAGES
    ]
    pipeline_workers = require_exact_rows(
        load(result_dir, "pipeline-workers.txt"),
        worker_names,
        "pipeline-workers.txt",
    )
    worker_stdlib_names = [
        worker_stdlib_name(worker_count, count, message)
        for count in RELEASE_BATCH_COUNTS
        for message in MESSAGES
    ]
    worker_stdlib = require_exact_rows(
        load(result_dir, "pipeline-worker-baselines.txt"),
        worker_stdlib_names,
        "pipeline-worker-baselines.txt",
    )
    single_baselines = require_exact_rows(
        load(result_dir, "single-baseline.txt"),
        [f"BenchmarkVerify/impl=stdlib/msg={message}" for message in MESSAGES],
        "single-baseline.txt",
    )
    single_ifma = require_exact_rows(
        load(result_dir, "single-ifma.txt"),
        [
            f"BenchmarkIFMABackendVerify/profile=strict/msg={message}"
            for message in MESSAGES
        ],
        "single-ifma.txt",
    )
    strict_precheck_names = [
        (
            "BenchmarkStrictPrecheckCompletePipeline/"
            f"profile={profile}/mode={mode}/msg={message}"
        )
        for profile in ("strict", "compat")
        for mode in ("legacy-decode-cofactor", "seven-value")
        for message in MESSAGES
    ]
    strict_prechecks = require_exact_rows(
        load(result_dir, "strict-precheck.txt"),
        strict_precheck_names,
        "strict-precheck.txt",
    )
    unaffected_names = [
        unaffected_name(count, message)
        for count in (1, *RELEASE_BATCH_COUNTS)
        for message in MESSAGES
    ]
    unaffected_baseline = require_exact_rows(
        load(result_dir, "unaffected-compat-baseline.txt"),
        unaffected_names,
        "unaffected-compat-baseline.txt",
    )
    unaffected_current = require_exact_rows(
        load(result_dir, "unaffected-compat-current.txt"),
        unaffected_names,
        "unaffected-compat-current.txt",
    )
    paired_modes = (
        ("single-A", "encoded-Q"),
        ("paired-AR", "projective"),
    )
    paired_names = [
        (
            "BenchmarkR51IFMAPairedGate/stage=cold-A/"
            f"path={path}/decode={decode}/final={final}/"
            f"radixA=32/fixedB=shared/n={count}/msg={message}"
        )
        for path in PATHS
        for decode, final in paired_modes
        for count in (1, *RELEASE_BATCH_COUNTS)
        for message in MESSAGES
    ]
    paired_gate = require_exact_rows(
        load(result_dir, "paired-gate.txt"),
        paired_names,
        "paired-gate.txt",
    )
    heea_names = [
        heea_name(path, count, message)
        for path in PATHS
        for count in RELEASE_BATCH_COUNTS
        for message in MESSAGES
    ]
    heea = require_exact_rows(
        load(result_dir, "heea-complete.txt"),
        heea_names,
        "heea-complete.txt",
    )
    heea_worker_names = [
        heea_worker_name(worker_count, path, count, message)
        for path in PATHS
        for count in RELEASE_BATCH_COUNTS
        for message in MESSAGES
    ]
    heea_workers = require_exact_rows(
        load(result_dir, "heea-workers.txt"),
        heea_worker_names,
        "heea-workers.txt",
    )
    heea_fallback_names = [
        heea_fallback_name(path, message, pattern)
        for path in PATHS
        for message in MESSAGES
        for pattern in HEEA_FALLBACK_PATTERNS
    ]
    heea_fallback = require_exact_rows(
        load(result_dir, "heea-fallback.txt"),
        heea_fallback_names,
        "heea-fallback.txt",
    )
    sha_names = [
        f"BenchmarkNativeTails/impl={implementation}/count={count}"
        for implementation in ("scalar", "native-x4", "native-x8")
        for count in range(1, 18)
    ]
    sha_tails = require_exact_rows(
        load(result_dir, "sha-tails.txt"),
        sha_names,
        "sha-tails.txt",
    )

    mandatory_ok = True
    micro_gates: dict[str, bool] = {
        "strict_byte_precheck": True,
        "stdlib_compat_unaffected": True,
        "paired_decode_projective_equality": True,
        "r43_cold_single_public_api": True,
        "r51_serial_batch": True,
        "r51_production_worker": True,
    }
    print("Zen 4 median gate report")
    print("========================")

    print(
        "\nStrict byte-precheck gate "
        "(>=3% complete strict gain; compat regression <=1%)"
    )
    for message in MESSAGES:
        def precheck_row(profile: str, mode: str) -> Stats:
            return strict_prechecks[
                "BenchmarkStrictPrecheckCompletePipeline/"
                f"profile={profile}/mode={mode}/msg={message}"
            ]

        strict_legacy = precheck_row("strict", "legacy-decode-cofactor")
        strict_fast = precheck_row("strict", "seven-value")
        strict_gain = improvement(
            strict_legacy.nanoseconds, strict_fast.nanoseconds
        )
        strict_allocation_ok = allocations_do_not_increase(
            strict_legacy, strict_fast
        )
        strict_passed = (
            strict_gain + EPSILON >= STRICT_PRECHECK_GAIN
            and strict_allocation_ok
        )
        mandatory_ok = mandatory_ok and strict_passed
        micro_gates["strict_byte_precheck"] = (
            micro_gates["strict_byte_precheck"] and strict_passed
        )

        compat_legacy = precheck_row("compat", "legacy-decode-cofactor")
        compat_fast = precheck_row("compat", "seven-value")
        compat_change = improvement(
            compat_legacy.nanoseconds, compat_fast.nanoseconds
        )
        compat_allocation_ok = allocations_do_not_increase(
            compat_legacy, compat_fast
        )
        compat_passed = (
            compat_change + EPSILON >= -COMPAT_REGRESSION_LIMIT
            and compat_allocation_ok
        )
        mandatory_ok = mandatory_ok and compat_passed
        micro_gates["strict_byte_precheck"] = (
            micro_gates["strict_byte_precheck"] and compat_passed
        )
        print(
            f"  msg={message:4d}: strict={strict_gain:7.2%} "
            f"({allocation_metrics(strict_fast)}) "
            f"{'PASS' if strict_passed else 'FAIL'}; "
            f"compat={compat_change:7.2%} "
            f"({allocation_metrics(compat_fast)}) "
            f"{'PASS' if compat_passed else 'FAIL'}"
        )

    print(
        "\nGeneral unaffected StdlibCompat gate "
        "(current tree versus frozen 05bf37c; regression <=1%)"
    )
    for count in (1, *RELEASE_BATCH_COUNTS):
        for message in MESSAGES:
            name = unaffected_name(count, message)
            baseline = unaffected_baseline[name]
            current = unaffected_current[name]
            change = improvement(
                baseline.nanoseconds, current.nanoseconds
            )
            passed = unaffected_path_passes(baseline, current)
            mandatory_ok = mandatory_ok and passed
            micro_gates["stdlib_compat_unaffected"] = (
                micro_gates["stdlib_compat_unaffected"] and passed
            )
            print(
                f"  n={count:2d} msg={message:4d}: {change:7.2%} "
                f"{allocation_metrics(current)} "
                f"{'PASS' if passed else 'FAIL'}"
            )

    print(
        "\nPaired decode/projective-equality gate "
        "(>=2% over single-A decode plus encoded-Q)"
    )
    paired_admitted_paths: set[str] = set()
    for path in PATHS:
        path_passed = True
        worst_gain = float("inf")
        for count in (1, *RELEASE_BATCH_COUNTS):
            for message in MESSAGES:
                prefix = (
                    "BenchmarkR51IFMAPairedGate/stage=cold-A/"
                    f"path={path}/"
                )
                baseline = paired_gate[
                    prefix
                    + "decode=single-A/final=encoded-Q/"
                    + f"radixA=32/fixedB=shared/n={count}/msg={message}"
                ]
                candidate = paired_gate[
                    prefix
                    + "decode=paired-AR/final=projective/"
                    + f"radixA=32/fixedB=shared/n={count}/msg={message}"
                ]
                gain = improvement(
                    baseline.nanoseconds, candidate.nanoseconds
                )
                worst_gain = min(worst_gain, gain)
                allocation_ok = allocations_do_not_increase(
                    baseline, candidate
                )
                passed = (
                    gain + EPSILON >= PAIRED_PIPELINE_GAIN
                    and allocation_ok
                )
                path_passed = path_passed and passed
                print(
                    f"  path={path:7s} n={count:2d} msg={message:4d}: "
                    f"{gain:7.2%} {'PASS' if passed else 'FAIL'}"
                )
        if path_passed:
            paired_admitted_paths.add(path)
        print(
            f"  path={path:7s} worst={worst_gain:7.2%} "
            f"PAIRED_ADMITTED={'yes' if path_passed else 'no'}"
        )
    if not paired_admitted_paths:
        micro_gates["paired_decode_projective_equality"] = False
        raise GateError(
            "no r51 SIMD path cleared the complete paired-decode 2% gate"
        )

    print(
        "\nCold single-signature gate "
        "(r43 public single-call API only, >=10% faster than public stdlib)"
    )
    public_stdlib = {
        message: single_baselines[f"BenchmarkVerify/impl=stdlib/msg={message}"]
        for message in MESSAGES
    }
    r43_values = {
        message: single_ifma[
            f"BenchmarkIFMABackendVerify/profile=strict/msg={message}"
        ]
        for message in MESSAGES
    }
    single_candidate, r43_policy_passed, r43_policy_rows = (
        select_cold_single_candidate(public_stdlib, r43_values)
    )
    mandatory_ok = mandatory_ok and r43_policy_passed
    micro_gates["r43_cold_single_public_api"] = r43_policy_passed
    print(
        f"  candidate={single_candidate} "
        "(r51 batch-pipeline percentages cannot substitute)"
    )
    for row in r43_policy_rows:
        message = int(row["message_bytes"])
        candidate = r43_values[message]
        print(
            f"  msg={message:4d}: {row['gain']:7.2%}, "
            f"{allocation_metrics(candidate)}  "
            f"{'PASS' if row['passed'] else 'FAIL'}"
        )

    print(
        "\nR51 n=1 batch-pipeline evidence "
        "(informational tail evidence; not a cold-single candidate)"
    )
    pipeline_stdlib = {
        message: pipeline_baselines[
            "BenchmarkR51IFMAPipeline/stage=cold-A/"
            f"path=stdlib/n=1/msg={message}"
        ]
        for message in MESSAGES
    }
    r51_matrix = matrix_for_count(pipeline_candidates, 1)
    admitted_r51, single_reasons = admit_complete_variants(
        r51_matrix, None
    )
    admitted_r51 = {
        configuration: values
        for configuration, values in admitted_r51.items()
        if configuration.path in paired_admitted_paths
    }
    if not admitted_r51:
        raise GateError("no paired-decode-approved r51 tail candidate remains")
    r51_informational = choose_against_baseline(admitted_r51, pipeline_stdlib)
    print(f"  fastest-observed=r51:{r51_informational.label}")
    print_variant_admission(single_reasons, "    ")
    r51_informational_rows: list[dict[str, Any]] = []
    for message in MESSAGES:
        baseline = pipeline_stdlib[message]
        candidate = admitted_r51[r51_informational][message]
        gain = improvement(baseline.nanoseconds, candidate.nanoseconds)
        allocation_ok = allocations_do_not_increase(baseline, candidate)
        r51_informational_rows.append(
            {
                "message_bytes": message,
                "gain": gain,
                "allocation_gate_passed": allocation_ok,
                "baseline": stats_record(baseline),
                "candidate": stats_record(candidate),
            }
        )
        print(
            f"  msg={message:4d}: {gain:7.2%}, "
            f"{allocation_metrics(candidate)}"
        )

    print(
        "\nBatch gate "
        "(coherent per width across messages, >=15% faster per signature)"
    )
    serial_release_matrices: dict[
        int, dict[Configuration, dict[int, Stats]]
    ] = {}
    serial_stdlib_by_count: dict[int, dict[int, Stats]] = {}
    serial_admitted_by_count: dict[
        int, dict[Configuration, Mapping[int, Stats]]
    ] = {}
    for count in RELEASE_BATCH_COUNTS:
        baselines = {
            message: pipeline_baselines[
                "BenchmarkR51IFMAPipeline/stage=cold-A/"
                f"path=stdlib/n={count}/msg={message}"
            ]
            for message in MESSAGES
        }
        serial_stdlib_by_count[count] = baselines
        matrix = matrix_for_count(pipeline_candidates, count)
        serial_release_matrices[count] = matrix
        admitted, reasons = admit_complete_variants(matrix, baselines)
        admitted = {
            configuration: values
            for configuration, values in admitted.items()
            if configuration.path in paired_admitted_paths
        }
        if not admitted:
            raise GateError(
                f"no paired-decode-approved r51 candidate remains at n={count}"
            )
        serial_admitted_by_count[count] = admitted
        selected = choose_against_baseline(admitted, baselines)
        print(f"  n={count:2d} selected=r51:{selected.label}")
        print_variant_admission(reasons, "    ")
        for message in MESSAGES:
            candidate = admitted[selected][message]
            gain = improvement(
                baselines[message].nanoseconds, candidate.nanoseconds
            )
            allocation_ok = allocations_do_not_increase(
                baselines[message], candidate
            )
            passed = gain + EPSILON >= 0.15 and allocation_ok
            mandatory_ok = mandatory_ok and passed
            micro_gates["r51_serial_batch"] = (
                micro_gates["r51_serial_batch"] and passed
            )
            print(
                f"    msg={message:4d}: {gain:7.2%}, "
                f"{allocation_metrics(candidate)} "
                f" {'PASS' if passed else 'FAIL'}"
            )

    print(
        f"\nProduction-worker shortlist (workers={worker_count}, "
        "one coherent configuration across n=8/64 and release messages)"
    )
    workers = worker_matrix(pipeline_workers, worker_count)
    serial_by_workload = {
        configuration: {
            (count, message): serial_release_matrices[count][configuration][message]
            for count in RELEASE_BATCH_COUNTS
            for message in MESSAGES
        }
        for configuration in ORDINARY_R51_CONFIGS
    }
    worker_stdlib_by_workload = {
        (count, message): worker_stdlib[
            worker_stdlib_name(worker_count, count, message)
        ]
        for count in RELEASE_BATCH_COUNTS
        for message in MESSAGES
    }
    admitted_workers, worker_reasons = admit_complete_variants(
        workers, worker_stdlib_by_workload
    )
    admitted_workers = {
        configuration: values
        for configuration, values in admitted_workers.items()
        if configuration.path in paired_admitted_paths
    }
    serial_release_eligible = serial_worker_eligible_configurations(
        serial_release_matrices,
        serial_stdlib_by_count,
        serial_admitted_by_count,
    )
    for configuration in list(admitted_workers):
        if configuration not in serial_release_eligible:
            del admitted_workers[configuration]
            worker_reasons[configuration] = (
                "not release-eligible in both serial n=8/64 matrices"
            )
    # Production-worker admission has two independent references: the
    # concurrent stdlib throughput baseline and the identical serial r51 path.
    # A candidate must clear both before coherent selection.
    for configuration in list(admitted_workers):
        values = admitted_workers[configuration]
        if not production_worker_candidate_passes(
            worker_stdlib_by_workload,
            serial_by_workload[configuration],
            values,
        ):
            del admitted_workers[configuration]
            worker_reasons[configuration] = (
                "fails >=15% concurrent-stdlib gain, <=1% identical-serial "
                "regression, or allocation gate"
            )
    if not admitted_workers:
        raise GateError("no allocation-safe production-worker candidate remains")
    selected_worker = choose_minimax(admitted_workers)
    print(f"  selected=r51:{selected_worker.label}")
    print_variant_admission(worker_reasons, "    ")
    for count in RELEASE_BATCH_COUNTS:
        for message in MESSAGES:
            workload = (count, message)
            serial = serial_by_workload[selected_worker][workload]
            stdlib = worker_stdlib_by_workload[workload]
            concurrent = admitted_workers[selected_worker][workload]
            stdlib_gain = improvement(
                stdlib.nanoseconds, concurrent.nanoseconds
            )
            scaling = improvement(serial.nanoseconds, concurrent.nanoseconds)
            allocation_ok = (
                allocations_do_not_increase(stdlib, concurrent)
                and allocations_do_not_increase(serial, concurrent)
            )
            passed = (
                stdlib_gain + EPSILON >= 0.15
                and scaling + EPSILON >= -WORKER_REGRESSION_LIMIT
                and allocation_ok
            )
            mandatory_ok = mandatory_ok and passed
            micro_gates["r51_production_worker"] = (
                micro_gates["r51_production_worker"] and passed
            )
            print(
                f"  n={count:2d} msg={message:4d}: "
                f"gain-vs-concurrent-stdlib={stdlib_gain:7.2%}, "
                f"wall-ns/op change={scaling:7.2%}, "
                f"{allocation_metrics(concurrent)} "
                f" {'PASS' if passed else 'FAIL'}"
            )

    print(
        "\nExact HEEA W132 gate "
        "(one coherent path, optional, >=5% over selected ordinary r51 "
        "in serial and worker matrices; <=5% adversarial fallback regression)"
    )
    heea_serial_candidates: dict[str, dict[tuple[int, int], Stats]] = {
        path: {} for path in PATHS
    }
    heea_worker_candidates: dict[str, dict[tuple[int, int], Stats]] = {
        path: {} for path in PATHS
    }
    heea_fallback_candidates: dict[str, dict[tuple[int, str], Stats]] = {
        path: {} for path in PATHS
    }
    for path in PATHS:
        for count in RELEASE_BATCH_COUNTS:
            for message in MESSAGES:
                workload = (count, message)
                heea_serial_candidates[path][workload] = heea[
                    heea_name(path, count, message)
                ]
                heea_worker_candidates[path][workload] = heea_workers[
                    heea_worker_name(worker_count, path, count, message)
                ]
        for message in MESSAGES:
            for pattern in HEEA_FALLBACK_PATTERNS:
                heea_fallback_candidates[path][(message, pattern)] = (
                    heea_fallback[
                        heea_fallback_name(path, message, pattern)
                    ]
                )

    selected_serial_ordinary = serial_by_workload[selected_worker]
    selected_worker_ordinary = admitted_workers[selected_worker]
    heea_admitted, heea_reasons = admit_heea_paths(
        heea_serial_candidates,
        heea_worker_candidates,
        heea_fallback_candidates,
        selected_serial_ordinary,
        selected_worker_ordinary,
    )
    print(f"  ordinary-reference=r51:{selected_worker.label}")

    selected_heea_path: str | None = None
    if heea_admitted:
        heea_as_configs = {
            Configuration(path, 32, "shared"): values
            for path, values in heea_admitted.items()
        }
        combined_ordinary = {
            **{
                ("serial", count, message): value
                for (count, message), value in selected_serial_ordinary.items()
            },
            **{
                ("worker", count, message): value
                for (count, message), value in selected_worker_ordinary.items()
            },
        }
        selected_heea_config = choose_against_baseline(
            heea_as_configs, combined_ordinary
        )
        selected_heea_path = selected_heea_config.path
        print(f"  selected=path={selected_heea_path}")
        for matrix_name, ordinary, candidates in (
            (
                "serial",
                selected_serial_ordinary,
                heea_serial_candidates[selected_heea_path],
            ),
            (
                "worker",
                selected_worker_ordinary,
                heea_worker_candidates[selected_heea_path],
            ),
        ):
            for count in RELEASE_BATCH_COUNTS:
                for message in MESSAGES:
                    workload = (count, message)
                    gain = improvement(
                        ordinary[workload].nanoseconds,
                        candidates[workload].nanoseconds,
                    )
                    print(
                        f"  matrix={matrix_name:6s} n={count:2d} "
                        f"msg={message:4d}: {gain:7.2%}, "
                        f"{allocation_metrics(candidates[workload])} PASS"
                    )
        fallback_rows = heea_fallback_candidates[selected_heea_path]
        worst_fallback = min(
            (
                improvement(
                    selected_serial_ordinary[(8, message)].nanoseconds,
                    fallback_rows[(message, pattern)].nanoseconds,
                ),
                message,
                pattern,
            )
            for message in MESSAGES
            for pattern in HEEA_FALLBACK_PATTERNS
        )
        print(
            "  matrix=fallback n=8 "
            f"worst-msg={worst_fallback[1]} "
            f"pattern={worst_fallback[2]}: "
            f"{worst_fallback[0]:7.2%} PASS"
        )
        print("  HEEA_ADMITTED=yes")
    else:
        print("  selected=none")
        for path in PATHS:
            print(f"  path={path}: {heea_reasons[path]}")
        print("  HEEA_ADMITTED=no")

    print("\nSHA-512 tail winners (informational dispatch input)")
    for count in range(1, 18):
        scalar = sha_tails[f"BenchmarkNativeTails/impl=scalar/count={count}"]
        candidates = [
            (implementation, sha_tails[
                f"BenchmarkNativeTails/impl={implementation}/count={count}"
            ])
            for implementation in ("scalar", "native-x4", "native-x8")
        ]
        allocation_safe = [
            candidate
            for candidate in candidates
            if allocations_do_not_increase(scalar, candidate[1])
        ]
        implementation, value = min(
            allocation_safe, key=lambda candidate: candidate[1].nanoseconds
        )
        print(
            f"  count={count:2d}: {implementation:9s} "
            f"{value.nanoseconds:12.1f} ns/op"
        )

    print("\nMITHRIL_REPLAY_GATE=pending (requires >=5% wall-time trace replay win)")
    print(f"MANDATORY_MICRO_GATES={'pass' if mandatory_ok else 'fail'}")

    ordinary_serial_rows: list[dict[str, Any]] = []
    ordinary_worker_rows: list[dict[str, Any]] = []
    for count in RELEASE_BATCH_COUNTS:
        for message in MESSAGES:
            workload = (count, message)
            serial_baseline = serial_stdlib_by_count[count][message]
            serial_candidate = selected_serial_ordinary[workload]
            ordinary_serial_rows.append(
                {
                    "count": count,
                    "message_bytes": message,
                    "gain_vs_stdlib": improvement(
                        serial_baseline.nanoseconds,
                        serial_candidate.nanoseconds,
                    ),
                    "baseline": stats_record(serial_baseline),
                    "candidate": stats_record(serial_candidate),
                }
            )
            worker_baseline = worker_stdlib_by_workload[workload]
            worker_candidate = selected_worker_ordinary[workload]
            ordinary_worker_rows.append(
                {
                    "count": count,
                    "message_bytes": message,
                    "gain_vs_concurrent_stdlib": improvement(
                        worker_baseline.nanoseconds,
                        worker_candidate.nanoseconds,
                    ),
                    "change_vs_identical_serial": improvement(
                        serial_candidate.nanoseconds,
                        worker_candidate.nanoseconds,
                    ),
                    "baseline": stats_record(worker_baseline),
                    "candidate": stats_record(worker_candidate),
                }
            )

    authoritative_hardware = benchmark_config["release_cpu_match"] == "true"
    require_evidence_unchanged(result_dir, provenance)
    pending_blockers = [
        {
            "id": blocker,
            "status": "pending",
        }
        for blocker in PENDING_PRODUCTION_BLOCKERS
    ]
    decision: dict[str, Any] = {
        "schema_version": DECISION_SCHEMA_VERSION,
        "artifact_kind": DECISION_KIND,
        "scope": "zen4_microbenchmark_only",
        # This evaluator has no authority to clear the system/replay/cache or
        # reviewed-source gates.  Keep this literal false even when every
        # numerical microbenchmark passes.
        "production_promotable": False,
        "microbenchmark_gate_passed": mandatory_ok,
        "measurement_authority": {
            "hardware_authoritative": authoritative_hardware,
            "cpu_model": benchmark_config["cpu_model"],
            "release_cpu_match": benchmark_config["release_cpu_match"] == "true",
            "non_release_cpu_override": (
                benchmark_config["non_release_cpu_override"] == "1"
            ),
            "primitive_core": benchmark_config["primitive_core"],
            "verifier_workers": worker_count,
            "verifier_cpuset": benchmark_config["verifier_cpuset"],
        },
        "provenance": provenance,
        "micro_gates": dict(sorted(micro_gates.items())),
        "cold_single_policy": {
            "surface": "public_single_verify",
            "candidate": single_candidate,
            "baseline": "public_stdlib",
            "minimum_gain": 0.10,
            "passed": r43_policy_passed,
            "rows": r43_policy_rows,
            "r51_can_substitute": False,
        },
        "r51_n1_informational": {
            "surface": "private_batch_pipeline_n1",
            "selected_observation": {
                "path": r51_informational.path,
                "radix_a": r51_informational.radix,
                "fixed_b": r51_informational.fixed_base,
                "label": r51_informational.label,
            },
            "rows": r51_informational_rows,
            "promotion_effect": "none",
        },
        "ordinary_batch_policy": {
            "surface": "private_r51_batch_pipeline",
            "selected": {
                "path": selected_worker.path,
                "radix_a": selected_worker.radix,
                "fixed_b": selected_worker.fixed_base,
                "label": selected_worker.label,
            },
            "serial_minimum_gain": 0.15,
            "worker_minimum_gain": 0.15,
            "rows_serial": ordinary_serial_rows,
            "rows_worker": ordinary_worker_rows,
        },
        "heea_policy": {
            "optional": True,
            "selected_path": selected_heea_path,
            "admitted": selected_heea_path is not None,
            "minimum_gain": HEEA_GAIN,
            "fallback_regression_limit": HEEA_FALLBACK_REGRESSION_LIMIT,
            "path_reasons": dict(sorted(heea_reasons.items())),
        },
        "pending_production_blockers": pending_blockers,
    }
    validate_decision(decision)
    return EvaluationOutcome(mandatory_ok, decision)


def validate_decision(decision: Mapping[str, Any]) -> None:
    if decision.get("schema_version") != DECISION_SCHEMA_VERSION:
        raise GateError("decision has an invalid schema version")
    if decision.get("artifact_kind") != DECISION_KIND:
        raise GateError("decision has an invalid artifact kind")
    if decision.get("scope") != "zen4_microbenchmark_only":
        raise GateError("decision has an invalid authority scope")
    if decision.get("production_promotable") is not False:
        raise GateError(
            "microbenchmark evaluator must never emit production_promotable=true"
        )
    micro_gates = decision.get("micro_gates")
    if not isinstance(micro_gates, dict) or not micro_gates:
        raise GateError("decision lacks micro-gate results")
    if any(type(value) is not bool for value in micro_gates.values()):
        raise GateError("decision has a non-boolean micro-gate result")
    if decision.get("microbenchmark_gate_passed") is not all(
        micro_gates.values()
    ):
        raise GateError("decision aggregate does not match its micro-gate results")

    single = decision.get("cold_single_policy")
    if not isinstance(single, dict):
        raise GateError("decision lacks the cold-single policy")
    if (
        single.get("surface") != "public_single_verify"
        or single.get("candidate") != "r43"
        or single.get("baseline") != "public_stdlib"
        or single.get("r51_can_substitute") is not False
    ):
        raise GateError("decision has an incoherent cold-single policy")
    r51_n1 = decision.get("r51_n1_informational")
    if not isinstance(r51_n1, dict) or r51_n1.get("promotion_effect") != "none":
        raise GateError("decision lets r51 n=1 evidence affect promotion")

    ordinary = decision.get("ordinary_batch_policy")
    if not isinstance(ordinary, dict) or not isinstance(
        ordinary.get("selected"), dict
    ):
        raise GateError("decision lacks a selected ordinary batch configuration")
    heea = decision.get("heea_policy")
    if not isinstance(heea, dict) or heea.get("optional") is not True:
        raise GateError("decision has an invalid HEEA policy")

    provenance = decision.get("provenance")
    if not isinstance(provenance, dict):
        raise GateError("decision lacks provenance")
    benchmark_config = provenance.get("benchmark_config")
    source_manifest = provenance.get("source_manifest")
    if not isinstance(benchmark_config, dict) or re.fullmatch(
        r"[0-9a-f]{64}", str(benchmark_config.get("file_sha256", ""))
    ) is None:
        raise GateError("decision lacks benchmark-config provenance")
    if not isinstance(source_manifest, dict) or re.fullmatch(
        r"[0-9a-f]{64}", str(source_manifest.get("source_tree_sha256", ""))
    ) is None:
        raise GateError("decision lacks source-manifest provenance")
    if re.fullmatch(
        r"[0-9a-f]{40}", str(provenance.get("recorded_git_head", ""))
    ) is None:
        raise GateError("decision lacks recorded Git HEAD provenance")
    evidence = provenance.get("evidence_file_sha256")
    if not isinstance(evidence, dict) or set(evidence) != set(
        DECISION_EVIDENCE_FILES
    ) or any(
        re.fullmatch(r"[0-9a-f]{64}", str(digest)) is None
        for digest in evidence.values()
    ):
        raise GateError("decision lacks a complete benchmark evidence binding")
    if (
        benchmark_config.get("file_sha256")
        != evidence["benchmark-config.txt"]
        or source_manifest.get("file_sha256")
        != evidence["source-manifest-start.tsv"]
    ):
        raise GateError("decision provenance digests are internally inconsistent")

    blockers = decision.get("pending_production_blockers")
    if not isinstance(blockers, list):
        raise GateError("decision lacks pending production blockers")
    blocker_ids = {
        blocker.get("id")
        for blocker in blockers
        if isinstance(blocker, dict) and blocker.get("status") == "pending"
    }
    if blocker_ids != set(PENDING_PRODUCTION_BLOCKERS):
        raise GateError("decision does not preserve every production blocker")
    try:
        json.dumps(decision, allow_nan=False)
    except (TypeError, ValueError) as error:
        raise GateError(f"decision is not strict JSON: {error}") from error


def write_decision(
    result_dir: Path, requested_output: Path, decision: Mapping[str, Any]
) -> Path:
    """Write one new decision artifact inside its evidence bundle.

    The exclusive create prevents an old or partially unrelated decision from
    being silently overwritten.  Restricting the output to a direct child of
    the result directory keeps the provenance and its decision co-located.
    """
    validate_decision(decision)
    try:
        canonical_result = result_dir.resolve(strict=True)
        output = (
            requested_output
            if requested_output.is_absolute()
            else canonical_result / requested_output
        )
        parent = output.parent.resolve(strict=True)
    except (OSError, ValueError) as error:
        raise GateError(f"invalid decision output path: {error}") from error
    if parent != canonical_result or output.name in ("", ".", ".."):
        raise GateError(
            "decision output must be a new direct child of the result directory"
        )
    require_evidence_unchanged(canonical_result, decision["provenance"])
    if output.exists() or output.is_symlink():
        raise GateError(f"decision output already exists: {output}")
    try:
        payload = (
            json.dumps(
                decision,
                sort_keys=True,
                indent=2,
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise GateError(f"decision is not strict JSON: {error}") from error

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        descriptor = os.open(output, flags, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short decision write")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
    except (OSError, ValueError) as error:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        try:
            output.unlink()
        except OSError:
            pass
        raise GateError(f"cannot write decision output {output}: {error}") from error
    return output


def make_stats(
    nanoseconds: float,
    allocations: float = 0.0,
    bytes_per_op: float = 0.0,
) -> Stats:
    return Stats(nanoseconds, bytes_per_op, allocations)


def assert_gate_error(function, fragment: str) -> None:
    try:
        function()
    except GateError as error:
        assert fragment in str(error), error
    else:
        raise AssertionError(f"expected GateError containing {fragment!r}")


def self_test() -> None:
    parsed = parse_lines(
        [
            "BenchmarkA/path=x-16  10  100.0 ns/op  0 B/op  0 allocs/op",
            "BenchmarkA/path=x-16  10  80.0 ns/op  2 B/op  1 allocs/op",
            "not a benchmark row",
        ]
    )
    summary = stats(parsed, "BenchmarkA/path=x", expected_samples=2)
    assert summary == Stats(90.0, 2.0, 1.0)
    assert abs(improvement(100.0, 85.0) - 0.15) < EPSILON

    # Relative percentages from unlike harnesses must never cross-rank the
    # single-call implementation.  The public r43 path (100 -> 80) is the
    # coherent cold-single candidate even though an unrelated private r51
    # batch harness reports the numerically larger 200 -> 150 percentage.
    adversarial_public = {
        message: make_stats(100.0) for message in MESSAGES
    }
    adversarial_r43 = {
        message: make_stats(80.0) for message in MESSAGES
    }
    adversarial_r51_baseline = {
        message: make_stats(200.0) for message in MESSAGES
    }
    adversarial_r51 = {
        message: make_stats(150.0) for message in MESSAGES
    }
    single_candidate, r43_passed, r43_rows = select_cold_single_candidate(
        adversarial_public, adversarial_r43
    )
    assert single_candidate == "r43"
    assert r43_passed
    assert all(row["passed"] for row in r43_rows)
    assert min(
        improvement(
            adversarial_r51_baseline[message].nanoseconds,
            adversarial_r51[message].nanoseconds,
        )
        for message in MESSAGES
    ) > min(float(row["gain"]) for row in r43_rows)

    # The unaffected-path threshold admits exactly a 1% slowdown, rejects a
    # 1.01% slowdown, and rejects any allocation increase independently of
    # timing. This guards the sign convention in the release comparison.
    assert unaffected_path_passes(make_stats(100.0), make_stats(101.0))
    assert not unaffected_path_passes(make_stats(100.0), make_stats(101.01))
    assert not unaffected_path_passes(
        make_stats(100.0), make_stats(90.0, allocations=1.0)
    )
    assert not unaffected_path_passes(
        make_stats(100.0), make_stats(90.0, bytes_per_op=1.0)
    )
    assert unaffected_name(1, 64).endswith("shape=single/n=1/msg=64")
    assert unaffected_name(8, 1232).endswith("shape=batch/n=8/msg=1232")
    with tempfile.TemporaryDirectory() as directory:
        source = Path(directory) / "unaffected-compat-source.txt"
        source.write_text(
            "baseline_revision=wrong\n"
            "current_head=" + "a" * 40 + "\n"
            "harness_blob=" + "b" * 40 + "\n",
            encoding="utf-8",
        )
        assert_gate_error(
            lambda: require_unaffected_source(Path(directory)),
            "baseline revision",
        )
        source.write_text(
            f"baseline_revision={UNAFFECTED_BASELINE_REVISION}\n"
            "current_head=" + "a" * 40 + "\n"
            "harness_blob=" + "b" * 40 + "\n",
            encoding="utf-8",
        )
        require_unaffected_source(Path(directory))

    with tempfile.TemporaryDirectory() as directory:
        config = Path(directory) / "benchmark-config.txt"
        config.write_text("verifier_workers=2\n", encoding="utf-8")
        assert_gate_error(
            lambda: read_worker_count(Path(directory)),
            "lacks required provenance keys",
        )
        config.write_text(
            "cpu_model=AMD Ryzen 7 PRO 8700GE\n"
            "release_cpu_match=true\n"
            "non_release_cpu_override=0\n"
            "primitive_core=2\n"
            "online_cpus=16\n"
            "verifier_workers=1\n"
            "verifier_cpuset=0-7\n",
            encoding="utf-8",
        )
        assert_gate_error(
            lambda: read_worker_count(Path(directory)),
            "at least 2",
        )
        config.write_text(
            config.read_text(encoding="utf-8").replace(
                "verifier_workers=1", "verifier_workers=2"
            ),
            encoding="utf-8",
        )
        assert read_worker_count(Path(directory)) == 2
        config.write_text(
            config.read_text(encoding="utf-8")
            + "verifier_workers=2\n",
            encoding="utf-8",
        )
        assert_gate_error(
            lambda: read_worker_count(Path(directory)), "duplicate"
        )

    assert_gate_error(
        lambda: stats(parsed, "BenchmarkA/path=x", expected_samples=3),
        "expected exactly 3",
    )
    assert_gate_error(
        lambda: require_exact_rows(
            parsed, ["BenchmarkA/path=x", "BenchmarkB"], "fixture", 2
        ),
        "matrix mismatch",
    )
    unexpected = dict(parsed)
    unexpected["BenchmarkUnexpected"] = [Sample(1.0, 0.0, 0.0)] * 2
    assert_gate_error(
        lambda: require_exact_rows(
            unexpected, ["BenchmarkA/path=x"], "fixture", 2
        ),
        "unexpected=",
    )
    no_byte_column = parse_lines(
        ["BenchmarkNoBytes-16  10  1 ns/op  0 allocs/op"]
    )
    assert_gate_error(
        lambda: stats(no_byte_column, "BenchmarkNoBytes", 1),
        "lacks B/op",
    )
    no_alloc_column = parse_lines(
        ["BenchmarkNoAlloc-16  10  1 ns/op  0 B/op"]
    )
    assert_gate_error(
        lambda: stats(no_alloc_column, "BenchmarkNoAlloc", 1),
        "lacks allocs/op",
    )

    # A per-message oracle must not win. Radix 64 wins one row but loses the
    # release-matrix worst case, while coherent radix 32 remains realizable.
    matrix: dict[Configuration, dict[int, Stats]] = {}
    for configuration in ORDINARY_R51_CONFIGS:
        matrix[configuration] = {}
        for message in MESSAGES:
            value = 85.0 if configuration == Configuration("x8", 32, "shared") else 110.0
            if configuration == Configuration("x8", 64, "shared"):
                value = 70.0 if message == 64 else 105.0
            matrix[configuration][message] = make_stats(value)
    baselines = {message: make_stats(100.0) for message in MESSAGES}
    admitted, _ = admit_complete_variants(matrix, baselines)
    selected = choose_against_baseline(admitted, baselines)
    assert selected == Configuration("x8", 32, "shared")

    # Optional variants need the full 2% complete-path gain at every release
    # size.  A 1.99% row rejects the variant; exactly 2% admits it.
    optional = Configuration("x8", 64, "shared")
    proper = optional.proper_baseline
    threshold_matrix = {
        configuration: {message: make_stats(120.0) for message in MESSAGES}
        for configuration in ORDINARY_R51_CONFIGS
    }
    threshold_matrix[proper] = {
        message: make_stats(100.0) for message in MESSAGES
    }
    threshold_matrix[Configuration("two-x4", 32, "shared")] = {
        message: make_stats(100.0) for message in MESSAGES
    }
    threshold_matrix[optional] = {
        64: make_stats(98.0),
        200: make_stats(98.0),
        1232: make_stats(98.01),
    }
    admitted, reasons = admit_complete_variants(threshold_matrix, baselines)
    assert optional not in admitted
    assert "< 2%" in reasons[optional]
    threshold_matrix[optional][1232] = make_stats(98.0)
    admitted, _ = admit_complete_variants(threshold_matrix, baselines)
    assert optional in admitted

    # Any allocation increase rejects an otherwise fast optional variant.
    threshold_matrix[optional][200] = make_stats(80.0, allocations=1.0)
    admitted, reasons = admit_complete_variants(threshold_matrix, baselines)
    assert optional not in admitted
    assert reasons[optional] == "allocation increase"
    threshold_matrix[optional][200] = make_stats(
        80.0, bytes_per_op=1.0
    )
    admitted, reasons = admit_complete_variants(threshold_matrix, baselines)
    assert optional not in admitted
    assert reasons[optional] == "allocation increase"

    # A sub-2% two-x4 lead is a tie in favor of x8; a material lead remains.
    two = Configuration("two-x4", 32, "shared")
    x8 = Configuration("x8", 32, "shared")
    tie_candidates = {
        two: {64: make_stats(100.0), 200: make_stats(100.0)},
        x8: {64: make_stats(101.0), 200: make_stats(101.99)},
    }
    assert prefer_simple_x8(two, tie_candidates) == x8
    tie_candidates[x8][200] = make_stats(102.01)
    assert prefer_simple_x8(two, tie_candidates) == two

    # Worker selection is one actual configuration across every count/message,
    # not a per-row oracle.
    worker_fixture = {
        configuration: {
            (count, message): make_stats(
                90.0
                if configuration == x8
                else (70.0 if count == 8 else 130.0)
            )
            for count in RELEASE_BATCH_COUNTS
            for message in MESSAGES
        }
        for configuration in (two, x8)
    }
    assert choose_minimax(worker_fixture) == x8

    worker_workloads = {
        (count, message)
        for count in RELEASE_BATCH_COUNTS
        for message in MESSAGES
    }
    concurrent_stdlib = {
        workload: make_stats(100.0) for workload in worker_workloads
    }
    identical_serial = {
        workload: make_stats(90.0) for workload in worker_workloads
    }
    exact_worker_limit = {
        workload: make_stats(85.0) for workload in worker_workloads
    }
    assert production_worker_candidate_passes(
        concurrent_stdlib, identical_serial, exact_worker_limit
    )
    too_slow_for_stdlib = dict(exact_worker_limit)
    too_slow_for_stdlib[(8, 64)] = make_stats(85.01)
    assert not production_worker_candidate_passes(
        concurrent_stdlib, identical_serial, too_slow_for_stdlib
    )
    regression_stdlib = {
        workload: make_stats(120.0) for workload in worker_workloads
    }
    regression_serial = {
        workload: make_stats(100.0) for workload in worker_workloads
    }
    exact_regression_limit = {
        workload: make_stats(101.0) for workload in worker_workloads
    }
    assert production_worker_candidate_passes(
        regression_stdlib, regression_serial, exact_regression_limit
    )
    too_slow_for_serial = dict(exact_regression_limit)
    too_slow_for_serial[(8, 64)] = make_stats(101.01)
    assert not production_worker_candidate_passes(
        regression_stdlib, regression_serial, too_slow_for_serial
    )
    worker_bytes_increase = dict(exact_worker_limit)
    worker_bytes_increase[(8, 64)] = make_stats(
        90.0, bytes_per_op=1.0
    )
    assert not production_worker_candidate_passes(
        concurrent_stdlib, identical_serial, worker_bytes_increase
    )

    # A coherent worker winner is still ineligible if that exact serial
    # configuration misses one n=8/64 release row.
    serial_matrices = {
        count: {
            configuration: {
                message: make_stats(80.0) for message in MESSAGES
            }
            for configuration in ORDINARY_R51_CONFIGS
        }
        for count in RELEASE_BATCH_COUNTS
    }
    serial_baselines = {
        count: {message: make_stats(100.0) for message in MESSAGES}
        for count in RELEASE_BATCH_COUNTS
    }
    serial_admitted = {
        count: {
            configuration: serial_matrices[count][configuration]
            for configuration in ORDINARY_R51_CONFIGS
        }
        for count in RELEASE_BATCH_COUNTS
    }
    serial_matrices[64][x8][1232] = make_stats(86.0)
    eligible = serial_worker_eligible_configurations(
        serial_matrices, serial_baselines, serial_admitted
    )
    assert x8 not in eligible
    assert two in eligible

    heea_workloads = {
        (count, message)
        for count in RELEASE_BATCH_COUNTS
        for message in MESSAGES
    }

    def heea_paths(
        two_value: float, x8_value: float
    ) -> dict[str, dict[tuple[int, int], Stats]]:
        return {
            "two-x4": {
                workload: make_stats(two_value) for workload in heea_workloads
            },
            "x8": {
                workload: make_stats(x8_value) for workload in heea_workloads
            },
        }

    def heea_fallback_paths(
        two_value: float, x8_value: float
    ) -> dict[str, dict[tuple[int, str], Stats]]:
        return {
            "two-x4": {
                (message, pattern): make_stats(two_value)
                for message in MESSAGES
                for pattern in HEEA_FALLBACK_PATTERNS
            },
            "x8": {
                (message, pattern): make_stats(x8_value)
                for message in MESSAGES
                for pattern in HEEA_FALLBACK_PATTERNS
            },
        }

    fallback_100 = heea_fallback_paths(100.0, 100.0)

    # A candidate that beats the old same-path radix-32 comparator must still
    # lose promotion when the actual ordinary winner (for example radix-64 or
    # a fixed-B comb) is faster. This is the regression the joint HEEA gate is
    # specifically meant to prevent.
    fixed_radix32 = {
        workload: make_stats(100.0) for workload in heea_workloads
    }
    selected_comb_winner = {
        workload: make_stats(80.0) for workload in heea_workloads
    }
    beats_only_radix32 = heea_paths(94.0, 94.0)
    assert all(
        improvement(
            fixed_radix32[workload].nanoseconds,
            beats_only_radix32["x8"][workload].nanoseconds,
        )
        >= HEEA_GAIN
        for workload in heea_workloads
    )
    heea_admitted, heea_reasons = admit_heea_paths(
        beats_only_radix32,
        beats_only_radix32,
        fallback_100,
        selected_comb_winner,
        selected_comb_winner,
    )
    assert not heea_admitted
    assert all("serial gain" in reason for reason in heea_reasons.values())

    # A serial-only HEEA win cannot stand in for a production-worker win.
    serial_heea_win = heea_paths(90.0, 90.0)
    worker_heea_loss = heea_paths(96.0, 96.0)
    ordinary_100 = {
        workload: make_stats(100.0) for workload in heea_workloads
    }
    heea_admitted, heea_reasons = admit_heea_paths(
        serial_heea_win,
        worker_heea_loss,
        fallback_100,
        ordinary_100,
        ordinary_100,
    )
    assert not heea_admitted
    assert all("worker gain" in reason for reason in heea_reasons.values())

    fully_qualified_heea = heea_paths(90.0, 90.0)
    heea_admitted, _ = admit_heea_paths(
        fully_qualified_heea,
        fully_qualified_heea,
        fallback_100,
        ordinary_100,
        ordinary_100,
    )
    assert set(heea_admitted) == set(PATHS)
    qualified_configs = {
        Configuration(path, 32, "shared"): values
        for path, values in heea_admitted.items()
    }
    qualified_baseline = {
        (matrix_name, count, message): make_stats(100.0)
        for matrix_name in ("serial", "worker")
        for count in RELEASE_BATCH_COUNTS
        for message in MESSAGES
    }
    assert choose_against_baseline(
        qualified_configs, qualified_baseline
    ).path == "x8"

    # Admission is path-coherent across both matrices, and an allocation in
    # either matrix rejects an otherwise qualifying path.
    coherent_serial = heea_paths(94.0, 90.0)
    coherent_workers = heea_paths(96.0, 90.0)
    coherent_workers["x8"][(64, 1232)] = make_stats(
        90.0, bytes_per_op=1.0
    )
    heea_admitted, heea_reasons = admit_heea_paths(
        coherent_serial,
        coherent_workers,
        fallback_100,
        ordinary_100,
        ordinary_100,
    )
    assert not heea_admitted
    assert "worker gain" in heea_reasons["two-x4"]
    assert "allocation increase" in heea_reasons["x8"]

    # Selector fallback is attacker-steerable. A hidden lane regression above
    # 5%, or any B/op/allocs/op increase, rejects an otherwise fully qualified
    # HEEA path. Exactly 5% is admitted.
    fallback_threshold = heea_fallback_paths(105.0, 105.0)
    heea_admitted, _ = admit_heea_paths(
        fully_qualified_heea,
        fully_qualified_heea,
        fallback_threshold,
        ordinary_100,
        ordinary_100,
    )
    assert set(heea_admitted) == set(PATHS)

    hidden_regression = heea_fallback_paths(105.0, 105.0)
    hidden_regression["x8"][(1232, "lane-7")] = make_stats(105.01)
    heea_admitted, heea_reasons = admit_heea_paths(
        fully_qualified_heea,
        fully_qualified_heea,
        hidden_regression,
        ordinary_100,
        ordinary_100,
    )
    assert "x8" not in heea_admitted
    assert "adversarial fallback change" in heea_reasons["x8"]

    fallback_allocation = heea_fallback_paths(100.0, 100.0)
    fallback_allocation["two-x4"][(64, "all")] = make_stats(
        100.0, allocations=1.0
    )
    heea_admitted, heea_reasons = admit_heea_paths(
        fully_qualified_heea,
        fully_qualified_heea,
        fallback_allocation,
        ordinary_100,
        ordinary_100,
    )
    assert "two-x4" not in heea_admitted
    assert "allocation increase" in heea_reasons["two-x4"]

    # Source manifests are structural provenance, not an unchecked string.
    with tempfile.TemporaryDirectory() as directory:
        result_dir = Path(directory)
        manifest = result_dir / "source-manifest-start.tsv"
        fixture_tree_digest = source_tree_digest(
            [(b"go.mod", "file", 0o644, 1, "b" * 64)]
        )
        manifest.write_text(
            "source_tree_sha256=" + fixture_tree_digest + "\n"
            "source_entry_count=1\n"
            "path_json\ttype\tmode_octal\tsize_bytes\tcontent_sha256\n"
            '"go.mod"\tfile\t644\t1\t' + "b" * 64 + "\n",
            encoding="utf-8",
        )
        source = read_source_manifest(result_dir)
        assert source["source_tree_sha256"] == fixture_tree_digest
        assert source["source_entry_count"] == 1
        manifest.write_text(
            manifest.read_text(encoding="utf-8").replace(
                "source_entry_count=1", "source_entry_count=2"
            ),
            encoding="utf-8",
        )
        assert_gate_error(
            lambda: read_source_manifest(result_dir), "entry count"
        )

    def decision_fixture() -> dict[str, Any]:
        empty_digest = hashlib.sha256(b"").hexdigest()
        return {
            "schema_version": DECISION_SCHEMA_VERSION,
            "artifact_kind": DECISION_KIND,
            "scope": "zen4_microbenchmark_only",
            "production_promotable": False,
            "microbenchmark_gate_passed": True,
            "measurement_authority": {
                "hardware_authoritative": True,
            },
            "provenance": {
                "benchmark_config": {"file_sha256": empty_digest},
                "source_manifest": {
                    "file_sha256": empty_digest,
                    "source_tree_sha256": "b" * 64,
                },
                "recorded_git_head": "c" * 40,
                "evidence_file_sha256": {
                    name: empty_digest
                    for name in DECISION_EVIDENCE_FILES
                },
            },
            "micro_gates": {"fixture": True},
            "cold_single_policy": {
                "surface": "public_single_verify",
                "candidate": "r43",
                "baseline": "public_stdlib",
                "r51_can_substitute": False,
            },
            "r51_n1_informational": {"promotion_effect": "none"},
            "ordinary_batch_policy": {"selected": {"path": "x8"}},
            "heea_policy": {"optional": True},
            "pending_production_blockers": [
                {"id": blocker, "status": "pending"}
                for blocker in PENDING_PRODUCTION_BLOCKERS
            ],
        }

    valid_decision = decision_fixture()
    validate_decision(valid_decision)
    unsafe_decision = decision_fixture()
    unsafe_decision["production_promotable"] = True
    assert_gate_error(
        lambda: validate_decision(unsafe_decision),
        "must never emit production_promotable=true",
    )
    incomplete_decision = decision_fixture()
    incomplete_decision["pending_production_blockers"] = (
        incomplete_decision["pending_production_blockers"][:-1]
    )
    assert_gate_error(
        lambda: validate_decision(incomplete_decision),
        "preserve every production blocker",
    )
    cross_rank_decision = decision_fixture()
    cross_rank_decision["cold_single_policy"]["r51_can_substitute"] = True
    assert_gate_error(
        lambda: validate_decision(cross_rank_decision),
        "incoherent cold-single policy",
    )

    with tempfile.TemporaryDirectory() as directory:
        result_dir = Path(directory)
        for name in DECISION_EVIDENCE_FILES:
            (result_dir / name).write_bytes(b"")
        output = write_decision(
            result_dir, Path("decision-v1.json"), valid_decision
        )
        decoded = json.loads(output.read_text(encoding="utf-8"))
        assert decoded["production_promotable"] is False
        assert output.stat().st_mode & 0o777 == 0o600
        assert_gate_error(
            lambda: write_decision(
                result_dir, Path("decision-v1.json"), valid_decision
            ),
            "already exists",
        )
        assert_gate_error(
            lambda: write_decision(
                result_dir, Path("../outside.json"), valid_decision
            ),
            "direct child",
        )
        assert_gate_error(
            lambda: write_decision(
                result_dir, Path("missing/decision.json"), valid_decision
            ),
            "invalid decision output path",
        )

    print("zen4-evaluate: self-test passed")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate the numerical Zen 4 microbenchmark gate"
    )
    parser.add_argument("result_dir", nargs="?")
    parser.add_argument(
        "--decision-output",
        help=(
            "write a new versioned JSON decision as a direct child of "
            "RESULT_DIR; a relative filename is resolved inside RESULT_DIR"
        ),
    )
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        if args.self_test:
            if args.result_dir is not None or args.decision_output is not None:
                parser.error("--self-test cannot be combined with result arguments")
            self_test()
            return 0
        if args.result_dir is None:
            parser.error("RESULT_DIR is required unless --self-test is used")
        result_dir = Path(args.result_dir)
        outcome = evaluate(result_dir)
        if args.decision_output is not None:
            write_decision(
                result_dir,
                Path(args.decision_output),
                outcome.decision,
            )
        return 0 if outcome.mandatory_micro_gates_passed else 1
    except GateError as error:
        print(f"zen4-evaluate: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
