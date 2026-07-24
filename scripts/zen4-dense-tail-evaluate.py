#!/usr/bin/env python3
"""Evaluate the post-shortlist r51 dense-tail benchmark.

The driver records one stdlib and one selected-candidate observation in each
of ten alternating rounds.  This evaluator keeps those observations paired,
rejects incomplete or over-broad output, and uses a deterministic paired
bootstrap (plus a conservative distribution-free median bound) instead of
promoting point medians.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import math
import random
import re
import statistics
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence


TAIL_SELECTION_SCHEMA = "narya.zen4.r51-tail-selection.v1"
RELEASE_DECISION_SCHEMAS = {
    "narya.zen4.release-decision.v1",
    "narya.zen4.micro-gate-decision.v1",
}
MICRO_DECISION_SCHEMA_VERSION = 1
MICRO_DECISION_KIND = "narya.zen4.microbenchmark-decision"
TAIL_DECISION_SCHEMA = "narya.zen4.r51-dense-tail-decision.v1"
SAMPLE_SCHEMA = "narya_dense_tail_sample_v1"
ROUNDS = 10
BOOTSTRAP_REPLICATES = 100_000
BOOTSTRAP_ALPHA = 0.05
MESSAGES = (64, 200, 1232)
COUNTS = tuple(range(1, 18)) + (32, 64)
RELEASE_COUNTS = (8, 64)
RELEASE_GAIN = 0.15
EPSILON = 1e-12

NUMBER = r"[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?"
ROW = re.compile(
    rf"^(Benchmark\S+)\s+\d+\s+({NUMBER})\s+ns/op(?P<metrics>.*)$"
)
BYTES = re.compile(rf"(?:^|\s)({NUMBER})\s+B/op(?:\s|$)")
ALLOCS = re.compile(rf"(?:^|\s)({NUMBER})\s+allocs/op(?:\s|$)")
CPU_SUFFIX = re.compile(r"-\d+$")
HEADER = re.compile(
    rf"^# {SAMPLE_SCHEMA} role=(baseline|candidate) round=([0-9]+) "
    r"sequence=([0-9]+) order=(baseline-candidate|candidate-baseline) "
    r"config=(\S+)$"
)


class GateError(RuntimeError):
    pass


@dataclass(frozen=True, order=True)
class Configuration:
    path: str
    radix_a: int
    fixed_b: str

    @property
    def label(self) -> str:
        return (
            f"path={self.path}/radixA={self.radix_a}/fixedB={self.fixed_b}"
        )

    def candidate_name(self, count: int, message: int) -> str:
        return (
            "BenchmarkR51IFMAPipeline/stage=cold-A/"
            f"{self.label}/n={count}/msg={message}"
        )

    @staticmethod
    def baseline_name(count: int, message: int) -> str:
        return (
            "BenchmarkR51IFMAPipeline/stage=cold-A/path=stdlib/"
            f"n={count}/msg={message}"
        )


@dataclass(frozen=True)
class Sample:
    nanoseconds: float
    bytes_per_op: float
    allocations: float


@dataclass(frozen=True)
class Confidence:
    point_median_gain: float
    bootstrap_lower_95_gain: float
    distribution_free_lower_gain: float
    admitted_lower_gain: float


def validate_configuration(config: Configuration) -> Configuration:
    if config.path not in {"two-x4", "x8"}:
        raise GateError("selected path must be two-x4 or x8")
    if config.fixed_b == "shared":
        if config.radix_a not in {16, 32, 64}:
            raise GateError("shared fixed-B requires radix_a 16, 32, or 64")
    elif config.fixed_b in {"comb16", "comb32", "comb256"}:
        if config.radix_a != 32:
            raise GateError("comb fixed-B candidates require radix_a 32")
    else:
        raise GateError("selected fixed_b must be shared, comb16, comb32, or comb256")
    return config


def config_from_object(value: Any, allow_label: bool = False) -> Configuration:
    if not isinstance(value, Mapping):
        raise GateError("selected configuration must be a JSON object")
    expected = {"path", "radix_a", "fixed_b"}
    allowed = expected | ({"label"} if allow_label else set())
    if set(value) - allowed or not expected.issubset(value):
        raise GateError(
            "selected configuration must contain exactly path, radix_a, fixed_b"
            + (" and an optional matching label" if allow_label else "")
        )
    path = value["path"]
    radix = value["radix_a"]
    fixed = value["fixed_b"]
    if not isinstance(path, str) or not isinstance(fixed, str):
        raise GateError("selected path and fixed_b must be strings")
    if isinstance(radix, bool) or not isinstance(radix, int):
        raise GateError("selected radix_a must be an integer")
    config = validate_configuration(Configuration(path, radix, fixed))
    if "label" in value and value["label"] != config.label:
        raise GateError("selected configuration label does not match its fields")
    return config


def config_object(config: Configuration) -> dict[str, Any]:
    return {
        "path": config.path,
        "radix_a": config.radix_a,
        "fixed_b": config.fixed_b,
        "label": config.label,
    }


def load_selection_document(path: Path) -> tuple[Configuration, str]:
    try:
        raw = path.read_bytes()
        document = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise GateError(f"cannot read selection JSON {path}: {error}") from error
    if not isinstance(document, Mapping):
        raise GateError("selection JSON must contain an object")
    schema = document.get("schema")
    if schema == TAIL_SELECTION_SCHEMA:
        if set(document) - {"schema", "selected", "source"}:
            raise GateError("tail selection JSON contains unexpected top-level fields")
        selected = document.get("selected")
    elif schema in RELEASE_DECISION_SCHEMAS:
        ordinary = document.get("ordinary_batch")
        if not isinstance(ordinary, Mapping):
            raise GateError("release decision lacks ordinary_batch object")
        selected = ordinary.get("selected_configuration")
    elif (
        document.get("schema_version") == MICRO_DECISION_SCHEMA_VERSION
        and document.get("artifact_kind") == MICRO_DECISION_KIND
    ):
        if document.get("scope") != "zen4_microbenchmark_only":
            raise GateError("microbenchmark decision has unexpected authority scope")
        if document.get("microbenchmark_gate_passed") is not True:
            raise GateError("microbenchmark decision did not pass its prerequisite gates")
        ordinary = document.get("ordinary_batch_policy")
        if not isinstance(ordinary, Mapping):
            raise GateError("microbenchmark decision lacks ordinary_batch_policy")
        selected = ordinary.get("selected")
        return config_from_object(selected, allow_label=True), hashlib.sha256(raw).hexdigest()
    else:
        raise GateError(
            "selection JSON has unsupported or missing versioned schema; "
            f"expected {TAIL_SELECTION_SCHEMA!r} or one of "
            f"{sorted(RELEASE_DECISION_SCHEMAS)!r}"
        )
    return config_from_object(selected), hashlib.sha256(raw).hexdigest()


def write_json_exclusive(path: Path, value: Mapping[str, Any]) -> None:
    try:
        with path.open("x", encoding="utf-8") as output:
            json.dump(value, output, allow_nan=False, indent=2, sort_keys=True)
            output.write("\n")
    except FileExistsError as error:
        raise GateError(f"refusing to overwrite {path}") from error


def normalize_selection(args: argparse.Namespace) -> None:
    if args.selection_json:
        if any(value is not None for value in (args.path, args.radix_a, args.fixed_b)):
            raise GateError("do not combine --selection-json with explicit config flags")
        source_path = Path(args.selection_json).resolve()
        config, digest = load_selection_document(source_path)
        source: dict[str, Any] = {
            "kind": "versioned-json",
            "sha256": digest,
        }
    else:
        if any(value is None for value in (args.path, args.radix_a, args.fixed_b)):
            raise GateError(
                "provide --selection-json or all of --path, --radix-a, --fixed-b"
            )
        config = validate_configuration(
            Configuration(args.path, args.radix_a, args.fixed_b)
        )
        source = {"kind": "explicit-command-line"}
    document = {
        "schema": TAIL_SELECTION_SCHEMA,
        "selected": {
            "path": config.path,
            "radix_a": config.radix_a,
            "fixed_b": config.fixed_b,
        },
        "source": source,
    }
    write_json_exclusive(Path(args.output), document)


def expected_order(round_number: int) -> str:
    return "baseline-candidate" if round_number % 2 == 1 else "candidate-baseline"


def expected_sequence(round_number: int, role: str) -> int:
    first = "baseline" if round_number % 2 == 1 else "candidate"
    offset = 1 if role == first else 2
    return (round_number - 1) * 2 + offset


def parse_sample_file(
    path: Path,
    role: str,
    round_number: int,
    config: Configuration,
) -> dict[tuple[int, int], Sample]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise GateError(f"cannot read sample file {path}: {error}") from error
    if not lines:
        raise GateError(f"empty sample file: {path}")
    header = HEADER.fullmatch(lines[0])
    if header is None:
        raise GateError(f"invalid sample header: {path}")
    if header.group(1) != role or int(header.group(2)) != round_number:
        raise GateError(f"sample identity mismatch: {path}")
    if int(header.group(3)) != expected_sequence(round_number, role):
        raise GateError(f"sample sequence mismatch: {path}")
    if header.group(4) != expected_order(round_number):
        raise GateError(f"sample order mismatch: {path}")
    if header.group(5) != config.label:
        raise GateError(f"sample selected-config mismatch: {path}")

    expected_names = {
        (
            config.candidate_name(count, message)
            if role == "candidate"
            else config.baseline_name(count, message)
        ): (count, message)
        for count in COUNTS
        for message in MESSAGES
    }
    samples: dict[tuple[int, int], Sample] = {}
    observed_names: set[str] = set()
    for line in lines[1:]:
        match = ROW.fullmatch(line.strip())
        if match is None:
            continue
        name = CPU_SUFFIX.sub("", match.group(1))
        if name not in expected_names:
            raise GateError(f"unexpected benchmark row in {path}: {name}")
        if name in observed_names:
            raise GateError(f"duplicate benchmark row in {path}: {name}")
        byte_match = BYTES.search(match.group("metrics"))
        allocation_match = ALLOCS.search(match.group("metrics"))
        if byte_match is None or allocation_match is None:
            raise GateError(f"benchmark row lacks B/op or allocs/op in {path}: {name}")
        sample = Sample(
            float(match.group(2)),
            float(byte_match.group(1)),
            float(allocation_match.group(1)),
        )
        if not all(
            math.isfinite(value) and value >= 0
            for value in (
                sample.nanoseconds,
                sample.bytes_per_op,
                sample.allocations,
            )
        ) or sample.nanoseconds == 0:
            raise GateError(f"invalid benchmark metric in {path}: {name}")
        observed_names.add(name)
        samples[expected_names[name]] = sample
    missing = sorted(set(expected_names) - observed_names)
    if missing:
        raise GateError(f"missing benchmark rows in {path}: {missing[:3]}")
    return samples


def quantile(values: list[float], probability: float) -> float:
    if not values:
        raise GateError("cannot take quantile of empty data")
    values.sort()
    index = max(0, min(len(values) - 1, math.ceil(probability * len(values)) - 1))
    return values[index]


def confidence_for_pairs(
    baseline: Sequence[Sample],
    candidate: Sequence[Sample],
    seed_label: str,
    replicates: int = BOOTSTRAP_REPLICATES,
) -> Confidence:
    if len(baseline) != ROUNDS or len(candidate) != ROUNDS:
        raise GateError(f"paired confidence requires exactly {ROUNDS} rounds")
    if replicates < 1:
        raise GateError("bootstrap replicate count must be positive")
    gains = [
        1.0 - candidate[index].nanoseconds / baseline[index].nanoseconds
        for index in range(ROUNDS)
    ]
    point = statistics.median(gains)
    seed = int.from_bytes(hashlib.sha256(seed_label.encode("ascii")).digest()[:8], "big")
    generator = random.Random(seed)
    bootstrapped: list[float] = []
    for _ in range(replicates):
        bootstrapped.append(
            statistics.median(gains[generator.randrange(ROUNDS)] for _ in range(ROUNDS))
        )
    bootstrap_lower = quantile(bootstrapped, BOOTSTRAP_ALPHA)
    # For ten independent paired observations, the second order statistic is
    # a conservative one-sided lower confidence bound for the population
    # median (coverage 1 - 11/1024 = 98.925%).  Gate on the more conservative
    # of this distribution-free bound and the requested paired bootstrap.
    distribution_free = sorted(gains)[1]
    return Confidence(
        point,
        bootstrap_lower,
        distribution_free,
        min(bootstrap_lower, distribution_free),
    )


def assess(
    config: Configuration,
    baselines: Mapping[tuple[int, int], Sequence[Sample]],
    candidates: Mapping[tuple[int, int], Sequence[Sample]],
    replicates: int = BOOTSTRAP_REPLICATES,
) -> tuple[bool, list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    results: list[dict[str, Any]] = []
    by_count: dict[int, list[dict[str, Any]]] = {count: [] for count in COUNTS}
    failures: list[str] = []
    expected = {(count, message) for count in COUNTS for message in MESSAGES}
    if set(baselines) != expected or set(candidates) != expected:
        raise GateError("in-memory workload set is incomplete or unexpected")
    for count in COUNTS:
        for message in MESSAGES:
            workload = (count, message)
            baseline = list(baselines[workload])
            candidate = list(candidates[workload])
            confidence = confidence_for_pairs(
                baseline,
                candidate,
                f"{config.label}/n={count}/msg={message}",
                replicates,
            )
            memory_ok = all(
                candidate[index].bytes_per_op
                <= baseline[index].bytes_per_op + EPSILON
                and candidate[index].allocations
                <= baseline[index].allocations + EPSILON
                for index in range(ROUNDS)
            )
            workload_result = {
                "n": count,
                "message_bytes": message,
                "mandatory_r51_gain": RELEASE_GAIN if count in RELEASE_COUNTS else None,
                "point_median_gain": confidence.point_median_gain,
                "bootstrap_lower_95_gain": confidence.bootstrap_lower_95_gain,
                "distribution_free_lower_gain": confidence.distribution_free_lower_gain,
                "admitted_lower_gain": confidence.admitted_lower_gain,
                "baseline_median_ns_per_signature": statistics.median(
                    sample.nanoseconds / count for sample in baseline
                ),
                "candidate_median_ns_per_signature": statistics.median(
                    sample.nanoseconds / count for sample in candidate
                ),
                "memory_nonincrease": memory_ok,
            }
            results.append(workload_result)
            by_count[count].append(workload_result)

    recommendations: list[dict[str, Any]] = []
    for count in COUNTS:
        count_results = by_count[count]
        minimum_lower_gain = min(
            float(result["admitted_lower_gain"]) for result in count_results
        )
        memory_ok = all(bool(result["memory_nonincrease"]) for result in count_results)
        if count in RELEASE_COUNTS:
            admitted = minimum_lower_gain + EPSILON >= RELEASE_GAIN and memory_ok
            choice = "selected-r51" if admitted else "unadmitted"
            if minimum_lower_gain + EPSILON < RELEASE_GAIN:
                failures.append(
                    f"n={count}: minimum lower confidence gain "
                    f"{minimum_lower_gain:.6f} < mandatory {RELEASE_GAIN:.6f}"
                )
            if not memory_ok:
                failures.append(f"n={count}: selected r51 increases B/op or allocs/op")
            reason = (
                "mandatory r51 release width meets confidence and memory gates"
                if admitted
                else "mandatory r51 release width failed confidence or memory gate"
            )
        else:
            # Sparse/tail widths are dispatch-policy evidence, not a reason to
            # reject a batch backend that wins at its production widths.  Only
            # choose r51 when every release message size has a strictly
            # positive conservative lower confidence bound and no memory
            # increase; otherwise preserve the measured stdlib fallback.
            admitted = minimum_lower_gain > EPSILON and memory_ok
            choice = "selected-r51" if admitted else "stdlib-fallback"
            reason = (
                "selected r51 is confidently faster for every message size"
                if admitted
                else "portable baseline retained because r51 lacks a safe all-message admission"
            )
        if choice == "selected-r51":
            threshold = RELEASE_GAIN if count in RELEASE_COUNTS else 0.0
            if minimum_lower_gain + EPSILON < threshold or not memory_ok:
                raise GateError(
                    f"internal unsafe r51 dispatch recommendation for n={count}"
                )
        for workload_result in count_results:
            workload_result["recommended_path_for_count"] = choice
        recommendations.append(
            {
                "n": count,
                "choice": choice,
                "minimum_admitted_lower_gain_across_messages": minimum_lower_gain,
                "memory_nonincrease_across_messages": memory_ok,
                "reason": reason,
            }
        )
    return not failures, results, recommendations, failures


def read_key_value(path: Path) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise GateError(f"cannot read provenance file {path}: {error}") from error
    result: dict[str, str] = {}
    for line in lines:
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise GateError(f"invalid provenance line in {path}: {line!r}")
        key, value = line.split("=", 1)
        if not key or key in result:
            raise GateError(f"duplicate/empty provenance key in {path}: {key!r}")
        result[key] = value
    return result


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
    except OSError as error:
        raise GateError(f"cannot hash evidence file {path}: {error}") from error
    return digest.hexdigest()


def source_manifest_digest(path: Path) -> str:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise GateError(f"cannot read source manifest {path}: {error}") from error
    matches = [
        line.split("=", 1)[1]
        for line in lines
        if line.startswith("source_tree_sha256=")
    ]
    digest = matches[0] if len(matches) == 1 else None
    if digest is None or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise GateError(f"invalid source manifest digest: {path}")
    return digest


def evaluate_result_dir(
    result_dir: Path,
    output: Path,
    replicates: int = BOOTSTRAP_REPLICATES,
) -> bool:
    if output.parent != result_dir or output.name in {"", ".", ".."}:
        raise GateError("decision output must be a new direct child of the result directory")
    selection_path = result_dir / "selection.normalized.json"
    config, selection_digest = load_selection_document(selection_path)
    expected_sample_files = {
        f"round-{round_number:02d}-{role}.txt"
        for round_number in range(1, ROUNDS + 1)
        for role in ("baseline", "candidate")
    }
    observed_sample_files = {path.name for path in result_dir.glob("round-*.txt")}
    if observed_sample_files != expected_sample_files:
        missing = sorted(expected_sample_files - observed_sample_files)
        unexpected = sorted(observed_sample_files - expected_sample_files)
        raise GateError(
            f"sample file set mismatch: missing={missing[:3]} unexpected={unexpected[:3]}"
        )
    baselines: dict[tuple[int, int], list[Sample]] = {
        workload: [] for workload in ((n, m) for n in COUNTS for m in MESSAGES)
    }
    candidates: dict[tuple[int, int], list[Sample]] = {
        workload: [] for workload in baselines
    }
    for round_number in range(1, ROUNDS + 1):
        for role, destination in (("baseline", baselines), ("candidate", candidates)):
            path = result_dir / f"round-{round_number:02d}-{role}.txt"
            samples = parse_sample_file(path, role, round_number, config)
            for workload, sample in samples.items():
                destination[workload].append(sample)

    passed, workloads, recommendations, failures = assess(
        config, baselines, candidates, replicates=replicates
    )
    config_values = read_key_value(result_dir / "benchmark-config.txt")
    required_config_keys = {
        "cpu_model",
        "release_cpu_match",
        "non_release_cpu_override",
        "primitive_core",
        "gomaxprocs",
        "rounds",
        "benchtime",
        "test_binary_sha256",
        "source_tree_sha256",
        "selection_sha256",
        "git_head",
        "go_version",
    }
    if set(config_values) != required_config_keys:
        raise GateError("benchmark-config fields are incomplete or unexpected")
    if config_values["rounds"] != str(ROUNDS) or config_values["benchtime"] != "3s":
        raise GateError("benchmark rounds/benchtime do not match the release protocol")
    if config_values["gomaxprocs"] != "1":
        raise GateError("dense-tail primitive gate requires GOMAXPROCS=1")
    if config_values["release_cpu_match"] not in {"true", "false"}:
        raise GateError("invalid release_cpu_match provenance")
    for key in ("test_binary_sha256", "source_tree_sha256", "selection_sha256"):
        if re.fullmatch(r"[0-9a-f]{64}", config_values[key]) is None:
            raise GateError(f"invalid {key} provenance")
    if re.fullmatch(r"[0-9a-f]{40,64}", config_values["git_head"]) is None:
        raise GateError("invalid git_head provenance")

    evidence_names = [
        "benchmark-config.txt",
        "benchmark-list.txt",
        "selection.normalized.json",
        "source-manifest-start.tsv",
        "source-manifest-built.tsv",
        "ed25519.test",
    ] + sorted(expected_sample_files)
    if (result_dir / "selection-input.json").is_file():
        evidence_names.append("selection-input.json")
    evidence_sha256 = {
        name: sha256_file(result_dir / name) for name in sorted(evidence_names)
    }
    if evidence_sha256["selection.normalized.json"] != config_values["selection_sha256"]:
        raise GateError("normalized selection digest does not match benchmark config")
    if evidence_sha256["ed25519.test"] != config_values["test_binary_sha256"]:
        raise GateError("test binary digest does not match benchmark config")
    start_manifest = result_dir / "source-manifest-start.tsv"
    built_manifest = result_dir / "source-manifest-built.tsv"
    if start_manifest.read_bytes() != built_manifest.read_bytes():
        raise GateError("source manifests differ between start and binary build")
    if source_manifest_digest(start_manifest) != config_values["source_tree_sha256"]:
        raise GateError("source tree digest does not match benchmark config")

    decision = {
        "schema": TAIL_DECISION_SCHEMA,
        "gate_pass": passed,
        "production_promotable": False,
        "production_promotable_reason": (
            "This artifact proves only the post-shortlist dense-tail gate; "
            "the complete Zen 4, trace/cache, and Mithril replay gates remain authoritative."
        ),
        "selected": config_object(config),
        "selection_document_sha256": selection_digest,
        "measurement": {
            **config_values,
            "paired_rounds": ROUNDS,
            "bootstrap_replicates": replicates,
            "bootstrap_one_sided_alpha": BOOTSTRAP_ALPHA,
            "distribution_free_bound": "second-order-statistic-of-10-paired-gains",
            "hardware_authoritative": config_values["release_cpu_match"] == "true",
        },
        "evidence_sha256": evidence_sha256,
        "requirements": {
            "n_8_and_64_lower_confidence_gain_at_least": RELEASE_GAIN,
            "other_width_policy": (
                "select r51 only when every message has lower-confidence gain > 0 "
                "and no per-round B/op or allocs/op increase; otherwise stdlib fallback"
            ),
            "selected_r51_b_per_op_no_increase_each_round": True,
            "selected_r51_allocs_per_op_no_increase_each_round": True,
        },
        "per_count_recommendations": recommendations,
        "workloads": workloads,
        "failures": failures,
    }
    write_json_exclusive(output, decision)
    if failures:
        for failure in failures:
            print(f"zen4-dense-tail-evaluate: {failure}", file=sys.stderr)
    return passed


def synthetic_samples(
    candidate_factor: Mapping[int, float] | None = None,
    candidate_bytes: float = 0.0,
    replicates_noise: bool = False,
) -> tuple[dict[tuple[int, int], list[Sample]], dict[tuple[int, int], list[Sample]]]:
    factors = candidate_factor or {}
    baselines: dict[tuple[int, int], list[Sample]] = {}
    candidates: dict[tuple[int, int], list[Sample]] = {}
    for count in COUNTS:
        for message in MESSAGES:
            base = 100_000.0 + count * 101.0 + message
            baseline = [Sample(base * (1.0 + round_number / 10_000), 0, 0) for round_number in range(ROUNDS)]
            factor = factors.get(count, 0.70)
            candidate = [
                Sample(
                    baseline[round_number].nanoseconds * factor,
                    candidate_bytes,
                    0,
                )
                for round_number in range(ROUNDS)
            ]
            if replicates_noise and count == 8:
                for index in (0, 1):
                    candidate[index] = Sample(
                        baseline[index].nanoseconds * 0.96,
                        candidate_bytes,
                        0,
                    )
            baselines[(count, message)] = baseline
            candidates[(count, message)] = candidate
    return baselines, candidates


def self_test() -> None:
    config = validate_configuration(Configuration("x8", 32, "shared"))
    baselines, candidates = synthetic_samples()
    passed, _, recommendations, failures = assess(
        config, baselines, candidates, replicates=2_000
    )
    assert passed and not failures
    assert all(item["choice"] == "selected-r51" for item in recommendations)

    # This is the regression the sparse 1/8/64 matrix could miss: it wins all
    # three sparse points but is catastrophically slow at a live tail width.
    baselines, candidates = synthetic_samples({1: 0.70, 8: 0.70, 10: 10.0, 64: 0.70})
    passed, _, recommendations, failures = assess(
        config, baselines, candidates, replicates=2_000
    )
    assert passed and not failures
    choices = {item["n"]: item["choice"] for item in recommendations}
    assert choices[1] == "selected-r51"
    assert choices[8] == "selected-r51"
    assert choices[10] == "stdlib-fallback"
    assert choices[64] == "selected-r51"

    baselines, candidates = synthetic_samples(candidate_bytes=1.0)
    passed, _, _, failures = assess(config, baselines, candidates, replicates=2_000)
    assert not passed and any("increases B/op or allocs/op" in item for item in failures)

    baselines, candidates = synthetic_samples(replicates_noise=True)
    passed, _, _, failures = assess(config, baselines, candidates, replicates=2_000)
    assert not passed
    assert any(item.startswith("n=8:") for item in failures)

    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        valid = root / "valid.json"
        valid.write_text(
            json.dumps(
                {
                    "schema": TAIL_SELECTION_SCHEMA,
                    "selected": {"path": "two-x4", "radix_a": 64, "fixed_b": "shared"},
                }
            ),
            encoding="utf-8",
        )
        selected, digest = load_selection_document(valid)
        assert selected == Configuration("two-x4", 64, "shared")
        assert len(digest) == 64
        invalid = root / "invalid.json"
        invalid.write_text(
            json.dumps(
                {
                    "selected": {"path": "x8", "radix_a": 32, "fixed_b": "shared"}
                }
            ),
            encoding="utf-8",
        )
        try:
            load_selection_document(invalid)
        except GateError:
            pass
        else:
            raise AssertionError("unversioned selection JSON was accepted")

        micro = root / "micro.json"
        micro.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "artifact_kind": MICRO_DECISION_KIND,
                    "scope": "zen4_microbenchmark_only",
                    "microbenchmark_gate_passed": True,
                    "ordinary_batch_policy": {
                        "selected": {
                            "path": "x8",
                            "radix_a": 32,
                            "fixed_b": "comb32",
                            "label": "path=x8/radixA=32/fixedB=comb32",
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        selected, _ = load_selection_document(micro)
        assert selected == Configuration("x8", 32, "comb32")
        output = root / "exclusive.json"
        write_json_exclusive(output, {"ok": True})
        try:
            write_json_exclusive(output, {"ok": False})
        except GateError:
            pass
        else:
            raise AssertionError("exclusive decision writer overwrote an artifact")

        sample_path = root / "sample.txt"
        sample_lines = [
            f"# {SAMPLE_SCHEMA} role=baseline round=1 "
            f"sequence=1 order=baseline-candidate config={config.label}"
        ]
        for count in COUNTS:
            for message in MESSAGES:
                sample_lines.append(
                    f"{config.baseline_name(count, message)}-16 100 1000 ns/op 0 B/op 0 allocs/op"
                )
        sample_path.write_text("\n".join(sample_lines) + "\n", encoding="utf-8")
        parsed = parse_sample_file(sample_path, "baseline", 1, config)
        assert len(parsed) == len(COUNTS) * len(MESSAGES)
        sample_path.write_text("\n".join(sample_lines[:-1]) + "\n", encoding="utf-8")
        try:
            parse_sample_file(sample_path, "baseline", 1, config)
        except GateError as error:
            assert "missing benchmark rows" in str(error)
        else:
            raise AssertionError("missing dense-tail row was accepted")
        mismatched = list(sample_lines)
        mismatched[0] = mismatched[0].replace("path=x8", "path=two-x4")
        sample_path.write_text("\n".join(mismatched) + "\n", encoding="utf-8")
        try:
            parse_sample_file(sample_path, "baseline", 1, config)
        except GateError as error:
            assert "selected-config mismatch" in str(error)
        else:
            raise AssertionError("mismatched selected config was accepted")
        unexpected = list(sample_lines)
        unexpected.append(
            "BenchmarkR51IFMAPipeline/stage=cold-A/path=generic-strict/n=1/msg=64-16 "
            "100 1000 ns/op 0 B/op 0 allocs/op"
        )
        sample_path.write_text("\n".join(unexpected) + "\n", encoding="utf-8")
        try:
            parse_sample_file(sample_path, "baseline", 1, config)
        except GateError as error:
            assert "unexpected benchmark row" in str(error)
        else:
            raise AssertionError("unexpected dense-tail row was accepted")

        bundle = root / "bundle"
        bundle.mkdir()
        normalized = bundle / "selection.normalized.json"
        normalized.write_text(
            json.dumps(
                {
                    "schema": TAIL_SELECTION_SCHEMA,
                    "selected": {
                        "path": config.path,
                        "radix_a": config.radix_a,
                        "fixed_b": config.fixed_b,
                    },
                    "source": {"kind": "self-test"},
                }
            ),
            encoding="utf-8",
        )
        selection_digest = sha256_file(normalized)
        binary = bundle / "ed25519.test"
        binary.write_bytes(b"self-test-binary")
        binary_digest = sha256_file(binary)
        source_digest = "b" * 64
        manifest = (
            f"source_tree_sha256={source_digest}\n"
            "source_entry_count=1\n"
            "path_json\ttype\tmode_octal\tsize_bytes\tcontent_sha256\n"
            f'"self-test"\tfile\t600\t1\t{"e" * 64}\n'
        )
        (bundle / "source-manifest-start.tsv").write_text(manifest, encoding="utf-8")
        (bundle / "source-manifest-built.tsv").write_text(manifest, encoding="utf-8")
        (bundle / "benchmark-list.txt").write_text(
            "BenchmarkR51IFMAPipeline\n", encoding="utf-8"
        )
        (bundle / "benchmark-config.txt").write_text(
            "\n".join(
                (
                    "cpu_model=self-test",
                    "release_cpu_match=true",
                    "non_release_cpu_override=0",
                    "primitive_core=2",
                    "gomaxprocs=1",
                    "rounds=10",
                    "benchtime=3s",
                    f"test_binary_sha256={binary_digest}",
                    f"source_tree_sha256={source_digest}",
                    f"selection_sha256={selection_digest}",
                    f"git_head={'d' * 40}",
                    "go_version=go version self-test",
                )
            )
            + "\n",
            encoding="utf-8",
        )
        for round_number in range(1, ROUNDS + 1):
            order = expected_order(round_number)
            for role, factor in (("baseline", 1.0), ("candidate", 0.70)):
                lines = [
                    f"# {SAMPLE_SCHEMA} role={role} round={round_number} "
                    f"sequence={expected_sequence(round_number, role)} "
                    f"order={order} config={config.label}"
                ]
                for count in COUNTS:
                    for message in MESSAGES:
                        name = (
                            config.baseline_name(count, message)
                            if role == "baseline"
                            else config.candidate_name(count, message)
                        )
                        lines.append(
                            f"{name}-16 100 {100000 * factor:.0f} ns/op "
                            "0 B/op 0 allocs/op"
                        )
                (bundle / f"round-{round_number:02d}-{role}.txt").write_text(
                    "\n".join(lines) + "\n", encoding="utf-8"
                )
        decision_path = bundle / "tail-decision.json"
        assert evaluate_result_dir(bundle, decision_path, replicates=2_000)
        end_to_end = json.loads(decision_path.read_text(encoding="utf-8"))
        assert end_to_end["gate_pass"] is True
        assert len(end_to_end["per_count_recommendations"]) == len(COUNTS)
        extra = bundle / "round-11-baseline.txt"
        extra.write_text("unexpected\n", encoding="utf-8")
        try:
            evaluate_result_dir(bundle, bundle / "second-decision.json", replicates=10)
        except GateError as error:
            assert "sample file set mismatch" in str(error)
        else:
            raise AssertionError("unexpected sample file was accepted")

    print("zen4-dense-tail-evaluate: self-test passed")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    subparsers = parser.add_subparsers(dest="command")

    selection = subparsers.add_parser("selection")
    selection.add_argument("--output", required=True)
    selection.add_argument("--selection-json")
    selection.add_argument("--path", choices=("two-x4", "x8"))
    selection.add_argument("--radix-a", type=int)
    selection.add_argument("--fixed-b", choices=("shared", "comb16", "comb32", "comb256"))

    evaluate = subparsers.add_parser("evaluate")
    evaluate.add_argument("result_dir")
    evaluate.add_argument("--output", required=True)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        if args.self_test:
            if args.command is not None:
                parser.error("--self-test does not accept a subcommand")
            self_test()
            return 0
        if args.command == "selection":
            normalize_selection(args)
            return 0
        if args.command == "evaluate":
            passed = evaluate_result_dir(
                Path(args.result_dir).resolve(), Path(args.output).resolve()
            )
            return 0 if passed else 1
        parser.error("select a command or use --self-test")
    except (GateError, OSError, ValueError) as error:
        print(f"zen4-dense-tail-evaluate: {error}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
