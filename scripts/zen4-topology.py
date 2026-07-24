#!/usr/bin/env python3
"""Validate and canonically record CPU topology used by the Zen 4 gate."""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


CPU_COMPONENT_RE = re.compile(r"^(0|[1-9][0-9]*)(?:-(0|[1-9][0-9]*))?$")
NODE_RE = re.compile(r"^node(0|[1-9][0-9]*)$")


class TopologyError(ValueError):
    pass


@dataclass(frozen=True)
class CPUIdentity:
    cpu: int
    package: int
    core: int
    node: int


def parse_cpu_list(value: str, label: str) -> tuple[int, ...]:
    value = value.strip()
    if not value:
        raise TopologyError(f"{label} is empty")

    cpus: list[int] = []
    seen: set[int] = set()
    for component in value.split(","):
        match = CPU_COMPONENT_RE.fullmatch(component)
        if match is None:
            raise TopologyError(
                f"{label} has invalid component {component!r}; "
                "use comma-separated CPU numbers or inclusive ranges"
            )
        start = int(match.group(1))
        end = int(match.group(2)) if match.group(2) is not None else start
        if end < start:
            raise TopologyError(f"{label} range {component!r} is descending")
        for cpu in range(start, end + 1):
            if cpu in seen:
                raise TopologyError(f"{label} selects CPU {cpu} more than once")
            seen.add(cpu)
            cpus.append(cpu)
    return tuple(sorted(cpus))


def parse_single_cpu(value: str, label: str) -> int:
    cpus = parse_cpu_list(value, label)
    if len(cpus) != 1:
        raise TopologyError(f"{label} must select exactly one CPU")
    return cpus[0]


def format_cpu_list(cpus: tuple[int, ...] | list[int] | set[int]) -> str:
    ordered = sorted(cpus)
    if not ordered:
        raise TopologyError("cannot format an empty CPU list")
    parts: list[str] = []
    start = ordered[0]
    end = start
    for cpu in ordered[1:]:
        if cpu == end + 1:
            end = cpu
            continue
        parts.append(str(start) if start == end else f"{start}-{end}")
        start = end = cpu
    parts.append(str(start) if start == end else f"{start}-{end}")
    return ",".join(parts)


def read_text(path: Path, label: str) -> str:
    try:
        value = path.read_text(encoding="ascii").strip()
    except OSError as error:
        raise TopologyError(f"cannot read {label} from {path}: {error}") from error
    if not value:
        raise TopologyError(f"{label} at {path} is empty")
    return value


def read_nonnegative_int(path: Path, label: str) -> int:
    value = read_text(path, label)
    if not re.fullmatch(r"0|[1-9][0-9]*", value):
        raise TopologyError(f"{label} at {path} is not a nonnegative integer: {value!r}")
    return int(value)


def cpu_node(cpu_root: Path, cpu: int) -> int:
    cpu_dir = cpu_root / f"cpu{cpu}"
    direct_nodes: list[int] = []
    try:
        entries = tuple(cpu_dir.iterdir())
    except OSError as error:
        raise TopologyError(f"cannot inspect CPU {cpu} at {cpu_dir}: {error}") from error
    for entry in entries:
        match = NODE_RE.fullmatch(entry.name)
        if match is not None:
            direct_nodes.append(int(match.group(1)))
    direct_nodes = sorted(set(direct_nodes))
    if len(direct_nodes) == 1:
        return direct_nodes[0]
    if len(direct_nodes) > 1:
        raise TopologyError(f"CPU {cpu} is associated with multiple NUMA nodes: {direct_nodes}")

    node_root = cpu_root.parent / "node"
    containing_nodes: list[int] = []
    if node_root.is_dir():
        for entry in sorted(node_root.iterdir(), key=lambda path: path.name):
            match = NODE_RE.fullmatch(entry.name)
            if match is None or not entry.is_dir():
                continue
            cpulist_path = entry / "cpulist"
            if not cpulist_path.is_file():
                continue
            node_cpus = parse_cpu_list(
                read_text(cpulist_path, f"NUMA node {entry.name} CPU list"),
                f"NUMA node {entry.name} CPU list",
            )
            if cpu in node_cpus:
                containing_nodes.append(int(match.group(1)))
    if len(containing_nodes) == 1:
        return containing_nodes[0]
    if len(containing_nodes) > 1:
        raise TopologyError(
            f"CPU {cpu} appears in multiple NUMA node CPU lists: {containing_nodes}"
        )
    raise TopologyError(f"cannot determine a NUMA node for CPU {cpu}")


def cpu_identity(cpu_root: Path, cpu: int) -> CPUIdentity:
    topology = cpu_root / f"cpu{cpu}" / "topology"
    return CPUIdentity(
        cpu=cpu,
        package=read_nonnegative_int(
            topology / "physical_package_id", f"CPU {cpu} physical package ID"
        ),
        core=read_nonnegative_int(topology / "core_id", f"CPU {cpu} core ID"),
        node=cpu_node(cpu_root, cpu),
    )


def topology_record(
    cpu_root: Path,
    primitive_core_text: str,
    worker_cpuset_text: str,
    worker_count: int,
    allowed_cpuset_text: str,
) -> str:
    if worker_count < 1:
        raise TopologyError("worker count must be positive")

    online = parse_cpu_list(
        read_text(cpu_root / "online", "online CPU list"), "online CPU list"
    )
    online_set = set(online)
    allowed = parse_cpu_list(allowed_cpuset_text, "process-allowed CPU list")
    allowed_set = set(allowed)
    primitive = parse_single_cpu(primitive_core_text, "primitive benchmark core")
    workers = parse_cpu_list(worker_cpuset_text, "verifier worker CPU set")

    if primitive not in online_set:
        raise TopologyError(f"primitive benchmark CPU {primitive} is not online")
    if primitive not in allowed_set:
        raise TopologyError(
            f"primitive benchmark CPU {primitive} is outside the process-allowed CPU list"
        )
    offline_workers = sorted(set(workers) - online_set)
    if offline_workers:
        raise TopologyError(
            "verifier worker CPU set includes offline CPUs: "
            + format_cpu_list(offline_workers)
        )
    disallowed_workers = sorted(set(workers) - allowed_set)
    if disallowed_workers:
        raise TopologyError(
            "verifier worker CPU set includes CPUs outside the process-allowed list: "
            + format_cpu_list(disallowed_workers)
        )
    if len(workers) != worker_count:
        raise TopologyError(
            f"verifier worker CPU set selects {len(workers)} CPUs for "
            f"exactly {worker_count} workers"
        )

    identities = {cpu: cpu_identity(cpu_root, cpu) for cpu in set(workers) | {primitive}}
    worker_identities = tuple(identities[cpu] for cpu in workers)
    physical_cores = sorted({(identity.package, identity.core) for identity in worker_identities})
    if len(physical_cores) != worker_count:
        raise TopologyError(
            "verifier worker CPU set provides only "
            f"{len(physical_cores)} distinct physical package/core pairs for "
            f"{worker_count} workers; SMT siblings cannot substitute for physical cores"
        )

    primitive_identity = identities[primitive]
    mapping = ";".join(
        f"cpu={identity.cpu},package={identity.package},core={identity.core},node={identity.node}"
        for identity in worker_identities
    )
    physical_core_list = ",".join(
        f"package={package}:core={core}" for package, core in physical_cores
    )
    canonical_lines = [
        "topology_schema=1",
        f"online_cpu_list={format_cpu_list(online)}",
        f"process_allowed_cpu_list={format_cpu_list(allowed)}",
        f"primitive_cpu={primitive_identity.cpu}",
        f"primitive_cpu_package={primitive_identity.package}",
        f"primitive_cpu_core={primitive_identity.core}",
        f"primitive_cpu_node={primitive_identity.node}",
        f"verifier_worker_count={worker_count}",
        f"verifier_cpu_list={format_cpu_list(workers)}",
        f"verifier_cpu_cardinality={len(workers)}",
        f"verifier_distinct_physical_cores={len(physical_cores)}",
        f"verifier_physical_core_list={physical_core_list}",
        f"verifier_cpu_mapping={mapping}",
    ]
    canonical = "\n".join(canonical_lines) + "\n"
    digest = hashlib.sha256(canonical.encode("ascii")).hexdigest()
    return canonical + f"topology_sha256={digest}\n"


def write_fixture(
    root: Path,
    online: str = "0-7",
    with_direct_nodes: bool = True,
) -> Path:
    cpu_root = root / "cpu"
    cpu_root.mkdir(parents=True)
    (cpu_root / "online").write_text(online + "\n", encoding="ascii")
    for cpu in range(8):
        cpu_dir = cpu_root / f"cpu{cpu}"
        topology = cpu_dir / "topology"
        topology.mkdir(parents=True)
        (topology / "physical_package_id").write_text("0\n", encoding="ascii")
        (topology / "core_id").write_text(f"{cpu % 4}\n", encoding="ascii")
        if with_direct_nodes:
            (cpu_dir / "node0").mkdir()
    if not with_direct_nodes:
        node = root / "node" / "node0"
        node.mkdir(parents=True)
        (node / "cpulist").write_text("0-7\n", encoding="ascii")
    return cpu_root


def expect_error(action, fragment: str) -> None:
    try:
        action()
    except TopologyError as error:
        if fragment not in str(error):
            raise AssertionError(f"expected {fragment!r} in {str(error)!r}") from error
    else:
        raise AssertionError(f"expected TopologyError containing {fragment!r}")


def self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="zen4-topology-selftest-") as temp:
        cpu_root = write_fixture(Path(temp))
        record = topology_record(cpu_root, "2", "0-3", 4, "0-7")
        assert "primitive_cpu=2\n" in record
        assert "verifier_cpu_cardinality=4\n" in record
        assert "verifier_distinct_physical_cores=4\n" in record
        assert "verifier_cpu_mapping=cpu=0,package=0,core=0,node=0;" in record
        digest = record.rstrip().rsplit("topology_sha256=", 1)[1]
        assert re.fullmatch(r"[0-9a-f]{64}", digest)
        assert record == topology_record(cpu_root, "2", "0-3", 4, "0-7")

        expect_error(
            lambda: topology_record(cpu_root, "2", "0-2", 4, "0-7"),
            "selects 3 CPUs for exactly 4 workers",
        )
        expect_error(
            lambda: topology_record(cpu_root, "2", "0-4", 4, "0-7"),
            "selects 5 CPUs for exactly 4 workers",
        )
        expect_error(
            lambda: topology_record(cpu_root, "2", "0,4", 2, "0-7"),
            "SMT siblings cannot substitute",
        )
        expect_error(
            lambda: topology_record(cpu_root, "2", "0,8", 2, "0-8"),
            "offline CPUs: 8",
        )
        expect_error(
            lambda: topology_record(cpu_root, "8", "0-3", 4, "0-8"),
            "primitive benchmark CPU 8 is not online",
        )
        expect_error(
            lambda: topology_record(cpu_root, "2", "0-3", 4, "0-2"),
            "outside the process-allowed list: 3",
        )
        expect_error(
            lambda: topology_record(cpu_root, "2", "0-3", 4, "0-1,3-7"),
            "primitive benchmark CPU 2 is outside",
        )
        expect_error(
            lambda: topology_record(cpu_root, "2", "0-3", 0, "0-7"),
            "worker count must be positive",
        )
        expect_error(
            lambda: topology_record(cpu_root, "0-1", "0-3", 4, "0-7"),
            "must select exactly one CPU",
        )
        expect_error(lambda: parse_cpu_list("0-3:2", "fixture"), "invalid component")
        expect_error(lambda: parse_cpu_list("3-1", "fixture"), "is descending")
        expect_error(lambda: parse_cpu_list("0-2,2", "fixture"), "more than once")

    with tempfile.TemporaryDirectory(prefix="zen4-topology-node-fallback-") as temp:
        cpu_root = write_fixture(Path(temp), with_direct_nodes=False)
        record = topology_record(cpu_root, "2", "0-3", 4, "0-7")
        assert "primitive_cpu_node=0\n" in record

    with tempfile.TemporaryDirectory(prefix="zen4-topology-node-missing-") as temp:
        cpu_root = write_fixture(Path(temp), with_direct_nodes=False)
        (Path(temp) / "node" / "node0" / "cpulist").unlink()
        expect_error(
            lambda: topology_record(cpu_root, "2", "0-3", 4, "0-7"),
            "cannot determine a NUMA node",
        )
    print("zen4-topology self-test: PASS")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cpu-root", type=Path, default=Path("/sys/devices/system/cpu"))
    parser.add_argument("--primitive-core")
    parser.add_argument("--worker-cpuset")
    parser.add_argument("--workers", type=int)
    parser.add_argument("--allowed-cpuset")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return 0
    required = {
        "--primitive-core": args.primitive_core,
        "--worker-cpuset": args.worker_cpuset,
        "--workers": args.workers,
        "--allowed-cpuset": args.allowed_cpuset,
    }
    missing = [name for name, value in required.items() if value is None]
    if missing:
        parser.error("required arguments: " + ", ".join(missing))
    try:
        sys.stdout.write(
            topology_record(
                args.cpu_root,
                args.primitive_core,
                args.worker_cpuset,
                args.workers,
                args.allowed_cpuset,
            )
        )
    except TopologyError as error:
        print(f"zen4-topology: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
