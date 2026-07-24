#!/usr/bin/env python3
"""Hash the exact nonignored source tree used by a Zen 4 profile build."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path


def git_source_paths(repo: Path) -> list[bytes]:
    completed = subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.decode("utf-8", "replace").strip())
    return sorted(set(path for path in completed.stdout.split(b"\0") if path))


def excluded(path: bytes, prefixes: list[bytes]) -> bool:
    return any(path == prefix or path.startswith(prefix + b"/") for prefix in prefixes)


def file_record(repo_bytes: bytes, path: bytes) -> tuple[str, int, int, str]:
    absolute = os.path.join(repo_bytes, path)
    try:
        metadata = os.lstat(absolute)
    except FileNotFoundError:
        return ("missing", 0, 0, hashlib.sha256(b"").hexdigest())

    mode = stat.S_IMODE(metadata.st_mode)
    if stat.S_ISREG(metadata.st_mode):
        digest = hashlib.sha256()
        size = 0
        with open(absolute, "rb") as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
                size += len(chunk)
        return ("file", mode, size, digest.hexdigest())
    if stat.S_ISLNK(metadata.st_mode):
        target = os.readlink(absolute)
        if isinstance(target, str):
            target = os.fsencode(target)
        return ("symlink", mode, len(target), hashlib.sha256(target).hexdigest())
    raise RuntimeError(
        f"unsupported source-tree entry {os.fsdecode(path)!r}: mode {metadata.st_mode:o}"
    )


def build_manifest(repo: Path, exclude_prefixes: list[str]) -> list[tuple[bytes, str, int, int, str]]:
    prefixes = [os.fsencode(prefix.strip("/")) for prefix in exclude_prefixes if prefix.strip("/")]
    repo_bytes = os.fsencode(str(repo))
    records = []
    for path in git_source_paths(repo):
        if excluded(path, prefixes):
            continue
        kind, mode, size, digest = file_record(repo_bytes, path)
        records.append((path, kind, mode, size, digest))
    if not records:
        raise RuntimeError("source manifest is empty")
    return records


def tree_digest(records: list[tuple[bytes, str, int, int, str]]) -> str:
    digest = hashlib.sha256()
    for path, kind, mode, size, content_digest in records:
        for field in (
            path,
            kind.encode("ascii"),
            f"{mode:o}".encode("ascii"),
            str(size).encode("ascii"),
            content_digest.encode("ascii"),
        ):
            digest.update(len(field).to_bytes(8, "big"))
            digest.update(field)
    return digest.hexdigest()


def write_manifest(args: argparse.Namespace) -> None:
    repo = Path(args.repo).resolve()
    records = build_manifest(repo, args.exclude_prefix)
    digest = tree_digest(records)
    with Path(args.output).open("w", encoding="utf-8") as output:
        output.write(f"source_tree_sha256={digest}\n")
        output.write(f"source_entry_count={len(records)}\n")
        output.write("path_json\ttype\tmode_octal\tsize_bytes\tcontent_sha256\n")
        for path, kind, mode, size, content_digest in records:
            rendered_path = json.dumps(os.fsdecode(path), ensure_ascii=True)
            output.write(
                f"{rendered_path}\t{kind}\t{mode:o}\t{size}\t{content_digest}\n"
            )


def self_test() -> None:
    fixtures = [
        (b"a", "file", 0o644, 1, "0" * 64),
        (b"dir/b", "file", 0o755, 2, "1" * 64),
    ]
    first = tree_digest(fixtures)
    assert first == tree_digest(list(fixtures))
    changed = list(fixtures)
    changed[1] = (b"dir/b", "file", 0o755, 3, "1" * 64)
    assert first != tree_digest(changed)
    assert excluded(b"results/profile/a", [b"results"])
    assert not excluded(b"results-old/a", [b"results"])
    print("zen4-source-manifest: self-test passed")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--repo", default=".")
    parser.add_argument("--output")
    parser.add_argument("--exclude-prefix", action="append", default=[])
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test()
        elif not args.output:
            parser.error("--output is required")
        else:
            write_manifest(args)
    except (OSError, RuntimeError) as error:
        print(f"zen4-source-manifest: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
