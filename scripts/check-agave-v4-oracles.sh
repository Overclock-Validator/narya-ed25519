#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/narya-agave-v4-oracle.XXXXXX")
corpus_path="$work_dir/corpus.jsonl"

cleanup() {
  rm -rf -- "$work_dir"
}
trap cleanup EXIT

cd "$repo_dir"
NARYA_AGAVE_V4_CORPUS_OUT="$corpus_path" \
  go test ./ed25519 -run '^TestExportAgaveV4OracleCorpus$' -count=1 -v
cargo +1.89.0 run --quiet --locked \
  --manifest-path contrib/agave-v4-oracle/Cargo.toml \
  -- "$corpus_path"
