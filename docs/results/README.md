# Reproducibility artifacts

This directory contains dated raw evidence: benchmark output, correctness and
fuzz logs, environment captures, commands, and checksum manifests. It is kept
separate from the explanatory documents in `docs/performance`, `docs/proofs`,
`docs/architecture`, and `docs/audits`.

An artifact can remain historically useful after the implementation changes.
Do not quote a number without also checking the recorded commit, CPU, message
size, batch width, profile, cache state, and whether the path was public or an
experimental prepared-core seam.

New result directories should include, where applicable:

1. `README.md` stating the question and verdict;
2. `environment.txt` with CPU, OS, governor, Go version, and source commit;
3. `commands.txt` with exact invocations;
4. unedited raw outputs and status files;
5. `SHA256SUMS` covering the evidence set.
