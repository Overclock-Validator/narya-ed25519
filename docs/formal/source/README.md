# Whole-window research source archive

This directory preserves the two prose artifacts supplied with the Edwards
whole-window search, byte for byte. They are research inputs and historical
design records, not the current implementation contract.

- [`edwards_whole_window_initial_result.md`](edwards_whole_window_initial_result.md)
  describes the initial six-doubling abstract search result.
- [`narya_whole_window_implementation_plan.md`](narya_whole_window_implementation_plan.md)
  is the accompanying pre-implementation plan.

Both documents predate the mapping to Narya's live five-doubling
radix-32/B10 schedule. The candidate was subsequently implemented, tested on
native Zen 5 hardware, and retained as an unwired experiment after improving
the prepared evaluator by about 0.53%. The authoritative current disposition,
proof boundary, implementation mapping, and measured verdict are in
[`../EDWARDS_WHOLE_WINDOW_RANGE_CERTIFICATE.md`](../EDWARDS_WHOLE_WINDOW_RANGE_CERTIFICATE.md).

`SHA256SUMS` pins the verbatim source files and can be checked from the
repository root with `shasum -c docs/formal/source/SHA256SUMS`. Keeping the
source record separate prevents historical assumptions from being mistaken
for supported production behavior while preserving the full reasoning for
future remeasurement.
