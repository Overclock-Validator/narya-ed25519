# Standalone Firedancer C comparison

This harness measures Firedancer's native C Ed25519 implementation directly.
It is compiled inside a pinned Firedancer checkout and links the unmodified
Firedancer `ballet` objects; it does not use cgo and is not a Narya runtime
dependency.

The comparison is pinned to Firedancer commit
[`3ed37488372b7e50bb03ca30477be48508ee7022`](https://github.com/firedancer-io/firedancer/tree/3ed37488372b7e50bb03ca30477be48508ee7022).
The driver adds the missing `low255(R) < p` gate before calling Firedancer.
Together with Firedancer's small-order rejection, that makes valid and invalid
inputs comparable to Narya's `DalekStrict` profile. The independent Narya
differential corpus remains the predicate oracle; this program is a native
performance harness, not a replacement for those tests.

The exact checkout, build, link, pinning, and execution commands used for PR 1
are recorded with the raw output in the dated `docs/results` directory. The
resulting executable is run as:

```sh
taskset -c 2 ./fd_ed25519_compare 20000
```

The argument is a target number of signatures per row. Since each row uses an
integer number of calls, the output records both `calls` and the actual
`signatures` count. Shared-message rows call Firedancer's native batch entry
point (chunked at its 16-signature maximum); distinct-message rows call the
native single-signature verifier in a C loop. Widths, messages, keys, and
signatures are prepared outside the timed region.
