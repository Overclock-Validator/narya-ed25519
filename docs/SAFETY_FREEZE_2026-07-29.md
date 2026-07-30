# Safety freeze — 2026-07-29

This note defines the pre-audit boundary after the final cold-path performance
work. It is a review checklist and evidence index, not an independent audit.

## Supported versus experimental

The public contract remains unchanged: `generic` is selected automatically;
`r51` is registered only for explicit activation on supported hardware. Both
return an independent verdict for every signature under the selected profile.

The last supported-path change is commit
`bbc6c2194438090b0c48ac9bd95eab6b92602d6f`: Zen 5 strict n=2 calls put one
complete coordinate-packed verification equation in each 256-bit half of one
ZMM register. Zen 4 and unknown IFMA CPUs retain two packed singleton calls.

The whole-window completed-coordinate implementation at
`5d8a3e4049f565e807e4b8e130de1ae55c3c429b` is **not dispatched**. It remains
an exact, dead-stripped measurement candidate with a portable oracle and an
executable range certificate. HEEA, alternate radix/window schedules, and
other `Experimental*` symbols likewise remain outside the supported contract.

## Packed-pair audit map

### Acceptance predicate

Each half independently performs the complete `DalekStrict` byte precheck:
canonical `S`, small-order `A` rejection, small-order `R` rejection, and
canonical `R`. It deliberately does not add a canonical-`A` check. The
challenge hashes the original `R || A || message` bytes, including a
permissive non-canonical `A` encoding accepted by the profile.

Both A and R are decoded for each candidate. The final comparison checks both
projective cross-products against the decoded affine R. An ordinary invalid
input clears only its own live bit; a native/platform error returns an error so
the public backend recomputes the complete batch through `generic` and
increments `InternalFaultFallbacks`.

### Layout and lane ownership

- low ZMM half, coordinate lanes 0..3: input and verdict 0;
- high ZMM half, coordinate lanes 4..7: input and verdict 1;
- decode lanes 0/1 contain A0/R0 and lanes 2/3 contain A1/R1 before repacking;
- final comparison uses decoded R lanes 1 and 3 respectively;
- generator entries are replicated between halves, but digit selection and
  sign masks are independent;
- the only shared control value is the public loop bit position. A shorter NAF
  chain doubles its identity until its own first nonzero digit.

The two-chain arithmetic tests trace each half against an independent packed-x4
oracle through doubling and cached addition. Complete route tests place invalid
equations in each result position and require the adjacent verdict to remain
unchanged.

### CPU and operational dispatch

`PreferPackedPairX8IFMA` is true only for the complete IFMA feature set on
measured AMD family 1Ah (Zen 5), except in the compile-time-only
`narya_test_amd_policy` SDE coverage build. Ordinary binaries cannot contain
that override. Unsupported forced activation fails synchronously; native
faults do not fail open or silently return a partial SIMD verdict.

## Whole-window certificate boundary

The exact certificate and its source are indexed in
[`formal/README.md`](formal/README.md). Native tests bind the source assembly
leaf to an independently scheduled portable oracle on maximum bounds and
generated inputs. What remains unproved is the final source/macro/binary
refinement: no theorem currently decodes the assembled x86 instructions and
proves their register and memory trace equivalent to the oracle.

## Gates completed at the freeze

- full portable repository tests and pure-Go build/tests;
- Go vet and diff whitespace checks;
- native Zen 5 full suite, race detector, AMD-policy build, and zero-allocation
  gates at the benchmarked live-path commit;
- native Zen 5 CCTV and Wycheproof corpora through the exact packed n=2 route;
- per-lane valid/invalid dispatcher differentials at n=0,1,2,3,4,5,7,8,9,15,
  16,17,32,64,65 for both profiles;
- injected singleton, packed-pair, and wider-batch native faults with generic
  recomputation and exact counter checks;
- deterministic regeneration of all whole-window certificate JSON;
- SDE's AMD-policy public test includes n=2 valid and single-invalid-lane
  checks; the focused pair arithmetic tests are included in the tagged SDE
  kernel regex.

Raw native evidence and commands are in
[`results/zen5-packed-pair-whole-window-2026-07-29/`](results/zen5-packed-pair-whole-window-2026-07-29/).

## Still open

- independent cryptographic and assembly review;
- the documented long differential fuzz target of approximately 10^9
  executions (only smoke-scale fuzzing is complete);
- native performance measurements on Intel and server-class CPUs;
- machine-linked proofs for assembly register, memory, mask, and alias traces;
- review and resolution of any findings before changing automatic dispatch.

Performance work is frozen at this checkpoint. Reopening an experiment should
cite a regime change (CPU, SIMD width, point schedule, or profile) and must not
replace these safety gates with a microbenchmark result.
