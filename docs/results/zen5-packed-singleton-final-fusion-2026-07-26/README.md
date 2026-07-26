# Zen 5 packed singleton final-stage fusion

Implementation commit: `b7d8acb`

This checkpoint fuses the packed doubling's final linear/carry stage with the
normalized field multiply that consumes it. The benchmark used an AMD Ryzen 7
9700X, Go 1.26.4, the performance governor, a pinned physical core, and
`GOMAXPROCS=1`.

The motivating pre-change n=1 profile was captured after the register-resident
decoder square-chain change. It put 53.5% cumulative time in packed doubling
and 13.4% flat time in the final operand-construction stage.

Results:

- reused-workspace packed doubling: 31.96 to 30.575 ns/op (-4.3%);
- public cold n=1, msg=1232: 15.440 to 15.085 µs/signature (-2.3%);
- public cold n=2, msg=1232: 15.380 to 14.960 µs/signature (-2.7%);
- public cold n=4, msg=1232: unchanged within noise at 9.538 versus 9.550
  µs/signature.

Every timed public row reported zero allocations and zero internal-fault
fallbacks. `tests.after` is the complete native repository suite. The exact
redundant-representation oracle, maximum-u52 coverage, deterministic random
coverage, aliasing, scratch-poison, and allocation tests are part of the
source tree.

Files:

- `profile.before.bench`, `profile.before.top`: motivating pushed-baseline
  profile;
- `double.after`: affected doubling microbenchmarks;
- `public.after`: n=1/2/4 public API gate;
- `tests.after`: complete native repository test output;
- `SHA256SUMS`: checksums for all evidence files except itself.
