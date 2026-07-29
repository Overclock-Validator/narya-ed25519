//go:build narya_test_amd_policy

package cpufeat

// forceAMDPolicy makes the microarchitecture-gated dispatch policies report
// true on any IFMA-capable machine, instead of only on the measured AMD parts.
//
// Why this exists. PreferWideIFMA, PreferDecodedAIFMA, PreferWarmX8IFMA,
// PreferRawSquareIFMA, PreferWideHashX4IFMA, PreferBatchEncodeX8IFMA,
// PreferProjectiveDoubleX8IFMA, PreferAsymmetricFixedB10X8IFMA,
// PreferNativeScalarReduceX8IFMA and PreferPackedMul19X4IFMA all require an
// AuthenticAMD vendor string and a family check. Intel SDE, which is how CI
// executes the AVX-512 kernels at all, emulates Intel parts.
// Every one of those policies therefore reports false under emulation, so the
// x8/ZMM groups, decoded-A cache tier, warm x4 pairing, raw-square schedule,
// wide-hash x4 tail, x8 finalizer, projective-doubling schedule, B10 comb,
// native scalar reducer and packed-x4 VPMULLQ fold have no automated coverage
// anywhere: they run only on contributors' own hardware. A regression in the
// library's headline path merges green.
//
// Why a build tag rather than an environment variable or a settable var. This
// changes which arithmetic a consensus-critical verifier executes. A tag is
// resolved at compile time, so an ordinary build cannot contain the override at
// all, and no operator, configuration file or attacker can reach it at runtime.
// The cost is that exercising it requires an explicit, visible build.
//
// What it does NOT mean. This is a correctness-coverage switch only. It makes
// no claim that the wide path is the right choice on the host, and it must
// never be used for benchmarking or in a release build: the policies it
// overrides were set by measurement on specific parts, and forcing them
// elsewhere discards exactly that measurement.
const forceAMDPolicy = true
