//go:build narya_test_amd_policy

package cpufeat

import "testing"

// The coverage half of the pair. Under the override every microarchitecture
// gated policy must report true on an IFMA-capable host, which is what makes
// the x8/ZMM groups, the decoded-A tier, warm x4 pairing and the raw-square
// schedule reachable under Intel SDE.
//
// If this fails, the tagged CI job is running the same x4 paths as the untagged
// one and the extra job is buying nothing.
func TestAMDPolicyOverrideReachesTheGatedPaths(t *testing.T) {
	if !forceAMDPolicy {
		t.Fatal("forceAMDPolicy is unset in a tagged build")
	}
	if !IFMA() {
		t.Skip("no AVX512-IFMA on this host; the override widens the family gate, not the feature gate")
	}
	for _, policy := range []struct {
		name string
		got  bool
	}{
		{"PreferWideIFMA", PreferWideIFMA()},
		{"PreferDecodedAIFMA", PreferDecodedAIFMA()},
		{"PreferWarmX8IFMA", PreferWarmX8IFMA()},
		{"PreferRawSquareIFMA", PreferRawSquareIFMA()},
		{"PreferWideHashX4IFMA", PreferWideHashX4IFMA()},
		{"PreferBatchEncodeX8IFMA", PreferBatchEncodeX8IFMA()},
		{"PreferProjectiveDoubleX8IFMA", PreferProjectiveDoubleX8IFMA()},
		{"PreferAsymmetricFixedB10X8IFMA", PreferAsymmetricFixedB10X8IFMA()},
	} {
		if !policy.got {
			t.Errorf("%s = false under the override; the gated path stays unreachable", policy.name)
		}
	}
}
