//go:build !narya_test_amd_policy && amd64

package cpufeat

import "testing"

// The dispatch override must be absent from every build that does not ask for
// it by name. This is the safety half of the pair: the override changes which
// arithmetic a consensus-critical verifier runs, so a build that did not opt in
// must be unable to contain it.
//
// A failure here means an ordinary `go build` is producing a binary whose
// backend dispatch no longer reflects the measurements the policies encode.
func TestAMDPolicyOverrideIsAbsentByDefault(t *testing.T) {
	if forceAMDPolicy {
		t.Fatal("forceAMDPolicy is set in an untagged build; dispatch policy would ignore the measured microarchitecture")
	}
}

// Without the override, the gated policies must agree exactly with the raw
// microarchitecture detection. If they can diverge, something other than the
// build tag is widening them.
func TestGatedPoliciesFollowDetectionByDefault(t *testing.T) {
	if !IFMA() {
		t.Skip("no AVX512-IFMA on this host; the gated policies are unconditionally false")
	}
	for _, policy := range []struct {
		name string
		got  bool
	}{
		{"PreferWideIFMA", PreferWideIFMA()},
		{"PreferDecodedAIFMA", PreferDecodedAIFMA()},
		{"PreferWarmX8IFMA", PreferWarmX8IFMA()},
	} {
		if want := amdFamily >= 0x19; policy.got != want {
			t.Errorf("%s = %v, want %v (family detection)", policy.name, policy.got, want)
		}
	}
	if got, want := PreferWideHashX4IFMA(), wideHashX4ForAMDVersion(IFMA(), amdFamily); got != want {
		t.Errorf("PreferWideHashX4IFMA = %v, want %v (family detection)", got, want)
	}
}
