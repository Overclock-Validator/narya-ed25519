//go:build !narya_test_amd_policy

package cpufeat

// forceAMDPolicy is false in every ordinary build. See policyoverride_on.go for
// what setting it does and why it is a build tag rather than a variable.
const forceAMDPolicy = false
