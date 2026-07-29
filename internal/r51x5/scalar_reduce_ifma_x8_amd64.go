//go:build amd64 && !purego

package r51x5

// Constants are memory operands for the native radix-2^21 schedule. Keeping
// them named here lets objdump-based review tie each broadcast to the source
// identity in the reduction contract.
var (
	scalarReduce666643  uint64 = 666643
	scalarReduce470296  uint64 = 470296
	scalarReduce654183  uint64 = 654183
	scalarReduce997805  uint64 = 997805
	scalarReduce136657  uint64 = 136657
	scalarReduce683901  uint64 = 683901
	scalarReduceRound21 uint64 = 1 << 20
)

// scalarReduceRadix21IFMAX8 mutates the 24 signed radix-2^21 rows in place.
//
// The instruction schedule is a Go-assembly translation of the project-owned
// standalone Narya assembly schedule at commit
// 571f224057b11faa1f0fd968d6d282d515a4a7bf. That source is accompanied by a
// 389-intermediate signed-range certificate and a Lean proof of its canonical
// tail. This translation still requires its own assembled-opcode differential;
// those upstream artifacts do not by themselves prove Go ABI refinement.
//
//go:noescape
func scalarReduceRadix21IFMAX8(limbs *scalarRadix21X8)
