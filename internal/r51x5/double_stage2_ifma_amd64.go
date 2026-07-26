//go:build amd64

package r51x5

// ifmaDoubleStage2WorkspaceX4 is a private state-transition boundary for the
// direct-XY point-doubling schedule. On entry its slots are exact folded raw
// products in this order:
//
//	[A = X^2, B = Y^2, C = Z^2, E = X*Y].
//
// Each input must be the output of ifmaMulRawX4 on u52 operands, not merely an
// arbitrary value whose limbs happen to be below 2^61. On return the same
// storage contains carried u52 representatives in this order:
//
//	[E = 2*X*Y, F, G, H].
//
// The distinct state transition is intentionally confined to this type; it
// does not widen the general IFMAProductX4 contract.
type ifmaDoubleStage2WorkspaceX4 [4]IFMAProductX4

// ifmaDoubleStage2X4 performs the direct-XY linear middle stage in
// place. For radix R=2^51, the exact raw-product limb bounds are
//
//	[267, 213, 159, 105, 51] * 2^52.
//
// It computes
//
//	G = B + 535*p - A
//	H = 1069*p - A - B
//	F = G + 1068*p - 2*C
//	E = 2*E
//
// limb-wise before carrying. Equivalently F has a total bias of 1603*p.
// E, G, and H are below 1069*R < 2^62; F is below 2137*R <
// 2^63. All expressions are non-negative and below 2^64. Their carry-outs are
// at most 2136, so one independent radix-51 carry/fold pass per output returns
// every limb below 2^52.
//
// The caller must enforce the IFMA CPU gate and the exact raw-product input
// contract. The assembly loads all twenty input vectors before its first
// output store.
//
//go:noescape
func ifmaDoubleStage2X4(workspace *ifmaDoubleStage2WorkspaceX4)
