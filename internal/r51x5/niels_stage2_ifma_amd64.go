//go:build amd64

package r51x5

// ifmaNielsStage2WorkspaceX4 is the four-lane counterpart of the x8 state
// transition below. A/B/C are exact raw products and D may be either a raw
// product or an already-composable u52 representative.
type ifmaNielsStage2WorkspaceX4 [4]IFMAProductX4

// ifmaNielsStage2WorkspaceX8 is a private state-transition boundary for the
// projective-Niels mixed-add schedule. On entry its slots are exact folded raw
// products in this order:
//
//	[A, B, C, D].
//
// A, B, and C must be the output of ifmaMulRawX8 on u52 operands. D may be
// either another raw product or an already-composable u52 representative. The
// latter is the affine-cached specialization D=Z used by the fixed-base comb;
// its tighter bound is a strict subset of the raw-product range below. On
// return the same storage contains carried u52 representatives in this order:
//
//	[E = B-A, F = 2D-C, G = 2D+C, H = B+A].
//
// The exact raw-product limb bounds are [267,213,159,105,51]*2^52. Adding
// 535*p to E and F is sufficient to prevent unsigned underflow. Every wide
// expression remains below 1604*2^51 < 2^62, so its carry-out is at most
// 1603; one independent radix-51 carry/fold pass returns every limb below
// 2^52. This stage-specific contract deliberately does not widen the general
// IFMAProductX8 contract.
type ifmaNielsStage2WorkspaceX8 [4]IFMAProductX8

// ifmaNielsStage2X4 performs the four-lane mixed-add linear middle stage in
// place. The caller must enforce the IFMA CPU gate and the entry contract. The
// assembly loads all twenty input vectors before its first output store.
//
//go:noescape
func ifmaNielsStage2X4(workspace *ifmaNielsStage2WorkspaceX4)

// ifmaNielsStage2X8 performs the mixed-add linear middle stage in place. The
// caller must enforce the IFMA CPU gate and raw-product provenance contract.
// The assembly loads all twenty input vectors before its first output store.
//
//go:noescape
func ifmaNielsStage2X8(workspace *ifmaNielsStage2WorkspaceX8)
