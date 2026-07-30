//go:build amd64 && !purego

package r51x5

const nativeIFMAKernelsBuilt = true

// ifmaMulRawX8 multiplies eight lanes whose limbs are below 2^52 and emits an
// exact folded IFMAProductX8 below 2^61. The caller must enforce cpufeat.IFMA
// before entry and carry-normalize the result before reusing it.
//
//go:noescape
func ifmaMulRawX8(out *IFMAProductX8, x, y *LimbsX8)

// ifmaFourRawProductsUncheckedX8 computes four independent exact folded-u61
// products into four consecutive output slots. Every input must satisfy the
// same u52 contract as ifmaMulRawX8, and output may not overlap an input. The
// native leaf is representation-identical to four ifmaMulRawX8 calls while
// sharing one Go/assembly transition and one VZEROUPPER.
//
//go:noescape
func ifmaFourRawProductsUncheckedX8(
	out *[4]IFMAProductX8,
	x0, y0, x1, y1, x2, y2, x3, y3 *LimbsX8,
)

// The Stage-2 continuations compute the same four products as
// ifmaFourRawProductsUncheckedX8 and then tail-enter the existing double or
// Niels linear/carry leaf. Their output pointer must refer to the corresponding
// four-slot workspace. Input, output, range, and non-overlap contracts are the
// conjunction of the raw-product and named Stage-2 contracts.
//
//go:noescape
func ifmaFourRawProductsDoubleStage2UncheckedX8(
	out *ifmaDoubleStage2WorkspaceX8,
	x0, y0, x1, y1, x2, y2, x3, y3 *LimbsX8,
)

//go:noescape
func ifmaFourRawProductsNielsStage2UncheckedX8(
	out *ifmaNielsStage2WorkspaceX8,
	x0, y0, x1, y1, x2, y2, x3, y3 *LimbsX8,
)

// ifmaPointLinearFourRawNielsStage2ExperimentX8 computes normalized point-side
// Y-X/Y+X, the four projective-Niels raw products, and the existing Niels
// Stage-2 transition in one native leaf. It is retained only as a measured
// regime experiment: the leaf is faster in isolation but regresses the full
// Zen 5 verifier. No production path calls it. out points to a four-slot Niels
// workspace and must not overlap point or cached. Inputs remain unchanged.
//
//go:noescape
func ifmaPointLinearFourRawNielsStage2ExperimentX8(
	out *ifmaNielsStage2WorkspaceX8,
	point *IFMAPointX8,
	cached *IFMAProjectiveNielsX8,
)

// ifmaThreeRawProductsNielsStage2UncheckedX8 is the affine-cached
// specialization. It writes three exact raw products plus one copied u52 D
// coordinate, then tail-enters the existing Niels Stage-2 leaf. out must point
// to a four-slot Niels workspace and may not overlap any input.
//
//go:noescape
func ifmaThreeRawProductsNielsStage2UncheckedX8(
	out *ifmaNielsStage2WorkspaceX8,
	x0, y0, x1, y1, x2, y2, d *LimbsX8,
)

// ifmaMulRawX4 is the AVX-512VL/YMM analogue of ifmaMulRawX8.
//
//go:noescape
func ifmaMulRawX4(out *IFMAProductX4, x, y *LimbsX4)

// ifmaMulNormalizedUncheckedX8 fuses the raw folded multiply and the parallel
// carry/fold pass, keeping the u61 intermediate entirely in vector registers.
// Inputs must be u52 composable limbs. The output is u52, inputs and output may
// alias, and the caller must enforce cpufeat.IFMA before entry.
//
//go:noescape
func ifmaMulNormalizedUncheckedX8(out, x, y *LimbsX8)

// ifmaPointFinalProductsUncheckedX8 computes the four independent Edwards
// output products from four consecutive carried-u52 operands in E,F,G,H
// order. The output must not overlap the operand workspace. The native leaf is
// representation-identical to four ifmaMulNormalizedUncheckedX8 calls while
// sharing one Go/assembly transition and one VZEROUPPER.
//
//go:noescape
func ifmaPointFinalProductsUncheckedX8(out *IFMAPointX8, operands *IFMAProductX8)

// ifmaProjectiveFinalProductsUncheckedX8 is the P2-only counterpart. It
// computes X=E*F, Y=G*H and Z=F*G but deliberately has no storage for T=E*H.
// Its input, output and non-overlap contracts match the complete leaf above.
//
//go:noescape
func ifmaProjectiveFinalProductsUncheckedX8(out *ifmaProjectivePointX8, operands *IFMAProductX8)

// ifmaMulNormalizedMul19ExperimentX8 replaces each shift/add multiplication
// by 19 in the x8 pre-carry fold with one AVX-512DQ VPMULLQ. It is kept
// separate until exact-representation and complete-verifier gates pass.
//
//go:noescape
func ifmaMulNormalizedMul19ExperimentX8(out, x, y *LimbsX8)

// ifmaMulNormalizedUncheckedX4 is the AVX-512VL/YMM counterpart. It is kept
// separate from the split primitives so benchmarks can measure the avoided
// IFMAProduct store/reload and call boundary directly.
//
//go:noescape
func ifmaMulNormalizedUncheckedX4(out, x, y *LimbsX4)

// ifmaNormalizeProductUncheckedX8 carries a proven-u61 folded product back
// into the composable u52 domain in parallel across all eight lanes. The
// caller owns the input-range proof; this deliberately has no data-dependent
// error path so internal point schedules do not serialize the lanes merely to
// re-check a bound established by the raw multiply and formula algebra.
//
//go:noescape
func ifmaNormalizeProductUncheckedX8(out *LimbsX8, x *IFMAProductX8)

// ifmaNormalizeProductUncheckedX4 is the AVX-512VL/YMM counterpart.
//
//go:noescape
func ifmaNormalizeProductUncheckedX4(out *LimbsX4, x *IFMAProductX4)

// The normalized add/subtract/negate helpers combine the limb-wise operation
// and carry/fold pass in one vector call. Their inputs are composable u52
// values, so their u53/u54 intermediates satisfy the normalizer's u61
// precondition without another range scan.
//
//go:noescape
func ifmaAddNormalizedUncheckedX8(out, x, y *LimbsX8)

//go:noescape
func ifmaSubtractNormalizedUncheckedX8(out, x, y *LimbsX8)

//go:noescape
func ifmaNegateNormalizedUncheckedX8(out, x *LimbsX8)

//go:noescape
func ifmaAddNormalizedUncheckedX4(out, x, y *LimbsX4)

//go:noescape
func ifmaSubtractNormalizedUncheckedX4(out, x, y *LimbsX4)

//go:noescape
func ifmaNegateNormalizedUncheckedX4(out, x *LimbsX4)

// ifmaConditionalNegateNormalizedUncheckedX4 selects x or -x independently
// in each public lane according to negativeMask, then applies the same
// carry/fold normalization as the portable reference. It is safe in place.
//
//go:noescape
func ifmaConditionalNegateNormalizedUncheckedX4(out, x *LimbsX4, negativeMask uint8)

// ifmaConditionalNegateNormalizedUncheckedX8 is the native-width analogue
// of ifmaConditionalNegateNormalizedUncheckedX4. The public eight-bit mask
// selects x or -x independently in each lane, and out may alias x.
//
//go:noescape
func ifmaConditionalNegateNormalizedUncheckedX8(out, x *LimbsX8, negativeMask uint8)
