package r51x5

import "errors"

const (
	// ExperimentalIFMABatchEncodeMaxX4Groups bounds the forced r51 x4 batch-
	// encoding schedule to 64 independent points. The encoder batches across
	// x4 groups: each field operation still acts on four independent lanes,
	// while Montgomery's trick amortizes one inversion across up to 16 group
	// vectors.
	ExperimentalIFMABatchEncodeMaxX4Groups = 16
)

var (
	errIFMABatchEncodeGroupCount = errors.New("r51x5: invalid x4 batch-encode group count")
	errIFMABatchEncodeActiveMask = errors.New("r51x5: invalid x4 batch-encode active mask")
	errIFMABatchEncodeZeroZ      = errors.New("r51x5: active x4 batch-encode lane has zero Z")
)

// ExperimentalIFMABatchEncodeWorkspaceX4 owns the prefix products and staged
// output used to encode up to 16 ready IFMA point groups. It is deliberately
// mutable and non-concurrent. The explicitly forced r51 batch verifier owns
// one workspace per pooled worker; automatic dispatch cannot reach it.
//
// The workspace consumes IFMAPointX4 directly, so DSM output does not first
// pay a four-coordinate canonical-reduction boundary. Only the final affine X
// and Y coordinates are reduced for canonical Ed25519 serialization.
type ExperimentalIFMABatchEncodeWorkspaceX4 struct {
	prefix   [ExperimentalIFMABatchEncodeMaxX4Groups]IFMAElementX4
	inverseZ [ExperimentalIFMABatchEncodeMaxX4Groups]IFMAElementX4
	staged   [ExperimentalIFMABatchEncodeMaxX4Groups][X4Lanes][32]byte
}

// Encode canonically encodes groups ready IFMAPointX4 values. The low four
// bits of active[group] select live lanes in that group; any high bit is an
// error. Inactive denominators are replaced by one before the cross-group
// prefix product. This is required so a tail lane with Z=0 cannot zero the
// same lane in every other group.
//
// The output is committed only after the entire IFMA schedule succeeds. It is
// therefore unchanged on an unavailable CPU, invalid group count or mask,
// invalid u52 point input, active field-zero Z, or arithmetic error. Inactive
// output lanes within the selected groups are zero; output groups beyond
// groups are left unchanged.
//
// Each active lane must be a valid extended Edwards point with Z != 0. The
// composable DSM guarantees this precondition. Inactive coordinates may be
// arbitrary valid-range u52 values (including Z=0); values at or above 2^52
// are rejected by the whole-point boundary check even when their lane is
// inactive.
func (w *ExperimentalIFMABatchEncodeWorkspaceX4) Encode(
	out *[ExperimentalIFMABatchEncodeMaxX4Groups][X4Lanes][32]byte,
	points *[ExperimentalIFMABatchEncodeMaxX4Groups]IFMAPointX4,
	active *[ExperimentalIFMABatchEncodeMaxX4Groups]uint8,
	groups int,
) error {
	if !ExperimentalIFMAAvailable() {
		return ErrIFMAUnavailable
	}
	ops := decode2IFMAOpsX4{hardware: true, uncheckedInputs: true}
	return batchEncodeIFMAX4(w, out, points, active, groups, &ops)
}

// batchEncodeIFMAModelX4 executes the identical schedule through the reduced
// scalar-lane oracle. It keeps the batch-inversion algorithm testable on
// machines without AVX-512 IFMA.
func batchEncodeIFMAModelX4(
	w *ExperimentalIFMABatchEncodeWorkspaceX4,
	out *[ExperimentalIFMABatchEncodeMaxX4Groups][X4Lanes][32]byte,
	points *[ExperimentalIFMABatchEncodeMaxX4Groups]IFMAPointX4,
	active *[ExperimentalIFMABatchEncodeMaxX4Groups]uint8,
	groups int,
) error {
	ops := decode2IFMAOpsX4{}
	return batchEncodeIFMAX4(w, out, points, active, groups, &ops)
}

func batchEncodeIFMAX4(
	w *ExperimentalIFMABatchEncodeWorkspaceX4,
	out *[ExperimentalIFMABatchEncodeMaxX4Groups][X4Lanes][32]byte,
	points *[ExperimentalIFMABatchEncodeMaxX4Groups]IFMAPointX4,
	active *[ExperimentalIFMABatchEncodeMaxX4Groups]uint8,
	groups int,
	ops *decode2IFMAOpsX4,
) error {
	if groups < 1 || groups > ExperimentalIFMABatchEncodeMaxX4Groups {
		return errIFMABatchEncodeGroupCount
	}

	// Validate the external-to-composable boundary exactly once. The fixed
	// exponent and prefix schedules can then use unchecked IFMA products while
	// preserving their u52 input invariant.
	var anyActive uint8
	for group := 0; group < groups; group++ {
		if active[group]&^uint8(0x0f) != 0 {
			return errIFMABatchEncodeActiveMask
		}
		point := &points[group]
		if !isIFMAElementX4(&point.X) || !isIFMAElementX4(&point.Y) ||
			!isIFMAElementX4(&point.Z) || !isIFMAElementX4(&point.T) {
			return errIFMAComposableInputRange
		}
		anyActive |= active[group]
	}

	for group := 0; group < groups; group++ {
		w.staged[group] = [X4Lanes][32]byte{}
	}
	if anyActive == 0 {
		for group := 0; group < groups; group++ {
			out[group] = w.staged[group]
		}
		return nil
	}

	if err := batchInvertPointZX4(&w.inverseZ, &w.prefix, points, active, groups, ops); err != nil {
		return err
	}
	for group := 0; group < groups; group++ {
		mask := active[group] & 0x0f
		if mask == 0 {
			continue
		}
		if err := encodeAffineIFMAX4(&w.staged[group], &points[group], &w.inverseZ[group], mask, ops); err != nil {
			return err
		}
	}

	for group := 0; group < groups; group++ {
		out[group] = w.staged[group]
	}
	return nil
}

// batchInvertPointZX4 is the reusable cross-group Montgomery core. It writes
// one reciprocal-Z vector per group while treating inactive lanes as one.
// Keeping recovery separate from serialization lets a later strict-only
// comparator batch-invert only the lanes that survive a projective Y check.
func batchInvertPointZX4(
	out, prefix *[ExperimentalIFMABatchEncodeMaxX4Groups]IFMAElementX4,
	points *[ExperimentalIFMABatchEncodeMaxX4Groups]IFMAPointX4,
	active *[ExperimentalIFMABatchEncodeMaxX4Groups]uint8,
	groups int,
	ops *decode2IFMAOpsX4,
) error {
	var oneScalar Element
	oneScalar.One()
	oneReduced := broadcastX4(&oneScalar)
	var one IFMAElementX4
	one.SetReduced(&oneReduced)

	// Inclusive prefix products start at the first nonempty group. Starting at
	// group zero would waste three multiplications whenever one or more leading
	// groups are empty: one in the forward pass and two in recovery.
	first := 0
	for first < groups && active[first] == 0 {
		first++
	}
	if first == groups {
		return nil
	}
	prefix[first] = sanitizedBatchEncodeZX4(&points[first].Z, active[first], &one)
	for group := first + 1; group < groups; group++ {
		mask := active[group] & 0x0f
		if mask == 0 {
			prefix[group] = prefix[group-1]
			continue
		}
		z := sanitizedBatchEncodeZX4(&points[group].Z, mask, &one)
		if err := ops.mul(&prefix[group], &prefix[group-1], &z); err != nil {
			return err
		}
	}

	// A valid extended Edwards point has a nonzero field Z. Reject a violated
	// caller invariant before Fermat inversion maps zero to zero and contaminates
	// every active point in the same SIMD lane. Reducing the final product also
	// catches bounded noncanonical zero representatives such as p.
	activeLanes := uint8(0)
	for group := first; group < groups; group++ {
		activeLanes |= active[group]
	}
	total := prefix[groups-1].Reduced()
	for lane := 0; lane < X4Lanes; lane++ {
		totalLane := total.Lane(lane)
		if activeLanes&(1<<lane) != 0 && totalLane.IsZero() != 0 {
			return errIFMABatchEncodeZeroZ
		}
	}

	// One exact x4 inversion replaces one inversion per x4 group. The reverse
	// pass reconstructs each reciprocal with two multiplications per preceding
	// prefix. Serialization separately pays X/Z and Y/Z per nonempty group.
	var inverseProduct IFMAElementX4
	if err := invertIFMAX4(&inverseProduct, &prefix[groups-1], ops); err != nil {
		return err
	}
	for group := groups - 1; group > first; group-- {
		mask := active[group] & 0x0f
		if mask == 0 {
			continue
		}
		if err := ops.mul(&out[group], &inverseProduct, &prefix[group-1]); err != nil {
			return err
		}
		z := sanitizedBatchEncodeZX4(&points[group].Z, mask, &one)
		if err := ops.mul(&inverseProduct, &inverseProduct, &z); err != nil {
			return err
		}
	}
	out[first] = inverseProduct
	return nil
}

func sanitizedBatchEncodeZX4(z *IFMAElementX4, active uint8, one *IFMAElementX4) IFMAElementX4 {
	var out IFMAElementX4
	decodeSelectIFMAX4(&out, one, z, active&0x0f)
	return out
}

func encodeAffineIFMAX4(
	out *[X4Lanes][32]byte,
	point *IFMAPointX4,
	inverseZ *IFMAElementX4,
	active uint8,
	ops *decode2IFMAOpsX4,
) error {
	var x, y IFMAElementX4
	if err := ops.mul(&x, &point.X, inverseZ); err != nil {
		return err
	}
	if err := ops.mul(&y, &point.Y, inverseZ); err != nil {
		return err
	}
	xReduced, yReduced := x.Reduced(), y.Reduced()
	for lane := 0; lane < X4Lanes; lane++ {
		if active&(1<<lane) == 0 {
			continue
		}
		xLane, yLane := xReduced.Lane(lane), yReduced.Lane(lane)
		encoded := yLane.Bytes()
		encoded[31] |= byte(xLane.IsNegative() << 7)
		out[lane] = encoded
	}
	return nil
}

// invertIFMAX4 mirrors Element.Invert exactly in the composable x4 domain.
// Its addition chain computes x^(p-2) using 254 squarings and 11 general
// multiplications. Squarings deliberately use the current composable multiply
// primitive; a future dedicated square kernel can change the implementation
// without changing this encoder's exponent or range contract.
func invertIFMAX4(z, x *IFMAElementX4, ops *decode2IFMAOpsX4) error {
	base := *x
	var x2, x9, x11 IFMAElementX4
	if err := ops.mul(&x2, &base, &base); err != nil {
		return err
	}
	if err := repeatedSquareMultiplyIFMAX4(&x9, &x2, &base, 2, ops); err != nil {
		return err
	}
	if err := ops.mul(&x11, &x9, &x2); err != nil {
		return err
	}

	var x5, x10, x20, x40, x50, x100, x200, x250 IFMAElementX4
	if err := repeatedSquareMultiplyIFMAX4(&x5, &x11, &x9, 1, ops); err != nil {
		return err
	}
	if err := repeatedSquareMultiplyIFMAX4(&x10, &x5, &x5, 5, ops); err != nil {
		return err
	}
	if err := repeatedSquareMultiplyIFMAX4(&x20, &x10, &x10, 10, ops); err != nil {
		return err
	}
	if err := repeatedSquareMultiplyIFMAX4(&x40, &x20, &x20, 20, ops); err != nil {
		return err
	}
	if err := repeatedSquareMultiplyIFMAX4(&x50, &x40, &x10, 10, ops); err != nil {
		return err
	}
	if err := repeatedSquareMultiplyIFMAX4(&x100, &x50, &x50, 50, ops); err != nil {
		return err
	}
	if err := repeatedSquareMultiplyIFMAX4(&x200, &x100, &x100, 100, ops); err != nil {
		return err
	}
	if err := repeatedSquareMultiplyIFMAX4(&x250, &x200, &x50, 50, ops); err != nil {
		return err
	}
	return repeatedSquareMultiplyIFMAX4(z, &x250, &x11, 5, ops)
}
