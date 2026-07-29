package r51x5

import "errors"

const ExperimentalIFMABatchEncodeMaxX8Groups = ExperimentalIFMABatchEncodeMaxX4Groups / 2

var (
	errIFMABatchEncodeX8GroupCount = errors.New("r51x5: invalid x8 batch-encode group count")
	errIFMABatchEncodeX8ZeroZ      = errors.New("r51x5: active x8 batch-encode lane has zero Z")
)

// ExperimentalIFMABatchEncodeWorkspaceX8 is the native-wide counterpart of
// ExperimentalIFMABatchEncodeWorkspaceX4. It retains the same one-inversion-
// per-chunk Montgomery schedule while doing the prefix, recovery, affine, and
// reduction work in eight lanes. It remains a measurement candidate until a
// complete 1,232-byte cold-verifier gate admits it.
type ExperimentalIFMABatchEncodeWorkspaceX8 struct {
	prefix   [ExperimentalIFMABatchEncodeMaxX8Groups]IFMAElementX8
	inverseZ [ExperimentalIFMABatchEncodeMaxX8Groups]IFMAElementX8
	staged   [ExperimentalIFMABatchEncodeMaxX8Groups][X8Lanes][32]byte
}

// Encode canonically encodes groups ready IFMAPointX8 values. Inactive Z
// coordinates are replaced by one before the shared prefix product, and an
// active field-zero Z fails before inversion. Output is committed atomically.
func (w *ExperimentalIFMABatchEncodeWorkspaceX8) Encode(
	out *[ExperimentalIFMABatchEncodeMaxX8Groups][X8Lanes][32]byte,
	points *[ExperimentalIFMABatchEncodeMaxX8Groups]IFMAPointX8,
	active *[ExperimentalIFMABatchEncodeMaxX8Groups]uint8,
	groups int,
) error {
	if !ExperimentalIFMAAvailable() {
		return ErrIFMAUnavailable
	}
	ops := decode2IFMAOpsX8{hardware: true, uncheckedInputs: true}
	return batchEncodeIFMAX8(w, out, points, active, groups, &ops)
}

func batchEncodeIFMAModelX8(
	w *ExperimentalIFMABatchEncodeWorkspaceX8,
	out *[ExperimentalIFMABatchEncodeMaxX8Groups][X8Lanes][32]byte,
	points *[ExperimentalIFMABatchEncodeMaxX8Groups]IFMAPointX8,
	active *[ExperimentalIFMABatchEncodeMaxX8Groups]uint8,
	groups int,
) error {
	ops := decode2IFMAOpsX8{}
	return batchEncodeIFMAX8(w, out, points, active, groups, &ops)
}

func batchEncodeIFMAX8(
	w *ExperimentalIFMABatchEncodeWorkspaceX8,
	out *[ExperimentalIFMABatchEncodeMaxX8Groups][X8Lanes][32]byte,
	points *[ExperimentalIFMABatchEncodeMaxX8Groups]IFMAPointX8,
	active *[ExperimentalIFMABatchEncodeMaxX8Groups]uint8,
	groups int,
	ops *decode2IFMAOpsX8,
) error {
	if groups < 1 || groups > ExperimentalIFMABatchEncodeMaxX8Groups {
		return errIFMABatchEncodeX8GroupCount
	}

	var anyActive uint8
	for group := 0; group < groups; group++ {
		point := &points[group]
		if !isIFMAElementX8(&point.X) || !isIFMAElementX8(&point.Y) ||
			!isIFMAElementX8(&point.Z) || !isIFMAElementX8(&point.T) {
			return errIFMAComposableInputRange
		}
		anyActive |= active[group]
		w.staged[group] = [X8Lanes][32]byte{}
	}
	if anyActive == 0 {
		for group := 0; group < groups; group++ {
			out[group] = w.staged[group]
		}
		return nil
	}

	if err := batchInvertPointZX8(&w.inverseZ, &w.prefix, points, active, groups, ops); err != nil {
		return err
	}
	for group := 0; group < groups; group++ {
		if active[group] == 0 {
			continue
		}
		if err := encodeAffineIFMAX8(&w.staged[group], &points[group], &w.inverseZ[group], active[group], ops); err != nil {
			return err
		}
	}
	for group := 0; group < groups; group++ {
		out[group] = w.staged[group]
	}
	return nil
}

func batchInvertPointZX8(
	out, prefix *[ExperimentalIFMABatchEncodeMaxX8Groups]IFMAElementX8,
	points *[ExperimentalIFMABatchEncodeMaxX8Groups]IFMAPointX8,
	active *[ExperimentalIFMABatchEncodeMaxX8Groups]uint8,
	groups int,
	ops *decode2IFMAOpsX8,
) error {
	oneReduced := broadcastX8(new(Element).One())
	var one IFMAElementX8
	one.SetReduced(&oneReduced)

	first := 0
	for first < groups && active[first] == 0 {
		first++
	}
	if first == groups {
		return nil
	}
	prefix[first] = sanitizedBatchEncodeZX8(&points[first].Z, active[first], &one)
	for group := first + 1; group < groups; group++ {
		if active[group] == 0 {
			prefix[group] = prefix[group-1]
			continue
		}
		z := sanitizedBatchEncodeZX8(&points[group].Z, active[group], &one)
		if err := ops.mul(&prefix[group], &prefix[group-1], &z); err != nil {
			return err
		}
	}

	var activeLanes uint8
	for group := first; group < groups; group++ {
		activeLanes |= active[group]
	}
	total := prefix[groups-1].Reduced()
	for lane := 0; lane < X8Lanes; lane++ {
		totalLane := total.Lane(lane)
		if activeLanes&(1<<lane) != 0 && totalLane.IsZero() != 0 {
			return errIFMABatchEncodeX8ZeroZ
		}
	}

	var inverseProduct IFMAElementX8
	if err := invertIFMAX8(&inverseProduct, &prefix[groups-1], ops); err != nil {
		return err
	}
	for group := groups - 1; group > first; group-- {
		if active[group] == 0 {
			continue
		}
		if err := ops.mul(&out[group], &inverseProduct, &prefix[group-1]); err != nil {
			return err
		}
		z := sanitizedBatchEncodeZX8(&points[group].Z, active[group], &one)
		if err := ops.mul(&inverseProduct, &inverseProduct, &z); err != nil {
			return err
		}
	}
	out[first] = inverseProduct
	return nil
}

func sanitizedBatchEncodeZX8(z *IFMAElementX8, active uint8, one *IFMAElementX8) IFMAElementX8 {
	var out IFMAElementX8
	decodeSelectIFMAX8(&out, one, z, active)
	return out
}

func encodeAffineIFMAX8(
	out *[X8Lanes][32]byte,
	point *IFMAPointX8,
	inverseZ *IFMAElementX8,
	active uint8,
	ops *decode2IFMAOpsX8,
) error {
	var x, y IFMAElementX8
	if err := ops.mul(&x, &point.X, inverseZ); err != nil {
		return err
	}
	if err := ops.mul(&y, &point.Y, inverseZ); err != nil {
		return err
	}
	xReduced, yReduced := x.Reduced(), y.Reduced()
	for lane := 0; lane < X8Lanes; lane++ {
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

func invertIFMAX8(z, x *IFMAElementX8, ops *decode2IFMAOpsX8) error {
	base := *x
	var x2, x9, x11 IFMAElementX8
	if err := ops.mul(&x2, &base, &base); err != nil {
		return err
	}
	if err := repeatedSquareMultiplyIFMAX8(&x9, &x2, &base, 2, ops); err != nil {
		return err
	}
	if err := ops.mul(&x11, &x9, &x2); err != nil {
		return err
	}

	var x5, x10, x20, x40, x50, x100, x200, x250 IFMAElementX8
	if err := repeatedSquareMultiplyIFMAX8(&x5, &x11, &x9, 1, ops); err != nil {
		return err
	}
	if err := repeatedSquareMultiplyIFMAX8(&x10, &x5, &x5, 5, ops); err != nil {
		return err
	}
	if err := repeatedSquareMultiplyIFMAX8(&x20, &x10, &x10, 10, ops); err != nil {
		return err
	}
	if err := repeatedSquareMultiplyIFMAX8(&x40, &x20, &x20, 20, ops); err != nil {
		return err
	}
	if err := repeatedSquareMultiplyIFMAX8(&x50, &x40, &x10, 10, ops); err != nil {
		return err
	}
	if err := repeatedSquareMultiplyIFMAX8(&x100, &x50, &x50, 50, ops); err != nil {
		return err
	}
	if err := repeatedSquareMultiplyIFMAX8(&x200, &x100, &x100, 100, ops); err != nil {
		return err
	}
	if err := repeatedSquareMultiplyIFMAX8(&x250, &x200, &x50, 50, ops); err != nil {
		return err
	}
	return repeatedSquareMultiplyIFMAX8(z, &x250, &x11, 5, ops)
}
