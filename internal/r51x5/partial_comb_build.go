// Vectorised A6/r9 partial-comb table construction.
//
// Promoted verbatim from heterogeneous_partial_comb_vector_build_experiment_test.go.
// This is the only viable builder: the scalar four-builder path measures ~185x
// slower (2411us/key vs 13.05us/key on Zen 5), so the registered backend needs
// this one to make per-key tables affordable. Names are unchanged so the move is
// provably behaviour-neutral.

package r51x5

const (
	heterogeneousPartialCombA6R9VectorRowsExperiment       = 5
	heterogeneousPartialCombA6R9VectorEntriesExperiment    = 32
	heterogeneousPartialCombA6R9VectorPointCountExperiment = heterogeneousPartialCombA6R9VectorRowsExperiment * heterogeneousPartialCombA6R9VectorEntriesExperiment
)

// heterogeneousPartialCombA6R9VectorBuildWorkspaceExperiment owns every
// large temporary in the x4 construction schedule. One workspace is reusable
// but not concurrent. Its 160 projective vectors hold 640 scalar points: one
// A6/r9 table for each of four independent keys.
//
// The prefix and inverse arrays implement one Montgomery inversion schedule
// over all 160 projective Z vectors. staged keeps the caller's output atomic
// across unavailable-hardware, input-range, zero-Z, and injected arithmetic
// failures.
type heterogeneousPartialCombA6R9VectorBuildWorkspaceExperiment struct {
	// rowBase lives in caller-owned scratch because the model-capable point
	// helper conservatively makes its point argument escape under the Go 1.26
	// compiler. Keeping the 640-byte value here avoids one heap allocation per
	// hardware table build without weakening the shared model/hardware oracle.
	rowBase    IFMAPointX4
	projective [heterogeneousPartialCombA6R9VectorPointCountExperiment]IFMAPointX4
	prefix     [heterogeneousPartialCombA6R9VectorPointCountExperiment]IFMAElementX4
	inverseZ   [heterogeneousPartialCombA6R9VectorPointCountExperiment]IFMAElementX4
	staged     [X4Lanes][heterogeneousPartialCombA6R9VectorPointCountExperiment]ifmaAffine3MicroAoSEntryExperiment
}

// heterogeneousPartialCombA6R9VectorTableGroupExperiment is the reusable,
// allocation-free output. Call tablePointers after a deliberate value copy so
// the rebuilt slice headers point into the copy's own storage.
type heterogeneousPartialCombA6R9VectorTableGroupExperiment struct {
	storage [X4Lanes][heterogeneousPartialCombA6R9VectorPointCountExperiment]ifmaAffine3MicroAoSEntryExperiment
	tables  [X4Lanes]heterogeneousPartialCombTableExperiment
}

func (g *heterogeneousPartialCombA6R9VectorTableGroupExperiment) resetTableViews() {
	for lane := range g.tables {
		g.tables[lane] = heterogeneousPartialCombTableExperiment{
			points: g.storage[lane][:],
			spec:   heterogeneousPartialCombA6R9Experiment,
		}
	}
}

func (g *heterogeneousPartialCombA6R9VectorTableGroupExperiment) tablePointers() [X4Lanes]*heterogeneousPartialCombTableExperiment {
	g.resetTableViews()
	var out [X4Lanes]*heterogeneousPartialCombTableExperiment
	for lane := range out {
		out[lane] = &g.tables[lane]
	}
	return out
}

// buildHeterogeneousPartialCombA6R9VectorGroupExperiment executes the hardware
// construction experiment. bases must contain four valid reduced extended
// Edwards points with nonzero field Z. Inputs and output must not overlap the
// mutable workspace. The output remains unchanged on every error.
func buildHeterogeneousPartialCombA6R9VectorGroupExperiment(
	out *heterogeneousPartialCombA6R9VectorTableGroupExperiment,
	bases *PointX4,
	workspace *heterogeneousPartialCombA6R9VectorBuildWorkspaceExperiment,
) error {
	if !ExperimentalIFMAAvailable() {
		return ErrIFMAUnavailable
	}
	ops := decode2IFMAOpsX4{hardware: true, uncheckedInputs: true}
	return buildHeterogeneousPartialCombA6R9VectorGroupWithOpsExperiment(out, bases, workspace, &ops)
}

// buildHeterogeneousPartialCombA6R9VectorGroupModelExperiment keeps the same
// table, batch-inversion, affine conversion, and atomic-commit schedule
// executable on hosts without AVX-512 IFMA. A separate IFMA-gated test
// exhaustively compares the actual hardware builder with the scalar tables.
func buildHeterogeneousPartialCombA6R9VectorGroupModelExperiment(
	out *heterogeneousPartialCombA6R9VectorTableGroupExperiment,
	bases *PointX4,
	workspace *heterogeneousPartialCombA6R9VectorBuildWorkspaceExperiment,
) error {
	ops := decode2IFMAOpsX4{}
	return buildHeterogeneousPartialCombA6R9VectorGroupWithOpsExperiment(out, bases, workspace, &ops)
}

func buildHeterogeneousPartialCombA6R9VectorGroupWithOpsExperiment(
	out *heterogeneousPartialCombA6R9VectorTableGroupExperiment,
	bases *PointX4,
	workspace *heterogeneousPartialCombA6R9VectorBuildWorkspaceExperiment,
	ops *decode2IFMAOpsX4,
) error {
	// PointX4 is the reduced external boundary. Check it explicitly before
	// SetReduced imports values into the unchecked composable schedule.
	if !IsReducedX4(bases.X.limbs) || !IsReducedX4(bases.Y.limbs) ||
		!IsReducedX4(bases.Z.limbs) || !IsReducedX4(bases.T.limbs) {
		return errIFMAComposableInputRange
	}

	rowBase := &workspace.rowBase
	rowBase.SetReduced(bases)
	pointIndex := 0
	for row := 0; row < heterogeneousPartialCombA6R9VectorRowsExperiment; row++ {
		multiple := *rowBase
		for entry := 0; entry < heterogeneousPartialCombA6R9VectorEntriesExperiment; entry++ {
			workspace.projective[pointIndex] = multiple
			pointIndex++
			if entry+1 < heterogeneousPartialCombA6R9VectorEntriesExperiment {
				if err := heterogeneousPartialCombA6R9VectorPointAddExperiment(&multiple, &multiple, rowBase, ops); err != nil {
					return err
				}
			}
		}
		if row+1 < heterogeneousPartialCombA6R9VectorRowsExperiment {
			for doubling := 0; doubling < int(heterogeneousPartialCombA6R9Experiment.width)*heterogeneousPartialCombA6R9Experiment.passes; doubling++ {
				if err := heterogeneousPartialCombA6R9VectorPointDoubleExperiment(rowBase, rowBase, ops); err != nil {
					return err
				}
			}
		}
	}
	if pointIndex != heterogeneousPartialCombA6R9VectorPointCountExperiment {
		panic("r51x5: A6/r9 vector builder generated the wrong point count")
	}

	if err := batchInvertHeterogeneousPartialCombA6R9ZX4Experiment(workspace, ops); err != nil {
		return err
	}
	for index := range workspace.projective {
		point := &workspace.projective[index]
		inverseZ := &workspace.inverseZ[index]
		var x, y, xy, t2d, yPlusX, yMinusX IFMAElementX4
		if err := ops.mul(&x, &point.X, inverseZ); err != nil {
			return err
		}
		if err := ops.mul(&y, &point.Y, inverseZ); err != nil {
			return err
		}
		if err := ops.mul(&xy, &x, &y); err != nil {
			return err
		}
		if err := ops.mul(&t2d, &xy, &ifmaCurve2DX4); err != nil {
			return err
		}
		yPlusX.Add(&y, &x)
		yMinusX.Subtract(&y, &x)
		for lane := 0; lane < X4Lanes; lane++ {
			for limb := range yPlusX.limbs {
				workspace.staged[lane][index][limb] = [3]uint64{
					yPlusX.limbs[limb][lane],
					yMinusX.limbs[limb][lane],
					t2d.limbs[limb][lane],
				}
			}
		}
	}

	// Commit only after the entire arithmetic schedule has succeeded.
	out.storage = workspace.staged
	out.resetTableViews()
	return nil
}

func heterogeneousPartialCombA6R9VectorPointAddExperiment(
	out, a, b *IFMAPointX4,
	ops *decode2IFMAOpsX4,
) error {
	if ops.hardware && ops.uncheckedInputs {
		return ifmaPointAddComposableStaticX4(out, a, b)
	}
	return ifmaPointAddComposableX4(out, a, b, ops.mul)
}

func heterogeneousPartialCombA6R9VectorPointDoubleExperiment(
	out, point *IFMAPointX4,
	ops *decode2IFMAOpsX4,
) error {
	if ops.hardware && ops.uncheckedInputs {
		return ifmaPointDoubleComposableStaticX4(out, point)
	}
	return ifmaPointDoubleComposableX4(out, point, ops.mul)
}

// batchInvertHeterogeneousPartialCombA6R9ZX4Experiment is the fixed-160
// specialization of batchInvertPointZX4. All four lanes are live in every
// vector, so no identity sanitization or active-mask bookkeeping is needed.
// It performs 159 forward products, one x4 Fermat inversion, and 318 reverse
// products.
func batchInvertHeterogeneousPartialCombA6R9ZX4Experiment(
	workspace *heterogeneousPartialCombA6R9VectorBuildWorkspaceExperiment,
	ops *decode2IFMAOpsX4,
) error {
	workspace.prefix[0] = workspace.projective[0].Z
	for index := 1; index < heterogeneousPartialCombA6R9VectorPointCountExperiment; index++ {
		if err := ops.mul(&workspace.prefix[index], &workspace.prefix[index-1], &workspace.projective[index].Z); err != nil {
			return err
		}
	}

	// In a field, a product is zero iff at least one factor is zero. Reducing
	// the final loose product catches zero aliases as well as literal zero.
	total := workspace.prefix[heterogeneousPartialCombA6R9VectorPointCountExperiment-1].Reduced()
	for lane := 0; lane < X4Lanes; lane++ {
		totalLane := total.Lane(lane)
		if totalLane.IsZero() != 0 {
			return errIFMABatchEncodeZeroZ
		}
	}

	var inverseProduct IFMAElementX4
	if err := invertIFMAX4(&inverseProduct, &workspace.prefix[heterogeneousPartialCombA6R9VectorPointCountExperiment-1], ops); err != nil {
		return err
	}
	for index := heterogeneousPartialCombA6R9VectorPointCountExperiment - 1; index > 0; index-- {
		if err := ops.mul(&workspace.inverseZ[index], &inverseProduct, &workspace.prefix[index-1]); err != nil {
			return err
		}
		if err := ops.mul(&inverseProduct, &inverseProduct, &workspace.projective[index].Z); err != nil {
			return err
		}
	}
	workspace.inverseZ[0] = inverseProduct
	return nil
}

func reducedHeterogeneousPartialCombAffine3CoordinateExperiment(
	entry *ifmaAffine3MicroAoSEntryExperiment,
	coordinate int,
) Element {
	var packed IFMAElementX4
	for limb := range packed.limbs {
		packed.limbs[limb][0] = entry[limb][coordinate]
	}
	reduced := packed.Reduced()
	return reduced.Lane(0)
}
