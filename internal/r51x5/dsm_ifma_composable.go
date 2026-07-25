package r51x5

// ExperimentalIFMAFixedDSMWorkspaceX4 owns the positive tables and fixed
// scalar schedules for one four-lane, two-term DSM. The workspace is
// caller-owned and reusable, but is not safe for concurrent evaluation.
//
// It is deliberately unreachable from production dispatch. Its preparation
// methods and Evaluate execute the AVX-512 IFMA point path and return
// ErrIFMAUnavailable on CPUs without the complete feature set.
type experimentalIFMAFixedDSMWorkspaceX4[Storage ifmaFullTableStorageX4] struct {
	tables               [DSMTerms]ifmaFullTableX4[Storage]
	digits               [DSMTerms]FixedRadixDigitsX4
	radixBits            uint8
	fixedBasePrepared    bool
	variableBasePrepared bool
}

// ExperimentalIFMAFixedDSMWorkspaceX8 is the eight-lane counterpart of
// ExperimentalIFMAFixedDSMWorkspaceX4.
type experimentalIFMAFixedDSMWorkspaceX8[Storage ifmaFullTableStorageX8] struct {
	tables               [DSMTerms]ifmaFullTableX8[Storage]
	digits               [DSMTerms]FixedRadixDigitsX8
	radixBits            uint8
	fixedBasePrepared    bool
	variableBasePrepared bool
}

type ExperimentalIFMAFixedDSMWorkspaceRadix16X4 = experimentalIFMAFixedDSMWorkspaceX4[ifmaFullTableStorageRadix16X4]
type ExperimentalIFMAFixedDSMWorkspaceRadix16X8 = experimentalIFMAFixedDSMWorkspaceX8[ifmaFullTableStorageRadix16X8]

// The unsuffixed workspace is the radix-32 specialization used by the main
// forced verifier experiment.
type ExperimentalIFMAFixedDSMWorkspaceX4 = experimentalIFMAFixedDSMWorkspaceX4[ifmaFullTableStorageRadix32X4]
type ExperimentalIFMAFixedDSMWorkspaceX8 = experimentalIFMAFixedDSMWorkspaceX8[ifmaFullTableStorageRadix32X8]

type ExperimentalIFMAFixedDSMWorkspaceRadix64X4 = experimentalIFMAFixedDSMWorkspaceX4[ifmaFullTableStorageRadix64X4]
type ExperimentalIFMAFixedDSMWorkspaceRadix64X8 = experimentalIFMAFixedDSMWorkspaceX8[ifmaFullTableStorageRadix64X8]

// PrepareFixedBase builds [1]B through [radix/2]B for term zero directly in
// the composable u52 domain. A verifier can retain this table across arbitrary
// public keys. Repreparing B invalidates the per-key variable-base table.
func (w *experimentalIFMAFixedDSMWorkspaceX4[Storage]) PrepareFixedBase(base *PointX4, radixBits uint) error {
	fixedScalarRoundCount(radixBits) // validate before changing the workspace
	if !ExperimentalIFMAAvailable() {
		return ErrIFMAUnavailable
	}
	w.fixedBasePrepared = false
	w.variableBasePrepared = false
	if err := buildIFMAFullTableX4Into(&w.tables[0], base, radixBits); err != nil {
		return err
	}
	w.radixBits = uint8(radixBits)
	w.fixedBasePrepared = true
	return nil
}

// PrepareFixedBase is the x8 counterpart of
// ExperimentalIFMAFixedDSMWorkspaceX4.PrepareFixedBase.
func (w *experimentalIFMAFixedDSMWorkspaceX8[Storage]) PrepareFixedBase(base *PointX8, radixBits uint) error {
	fixedScalarRoundCount(radixBits)
	if !ExperimentalIFMAAvailable() {
		return ErrIFMAUnavailable
	}
	w.fixedBasePrepared = false
	w.variableBasePrepared = false
	if err := buildIFMAFullTableX8Into(&w.tables[0], base, radixBits); err != nil {
		return err
	}
	w.radixBits = uint8(radixBits)
	w.fixedBasePrepared = true
	return nil
}

// PrepareVariableBase builds the per-public-key table for term one. The fixed
// B table and its radix must already have been prepared. Repeated calls replace
// only A and retain B.
func (w *experimentalIFMAFixedDSMWorkspaceX4[Storage]) PrepareVariableBase(base *PointX4) error {
	if !w.fixedBasePrepared {
		panic("r51x5: experimental IFMA x4 fixed-base table is not prepared")
	}
	if !ExperimentalIFMAAvailable() {
		return ErrIFMAUnavailable
	}
	w.variableBasePrepared = false
	if err := buildIFMAFullTableX4Into(&w.tables[1], base, uint(w.radixBits)); err != nil {
		return err
	}
	w.variableBasePrepared = true
	return nil
}

// PrepareVariableBase is the x8 counterpart of
// ExperimentalIFMAFixedDSMWorkspaceX4.PrepareVariableBase.
func (w *experimentalIFMAFixedDSMWorkspaceX8[Storage]) PrepareVariableBase(base *PointX8) error {
	if !w.fixedBasePrepared {
		panic("r51x5: experimental IFMA x8 fixed-base table is not prepared")
	}
	if !ExperimentalIFMAAvailable() {
		return ErrIFMAUnavailable
	}
	w.variableBasePrepared = false
	if err := buildIFMAFullTableX8Into(&w.tables[1], base, uint(w.radixBits)); err != nil {
		return err
	}
	w.variableBasePrepared = true
	return nil
}

// PrepareBoth is an explicitly full-cold convenience operation. Verification
// throughput measurements should normally prepare B once, then time only
// PrepareVariableBase plus Evaluate for a cold arbitrary key.
func (w *experimentalIFMAFixedDSMWorkspaceX4[Storage]) PrepareBoth(bases *[DSMTerms]PointX4, radixBits uint) error {
	if err := w.PrepareFixedBase(&bases[0], radixBits); err != nil {
		return err
	}
	return w.PrepareVariableBase(&bases[1])
}

// PrepareBoth is the x8 counterpart of
// ExperimentalIFMAFixedDSMWorkspaceX4.PrepareBoth.
func (w *experimentalIFMAFixedDSMWorkspaceX8[Storage]) PrepareBoth(bases *[DSMTerms]PointX8, radixBits uint) error {
	if err := w.PrepareFixedBase(&bases[0], radixBits); err != nil {
		return err
	}
	return w.PrepareVariableBase(&bases[1])
}

// Evaluate computes [c0]P0+[c1]P1 using the tables most recently prepared in
// w. Scalars are canonical Ed25519 scalar encodings, but negativeMasks is an
// exact integer sign: in particular, -k is recoded as negative digits and is
// never replaced with L-k. This distinction is consensus-relevant for points
// with a torsion component.
//
// The returned mask is active restricted to lanes where both scalar encodings
// are canonical. Invalid and inactive lanes are identities. out is unchanged
// if an IFMA operation fails.
func (w *experimentalIFMAFixedDSMWorkspaceX4[Storage]) Evaluate(out *IFMAPointX4, scalars *FixedDSMScalarsX4, negativeMasks *[DSMTerms]uint8, active uint8) (uint8, error) {
	if !w.fixedBasePrepared || !w.variableBasePrepared {
		panic("r51x5: experimental IFMA x4 DSM workspace is not prepared")
	}
	if !ExperimentalIFMAAvailable() {
		return 0, ErrIFMAUnavailable
	}
	active &= 0x0f
	usable := active
	for term := 0; term < DSMTerms; term++ {
		usable &= RecodeCanonicalScalarsX4(&w.digits[term], &scalars[term], negativeMasks[term], active, uint(w.radixBits))
	}
	acc := identityIFMAPointX4Value()
	if usable == 0 {
		*out = acc
		return 0, nil
	}
	rounds := w.digits[0].RoundCount()
	for round := rounds - 1; round >= 0; round-- {
		if round != rounds-1 {
			for doubling := uint8(0); doubling < w.radixBits; doubling++ {
				if err := ifmaPointDoubleComposableStaticX4(&acc, &acc); err != nil {
					return 0, err
				}
			}
		}
		for term := 0; term < DSMTerms; term++ {
			digit := w.digits[term].Round(round)
			if digit.NonzeroMask&usable == 0 {
				continue
			}
			var selected IFMAPointX4
			selectIFMAFullTableX4PublicUncheckedNoAlias(&selected, &w.tables[term], digit, usable)
			if err := ifmaPointAddComposableStaticX4(&acc, &acc, &selected); err != nil {
				return 0, err
			}
		}
	}
	*out = acc
	return usable, nil
}

// Evaluate is the x8 counterpart of
// ExperimentalIFMAFixedDSMWorkspaceX4.Evaluate.
func (w *experimentalIFMAFixedDSMWorkspaceX8[Storage]) Evaluate(out *IFMAPointX8, scalars *FixedDSMScalarsX8, negativeMasks *[DSMTerms]uint8, active uint8) (uint8, error) {
	if !w.fixedBasePrepared || !w.variableBasePrepared {
		panic("r51x5: experimental IFMA x8 DSM workspace is not prepared")
	}
	if !ExperimentalIFMAAvailable() {
		return 0, ErrIFMAUnavailable
	}
	usable := active
	for term := 0; term < DSMTerms; term++ {
		usable &= RecodeCanonicalScalarsX8(&w.digits[term], &scalars[term], negativeMasks[term], active, uint(w.radixBits))
	}
	acc := identityIFMAPointX8Value()
	if usable == 0 {
		*out = acc
		return 0, nil
	}
	rounds := w.digits[0].RoundCount()
	for round := rounds - 1; round >= 0; round-- {
		if round != rounds-1 {
			for doubling := uint8(0); doubling < w.radixBits; doubling++ {
				if err := ifmaPointDoubleComposableStaticX8(&acc, &acc); err != nil {
					return 0, err
				}
			}
		}
		for term := 0; term < DSMTerms; term++ {
			digit := w.digits[term].Round(round)
			if digit.NonzeroMask&usable == 0 {
				continue
			}
			var selected IFMAPointX8
			selectIFMAFullTableX8PublicUncheckedNoAlias(&selected, &w.tables[term], digit, usable)
			if err := ifmaPointAddComposableStaticX8(&acc, &acc, &selected); err != nil {
				return 0, err
			}
		}
	}
	*out = acc
	return usable, nil
}

func buildIFMAFullTableX4Into[Storage ifmaFullTableStorageX4](table *ifmaFullTableX4[Storage], base *PointX4, radixBits uint) error {
	validateIFMAFullTableStorage(len(table.points), radixBits)
	table.entries = regularRadixEntries(radixBits)
	table.radixBits = radixBits
	var composableBase IFMAPointX4
	composableBase.SetReduced(base)
	table.points[0] = composableBase
	for entry := 1; entry < table.entries; entry++ {
		if err := ifmaPointAddComposableStaticX4(&table.points[entry], &table.points[entry-1], &composableBase); err != nil {
			return err
		}
	}
	return nil
}

func buildIFMAFullTableX8Into[Storage ifmaFullTableStorageX8](table *ifmaFullTableX8[Storage], base *PointX8, radixBits uint) error {
	validateIFMAFullTableStorage(len(table.points), radixBits)
	table.entries = regularRadixEntries(radixBits)
	table.radixBits = radixBits
	var composableBase IFMAPointX8
	composableBase.SetReduced(base)
	table.points[0] = composableBase
	for entry := 1; entry < table.entries; entry++ {
		if err := ifmaPointAddComposableStaticX8(&table.points[entry], &table.points[entry-1], &composableBase); err != nil {
			return err
		}
	}
	return nil
}
