package r51x5

// ExperimentalIFMAVariableBaseWorkspaceX4 owns exactly one arbitrary-point
// table and one fixed scalar schedule. It is the test-only companion to the
// two-term DSM workspace for experiments that evaluate [s]B separately with
// a shared fixed-base comb, so they do not retain or touch a dummy identity
// table. The workspace is caller-owned, reusable, and not concurrent-safe.
type experimentalIFMAVariableBaseWorkspaceX4[Storage ifmaFullTableStorageX4] struct {
	table     ifmaFullTableX4[Storage]
	digits    FixedRadixDigitsX4
	radixBits uint8
	prepared  bool
}

// ExperimentalIFMAVariableBaseWorkspaceX8 is the eight-lane counterpart of
// ExperimentalIFMAVariableBaseWorkspaceX4.
type experimentalIFMAVariableBaseWorkspaceX8[Storage ifmaFullTableStorageX8] struct {
	table     ifmaFullTableX8[Storage]
	digits    FixedRadixDigitsX8
	radixBits uint8
	prepared  bool
}

// experimentalIFMAVariableBaseMicroAoSWorkspaceX4 is the cold radix-32 x4
// workspace. It builds directly into per-key micro-AoS entries, avoiding both
// the grouped-SoA table and a post-build conversion/allocation.
type experimentalIFMAVariableBaseMicroAoSWorkspaceX4 struct {
	table    ifmaMicroAoSTableRadix32X4
	digits   FixedRadixDigitsX4
	prepared bool
}

type ExperimentalIFMAVariableBaseWorkspaceRadix16X4 = experimentalIFMAVariableBaseWorkspaceX4[ifmaFullTableStorageRadix16X4]
type ExperimentalIFMAVariableBaseWorkspaceRadix16X8 = experimentalIFMAVariableBaseWorkspaceX8[ifmaFullTableStorageRadix16X8]

type ExperimentalIFMAVariableBaseWorkspaceX4 = experimentalIFMAVariableBaseMicroAoSWorkspaceX4
type ExperimentalIFMAVariableBaseWorkspaceX8 = experimentalIFMAVariableBaseWorkspaceX8[ifmaFullTableStorageRadix32X8]

type ExperimentalIFMAVariableBaseWorkspaceRadix64X4 = experimentalIFMAVariableBaseWorkspaceX4[ifmaFullTableStorageRadix64X4]
type ExperimentalIFMAVariableBaseWorkspaceRadix64X8 = experimentalIFMAVariableBaseWorkspaceX8[ifmaFullTableStorageRadix64X8]

func (w *experimentalIFMAVariableBaseMicroAoSWorkspaceX4) Prepare(base *PointX4, radixBits uint) error {
	validateIFMAFullTableStorage(16, radixBits)
	if !ExperimentalIFMAAvailable() {
		return ErrIFMAUnavailable
	}
	w.prepared = false
	var composableBase IFMAPointX4
	composableBase.SetReduced(base)
	current := composableBase
	for entry := 0; entry < 16; entry++ {
		for limb := 0; limb < 5; limb++ {
			for lane := 0; lane < X4Lanes; lane++ {
				w.table[lane][entry][limb] = [4]uint64{
					current.X.limbs[limb][lane],
					current.Y.limbs[limb][lane],
					current.Z.limbs[limb][lane],
					current.T.limbs[limb][lane],
				}
			}
		}
		if entry != 15 {
			if err := ifmaPointAddComposableStaticX4(&current, &current, &composableBase); err != nil {
				return err
			}
		}
	}
	w.prepared = true
	return nil
}

func (w *experimentalIFMAVariableBaseMicroAoSWorkspaceX4) Evaluate(out *IFMAPointX4, scalar *[X4Lanes][32]byte, negativeMask, active uint8) (uint8, error) {
	if !w.prepared {
		panic("r51x5: experimental IFMA x4 variable-base workspace is not prepared")
	}
	if !ExperimentalIFMAAvailable() {
		return 0, ErrIFMAUnavailable
	}
	active &= 0x0f
	usable := RecodeCanonicalScalarsX4(&w.digits, scalar, negativeMask, active, 5)
	acc := identityIFMAPointX4Value()
	if usable == 0 {
		*out = acc
		return 0, nil
	}
	for round := w.digits.RoundCount() - 1; round >= 0; round-- {
		if round != w.digits.RoundCount()-1 {
			for doubling := uint8(0); doubling < 5; doubling++ {
				if err := ifmaPointDoubleComposableStaticX4(&acc, &acc); err != nil {
					return 0, err
				}
			}
		}
		digit := w.digits.Round(round)
		if digit.NonzeroMask&usable == 0 {
			continue
		}
		var selected IFMAPointX4
		selectIFMAMicroAoSRadix32UncheckedX4(&selected, &w.table, digit, usable)
		if err := ifmaPointAddComposableStaticX4(&acc, &acc, &selected); err != nil {
			return 0, err
		}
	}
	*out = acc
	return usable, nil
}

// EvaluateRawSquareExperiment uses the exact-representation raw-square x4
// candidate for every point doubling while keeping preparation, recoding,
// selection, addition, and output identical to Evaluate. The loop is separate
// so the registered evaluator pays no experiment branch in its 250-doubling
// hot path.
func (w *experimentalIFMAVariableBaseMicroAoSWorkspaceX4) EvaluateRawSquareExperiment(out *IFMAPointX4, scalar *[X4Lanes][32]byte, negativeMask, active uint8) (uint8, error) {
	if !w.prepared {
		panic("r51x5: experimental IFMA x4 variable-base workspace is not prepared")
	}
	if !ExperimentalIFMAAvailable() {
		return 0, ErrIFMAUnavailable
	}
	active &= 0x0f
	usable := RecodeCanonicalScalarsX4(&w.digits, scalar, negativeMask, active, 5)
	acc := identityIFMAPointX4Value()
	if usable == 0 {
		*out = acc
		return 0, nil
	}
	for round := w.digits.RoundCount() - 1; round >= 0; round-- {
		if round != w.digits.RoundCount()-1 {
			for doubling := uint8(0); doubling < 5; doubling++ {
				if err := ifmaPointDoubleRawSquareStage2ExperimentX4(&acc, &acc); err != nil {
					return 0, err
				}
			}
		}
		digit := w.digits.Round(round)
		if digit.NonzeroMask&usable == 0 {
			continue
		}
		var selected IFMAPointX4
		selectIFMAMicroAoSRadix32UncheckedX4(&selected, &w.table, digit, usable)
		if err := ifmaPointAddComposableStaticX4(&acc, &acc, &selected); err != nil {
			return 0, err
		}
	}
	*out = acc
	return usable, nil
}

// Prepare replaces the x4 arbitrary-point table. Radix bits must be four,
// five, or six. No production verifier dispatch reaches this experiment.
func (w *experimentalIFMAVariableBaseWorkspaceX4[Storage]) Prepare(base *PointX4, radixBits uint) error {
	fixedScalarRoundCount(radixBits)
	if !ExperimentalIFMAAvailable() {
		return ErrIFMAUnavailable
	}
	w.prepared = false
	if err := buildIFMAFullTableX4Into(&w.table, base, radixBits); err != nil {
		return err
	}
	w.radixBits = uint8(radixBits)
	w.prepared = true
	return nil
}

// Prepare is the x8 counterpart of
// ExperimentalIFMAVariableBaseWorkspaceX4.Prepare.
func (w *experimentalIFMAVariableBaseWorkspaceX8[Storage]) Prepare(base *PointX8, radixBits uint) error {
	fixedScalarRoundCount(radixBits)
	if !ExperimentalIFMAAvailable() {
		return ErrIFMAUnavailable
	}
	w.prepared = false
	if err := buildIFMAFullTableX8Into(&w.table, base, radixBits); err != nil {
		return err
	}
	w.radixBits = uint8(radixBits)
	w.prepared = true
	return nil
}

// Evaluate computes an exact signed [scalar]P from the most recently prepared
// x4 table. scalar must be a canonical modulo-L encoding, but negativeMask is
// an integer sign rather than an L-scalar negation. The returned mask excludes
// inactive and noncanonical lanes; those output lanes are identities.
func (w *experimentalIFMAVariableBaseWorkspaceX4[Storage]) Evaluate(out *IFMAPointX4, scalar *[X4Lanes][32]byte, negativeMask, active uint8) (uint8, error) {
	if !w.prepared {
		panic("r51x5: experimental IFMA x4 variable-base workspace is not prepared")
	}
	if !ExperimentalIFMAAvailable() {
		return 0, ErrIFMAUnavailable
	}
	active &= 0x0f
	usable := RecodeCanonicalScalarsX4(&w.digits, scalar, negativeMask, active, uint(w.radixBits))
	acc := identityIFMAPointX4Value()
	if usable == 0 {
		*out = acc
		return 0, nil
	}
	for round := w.digits.RoundCount() - 1; round >= 0; round-- {
		if round != w.digits.RoundCount()-1 {
			for doubling := uint8(0); doubling < w.radixBits; doubling++ {
				if err := ifmaPointDoubleComposableStaticX4(&acc, &acc); err != nil {
					return 0, err
				}
			}
		}
		digit := w.digits.Round(round)
		if digit.NonzeroMask&usable == 0 {
			continue
		}
		var selected IFMAPointX4
		selectIFMAFullTableX4PublicUncheckedNoAlias(&selected, &w.table, digit, usable)
		if err := ifmaPointAddComposableStaticX4(&acc, &acc, &selected); err != nil {
			return 0, err
		}
	}
	*out = acc
	return usable, nil
}

// Evaluate is the x8 counterpart of
// ExperimentalIFMAVariableBaseWorkspaceX4.Evaluate.
func (w *experimentalIFMAVariableBaseWorkspaceX8[Storage]) Evaluate(out *IFMAPointX8, scalar *[X8Lanes][32]byte, negativeMask, active uint8) (uint8, error) {
	if !w.prepared {
		panic("r51x5: experimental IFMA x8 variable-base workspace is not prepared")
	}
	if !ExperimentalIFMAAvailable() {
		return 0, ErrIFMAUnavailable
	}
	usable := RecodeCanonicalScalarsX8(&w.digits, scalar, negativeMask, active, uint(w.radixBits))
	acc := identityIFMAPointX8Value()
	var doubleWorkspace ifmaPointDoubleWorkspaceX8
	if usable == 0 {
		*out = acc
		return 0, nil
	}
	for round := w.digits.RoundCount() - 1; round >= 0; round-- {
		if round != w.digits.RoundCount()-1 {
			for doubling := uint8(0); doubling < w.radixBits; doubling++ {
				if err := ifmaPointDoubleComposableWorkspaceStaticX8(&acc, &acc, &doubleWorkspace); err != nil {
					return 0, err
				}
			}
		}
		digit := w.digits.Round(round)
		if digit.NonzeroMask&usable == 0 {
			continue
		}
		var selected IFMAPointX8
		selectIFMAFullTableX8PublicUncheckedNoAlias(&selected, &w.table, digit, usable)
		if err := ifmaPointAddComposableStaticX8(&acc, &acc, &selected); err != nil {
			return 0, err
		}
	}
	*out = acc
	return usable, nil
}
