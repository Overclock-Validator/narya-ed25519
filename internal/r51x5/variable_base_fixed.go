package r51x5

// ExperimentalVariableBaseWorkspaceX4 owns one ordinary arbitrary-point
// table and scalar schedule. It is the scalar model for split fixed-base-comb
// experiments and avoids a dummy identity term in a two-term DSM workspace.
type ExperimentalVariableBaseWorkspaceX4 struct {
	table     FullTableX4
	digits    FixedRadixDigitsX4
	radixBits uint8
	prepared  bool
}

// ExperimentalVariableBaseWorkspaceX8 is the eight-lane counterpart of
// ExperimentalVariableBaseWorkspaceX4.
type ExperimentalVariableBaseWorkspaceX8 struct {
	table     FullTableX8
	digits    FixedRadixDigitsX8
	radixBits uint8
	prepared  bool
}

func (w *ExperimentalVariableBaseWorkspaceX4) Prepare(base *PointX4, radixBits uint) {
	fixedScalarRoundCount(radixBits)
	w.prepared = false
	buildFullTableX4Into(&w.table, base, radixBits)
	w.radixBits = uint8(radixBits)
	w.prepared = true
}

func (w *ExperimentalVariableBaseWorkspaceX8) Prepare(base *PointX8, radixBits uint) {
	fixedScalarRoundCount(radixBits)
	w.prepared = false
	buildFullTableX8Into(&w.table, base, radixBits)
	w.radixBits = uint8(radixBits)
	w.prepared = true
}

func (w *ExperimentalVariableBaseWorkspaceX4) Evaluate(out *PointX4, scalar *[X4Lanes][32]byte, negativeMask, active uint8) uint8 {
	if !w.prepared {
		panic("r51x5: experimental x4 variable-base workspace is not prepared")
	}
	active &= 0x0f
	usable := RecodeCanonicalScalarsX4(&w.digits, scalar, negativeMask, active, uint(w.radixBits))
	acc := identityPointX4Value()
	if usable == 0 {
		*out = acc
		return 0
	}
	for round := w.digits.RoundCount() - 1; round >= 0; round-- {
		if round != w.digits.RoundCount()-1 {
			for doubling := uint8(0); doubling < w.radixBits; doubling++ {
				acc.Double(&acc)
			}
		}
		digit := w.digits.Round(round)
		if digit.NonzeroMask&usable == 0 {
			continue
		}
		var selected PointX4
		SelectFullTableX4Public(&selected, &w.table, digit, usable)
		acc.Add(&acc, &selected)
	}
	*out = acc
	return usable
}

func (w *ExperimentalVariableBaseWorkspaceX8) Evaluate(out *PointX8, scalar *[X8Lanes][32]byte, negativeMask, active uint8) uint8 {
	if !w.prepared {
		panic("r51x5: experimental x8 variable-base workspace is not prepared")
	}
	usable := RecodeCanonicalScalarsX8(&w.digits, scalar, negativeMask, active, uint(w.radixBits))
	acc := identityPointX8Value()
	if usable == 0 {
		*out = acc
		return 0
	}
	for round := w.digits.RoundCount() - 1; round >= 0; round-- {
		if round != w.digits.RoundCount()-1 {
			for doubling := uint8(0); doubling < w.radixBits; doubling++ {
				acc.Double(&acc)
			}
		}
		digit := w.digits.Round(round)
		if digit.NonzeroMask&usable == 0 {
			continue
		}
		var selected PointX8
		SelectFullTableX8Public(&selected, &w.table, digit, usable)
		acc.Add(&acc, &selected)
	}
	*out = acc
	return usable
}
