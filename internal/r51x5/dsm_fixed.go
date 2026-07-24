package r51x5

// FixedDSMScalarsX4 stores two canonical 32-byte Ed25519 scalar encodings per
// lane. It is the allocation-free ordinary-verifier counterpart of
// DSMScalarsX4; HEEA must continue using arbitrary-width SignedMagnitude.
type FixedDSMScalarsX4 [DSMTerms][X4Lanes][32]byte

// FixedDSMScalarsX8 is the eight-lane counterpart of FixedDSMScalarsX4.
type FixedDSMScalarsX8 [DSMTerms][X8Lanes][32]byte

// FixedDSMWorkspaceX4 owns the sizeable tables and digit schedules needed by
// an ordinary four-lane DSM. Callers can retain and reuse it so neither cold
// preparation nor evaluation needs per-call heap allocation.
type FixedDSMWorkspaceX4 struct {
	tables    [DSMTerms]FullTableX4
	digits    [DSMTerms]FixedRadixDigitsX4
	radixBits uint8
	prepared  bool
}

// FixedDSMWorkspaceX8 is the eight-lane counterpart of FixedDSMWorkspaceX4.
type FixedDSMWorkspaceX8 struct {
	tables    [DSMTerms]FullTableX8
	digits    [DSMTerms]FixedRadixDigitsX8
	radixBits uint8
	prepared  bool
}

// Prepare builds both positive full tables into caller-owned storage.
func (w *FixedDSMWorkspaceX4) Prepare(bases *[DSMTerms]PointX4, radixBits uint) {
	fixedScalarRoundCount(radixBits) // validate before changing the workspace
	for term := 0; term < DSMTerms; term++ {
		buildFullTableX4Into(&w.tables[term], &bases[term], radixBits)
	}
	w.radixBits = uint8(radixBits)
	w.prepared = true
}

// Prepare is the eight-lane counterpart of FixedDSMWorkspaceX4.Prepare.
func (w *FixedDSMWorkspaceX8) Prepare(bases *[DSMTerms]PointX8, radixBits uint) {
	fixedScalarRoundCount(radixBits)
	for term := 0; term < DSMTerms; term++ {
		buildFullTableX8Into(&w.tables[term], &bases[term], radixBits)
	}
	w.radixBits = uint8(radixBits)
	w.prepared = true
}

// Evaluate computes [c0]P0+[c1]P1 from the tables most recently prepared in
// w. negativeMasks applies an exact integer sign per term and lane. The return
// value is active restricted to lanes with two canonical scalar encodings;
// all other output lanes are identities.
func (w *FixedDSMWorkspaceX4) Evaluate(out *PointX4, scalars *FixedDSMScalarsX4, negativeMasks *[DSMTerms]uint8, active uint8) uint8 {
	if !w.prepared {
		panic("r51x5: fixed x4 DSM workspace is not prepared")
	}
	active &= 0x0f
	usable := active
	for term := 0; term < DSMTerms; term++ {
		usable &= RecodeCanonicalScalarsX4(&w.digits[term], &scalars[term], negativeMasks[term], active, uint(w.radixBits))
	}
	acc := identityPointX4Value()
	if usable == 0 {
		*out = acc
		return 0
	}
	for round := w.digits[0].RoundCount() - 1; round >= 0; round-- {
		if round != w.digits[0].RoundCount()-1 {
			for doubling := uint8(0); doubling < w.radixBits; doubling++ {
				acc.Double(&acc)
			}
		}
		for term := 0; term < DSMTerms; term++ {
			digit := w.digits[term].Round(round)
			if digit.NonzeroMask&usable == 0 {
				continue
			}
			var selected PointX4
			SelectFullTableX4Public(&selected, &w.tables[term], digit, usable)
			acc.Add(&acc, &selected)
		}
	}
	*out = acc
	return usable
}

// Evaluate is the eight-lane counterpart of FixedDSMWorkspaceX4.Evaluate.
func (w *FixedDSMWorkspaceX8) Evaluate(out *PointX8, scalars *FixedDSMScalarsX8, negativeMasks *[DSMTerms]uint8, active uint8) uint8 {
	if !w.prepared {
		panic("r51x5: fixed x8 DSM workspace is not prepared")
	}
	usable := active
	for term := 0; term < DSMTerms; term++ {
		usable &= RecodeCanonicalScalarsX8(&w.digits[term], &scalars[term], negativeMasks[term], active, uint(w.radixBits))
	}
	acc := identityPointX8Value()
	if usable == 0 {
		*out = acc
		return 0
	}
	for round := w.digits[0].RoundCount() - 1; round >= 0; round-- {
		if round != w.digits[0].RoundCount()-1 {
			for doubling := uint8(0); doubling < w.radixBits; doubling++ {
				acc.Double(&acc)
			}
		}
		for term := 0; term < DSMTerms; term++ {
			digit := w.digits[term].Round(round)
			if digit.NonzeroMask&usable == 0 {
				continue
			}
			var selected PointX8
			SelectFullTableX8Public(&selected, &w.tables[term], digit, usable)
			acc.Add(&acc, &selected)
		}
	}
	*out = acc
	return usable
}
