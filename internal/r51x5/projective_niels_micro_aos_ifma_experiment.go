package r51x5

// ifmaProjectiveNielsMicroAoSEntryX8 stores one lane's projective-Niels point
// as five contiguous [Y+X,Y-X,Z,2dT] limb rows. The experiment keeps the
// production table's exact 160-byte-per-key-entry payload, but changes the
// cold table layout so eight independently selected entries can be loaded in
// contiguous 256-bit rows and transposed into the x8 SoA arithmetic layout.
type ifmaProjectiveNielsMicroAoSEntryX8 [5][4]uint64

type ifmaProjectiveNielsMicroAoSTableX8 [X8Lanes][16]ifmaProjectiveNielsMicroAoSEntryX8

// ifmaProjectiveNielsPreSignedMicroAoSTableX8 is a measurement candidate for
// moving public-scalar sign handling out of the selector. Index 0 stores the
// positive point and index 1 stores its exact Niels negation. It doubles the
// cold A-table payload, so only a complete cold prepare+evaluate benchmark can
// admit it; a selector-only win is insufficient.
type ifmaProjectiveNielsPreSignedMicroAoSTableX8 [X8Lanes][2][16]ifmaProjectiveNielsMicroAoSEntryX8

var ifmaProjectiveNielsMicroAoSIdentityX8 = func() ifmaProjectiveNielsMicroAoSEntryX8 {
	var identity ifmaProjectiveNielsMicroAoSEntryX8
	identity[0] = [4]uint64{1, 1, 1, 0}
	return identity
}()

// ExperimentalIFMAProjectiveNielsMicroAoSVariableBaseWorkspaceX8 owns the
// selected cold x8 variable-base table. It deliberately retains the
// Experimental prefix because automatic backend selection cannot reach r51.
// Prepare and Evaluate are allocation-free, and the grouped-SoA projective-
// Niels workspace remains an independent differential reference.
//
// Regime tag: the first complete-verifier integration regressed on an older
// x8 point loop. Re-measure it whenever surrounding point-add or point-double
// traffic changes; the selector-only verdict is not a production verdict.
type ExperimentalIFMAProjectiveNielsMicroAoSVariableBaseWorkspaceX8 struct {
	table    ifmaProjectiveNielsMicroAoSTableX8
	digits   FixedRadixDigitsX8
	prepared bool
}

// ExperimentalIFMAProjectiveNielsPreSignedMicroAoSVariableBaseWorkspaceX8
// owns the selected cold x8 A table with both public-scalar signs prepared.
// Regime tag: Zen 5 native-x8, cold arbitrary A, radix 32. On the 2026-07-25
// 9700X gate, pre-signing improved cold table-build+loop by about 7.2% despite
// doubling this workspace from about 20.6 to 40.6 KiB. Automatic backend
// selection still cannot reach r51.
type ExperimentalIFMAProjectiveNielsPreSignedMicroAoSVariableBaseWorkspaceX8 struct {
	table    ifmaProjectiveNielsPreSignedMicroAoSTableX8
	digits   FixedRadixDigitsX8
	prepared bool
}

func storeIFMAProjectiveNielsMicroAoSEntryX8(
	table *ifmaProjectiveNielsMicroAoSTableX8,
	entry int,
	point *IFMAProjectiveNielsX8,
) {
	for lane := 0; lane < X8Lanes; lane++ {
		for limb := range modulusLimbs {
			table[lane][entry][limb] = [4]uint64{
				point.YPlusX.limbs[limb][lane],
				point.YMinusX.limbs[limb][lane],
				point.Z.limbs[limb][lane],
				point.T2D.limbs[limb][lane],
			}
		}
	}
}

func storeIFMAProjectiveNielsPreSignedMicroAoSEntryX8(
	table *ifmaProjectiveNielsPreSignedMicroAoSTableX8,
	entry int,
	point *IFMAProjectiveNielsX8,
) {
	var negativeT2D IFMAElementX8
	negativeT2D.Negate(&point.T2D)
	for lane := 0; lane < X8Lanes; lane++ {
		for limb := range modulusLimbs {
			table[lane][0][entry][limb] = [4]uint64{
				point.YPlusX.limbs[limb][lane],
				point.YMinusX.limbs[limb][lane],
				point.Z.limbs[limb][lane],
				point.T2D.limbs[limb][lane],
			}
			table[lane][1][entry][limb] = [4]uint64{
				point.YMinusX.limbs[limb][lane],
				point.YPlusX.limbs[limb][lane],
				point.Z.limbs[limb][lane],
				negativeT2D.limbs[limb][lane],
			}
		}
	}
}

func (workspace *ExperimentalIFMAProjectiveNielsMicroAoSVariableBaseWorkspaceX8) Prepare(base *PointX8, radixBits uint) error {
	fixedScalarRoundCount(radixBits)
	if radixBits != 5 {
		panic("r51x5: projective Niels micro-AoS x8 workspace requires radix 32")
	}
	if !ExperimentalIFMAAvailable() {
		return ErrIFMAUnavailable
	}
	workspace.prepared = false
	var current IFMAPointX8
	var addWorkspace ifmaPointAddProjectiveNielsScratchX8
	current.SetReduced(base)
	var baseCached IFMAProjectiveNielsX8
	if err := ifmaProjectiveNielsFromPointX8(&baseCached, &current); err != nil {
		return err
	}
	storeIFMAProjectiveNielsMicroAoSEntryX8(&workspace.table, 0, &baseCached)
	for entry := 1; entry < 16; entry++ {
		if err := ifmaPointAddProjectiveNielsWorkspaceX8(&current, &current, &baseCached, &addWorkspace); err != nil {
			return err
		}
		var cached IFMAProjectiveNielsX8
		if err := ifmaProjectiveNielsFromPointX8(&cached, &current); err != nil {
			return err
		}
		storeIFMAProjectiveNielsMicroAoSEntryX8(&workspace.table, entry, &cached)
	}
	workspace.prepared = true
	return nil
}

func (workspace *ExperimentalIFMAProjectiveNielsPreSignedMicroAoSVariableBaseWorkspaceX8) Prepare(base *PointX8, radixBits uint) error {
	fixedScalarRoundCount(radixBits)
	if radixBits != 5 {
		panic("r51x5: pre-signed projective Niels micro-AoS x8 workspace requires radix 32")
	}
	if !ExperimentalIFMAAvailable() {
		return ErrIFMAUnavailable
	}
	workspace.prepared = false
	var current IFMAPointX8
	var addWorkspace ifmaPointAddProjectiveNielsScratchX8
	current.SetReduced(base)
	var baseCached IFMAProjectiveNielsX8
	if err := ifmaProjectiveNielsFromPointX8(&baseCached, &current); err != nil {
		return err
	}
	storeIFMAProjectiveNielsPreSignedMicroAoSEntryX8(&workspace.table, 0, &baseCached)
	for entry := 1; entry < 16; entry++ {
		if err := ifmaPointAddProjectiveNielsWorkspaceX8(&current, &current, &baseCached, &addWorkspace); err != nil {
			return err
		}
		var cached IFMAProjectiveNielsX8
		if err := ifmaProjectiveNielsFromPointX8(&cached, &current); err != nil {
			return err
		}
		storeIFMAProjectiveNielsPreSignedMicroAoSEntryX8(&workspace.table, entry, &cached)
	}
	workspace.prepared = true
	return nil
}

func (workspace *ExperimentalIFMAProjectiveNielsMicroAoSVariableBaseWorkspaceX8) Evaluate(
	out *IFMAPointX8,
	scalar *[X8Lanes][32]byte,
	negativeMask, active uint8,
) (uint8, error) {
	if !workspace.prepared {
		panic("r51x5: projective Niels micro-AoS x8 workspace is not prepared")
	}
	if !ExperimentalIFMAAvailable() {
		return 0, ErrIFMAUnavailable
	}
	usable := RecodeCanonicalScalarsX8(&workspace.digits, scalar, negativeMask, active, 5)
	acc := identityIFMAPointX8Value()
	var doubleWorkspace ifmaPointDoubleWorkspaceX8
	var addWorkspace ifmaPointAddProjectiveNielsScratchX8
	if usable == 0 {
		*out = acc
		return 0, nil
	}
	for round := workspace.digits.RoundCount() - 1; round >= 0; round-- {
		if round != workspace.digits.RoundCount()-1 {
			for doubling := 0; doubling < 5; doubling++ {
				if err := ifmaPointDoubleComposableWorkspaceStaticX8(&acc, &acc, &doubleWorkspace); err != nil {
					return 0, err
				}
			}
		}
		digit := workspace.digits.Round(round)
		if digit.NonzeroMask&usable == 0 {
			continue
		}
		var selected IFMAProjectiveNielsX8
		selectIFMAProjectiveNielsMicroAoSX8(&selected, &workspace.table, digit, usable)
		if err := ifmaPointAddProjectiveNielsWorkspaceX8(&acc, &acc, &selected, &addWorkspace); err != nil {
			return 0, err
		}
	}
	*out = acc
	return usable, nil
}

func (workspace *ExperimentalIFMAProjectiveNielsPreSignedMicroAoSVariableBaseWorkspaceX8) Evaluate(
	out *IFMAPointX8,
	scalar *[X8Lanes][32]byte,
	negativeMask, active uint8,
) (uint8, error) {
	if !workspace.prepared {
		panic("r51x5: pre-signed projective Niels micro-AoS x8 workspace is not prepared")
	}
	if !ExperimentalIFMAAvailable() {
		return 0, ErrIFMAUnavailable
	}
	usable := RecodeCanonicalScalarsX8(&workspace.digits, scalar, negativeMask, active, 5)
	acc := identityIFMAPointX8Value()
	var doubleWorkspace ifmaPointDoubleWorkspaceX8
	var addWorkspace ifmaPointAddProjectiveNielsScratchX8
	if usable == 0 {
		*out = acc
		return 0, nil
	}
	for round := workspace.digits.RoundCount() - 1; round >= 0; round-- {
		if round != workspace.digits.RoundCount()-1 {
			for doubling := 0; doubling < 5; doubling++ {
				if err := ifmaPointDoubleComposableWorkspaceStaticX8(&acc, &acc, &doubleWorkspace); err != nil {
					return 0, err
				}
			}
		}
		digit := workspace.digits.Round(round)
		if digit.NonzeroMask&usable == 0 {
			continue
		}
		var selected IFMAProjectiveNielsX8
		selectIFMAProjectiveNielsPreSignedMicroAoSX8(&selected, &workspace.table, digit, usable)
		if err := ifmaPointAddProjectiveNielsWorkspaceX8(&acc, &acc, &selected, &addWorkspace); err != nil {
			return 0, err
		}
	}
	*out = acc
	return usable, nil
}

func selectIFMAProjectiveNielsMicroAoSX8(
	out *IFMAProjectiveNielsX8,
	table *ifmaProjectiveNielsMicroAoSTableX8,
	round *RadixRoundX8,
	active uint8,
) {
	lookupMask := round.NonzeroMask & active
	negativeMask := round.NegativeMask & lookupMask
	p0 := &ifmaProjectiveNielsMicroAoSIdentityX8
	p1, p2, p3, p4, p5, p6, p7 := p0, p0, p0, p0, p0, p0, p0
	if lookupMask == 0xff {
		p0 = &table[0][int(round.Magnitude[0])-1]
		p1 = &table[1][int(round.Magnitude[1])-1]
		p2 = &table[2][int(round.Magnitude[2])-1]
		p3 = &table[3][int(round.Magnitude[3])-1]
		p4 = &table[4][int(round.Magnitude[4])-1]
		p5 = &table[5][int(round.Magnitude[5])-1]
		p6 = &table[6][int(round.Magnitude[6])-1]
		p7 = &table[7][int(round.Magnitude[7])-1]
	} else {
		pointers := [X8Lanes]**ifmaProjectiveNielsMicroAoSEntryX8{&p0, &p1, &p2, &p3, &p4, &p5, &p6, &p7}
		for lane := 0; lane < X8Lanes; lane++ {
			if lookupMask&(1<<lane) != 0 {
				*pointers[lane] = &table[lane][int(round.Magnitude[lane])-1]
			}
		}
	}
	ifmaProjectiveNielsMicroAoSTransposeX8(out, p0, p1, p2, p3, p4, p5, p6, p7)
	for limb := range modulusLimbs {
		for lane := 0; lane < X8Lanes; lane++ {
			if negativeMask&(1<<lane) != 0 {
				out.YPlusX.limbs[limb][lane], out.YMinusX.limbs[limb][lane] =
					out.YMinusX.limbs[limb][lane], out.YPlusX.limbs[limb][lane]
			}
		}
	}
	conditionalNegateIFMAElementX8(&out.T2D, negativeMask)
}

func selectIFMAProjectiveNielsPreSignedMicroAoSX8(
	out *IFMAProjectiveNielsX8,
	table *ifmaProjectiveNielsPreSignedMicroAoSTableX8,
	round *RadixRoundX8,
	active uint8,
) {
	lookupMask := round.NonzeroMask & active
	negativeMask := round.NegativeMask & lookupMask
	p0 := &ifmaProjectiveNielsMicroAoSIdentityX8
	p1, p2, p3, p4, p5, p6, p7 := p0, p0, p0, p0, p0, p0, p0
	if lookupMask == 0xff {
		p0 = &table[0][(negativeMask>>0)&1][int(round.Magnitude[0])-1]
		p1 = &table[1][(negativeMask>>1)&1][int(round.Magnitude[1])-1]
		p2 = &table[2][(negativeMask>>2)&1][int(round.Magnitude[2])-1]
		p3 = &table[3][(negativeMask>>3)&1][int(round.Magnitude[3])-1]
		p4 = &table[4][(negativeMask>>4)&1][int(round.Magnitude[4])-1]
		p5 = &table[5][(negativeMask>>5)&1][int(round.Magnitude[5])-1]
		p6 = &table[6][(negativeMask>>6)&1][int(round.Magnitude[6])-1]
		p7 = &table[7][(negativeMask>>7)&1][int(round.Magnitude[7])-1]
	} else {
		pointers := [X8Lanes]**ifmaProjectiveNielsMicroAoSEntryX8{&p0, &p1, &p2, &p3, &p4, &p5, &p6, &p7}
		for lane := 0; lane < X8Lanes; lane++ {
			if lookupMask&(1<<lane) != 0 {
				sign := (negativeMask >> lane) & 1
				*pointers[lane] = &table[lane][sign][int(round.Magnitude[lane])-1]
			}
		}
	}
	ifmaProjectiveNielsMicroAoSTransposeX8(out, p0, p1, p2, p3, p4, p5, p6, p7)
}
