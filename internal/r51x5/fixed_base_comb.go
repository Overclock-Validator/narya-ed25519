package r51x5

// ExperimentalFixedBaseCombTable is a reusable, scalar-stored table for a
// public fixed Edwards point. It deliberately stores each cached point once,
// rather than duplicating the same point in every x4/x8 lane. Evaluation
// gathers public per-lane digits into a short-lived SoA cached point.
//
// The table is a two-way comb. Table position i contains positive multiples
// of [2^(2*w*i)]B. Odd digits are accumulated first, multiplied by 2^w, then
// the even digits are accumulated. Consequently an evaluation performs w
// doublings rather than one doubling chain per scalar.
//
// Construction allocates and normalizes the table once. Evaluation is
// allocation-free. This experiment is not reachable from production dispatch.
type ExperimentalFixedBaseCombTable struct {
	signedPoints []fixedBaseIFMASignedAffineCached
	radixBits    uint8
	rounds       uint8
	positions    uint8
	entries      uint8
}

// fixedBaseIFMASignedAffineCached stores both public signs of one affine
// cached point in the dense three-coordinate layout consumed by the native
// x4/x8 transpose. Index 0 is positive; index 1 swaps Y+X/Y-X and negates 2dT.
// The fixed B table is shared process-wide, so this 240-byte entry does not
// scale with the number of verified public keys.
type fixedBaseIFMASignedAffineCached [2]ifmaAffine3MicroAoSEntryExperiment

// A fixed-base affine cached point stores (y+x, y-x, 2*d*x*y). Three scalar
// field elements are enough for a mixed extended/affine addition, so the
// logical payload is exactly 120 bytes per entry in radix-2^51.
type fixedBaseAffineCached struct {
	YPlusX  Element
	YMinusX Element
	T2D     Element
}

type fixedBaseCachedX4 struct {
	YPlusX  ElementX4
	YMinusX ElementX4
	T2D     ElementX4
}

type fixedBaseCachedX8 struct {
	YPlusX  ElementX8
	YMinusX ElementX8
	T2D     ElementX8
}

type fixedBaseIFMACachedX4 struct {
	YPlusX  IFMAElementX4
	YMinusX IFMAElementX4
	T2D     IFMAElementX4
}

type fixedBaseIFMACachedX8 struct {
	YPlusX  IFMAElementX8
	YMinusX IFMAElementX8
	T2D     IFMAElementX8
}

type fixedBaseDigitsX4 struct {
	rounds    [maxFixedScalarRounds]RadixRoundX4
	count     uint8
	radixBits uint8
}

type fixedBaseDigitsX8 struct {
	rounds    [maxFixedScalarRounds]RadixRoundX8
	count     uint8
	radixBits uint8
}

// BuildExperimentalFixedBaseCombTable constructs the scalar cached table for
// base. Supported widths are 4, 5, and 8. base must be a valid initialized
// extended Edwards point; it need not be affine.
func BuildExperimentalFixedBaseCombTable(base *Point, radixBits uint) *ExperimentalFixedBaseCombTable {
	rounds, positions, entries := fixedBaseCombShape(radixBits)
	table := &ExperimentalFixedBaseCombTable{
		signedPoints: make([]fixedBaseIFMASignedAffineCached, positions*entries),
		radixBits:    uint8(radixBits),
		rounds:       uint8(rounds),
		positions:    uint8(positions),
		entries:      uint8(entries),
	}

	positionBase := *base
	for position := 0; position < positions; position++ {
		multiple := positionBase
		for entry := 0; entry < entries; entry++ {
			index := position*entries + entry
			var cached fixedBaseAffineCached
			fixedBaseCacheAffine(&cached, &multiple)
			storeFixedBaseIFMASignedAffineCached(&table.signedPoints[index], &cached)
			if entry+1 < entries {
				fixedBasePointAdd(&multiple, &multiple, &positionBase)
			}
		}
		if position+1 < positions {
			for doubling := uint(0); doubling < 2*radixBits; doubling++ {
				fixedBasePointDouble(&positionBase, &positionBase)
			}
		}
	}
	return table
}

// RadixBits reports the signed digit width used by the table.
func (t *ExperimentalFixedBaseCombTable) RadixBits() uint { return uint(t.radixBits) }

// RoundCount reports the number of signed digits in a canonical scalar.
func (t *ExperimentalFixedBaseCombTable) RoundCount() int { return int(t.rounds) }

// PositionCount reports the number of comb positions stored by the table.
func (t *ExperimentalFixedBaseCombTable) PositionCount() int { return int(t.positions) }

// EntryCount reports the positive multiples stored at each position.
func (t *ExperimentalFixedBaseCombTable) EntryCount() int { return int(t.entries) }

// NominalPayloadBytes reports the exact coordinate payload, excluding the Go
// slice header and allocator rounding. Each entry stores both public signs of
// three affine cached coordinates: 2*3*5*8=240 bytes. Full pre-signing lets the
// x4/x8 selector transpose directly into SoA form without online sign work.
func (t *ExperimentalFixedBaseCombTable) NominalPayloadBytes() int {
	return len(t.signedPoints) * 2 * 3 * len(modulusLimbs) * 8
}

func storeFixedBaseIFMASignedAffineCached(out *fixedBaseIFMASignedAffineCached, source *fixedBaseAffineCached) {
	var negativeT2D Element
	negativeT2D.Negate(&source.T2D)
	for limb := range modulusLimbs {
		out[0][limb] = [3]uint64{
			source.YPlusX.limbs[limb],
			source.YMinusX.limbs[limb],
			source.T2D.limbs[limb],
		}
		out[1][limb] = [3]uint64{
			source.YMinusX.limbs[limb],
			source.YPlusX.limbs[limb],
			negativeT2D.limbs[limb],
		}
	}
}

// ExperimentalFixedBaseCombScalarMultX4 computes [s]B in four independent
// lanes using a reusable scalar-stored comb table. It returns active restricted
// to canonical scalar encodings. Invalid and inactive lanes are identities.
func ExperimentalFixedBaseCombScalarMultX4(out *PointX4, table *ExperimentalFixedBaseCombTable, scalars *[X4Lanes][32]byte, active uint8) uint8 {
	var digits fixedBaseDigitsX4
	usable := recodeFixedBaseScalarsX4(&digits, scalars, active, uint(table.radixBits))
	acc := identityPointX4Value()
	if usable == 0 {
		*out = acc
		return 0
	}

	for position := 0; position < int(table.positions); position++ {
		round := 2*position + 1
		if round >= int(digits.count) || digits.rounds[round].NonzeroMask&usable == 0 {
			continue
		}
		var selected fixedBaseCachedX4
		selectFixedBaseCachedX4(&selected, table, position, &digits.rounds[round], usable)
		addFixedBaseCachedX4(&acc, &acc, &selected)
	}
	for doubling := uint8(0); doubling < table.radixBits; doubling++ {
		acc.Double(&acc)
	}
	for position := 0; position < int(table.positions); position++ {
		round := 2 * position
		if digits.rounds[round].NonzeroMask&usable == 0 {
			continue
		}
		var selected fixedBaseCachedX4
		selectFixedBaseCachedX4(&selected, table, position, &digits.rounds[round], usable)
		addFixedBaseCachedX4(&acc, &acc, &selected)
	}
	*out = acc
	return usable
}

// ExperimentalFixedBaseCombScalarMultX8 is the eight-lane counterpart of
// ExperimentalFixedBaseCombScalarMultX4.
func ExperimentalFixedBaseCombScalarMultX8(out *PointX8, table *ExperimentalFixedBaseCombTable, scalars *[X8Lanes][32]byte, active uint8) uint8 {
	var digits fixedBaseDigitsX8
	usable := recodeFixedBaseScalarsX8(&digits, scalars, active, uint(table.radixBits))
	acc := identityPointX8Value()
	if usable == 0 {
		*out = acc
		return 0
	}

	for position := 0; position < int(table.positions); position++ {
		round := 2*position + 1
		if round >= int(digits.count) || digits.rounds[round].NonzeroMask&usable == 0 {
			continue
		}
		var selected fixedBaseCachedX8
		selectFixedBaseCachedX8(&selected, table, position, &digits.rounds[round], usable)
		addFixedBaseCachedX8(&acc, &acc, &selected)
	}
	for doubling := uint8(0); doubling < table.radixBits; doubling++ {
		acc.Double(&acc)
	}
	for position := 0; position < int(table.positions); position++ {
		round := 2 * position
		if digits.rounds[round].NonzeroMask&usable == 0 {
			continue
		}
		var selected fixedBaseCachedX8
		selectFixedBaseCachedX8(&selected, table, position, &digits.rounds[round], usable)
		addFixedBaseCachedX8(&acc, &acc, &selected)
	}
	*out = acc
	return usable
}

// ExperimentalIFMAFixedBaseCombScalarMultX4 evaluates the same comb with the
// composable YMM IFMA point schedule. It remains forced/test-only. out is
// unchanged when IFMA is unavailable or a point operation fails.
func ExperimentalIFMAFixedBaseCombScalarMultX4(out *IFMAPointX4, table *ExperimentalFixedBaseCombTable, scalars *[X4Lanes][32]byte, active uint8) (uint8, error) {
	if !ExperimentalIFMAAvailable() {
		return 0, ErrIFMAUnavailable
	}
	var digits fixedBaseDigitsX4
	usable := recodeFixedBaseScalarsX4(&digits, scalars, active, uint(table.radixBits))
	acc := identityIFMAPointX4Value()
	var addWorkspace fixedBaseIFMAAddScratchX4
	if usable == 0 {
		*out = acc
		return 0, nil
	}

	for position := 0; position < int(table.positions); position++ {
		round := 2*position + 1
		if round >= int(digits.count) || digits.rounds[round].NonzeroMask&usable == 0 {
			continue
		}
		var selected fixedBaseIFMACachedX4
		selectFixedBaseIFMACachedX4(&selected, table, position, &digits.rounds[round], usable)
		if err := addFixedBaseIFMACachedWorkspaceX4(&acc, &acc, &selected, &addWorkspace); err != nil {
			return 0, err
		}
	}
	for doubling := uint8(0); doubling < table.radixBits; doubling++ {
		if err := ifmaPointDoubleComposableStaticX4(&acc, &acc); err != nil {
			return 0, err
		}
	}
	for position := 0; position < int(table.positions); position++ {
		round := 2 * position
		if digits.rounds[round].NonzeroMask&usable == 0 {
			continue
		}
		var selected fixedBaseIFMACachedX4
		selectFixedBaseIFMACachedX4(&selected, table, position, &digits.rounds[round], usable)
		if err := addFixedBaseIFMACachedWorkspaceX4(&acc, &acc, &selected, &addWorkspace); err != nil {
			return 0, err
		}
	}
	*out = acc
	return usable, nil
}

// ExperimentalIFMAFixedBaseCombScalarMultX8 is the ZMM counterpart of
// ExperimentalIFMAFixedBaseCombScalarMultX4.
func ExperimentalIFMAFixedBaseCombScalarMultX8(out *IFMAPointX8, table *ExperimentalFixedBaseCombTable, scalars *[X8Lanes][32]byte, active uint8) (uint8, error) {
	if !ExperimentalIFMAAvailable() {
		return 0, ErrIFMAUnavailable
	}
	var digits fixedBaseDigitsX8
	var usable uint8
	if active == 0xff && table.radixBits == 8 {
		usable = recodeFixedBaseRadix256FullX8(&digits, scalars)
	} else {
		usable = recodeFixedBaseScalarsX8(&digits, scalars, active, uint(table.radixBits))
	}
	acc := identityIFMAPointX8Value()
	var doubleWorkspace ifmaPointDoubleWorkspaceX8
	var addWorkspace fixedBaseIFMAAddScratchX8
	if usable == 0 {
		*out = acc
		return 0, nil
	}

	for position := 0; position < int(table.positions); position++ {
		round := 2*position + 1
		if round >= int(digits.count) || digits.rounds[round].NonzeroMask&usable == 0 {
			continue
		}
		var selected fixedBaseIFMACachedX8
		selectFixedBaseIFMACachedUncheckedX8(&selected, table, position, &digits.rounds[round], usable)
		if err := addFixedBaseIFMACachedWorkspaceX8(&acc, &acc, &selected, &addWorkspace); err != nil {
			return 0, err
		}
	}
	for doubling := uint8(0); doubling < table.radixBits; doubling++ {
		if err := ifmaPointDoubleComposableWorkspaceStaticX8(&acc, &acc, &doubleWorkspace); err != nil {
			return 0, err
		}
	}
	for position := 0; position < int(table.positions); position++ {
		round := 2 * position
		if digits.rounds[round].NonzeroMask&usable == 0 {
			continue
		}
		var selected fixedBaseIFMACachedX8
		selectFixedBaseIFMACachedUncheckedX8(&selected, table, position, &digits.rounds[round], usable)
		if err := addFixedBaseIFMACachedWorkspaceX8(&acc, &acc, &selected, &addWorkspace); err != nil {
			return 0, err
		}
	}
	*out = acc
	return usable, nil
}

func fixedBaseCombShape(radixBits uint) (rounds, positions, entries int) {
	switch radixBits {
	case 4:
		rounds = 64
	case 5:
		rounds = 51
	case 8:
		rounds = 32
	default:
		panic("r51x5: fixed-base comb radix must be 16, 32, or 256")
	}
	return rounds, (rounds + 1) / 2, 1 << (radixBits - 1)
}

func recodeFixedBaseScalarsX4(out *fixedBaseDigitsX4, scalars *[X4Lanes][32]byte, active uint8, radixBits uint) uint8 {
	*out = fixedBaseDigitsX4{}
	rounds, _, _ := fixedBaseCombShape(radixBits)
	out.count, out.radixBits = uint8(rounds), uint8(radixBits)
	active &= 0x0f
	var valid uint8
	for lane := 0; lane < X4Lanes; lane++ {
		laneMask := uint8(1 << lane)
		if active&laneMask == 0 || !canonicalScalarBytes(&scalars[lane]) {
			continue
		}
		valid |= laneMask
		recodeFixedBaseLaneX4(out, lane, &scalars[lane])
	}
	return valid
}

func recodeFixedBaseScalarsX8(out *fixedBaseDigitsX8, scalars *[X8Lanes][32]byte, active uint8, radixBits uint) uint8 {
	*out = fixedBaseDigitsX8{}
	rounds, _, _ := fixedBaseCombShape(radixBits)
	out.count, out.radixBits = uint8(rounds), uint8(radixBits)
	var valid uint8
	for lane := 0; lane < X8Lanes; lane++ {
		laneMask := uint8(1 << lane)
		if active&laneMask == 0 || !canonicalScalarBytes(&scalars[lane]) {
			continue
		}
		valid |= laneMask
	}
	half := int16(1) << (out.radixBits - 1)
	var carries [X8Lanes]int16
	if out.radixBits == 8 {
		// The registered basepoint comb uses radix 256. Its round boundaries
		// are byte-aligned, so the general two-byte bit extractor is needless.
		for round := 0; round < int(out.count); round++ {
			for lane := 0; lane < X8Lanes; lane++ {
				laneMask := uint8(1 << lane)
				if valid&laneMask == 0 {
					continue
				}
				digit := int16(scalars[lane][round]) + carries[lane]
				carries[lane] = (digit + half) >> 8
				digit -= carries[lane] << 8
				setRadixRoundDigitX8(&out.rounds[round], lane, int8(digit))
			}
		}
	} else {
		for round := 0; round < int(out.count); round++ {
			bit := round * int(out.radixBits)
			for lane := 0; lane < X8Lanes; lane++ {
				laneMask := uint8(1 << lane)
				if valid&laneMask == 0 {
					continue
				}
				digit := int16(fixedScalarBits(&scalars[lane], bit, uint(out.radixBits))) + carries[lane]
				// fixedScalarBits is in [0, 2^w-1] and the incoming carry is
				// zero or one, so digit+half is nonnegative. For the power-of-two
				// radix the shifts are therefore exactly the signed division and
				// multiplication they replace, without an IDIV in every lane.
				carries[lane] = (digit + half) >> out.radixBits
				digit -= carries[lane] << out.radixBits
				setRadixRoundDigitX8(&out.rounds[round], lane, int8(digit))
			}
		}
	}
	for lane := 0; lane < X8Lanes; lane++ {
		if carries[lane] != 0 {
			panic("r51x5: canonical x8 scalar exceeded fixed-base comb width")
		}
	}
	return valid
}

// recodeFixedBaseRadix256FullX8 specializes the process-shared generator comb
// regime used by complete cold x8 groups. All scalar encodings remain checked;
// a noncanonical input re-enters the generic recoder so its per-lane
// fail-closed output is preserved exactly. The all-valid path has byte-aligned
// radix-256 digits and assigns every used round directly, avoiding dynamic
// shape and active-lane work in the inner loop.
func recodeFixedBaseRadix256FullX8(out *fixedBaseDigitsX8, scalars *[X8Lanes][32]byte) uint8 {
	for lane := 0; lane < X8Lanes; lane++ {
		if !canonicalScalarBytes(&scalars[lane]) {
			return recodeFixedBaseScalarsX8(out, scalars, 0xff, 8)
		}
	}

	*out = fixedBaseDigitsX8{}
	out.count = 32
	out.radixBits = 8
	var carries [X8Lanes]int16
	for round := 0; round < 32; round++ {
		record := &out.rounds[round]
		var nonzeroMask, negativeMask uint8
		for lane := 0; lane < X8Lanes; lane++ {
			digit := int16(scalars[lane][round]) + carries[lane]
			carries[lane] = (digit + 128) >> 8
			digit -= carries[lane] << 8
			laneMask := uint8(1 << lane)
			if digit < 0 {
				record.Magnitude[lane] = uint8(-digit)
				negativeMask |= laneMask
			} else {
				record.Magnitude[lane] = uint8(digit)
			}
			if digit != 0 {
				nonzeroMask |= laneMask
			}
		}
		record.NonzeroMask = nonzeroMask
		record.NegativeMask = negativeMask
	}
	for lane := 0; lane < X8Lanes; lane++ {
		if carries[lane] != 0 {
			panic("r51x5: canonical x8 scalar exceeded fixed-base recoding width")
		}
	}
	return 0xff
}

func recodeFixedBaseLaneX4(out *fixedBaseDigitsX4, lane int, scalar *[32]byte) {
	carry := int16(0)
	half := int16(1) << (out.radixBits - 1)
	if out.radixBits == 8 {
		for round := 0; round < int(out.count); round++ {
			digit := int16(scalar[round]) + carry
			carry = (digit + half) >> 8
			digit -= carry << 8
			setRadixRoundDigitX4(&out.rounds[round], lane, int8(digit))
		}
	} else {
		for round := 0; round < int(out.count); round++ {
			digit := int16(fixedScalarBits(scalar, round*int(out.radixBits), uint(out.radixBits))) + carry
			carry = (digit + half) >> out.radixBits
			digit -= carry << out.radixBits
			setRadixRoundDigitX4(&out.rounds[round], lane, int8(digit))
		}
	}
	if carry != 0 {
		panic("r51x5: canonical x4 scalar exceeded fixed-base comb width")
	}
}

func fixedBaseCacheAffine(out *fixedBaseAffineCached, point *Point) {
	var zInv, x, y Element
	zInv.Invert(&point.Z)
	x.Multiply(&point.X, &zInv)
	y.Multiply(&point.Y, &zInv)
	out.YPlusX.Add(&y, &x)
	out.YMinusX.Subtract(&y, &x)
	out.T2D.Multiply(&x, &y)
	out.T2D.Multiply(&out.T2D, &curve2D)
}

func fixedBasePointAdd(out, a, b *Point) {
	aa, bb := *a, *b
	var yMinusX1, yPlusX1, yMinusX2, yPlusX2 Element
	yMinusX1.Subtract(&aa.Y, &aa.X)
	yPlusX1.Add(&aa.Y, &aa.X)
	yMinusX2.Subtract(&bb.Y, &bb.X)
	yPlusX2.Add(&bb.Y, &bb.X)
	var A, B, C, D, E, F, G, H Element
	A.Multiply(&yMinusX1, &yMinusX2)
	B.Multiply(&yPlusX1, &yPlusX2)
	C.Multiply(&aa.T, &bb.T)
	C.Multiply(&C, &curve2D)
	D.Multiply(&aa.Z, &bb.Z)
	D.Add(&D, &D)
	E.Subtract(&B, &A)
	F.Subtract(&D, &C)
	G.Add(&D, &C)
	H.Add(&B, &A)
	var result Point
	result.X.Multiply(&E, &F)
	result.Y.Multiply(&G, &H)
	result.T.Multiply(&E, &H)
	result.Z.Multiply(&F, &G)
	*out = result
}

func fixedBasePointDouble(out, point *Point) {
	q := *point
	var A, B, C, D, E, F, G, H, xPlusY Element
	A.Square(&q.X)
	B.Square(&q.Y)
	C.Square(&q.Z)
	C.Add(&C, &C)
	D.Negate(&A)
	xPlusY.Add(&q.X, &q.Y)
	E.Square(&xPlusY)
	E.Subtract(&E, &A)
	E.Subtract(&E, &B)
	G.Add(&D, &B)
	F.Subtract(&G, &C)
	H.Subtract(&D, &B)
	var result Point
	result.X.Multiply(&E, &F)
	result.Y.Multiply(&G, &H)
	result.T.Multiply(&E, &H)
	result.Z.Multiply(&F, &G)
	*out = result
}

func selectFixedBaseCachedX4(out *fixedBaseCachedX4, table *ExperimentalFixedBaseCombTable, position int, round *RadixRoundX4, active uint8) {
	selected := identityFixedBaseCachedX4()
	lookupMask := round.NonzeroMask & active & 0x0f
	for lane := 0; lane < X4Lanes; lane++ {
		laneMask := uint8(1 << lane)
		magnitude := round.Magnitude[lane]
		validatePublicDigit(magnitude, round.NonzeroMask&laneMask != 0, round.NegativeMask&laneMask != 0, int(table.entries), active&laneMask != 0)
		if lookupMask&laneMask == 0 {
			continue
		}
		index := position*int(table.entries) + int(magnitude) - 1
		sign := fixedBasePublicSign(round.NegativeMask, laneMask)
		setFixedBaseSignedCachedLaneX4(&selected, &table.signedPoints[index][sign], lane)
	}
	*out = selected
}

func selectFixedBaseCachedX8(out *fixedBaseCachedX8, table *ExperimentalFixedBaseCombTable, position int, round *RadixRoundX8, active uint8) {
	selected := identityFixedBaseCachedX8()
	lookupMask := round.NonzeroMask & active
	for lane := 0; lane < X8Lanes; lane++ {
		laneMask := uint8(1 << lane)
		magnitude := round.Magnitude[lane]
		validatePublicDigit(magnitude, round.NonzeroMask&laneMask != 0, round.NegativeMask&laneMask != 0, int(table.entries), active&laneMask != 0)
		if lookupMask&laneMask == 0 {
			continue
		}
		index := position*int(table.entries) + int(magnitude) - 1
		sign := fixedBasePublicSign(round.NegativeMask, laneMask)
		setFixedBaseSignedCachedLaneX8(&selected, &table.signedPoints[index][sign], lane)
	}
	*out = selected
}

func selectFixedBaseIFMACachedX4(out *fixedBaseIFMACachedX4, table *ExperimentalFixedBaseCombTable, position int, round *RadixRoundX4, active uint8) {
	lookupMask := round.NonzeroMask & active & 0x0f
	p0 := &ifmaAffine3MicroAoSIdentityEntryExperiment
	p1, p2, p3 := p0, p0, p0
	for lane := 0; lane < X4Lanes; lane++ {
		laneMask := uint8(1 << lane)
		magnitude := round.Magnitude[lane]
		validatePublicDigit(magnitude, round.NonzeroMask&laneMask != 0, round.NegativeMask&laneMask != 0, int(table.entries), active&laneMask != 0)
		if lookupMask&laneMask == 0 {
			continue
		}
		index := position*int(table.entries) + int(magnitude) - 1
		source := &table.signedPoints[index][fixedBasePublicSign(round.NegativeMask, laneMask)]
		switch lane {
		case 0:
			p0 = source
		case 1:
			p1 = source
		case 2:
			p2 = source
		case 3:
			p3 = source
		}
	}
	ifmaAffine3MicroAoSTransposeSelectExperimentX4(out, p0, p1, p2, p3)
}

func selectFixedBaseIFMACachedX8(out *fixedBaseIFMACachedX8, table *ExperimentalFixedBaseCombTable, position int, round *RadixRoundX8, active uint8) {
	lookupMask := round.NonzeroMask & active
	p0 := &ifmaAffine3MicroAoSIdentityEntryExperiment
	p1, p2, p3, p4, p5, p6, p7 := p0, p0, p0, p0, p0, p0, p0
	for lane := 0; lane < X8Lanes; lane++ {
		laneMask := uint8(1 << lane)
		magnitude := round.Magnitude[lane]
		validatePublicDigit(magnitude, round.NonzeroMask&laneMask != 0, round.NegativeMask&laneMask != 0, int(table.entries), active&laneMask != 0)
		if lookupMask&laneMask == 0 {
			continue
		}
		index := position*int(table.entries) + int(magnitude) - 1
		source := &table.signedPoints[index][fixedBasePublicSign(round.NegativeMask, laneMask)]
		switch lane {
		case 0:
			p0 = source
		case 1:
			p1 = source
		case 2:
			p2 = source
		case 3:
			p3 = source
		case 4:
			p4 = source
		case 5:
			p5 = source
		case 6:
			p6 = source
		case 7:
			p7 = source
		}
	}
	ifmaAffine3MicroAoSTransposeSelectExperimentX8(out, p0, p1, p2, p3, p4, p5, p6, p7)
}

// selectFixedBaseIFMACachedUncheckedX4 is a retained measurement counterpart
// of the checked selector above. round must come from
// recodeFixedBaseScalarsX4 for table.radixBits. The straight-line selector is
// faster in isolation, but a Zen 5 complete n=4 gate at 7b22c5b regressed by
// about 0.2%, so the registered x4 route deliberately remains checked.
func selectFixedBaseIFMACachedUncheckedX4(out *fixedBaseIFMACachedX4, table *ExperimentalFixedBaseCombTable, position int, round *RadixRoundX4, active uint8) {
	lookupMask := round.NonzeroMask & active & 0x0f
	p0 := &ifmaAffine3MicroAoSIdentityEntryExperiment
	p1, p2, p3 := p0, p0, p0
	base := position * int(table.entries)
	if lookupMask == 0x0f {
		p0 = &table.signedPoints[base+int(round.Magnitude[0])-1][(round.NegativeMask>>0)&1]
		p1 = &table.signedPoints[base+int(round.Magnitude[1])-1][(round.NegativeMask>>1)&1]
		p2 = &table.signedPoints[base+int(round.Magnitude[2])-1][(round.NegativeMask>>2)&1]
		p3 = &table.signedPoints[base+int(round.Magnitude[3])-1][(round.NegativeMask>>3)&1]
	} else {
		pointers := [X4Lanes]**ifmaAffine3MicroAoSEntryExperiment{&p0, &p1, &p2, &p3}
		for lane := 0; lane < X4Lanes; lane++ {
			if lookupMask&(1<<lane) != 0 {
				*pointers[lane] = &table.signedPoints[base+int(round.Magnitude[lane])-1][(round.NegativeMask>>lane)&1]
			}
		}
	}
	ifmaAffine3MicroAoSTransposeSelectExperimentX4(out, p0, p1, p2, p3)
}

// selectFixedBaseIFMACachedUncheckedX8 is the native-wide analogue. The
// overwhelmingly common all-nonzero case is deliberately straight-line;
// zero digits and tail masks retain an identity-filled fallback.
func selectFixedBaseIFMACachedUncheckedX8(out *fixedBaseIFMACachedX8, table *ExperimentalFixedBaseCombTable, position int, round *RadixRoundX8, active uint8) {
	lookupMask := round.NonzeroMask & active
	p0 := &ifmaAffine3MicroAoSIdentityEntryExperiment
	p1, p2, p3, p4, p5, p6, p7 := p0, p0, p0, p0, p0, p0, p0
	base := position * int(table.entries)
	if lookupMask == 0xff {
		p0 = &table.signedPoints[base+int(round.Magnitude[0])-1][(round.NegativeMask>>0)&1]
		p1 = &table.signedPoints[base+int(round.Magnitude[1])-1][(round.NegativeMask>>1)&1]
		p2 = &table.signedPoints[base+int(round.Magnitude[2])-1][(round.NegativeMask>>2)&1]
		p3 = &table.signedPoints[base+int(round.Magnitude[3])-1][(round.NegativeMask>>3)&1]
		p4 = &table.signedPoints[base+int(round.Magnitude[4])-1][(round.NegativeMask>>4)&1]
		p5 = &table.signedPoints[base+int(round.Magnitude[5])-1][(round.NegativeMask>>5)&1]
		p6 = &table.signedPoints[base+int(round.Magnitude[6])-1][(round.NegativeMask>>6)&1]
		p7 = &table.signedPoints[base+int(round.Magnitude[7])-1][(round.NegativeMask>>7)&1]
	} else {
		pointers := [X8Lanes]**ifmaAffine3MicroAoSEntryExperiment{&p0, &p1, &p2, &p3, &p4, &p5, &p6, &p7}
		for lane := 0; lane < X8Lanes; lane++ {
			if lookupMask&(1<<lane) != 0 {
				*pointers[lane] = &table.signedPoints[base+int(round.Magnitude[lane])-1][(round.NegativeMask>>lane)&1]
			}
		}
	}
	ifmaAffine3MicroAoSTransposeSelectExperimentX8(out, p0, p1, p2, p3, p4, p5, p6, p7)
}

func fixedBasePublicSign(negativeMask, laneMask uint8) int {
	if negativeMask&laneMask != 0 {
		return 1
	}
	return 0
}

func setFixedBaseSignedCachedLaneX4(out *fixedBaseCachedX4, source *ifmaAffine3MicroAoSEntryExperiment, lane int) {
	for limb := range modulusLimbs {
		out.YPlusX.limbs[limb][lane] = source[limb][0]
		out.YMinusX.limbs[limb][lane] = source[limb][1]
		out.T2D.limbs[limb][lane] = source[limb][2]
	}
}

func setFixedBaseSignedCachedLaneX8(out *fixedBaseCachedX8, source *ifmaAffine3MicroAoSEntryExperiment, lane int) {
	for limb := range modulusLimbs {
		out.YPlusX.limbs[limb][lane] = source[limb][0]
		out.YMinusX.limbs[limb][lane] = source[limb][1]
		out.T2D.limbs[limb][lane] = source[limb][2]
	}
}

func setFixedBaseCachedLaneX4(out *fixedBaseCachedX4, source *fixedBaseAffineCached, lane int, negative bool) {
	yPlusX, yMinusX, t2d := &source.YPlusX, &source.YMinusX, source.T2D
	if negative {
		yPlusX, yMinusX = yMinusX, yPlusX
		t2d.Negate(&t2d)
	}
	out.YPlusX.SetLane(lane, yPlusX)
	out.YMinusX.SetLane(lane, yMinusX)
	out.T2D.SetLane(lane, &t2d)
}

func setFixedBaseCachedLaneX8(out *fixedBaseCachedX8, source *fixedBaseAffineCached, lane int, negative bool) {
	yPlusX, yMinusX, t2d := &source.YPlusX, &source.YMinusX, source.T2D
	if negative {
		yPlusX, yMinusX = yMinusX, yPlusX
		t2d.Negate(&t2d)
	}
	out.YPlusX.SetLane(lane, yPlusX)
	out.YMinusX.SetLane(lane, yMinusX)
	out.T2D.SetLane(lane, &t2d)
}

func setFixedBaseIFMACachedLaneX4(out *fixedBaseIFMACachedX4, source *fixedBaseAffineCached, lane int, negative bool) {
	yPlusX, yMinusX, t2d := &source.YPlusX, &source.YMinusX, source.T2D
	if negative {
		yPlusX, yMinusX = yMinusX, yPlusX
		t2d.Negate(&t2d)
	}
	for limb := range modulusLimbs {
		out.YPlusX.limbs[limb][lane] = yPlusX.limbs[limb]
		out.YMinusX.limbs[limb][lane] = yMinusX.limbs[limb]
		out.T2D.limbs[limb][lane] = t2d.limbs[limb]
	}
}

func setFixedBaseIFMACachedLaneX8(out *fixedBaseIFMACachedX8, source *fixedBaseAffineCached, lane int, negative bool) {
	yPlusX, yMinusX, t2d := &source.YPlusX, &source.YMinusX, source.T2D
	if negative {
		yPlusX, yMinusX = yMinusX, yPlusX
		t2d.Negate(&t2d)
	}
	for limb := range modulusLimbs {
		out.YPlusX.limbs[limb][lane] = yPlusX.limbs[limb]
		out.YMinusX.limbs[limb][lane] = yMinusX.limbs[limb]
		out.T2D.limbs[limb][lane] = t2d.limbs[limb]
	}
}

func identityFixedBaseCachedX4() fixedBaseCachedX4 {
	var result fixedBaseCachedX4
	for lane := 0; lane < X4Lanes; lane++ {
		result.YPlusX.limbs[0][lane] = 1
		result.YMinusX.limbs[0][lane] = 1
	}
	return result
}

func identityFixedBaseCachedX8() fixedBaseCachedX8 {
	var result fixedBaseCachedX8
	for lane := 0; lane < X8Lanes; lane++ {
		result.YPlusX.limbs[0][lane] = 1
		result.YMinusX.limbs[0][lane] = 1
	}
	return result
}

func identityFixedBaseIFMACachedX4() fixedBaseIFMACachedX4 {
	var result fixedBaseIFMACachedX4
	for lane := 0; lane < X4Lanes; lane++ {
		result.YPlusX.limbs[0][lane] = 1
		result.YMinusX.limbs[0][lane] = 1
	}
	return result
}

func identityFixedBaseIFMACachedX8() fixedBaseIFMACachedX8 {
	var result fixedBaseIFMACachedX8
	for lane := 0; lane < X8Lanes; lane++ {
		result.YPlusX.limbs[0][lane] = 1
		result.YMinusX.limbs[0][lane] = 1
	}
	return result
}

func addFixedBaseCachedX4(out, point *PointX4, cached *fixedBaseCachedX4) {
	p := *point
	var yMinusX, yPlusX, A, B, C, D, E, F, G, H ElementX4
	yMinusX.Subtract(&p.Y, &p.X)
	yPlusX.Add(&p.Y, &p.X)
	A.Multiply(&yMinusX, &cached.YMinusX)
	B.Multiply(&yPlusX, &cached.YPlusX)
	C.Multiply(&p.T, &cached.T2D)
	D.Add(&p.Z, &p.Z)
	E.Subtract(&B, &A)
	F.Subtract(&D, &C)
	G.Add(&D, &C)
	H.Add(&B, &A)
	var result PointX4
	result.X.Multiply(&E, &F)
	result.Y.Multiply(&G, &H)
	result.T.Multiply(&E, &H)
	result.Z.Multiply(&F, &G)
	*out = result
}

func addFixedBaseCachedX8(out, point *PointX8, cached *fixedBaseCachedX8) {
	p := *point
	var yMinusX, yPlusX, A, B, C, D, E, F, G, H ElementX8
	yMinusX.Subtract(&p.Y, &p.X)
	yPlusX.Add(&p.Y, &p.X)
	A.Multiply(&yMinusX, &cached.YMinusX)
	B.Multiply(&yPlusX, &cached.YPlusX)
	C.Multiply(&p.T, &cached.T2D)
	D.Add(&p.Z, &p.Z)
	E.Subtract(&B, &A)
	F.Subtract(&D, &C)
	G.Add(&D, &C)
	H.Add(&B, &A)
	var result PointX8
	result.X.Multiply(&E, &F)
	result.Y.Multiply(&G, &H)
	result.T.Multiply(&E, &H)
	result.Z.Multiply(&F, &G)
	*out = result
}

func addFixedBaseIFMACachedX4(out, point *IFMAPointX4, cached *fixedBaseIFMACachedX4) error {
	var workspace fixedBaseIFMAAddScratchX4
	return addFixedBaseIFMACachedWorkspaceX4(out, point, cached, &workspace)
}

type fixedBaseIFMAAddScratchX4 struct {
	yMinusX, yPlusX IFMAElementX4
	stage2          ifmaNielsStage2WorkspaceX4
}

func addFixedBaseIFMACachedWorkspaceX4(
	out, point *IFMAPointX4,
	cached *fixedBaseIFMACachedX4,
	workspace *fixedBaseIFMAAddScratchX4,
) error {
	ifmaSubtractComposableUncheckedX4(&workspace.yMinusX, &point.Y, &point.X)
	ifmaAddComposableUncheckedX4(&workspace.yPlusX, &point.Y, &point.X)

	stage2 := &workspace.stage2
	ifmaMulRawX4(&stage2[0], &workspace.yMinusX.limbs, &cached.YMinusX.limbs)
	ifmaMulRawX4(&stage2[1], &workspace.yPlusX.limbs, &cached.YPlusX.limbs)
	ifmaMulRawX4(&stage2[2], &point.T.limbs, &cached.T2D.limbs)
	stage2[3] = IFMAProductX4(point.Z.limbs)
	ifmaNielsStage2X4(stage2)

	E := (*LimbsX4)(&stage2[0])
	F := (*LimbsX4)(&stage2[1])
	G := (*LimbsX4)(&stage2[2])
	H := (*LimbsX4)(&stage2[3])
	ifmaMulNormalizedUncheckedX4(&out.X.limbs, E, F)
	ifmaMulNormalizedUncheckedX4(&out.Y.limbs, G, H)
	ifmaMulNormalizedUncheckedX4(&out.T.limbs, E, H)
	ifmaMulNormalizedUncheckedX4(&out.Z.limbs, F, G)
	return nil
}

func addFixedBaseIFMACachedX8(out, point *IFMAPointX8, cached *fixedBaseIFMACachedX8) error {
	var workspace fixedBaseIFMAAddScratchX8
	return addFixedBaseIFMACachedWorkspaceX8(out, point, cached, &workspace)
}

// fixedBaseIFMAAddScratchX8 owns the fully overwritten affine-cached mixed-add
// scratch. A/B/C are exact raw products while slot D carries the already-u52
// point Z coordinate. The common Niels Stage-2 leaf accepts both forms and
// produces E/F/G/H with one parallel carry layer.
type fixedBaseIFMAAddScratchX8 struct {
	yMinusX, yPlusX IFMAElementX8
	stage2          ifmaNielsStage2WorkspaceX8
}

func addFixedBaseIFMACachedWorkspaceX8(
	out, point *IFMAPointX8,
	cached *fixedBaseIFMACachedX8,
	workspace *fixedBaseIFMAAddScratchX8,
) error {
	ifmaSubtractComposableUncheckedX8(&workspace.yMinusX, &point.Y, &point.X)
	ifmaAddComposableUncheckedX8(&workspace.yPlusX, &point.Y, &point.X)

	stage2 := &workspace.stage2
	ifmaThreeRawProductsNielsStage2UncheckedX8(
		stage2,
		&workspace.yMinusX.limbs, &cached.YMinusX.limbs,
		&workspace.yPlusX.limbs, &cached.YPlusX.limbs,
		&point.T.limbs, &cached.T2D.limbs,
		&point.Z.limbs,
	)

	// point and cached are dead after A/B/C and Z have been captured. Direct
	// output is therefore safe for out==point and avoids a 1,280-byte result
	// temporary and copy.
	ifmaPointFinalProductsUncheckedX8(out, &stage2[0])
	return nil
}
