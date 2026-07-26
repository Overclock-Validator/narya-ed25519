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
	points    []fixedBaseAffineCached
	radixBits uint8
	rounds    uint8
	positions uint8
	entries   uint8
}

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
		points:    make([]fixedBaseAffineCached, positions*entries),
		radixBits: uint8(radixBits),
		rounds:    uint8(rounds),
		positions: uint8(positions),
		entries:   uint8(entries),
	}

	positionBase := *base
	for position := 0; position < positions; position++ {
		multiple := positionBase
		for entry := 0; entry < entries; entry++ {
			fixedBaseCacheAffine(&table.points[position*entries+entry], &multiple)
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
// slice header and allocator rounding. Each scalar cached point is 3*5*8=120
// bytes. The result is independent of whether evaluation uses x4 or x8.
func (t *ExperimentalFixedBaseCombTable) NominalPayloadBytes() int {
	return len(t.points) * 3 * len(modulusLimbs) * 8
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
		if err := addFixedBaseIFMACachedX4(&acc, &acc, &selected); err != nil {
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
		if err := addFixedBaseIFMACachedX4(&acc, &acc, &selected); err != nil {
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
	usable := recodeFixedBaseScalarsX8(&digits, scalars, active, uint(table.radixBits))
	acc := identityIFMAPointX8Value()
	var doubleWorkspace ifmaPointDoubleWorkspaceX8
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
		selectFixedBaseIFMACachedX8(&selected, table, position, &digits.rounds[round], usable)
		if err := addFixedBaseIFMACachedX8(&acc, &acc, &selected); err != nil {
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
		selectFixedBaseIFMACachedX8(&selected, table, position, &digits.rounds[round], usable)
		if err := addFixedBaseIFMACachedX8(&acc, &acc, &selected); err != nil {
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
		recodeFixedBaseLaneX8(out, lane, &scalars[lane])
	}
	return valid
}

func recodeFixedBaseLaneX4(out *fixedBaseDigitsX4, lane int, scalar *[32]byte) {
	carry := int16(0)
	radix, half := int16(1)<<out.radixBits, int16(1)<<(out.radixBits-1)
	for round := 0; round < int(out.count); round++ {
		digit := int16(fixedScalarBits(scalar, round*int(out.radixBits), uint(out.radixBits))) + carry
		carry = (digit + half) / radix
		digit -= carry * radix
		setRadixRoundDigitX4(&out.rounds[round], lane, int8(digit))
	}
	if carry != 0 {
		panic("r51x5: canonical x4 scalar exceeded fixed-base comb width")
	}
}

func recodeFixedBaseLaneX8(out *fixedBaseDigitsX8, lane int, scalar *[32]byte) {
	carry := int16(0)
	radix, half := int16(1)<<out.radixBits, int16(1)<<(out.radixBits-1)
	for round := 0; round < int(out.count); round++ {
		digit := int16(fixedScalarBits(scalar, round*int(out.radixBits), uint(out.radixBits))) + carry
		carry = (digit + half) / radix
		digit -= carry * radix
		setRadixRoundDigitX8(&out.rounds[round], lane, int8(digit))
	}
	if carry != 0 {
		panic("r51x5: canonical x8 scalar exceeded fixed-base comb width")
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
	*out = identityFixedBaseCachedX4()
	lookupMask := round.NonzeroMask & active & 0x0f
	for lane := 0; lane < X4Lanes; lane++ {
		laneMask := uint8(1 << lane)
		magnitude := round.Magnitude[lane]
		validatePublicDigit(magnitude, round.NonzeroMask&laneMask != 0, round.NegativeMask&laneMask != 0, int(table.entries), active&laneMask != 0)
		if lookupMask&laneMask == 0 {
			continue
		}
		source := &table.points[position*int(table.entries)+int(magnitude)-1]
		setFixedBaseCachedLaneX4(out, source, lane, round.NegativeMask&laneMask != 0)
	}
}

func selectFixedBaseCachedX8(out *fixedBaseCachedX8, table *ExperimentalFixedBaseCombTable, position int, round *RadixRoundX8, active uint8) {
	*out = identityFixedBaseCachedX8()
	lookupMask := round.NonzeroMask & active
	for lane := 0; lane < X8Lanes; lane++ {
		laneMask := uint8(1 << lane)
		magnitude := round.Magnitude[lane]
		validatePublicDigit(magnitude, round.NonzeroMask&laneMask != 0, round.NegativeMask&laneMask != 0, int(table.entries), active&laneMask != 0)
		if lookupMask&laneMask == 0 {
			continue
		}
		source := &table.points[position*int(table.entries)+int(magnitude)-1]
		setFixedBaseCachedLaneX8(out, source, lane, round.NegativeMask&laneMask != 0)
	}
}

func selectFixedBaseIFMACachedX4(out *fixedBaseIFMACachedX4, table *ExperimentalFixedBaseCombTable, position int, round *RadixRoundX4, active uint8) {
	*out = identityFixedBaseIFMACachedX4()
	lookupMask := round.NonzeroMask & active & 0x0f
	for lane := 0; lane < X4Lanes; lane++ {
		laneMask := uint8(1 << lane)
		magnitude := round.Magnitude[lane]
		validatePublicDigit(magnitude, round.NonzeroMask&laneMask != 0, round.NegativeMask&laneMask != 0, int(table.entries), active&laneMask != 0)
		if lookupMask&laneMask == 0 {
			continue
		}
		source := &table.points[position*int(table.entries)+int(magnitude)-1]
		setFixedBaseIFMACachedLaneX4(out, source, lane, round.NegativeMask&laneMask != 0)
	}
}

func selectFixedBaseIFMACachedX8(out *fixedBaseIFMACachedX8, table *ExperimentalFixedBaseCombTable, position int, round *RadixRoundX8, active uint8) {
	*out = identityFixedBaseIFMACachedX8()
	lookupMask := round.NonzeroMask & active
	for lane := 0; lane < X8Lanes; lane++ {
		laneMask := uint8(1 << lane)
		magnitude := round.Magnitude[lane]
		validatePublicDigit(magnitude, round.NonzeroMask&laneMask != 0, round.NegativeMask&laneMask != 0, int(table.entries), active&laneMask != 0)
		if lookupMask&laneMask == 0 {
			continue
		}
		source := &table.points[position*int(table.entries)+int(magnitude)-1]
		setFixedBaseIFMACachedLaneX8(out, source, lane, round.NegativeMask&laneMask != 0)
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
	p := *point
	var yMinusX, yPlusX, A, B, C, D, E, F, G, H IFMAElementX4
	yMinusX.Subtract(&p.Y, &p.X)
	yPlusX.Add(&p.Y, &p.X)
	if err := ifmaMultiplyComposableUncheckedX4(&A, &yMinusX, &cached.YMinusX); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX4(&B, &yPlusX, &cached.YPlusX); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX4(&C, &p.T, &cached.T2D); err != nil {
		return err
	}
	D.Add(&p.Z, &p.Z)
	E.Subtract(&B, &A)
	F.Subtract(&D, &C)
	G.Add(&D, &C)
	H.Add(&B, &A)
	var result IFMAPointX4
	if err := ifmaMultiplyComposableUncheckedX4(&result.X, &E, &F); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX4(&result.Y, &G, &H); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX4(&result.T, &E, &H); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX4(&result.Z, &F, &G); err != nil {
		return err
	}
	*out = result
	return nil
}

func addFixedBaseIFMACachedX8(out, point *IFMAPointX8, cached *fixedBaseIFMACachedX8) error {
	p := *point
	var yMinusX, yPlusX, A, B, C, D, E, F, G, H IFMAElementX8
	yMinusX.Subtract(&p.Y, &p.X)
	yPlusX.Add(&p.Y, &p.X)
	if err := ifmaMultiplyComposableUncheckedX8(&A, &yMinusX, &cached.YMinusX); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX8(&B, &yPlusX, &cached.YPlusX); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX8(&C, &p.T, &cached.T2D); err != nil {
		return err
	}
	D.Add(&p.Z, &p.Z)
	E.Subtract(&B, &A)
	F.Subtract(&D, &C)
	G.Add(&D, &C)
	H.Add(&B, &A)
	var result IFMAPointX8
	if err := ifmaMultiplyComposableUncheckedX8(&result.X, &E, &F); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX8(&result.Y, &G, &H); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX8(&result.T, &E, &H); err != nil {
		return err
	}
	if err := ifmaMultiplyComposableUncheckedX8(&result.Z, &F, &G); err != nil {
		return err
	}
	*out = result
	return nil
}
