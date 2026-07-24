package r51x5

import (
	"math/big"
	"math/bits"
)

const QSMTerms = 4

// SignedMagnitude is an arbitrary-width signed integer. Magnitude is stored
// little-endian and Negative is normalized to false for zero. It is not a
// scalar modulo L: exact integer semantics are required for points containing
// torsion and for products such as tau*s in the HEEA research path.
type SignedMagnitude struct {
	magnitude []byte
	negative  bool
}

// NewSignedMagnitude returns a normalized copy of magnitudeLE.
func NewSignedMagnitude(magnitudeLE []byte, negative bool) SignedMagnitude {
	end := len(magnitudeLE)
	for end > 0 && magnitudeLE[end-1] == 0 {
		end--
	}
	if end == 0 {
		return SignedMagnitude{}
	}
	magnitude := make([]byte, end)
	copy(magnitude, magnitudeLE[:end])
	return SignedMagnitude{magnitude: magnitude, negative: negative}
}

// NewSignedMagnitudeUint64 returns value as a signed magnitude.
func NewSignedMagnitudeUint64(value uint64, negative bool) SignedMagnitude {
	var encoded [8]byte
	for i := range encoded {
		encoded[i] = byte(value >> (8 * i))
	}
	return NewSignedMagnitude(encoded[:], negative)
}

// Sign returns -1, 0, or +1.
func (x SignedMagnitude) Sign() int {
	if len(x.magnitude) == 0 {
		return 0
	}
	if x.negative {
		return -1
	}
	return 1
}

// BitLen returns the bit length of the unsigned magnitude.
func (x SignedMagnitude) BitLen() int {
	if len(x.magnitude) == 0 {
		return 0
	}
	return (len(x.magnitude)-1)*8 + bits.Len8(x.magnitude[len(x.magnitude)-1])
}

// MagnitudeLE returns a copy of the unsigned little-endian magnitude.
func (x SignedMagnitude) MagnitudeLE() []byte {
	result := make([]byte, len(x.magnitude))
	copy(result, x.magnitude)
	return result
}

// Negative reports the sign bit. It is always false for zero.
func (x SignedMagnitude) Negative() bool { return x.negative }

// Negated returns -x without changing its magnitude.
func (x SignedMagnitude) Negated() SignedMagnitude {
	result := NewSignedMagnitude(x.magnitude, x.negative)
	if result.Sign() != 0 {
		result.negative = !result.negative
	}
	return result
}

// WithSign multiplies x by sign, which must be -1, 0, or +1.
func (x SignedMagnitude) WithSign(sign int) SignedMagnitude {
	switch sign {
	case -1:
		return x.Negated()
	case 0:
		return SignedMagnitude{}
	case 1:
		return NewSignedMagnitude(x.magnitude, x.negative)
	default:
		panic("r51x5: signed-magnitude sign must be -1, 0, or +1")
	}
}

// MultiplySignedMagnitudes returns the exact signed product x*y. It is
// deliberately not reduced modulo L and may be wider than either input.
func MultiplySignedMagnitudes(x, y SignedMagnitude) SignedMagnitude {
	if x.Sign() == 0 || y.Sign() == 0 {
		return SignedMagnitude{}
	}
	product := new(big.Int).Mul(x.absoluteBig(), y.absoluteBig())
	return signedMagnitudeFromBig(product, x.negative != y.negative)
}

func (x SignedMagnitude) absoluteBig() *big.Int {
	bigEndian := make([]byte, len(x.magnitude))
	for i := range x.magnitude {
		bigEndian[len(bigEndian)-1-i] = x.magnitude[i]
	}
	return new(big.Int).SetBytes(bigEndian)
}

func signedMagnitudeFromBig(value *big.Int, negative bool) SignedMagnitude {
	if value.Sign() == 0 {
		return SignedMagnitude{}
	}
	bigEndian := value.Bytes()
	littleEndian := make([]byte, len(bigEndian))
	for i := range bigEndian {
		littleEndian[len(bigEndian)-1-i] = bigEndian[i]
	}
	return NewSignedMagnitude(littleEndian, negative)
}

// RecodeRegularRadix reconstructs x exactly as sum(d[i]*2^(radixBits*i)).
// Supported radices are 16, 32, and 64. Lower digits lie in
// [-r/2,r/2-1], with a possible final +1 carry. The sign is applied to every
// digit after recoding.
func RecodeRegularRadix(x SignedMagnitude, radixBits uint) []int8 {
	if radixBits != 4 && radixBits != 5 && radixBits != 6 {
		panic("r51x5: regular radix must be 16, 32, or 64")
	}
	if x.Sign() == 0 {
		return []int8{0}
	}

	count := (x.BitLen() + int(radixBits) - 1) / int(radixBits)
	digits := make([]int16, count)
	mask := uint16((1 << radixBits) - 1)
	for i := 0; i < count; i++ {
		bit := i * int(radixBits)
		byteIndex := bit / 8
		shift := uint(bit % 8)
		word := uint16(x.magnitude[byteIndex])
		if byteIndex+1 < len(x.magnitude) {
			word |= uint16(x.magnitude[byteIndex+1]) << 8
		}
		digits[i] = int16((word >> shift) & mask)
	}

	radix := int16(1 << radixBits)
	half := radix / 2
	for i := 0; i < len(digits); i++ {
		carry := (digits[i] + half) / radix
		digits[i] -= carry * radix
		if carry != 0 {
			if i+1 == len(digits) {
				digits = append(digits, 0)
			}
			digits[i+1] += carry
		}
	}

	result := make([]int8, len(digits))
	for i := range digits {
		result[i] = int8(digits[i])
		if x.negative {
			result[i] = -result[i]
		}
	}
	return result
}

func regularRadixEntries(radixBits uint) int {
	switch radixBits {
	case 4:
		return 8
	case 5:
		return 16
	case 6:
		return 32
	default:
		panic("r51x5: regular radix must be 16, 32, or 64")
	}
}

// NominalFullTableBytes returns the coordinate payload for a full positive
// table A..(radix/2)A. coordinates must be 3 or 4. It excludes alignment,
// digit scratch, and duplicated signed entries.
func NominalFullTableBytes(lanes, coordinates int, radixBits uint) int {
	if lanes <= 0 || (coordinates != 3 && coordinates != 4) {
		panic("r51x5: invalid nominal table layout")
	}
	return regularRadixEntries(radixBits) * coordinates * 5 * lanes * 8
}

// FullTableX4 is a scalar reference table containing A through 8A, 16A, or
// 32A in every lane. Only the first entries points are initialized.
type FullTableX4 struct {
	points    [32]PointX4
	entries   int
	radixBits uint
}

// BuildFullTableX4 constructs a full positive table lane-wise.
func BuildFullTableX4(base *PointX4, radixBits uint) FullTableX4 {
	var table FullTableX4
	buildFullTableX4Into(&table, base, radixBits)
	return table
}

func buildFullTableX4Into(table *FullTableX4, base *PointX4, radixBits uint) {
	*table = FullTableX4{}
	table.entries = regularRadixEntries(radixBits)
	table.radixBits = radixBits
	table.points[0] = *base
	for i := 1; i < table.entries; i++ {
		table.points[i].Add(&table.points[i-1], base)
	}
}

// FullTableX8 is the eight-lane counterpart of FullTableX4.
type FullTableX8 struct {
	points    [32]PointX8
	entries   int
	radixBits uint
}

// BuildFullTableX8 constructs a full positive table lane-wise.
func BuildFullTableX8(base *PointX8, radixBits uint) FullTableX8 {
	var table FullTableX8
	buildFullTableX8Into(&table, base, radixBits)
	return table
}

func buildFullTableX8Into(table *FullTableX8, base *PointX8, radixBits uint) {
	*table = FullTableX8{}
	table.entries = regularRadixEntries(radixBits)
	table.radixBits = radixBits
	table.points[0] = *base
	for i := 1; i < table.entries; i++ {
		table.points[i].Add(&table.points[i-1], base)
	}
}

// RadixRoundX4 is one shared scalar-loop round for four independent lanes.
// Magnitude is zero for an inactive digit. NonzeroMask and NegativeMask make
// the public-data table lookup directly consumable by a future masked SIMD
// implementation without rediscovering signs lane by lane.
type RadixRoundX4 struct {
	Magnitude    [X4Lanes]uint8
	NonzeroMask  uint8
	NegativeMask uint8
}

// Digit returns the exact signed digit in lane.
func (r *RadixRoundX4) Digit(lane int) int8 {
	checkLane(lane, X4Lanes)
	magnitude := int8(r.Magnitude[lane])
	if r.NegativeMask&(1<<lane) != 0 {
		return -magnitude
	}
	return magnitude
}

// RadixDigitsX4 stores regular signed digits in round-major order. Scalars in
// Ed25519 verification are public, so the later indexed table selection is
// intentionally variable-time. This representation must not be reused for a
// secret-scalar API.
type RadixDigitsX4 struct {
	Rounds    []RadixRoundX4
	RadixBits uint
}

// RecodeRegularRadixX4 recodes every lane into shared, round-major records.
func RecodeRegularRadixX4(scalars *[X4Lanes]SignedMagnitude, radixBits uint) RadixDigitsX4 {
	var result RadixDigitsX4
	result.RadixBits = radixBits
	var laneDigits [X4Lanes][]int8
	maxRounds := 0
	for lane := range scalars {
		laneDigits[lane] = RecodeRegularRadix(scalars[lane], radixBits)
		if len(laneDigits[lane]) > maxRounds {
			maxRounds = len(laneDigits[lane])
		}
	}
	result.Rounds = make([]RadixRoundX4, maxRounds)
	for lane := range laneDigits {
		for round, digit := range laneDigits[lane] {
			setRadixRoundDigitX4(&result.Rounds[round], lane, digit)
		}
	}
	return result
}

// RadixRoundX8 is the eight-lane counterpart of RadixRoundX4.
type RadixRoundX8 struct {
	Magnitude    [X8Lanes]uint8
	NonzeroMask  uint8
	NegativeMask uint8
}

// Digit returns the exact signed digit in lane.
func (r *RadixRoundX8) Digit(lane int) int8 {
	checkLane(lane, X8Lanes)
	magnitude := int8(r.Magnitude[lane])
	if r.NegativeMask&(1<<lane) != 0 {
		return -magnitude
	}
	return magnitude
}

// RadixDigitsX8 stores regular signed digits in round-major order.
type RadixDigitsX8 struct {
	Rounds    []RadixRoundX8
	RadixBits uint
}

// RecodeRegularRadixX8 recodes every lane into shared, round-major records.
func RecodeRegularRadixX8(scalars *[X8Lanes]SignedMagnitude, radixBits uint) RadixDigitsX8 {
	var result RadixDigitsX8
	result.RadixBits = radixBits
	var laneDigits [X8Lanes][]int8
	maxRounds := 0
	for lane := range scalars {
		laneDigits[lane] = RecodeRegularRadix(scalars[lane], radixBits)
		if len(laneDigits[lane]) > maxRounds {
			maxRounds = len(laneDigits[lane])
		}
	}
	result.Rounds = make([]RadixRoundX8, maxRounds)
	for lane := range laneDigits {
		for round, digit := range laneDigits[lane] {
			setRadixRoundDigitX8(&result.Rounds[round], lane, digit)
		}
	}
	return result
}

func setRadixRoundDigitX4(round *RadixRoundX4, lane int, digit int8) {
	magnitude, negative := signedDigitMagnitude(digit)
	round.Magnitude[lane] = magnitude
	if magnitude != 0 {
		round.NonzeroMask |= 1 << lane
	}
	if negative {
		round.NegativeMask |= 1 << lane
	}
}

func setRadixRoundDigitX8(round *RadixRoundX8, lane int, digit int8) {
	magnitude, negative := signedDigitMagnitude(digit)
	round.Magnitude[lane] = magnitude
	if magnitude != 0 {
		round.NonzeroMask |= 1 << lane
	}
	if negative {
		round.NegativeMask |= 1 << lane
	}
}

func signedDigitMagnitude(digit int8) (uint8, bool) {
	if digit < 0 {
		return uint8(-digit), true
	}
	return uint8(digit), false
}

// ScalarMultLoopX4 evaluates pre-recoded lanes with a prebuilt table.
// Inactive lanes are identities. active must already include any decode-valid
// mask required by the caller.
func ScalarMultLoopX4(out *PointX4, table *FullTableX4, recoded *RadixDigitsX4, active uint8) *PointX4 {
	if table.radixBits != recoded.RadixBits {
		panic("r51x5: x4 table/recoding radix mismatch")
	}
	active &= 0x0f
	if active == 0 {
		return out.Set(NewIdentityPointX4())
	}
	acc := NewIdentityPointX4()
	for round := len(recoded.Rounds) - 1; round >= 0; round-- {
		if round != len(recoded.Rounds)-1 {
			for doubling := uint(0); doubling < recoded.RadixBits; doubling++ {
				acc.Double(acc)
			}
		}
		var selected PointX4
		SelectFullTableX4Public(&selected, table, &recoded.Rounds[round], active)
		acc.Add(acc, &selected)
	}
	return out.Set(acc)
}

// ScalarMultX4 includes regular recoding and variable-base table generation.
func ScalarMultX4(out *PointX4, base *PointX4, scalars *[X4Lanes]SignedMagnitude, radixBits uint, active uint8) *PointX4 {
	table := BuildFullTableX4(base, radixBits)
	recoded := RecodeRegularRadixX4(scalars, radixBits)
	return ScalarMultLoopX4(out, &table, &recoded, active)
}

// ScalarMultLoopX8 is the eight-lane counterpart of ScalarMultLoopX4.
func ScalarMultLoopX8(out *PointX8, table *FullTableX8, recoded *RadixDigitsX8, active uint8) *PointX8 {
	if table.radixBits != recoded.RadixBits {
		panic("r51x5: x8 table/recoding radix mismatch")
	}
	if active == 0 {
		return out.Set(NewIdentityPointX8())
	}
	acc := NewIdentityPointX8()
	for round := len(recoded.Rounds) - 1; round >= 0; round-- {
		if round != len(recoded.Rounds)-1 {
			for doubling := uint(0); doubling < recoded.RadixBits; doubling++ {
				acc.Double(acc)
			}
		}
		var selected PointX8
		SelectFullTableX8Public(&selected, table, &recoded.Rounds[round], active)
		acc.Add(acc, &selected)
	}
	return out.Set(acc)
}

// ScalarMultX8 includes regular recoding and variable-base table generation.
func ScalarMultX8(out *PointX8, base *PointX8, scalars *[X8Lanes]SignedMagnitude, radixBits uint, active uint8) *PointX8 {
	table := BuildFullTableX8(base, radixBits)
	recoded := RecodeRegularRadixX8(scalars, radixBits)
	return ScalarMultLoopX8(out, &table, &recoded, active)
}

// QSMScalarsX4 stores [term][lane] exact signed coefficients.
type QSMScalarsX4 [QSMTerms][X4Lanes]SignedMagnitude

// QSMScalarsX8 stores [term][lane] exact signed coefficients.
type QSMScalarsX8 [QSMTerms][X8Lanes]SignedMagnitude

// QSMX4 evaluates four simultaneous scalar terms per active lane. It is a
// scalar correctness scaffold, not an IFMA implementation.
func QSMX4(out *PointX4, bases *[QSMTerms]PointX4, coefficients *QSMScalarsX4, radixBits uint, active uint8) *PointX4 {
	var tables [QSMTerms]FullTableX4
	var recoded [QSMTerms]RadixDigitsX4
	for term := 0; term < QSMTerms; term++ {
		tables[term] = BuildFullTableX4(&bases[term], radixBits)
		recoded[term] = RecodeRegularRadixX4(&coefficients[term], radixBits)
	}
	active &= 0x0f
	if active == 0 {
		return out.Set(NewIdentityPointX4())
	}
	maxRounds := 0
	for term := range recoded {
		if len(recoded[term].Rounds) > maxRounds {
			maxRounds = len(recoded[term].Rounds)
		}
	}
	acc := NewIdentityPointX4()
	for round := maxRounds - 1; round >= 0; round-- {
		if round != maxRounds-1 {
			for doubling := uint(0); doubling < radixBits; doubling++ {
				acc.Double(acc)
			}
		}
		for term := 0; term < QSMTerms; term++ {
			var selected PointX4
			if round < len(recoded[term].Rounds) {
				SelectFullTableX4Public(&selected, &tables[term], &recoded[term].Rounds[round], active)
			} else {
				selected.Set(NewIdentityPointX4())
			}
			acc.Add(acc, &selected)
		}
	}
	return out.Set(acc)
}

// QSMX8 is the eight-lane counterpart of QSMX4.
func QSMX8(out *PointX8, bases *[QSMTerms]PointX8, coefficients *QSMScalarsX8, radixBits uint, active uint8) *PointX8 {
	var tables [QSMTerms]FullTableX8
	var recoded [QSMTerms]RadixDigitsX8
	for term := 0; term < QSMTerms; term++ {
		tables[term] = BuildFullTableX8(&bases[term], radixBits)
		recoded[term] = RecodeRegularRadixX8(&coefficients[term], radixBits)
	}
	if active == 0 {
		return out.Set(NewIdentityPointX8())
	}
	maxRounds := 0
	for term := range recoded {
		if len(recoded[term].Rounds) > maxRounds {
			maxRounds = len(recoded[term].Rounds)
		}
	}
	acc := NewIdentityPointX8()
	for round := maxRounds - 1; round >= 0; round-- {
		if round != maxRounds-1 {
			for doubling := uint(0); doubling < radixBits; doubling++ {
				acc.Double(acc)
			}
		}
		for term := 0; term < QSMTerms; term++ {
			var selected PointX8
			if round < len(recoded[term].Rounds) {
				SelectFullTableX8Public(&selected, &tables[term], &recoded[term].Rounds[round], active)
			} else {
				selected.Set(NewIdentityPointX8())
			}
			acc.Add(acc, &selected)
		}
	}
	return out.Set(acc)
}

// HEEAEquationX4 evaluates [tau*s]B-[tau]R-[epsilon*rho]A. Invalid epsilon
// lanes are removed from the returned usable mask and filled with identity.
// The fourth QSM slot is zero, reserved for a future explicitly proved
// correction term without changing this exact-signed handoff.
func HEEAEquationX4(out *PointX4, B, R, A *PointX4, s, tau, rho *[X4Lanes]SignedMagnitude, epsilon *[X4Lanes]int8, radixBits uint, active uint8) uint8 {
	usable := active & 0x0f
	var bases [QSMTerms]PointX4
	bases[0], bases[1], bases[2] = *B, *R, *A
	bases[3] = *NewIdentityPointX4()
	var coefficients QSMScalarsX4
	for lane := 0; lane < X4Lanes; lane++ {
		if usable&(1<<lane) == 0 {
			continue
		}
		if epsilon[lane] != -1 && epsilon[lane] != 1 {
			usable &^= 1 << lane
			continue
		}
		coefficients[0][lane] = MultiplySignedMagnitudes(tau[lane], s[lane])
		coefficients[1][lane] = tau[lane].Negated()
		coefficients[2][lane] = rho[lane].WithSign(int(epsilon[lane])).Negated()
	}
	QSMX4(out, &bases, &coefficients, radixBits, usable)
	return usable
}

// HEEAEquationX8 is the eight-lane counterpart of HEEAEquationX4.
func HEEAEquationX8(out *PointX8, B, R, A *PointX8, s, tau, rho *[X8Lanes]SignedMagnitude, epsilon *[X8Lanes]int8, radixBits uint, active uint8) uint8 {
	usable := active
	var bases [QSMTerms]PointX8
	bases[0], bases[1], bases[2] = *B, *R, *A
	bases[3] = *NewIdentityPointX8()
	var coefficients QSMScalarsX8
	for lane := 0; lane < X8Lanes; lane++ {
		if usable&(1<<lane) == 0 {
			continue
		}
		if epsilon[lane] != -1 && epsilon[lane] != 1 {
			usable &^= 1 << lane
			continue
		}
		coefficients[0][lane] = MultiplySignedMagnitudes(tau[lane], s[lane])
		coefficients[1][lane] = tau[lane].Negated()
		coefficients[2][lane] = rho[lane].WithSign(int(epsilon[lane])).Negated()
	}
	QSMX8(out, &bases, &coefficients, radixBits, usable)
	return usable
}
