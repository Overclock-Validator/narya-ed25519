// Asymmetric fixed-B DSM: table construction, scalar recoding, selection and
// prepared radix-64 evaluation.
//
// Promoted verbatim from asymmetric_fixed_b_dsm_experiment_test.go; the
// partial-comb construction in partial_comb.go depends on these symbols, so
// they must live outside _test.go for the registered backend to build.
// Names are unchanged so the move is provably behaviour-neutral.

package r51x5

import "encoding/binary"

// asymmetricFixedBTableExperiment is a deliberately test-only, one-row
// positive table for a public fixed base. Unlike ExperimentalFixedBaseCombTable
// this is an ordinary signed-window table: entry i is [(i+1)]B. It is stored
// once as scalar affine-cached points and gathered into four lanes at use.
type asymmetricFixedBTableExperiment struct {
	points      []fixedBaseAffineCached
	densePoints []ifmaAffine3MicroAoSEntryExperiment
	radixBits   uint
}

func asymmetricFixedBScalarWords(scalar *[32]byte) [5]uint64 {
	return [5]uint64{
		binary.LittleEndian.Uint64(scalar[0:8]),
		binary.LittleEndian.Uint64(scalar[8:16]),
		binary.LittleEndian.Uint64(scalar[16:24]),
		binary.LittleEndian.Uint64(scalar[24:32]),
		0, // Guard word for a final digit that straddles bit 255.
	}
}

func asymmetricFixedBScalarWordBits(words *[5]uint64, bit int, width uint) uint16 {
	wordIndex := bit >> 6
	shift := uint(bit & 63)
	value := words[wordIndex] >> shift
	if shift+width > 64 {
		value |= words[wordIndex+1] << (64 - shift)
	}
	return uint16(value & ((uint64(1) << width) - 1))
}

// asymmetricFixedBRoundX4 is local to this experiment because widths 9 and 10
// cannot use RadixRoundX4's int8/uint8 digit ABI. In particular it represents
// the balanced boundary digits -256 and -512 without truncation.
type asymmetricFixedBRoundX4 struct {
	Magnitude    [X4Lanes]uint16
	NonzeroMask  uint8
	NegativeMask uint8
}

type asymmetricFixedBDigitsX4 struct {
	rounds    [maxFixedScalarRounds]asymmetricFixedBRoundX4
	count     uint8
	radixBits uint8
}

func buildAsymmetricFixedBTableExperiment(base *Point, radixBits uint) *asymmetricFixedBTableExperiment {
	if radixBits < 6 || radixBits > 10 {
		panic("r51x5: asymmetric fixed-B experiment width must be 6 through 10")
	}
	entries := 1 << (radixBits - 1)
	table := &asymmetricFixedBTableExperiment{
		points:      make([]fixedBaseAffineCached, entries),
		densePoints: make([]ifmaAffine3MicroAoSEntryExperiment, entries),
		radixBits:   radixBits,
	}
	multiple := *base
	for entry := range table.points {
		fixedBaseCacheAffine(&table.points[entry], &multiple)
		importAsymmetricFixedBDenseAffine3EntryExperiment(&table.densePoints[entry], &table.points[entry])
		if entry+1 < len(table.points) {
			fixedBasePointAdd(&multiple, &multiple, base)
		}
	}
	return table
}

func importAsymmetricFixedBDenseAffine3EntryExperiment(
	out *ifmaAffine3MicroAoSEntryExperiment,
	source *fixedBaseAffineCached,
) {
	for limb := range modulusLimbs {
		out[limb][0] = source.YPlusX.limbs[limb]
		out[limb][1] = source.YMinusX.limbs[limb]
		out[limb][2] = source.T2D.limbs[limb]
	}
}

func asymmetricFixedBRoundCount(radixBits uint) int {
	if radixBits < 6 || radixBits > 10 {
		panic("r51x5: asymmetric fixed-B experiment width must be 6 through 10")
	}
	// Canonical Ed25519 scalars are below 2^253. The extra top zero bits are
	// intentional: they absorb the final carry of balanced recoding.
	return (253 + int(radixBits) - 1) / int(radixBits)
}

func recodeAsymmetricFixedBScalarsX4(
	out *asymmetricFixedBDigitsX4,
	scalars *[X4Lanes][32]byte,
	negativeMask, active uint8,
	radixBits uint,
) uint8 {
	*out = asymmetricFixedBDigitsX4{}
	out.count = uint8(asymmetricFixedBRoundCount(radixBits))
	out.radixBits = uint8(radixBits)
	active &= 0x0f
	var valid uint8
	for lane := 0; lane < X4Lanes; lane++ {
		laneMask := uint8(1 << lane)
		if active&laneMask == 0 || !canonicalScalarBytes(&scalars[lane]) {
			continue
		}
		valid |= laneMask
		words := asymmetricFixedBScalarWords(&scalars[lane])
		carry := int32(0)
		half := int32(1) << (radixBits - 1)
		for round := 0; round < int(out.count); round++ {
			digit := int32(asymmetricFixedBScalarWordBits(&words, round*int(radixBits), radixBits)) + carry
			// The extractor is nonnegative and carry is zero or one, so this
			// is exact power-of-two division without a hardware IDIV.
			carry = (digit + half) >> radixBits
			digit -= carry << radixBits
			if negativeMask&laneMask != 0 {
				digit = -digit
			}
			setAsymmetricFixedBRoundDigitX4(&out.rounds[round], lane, int16(digit))
		}
		if carry != 0 {
			panic("r51x5: canonical scalar exceeded asymmetric fixed-B width")
		}
	}
	return valid
}

// asymmetricFixedBScalarBitsExperiment intentionally reads three bytes. A
// two-byte extractor is insufficient for a width-10 digit starting at bit
// offset seven, which spans 17 source bits before the right shift.
func asymmetricFixedBScalarBitsExperiment(scalar *[32]byte, bit int, width uint) uint16 {
	byteIndex := bit >> 3
	shift := uint(bit & 7)
	var word uint32
	if byteIndex < len(scalar) {
		word = uint32(scalar[byteIndex])
	}
	if byteIndex+1 < len(scalar) {
		word |= uint32(scalar[byteIndex+1]) << 8
	}
	if byteIndex+2 < len(scalar) {
		word |= uint32(scalar[byteIndex+2]) << 16
	}
	return uint16((word >> shift) & ((uint32(1) << width) - 1))
}

func setAsymmetricFixedBRoundDigitX4(round *asymmetricFixedBRoundX4, lane int, digit int16) {
	if digit < -512 || digit > 512 {
		panic("r51x5: asymmetric fixed-B digit outside experiment ABI")
	}
	negative := digit < 0
	if negative {
		digit = -digit
	}
	round.Magnitude[lane] = uint16(digit)
	if digit != 0 {
		round.NonzeroMask |= 1 << lane
	}
	if negative {
		round.NegativeMask |= 1 << lane
	}
}

func selectAsymmetricFixedBIFMACachedX4(
	out *fixedBaseIFMACachedX4,
	table *asymmetricFixedBTableExperiment,
	round *asymmetricFixedBRoundX4,
	active uint8,
) {
	*out = identityFixedBaseIFMACachedX4()
	active &= 0x0f
	lookupMask := round.NonzeroMask & active
	for lane := 0; lane < X4Lanes; lane++ {
		laneMask := uint8(1 << lane)
		magnitude := int(round.Magnitude[lane])
		if active&laneMask == 0 {
			// The other DSM term can invalidate this lane after B has already
			// been recoded. Ignore B's now-dead public metadata and emit the
			// cached identity so the combined validity mask remains fail-closed.
			continue
		}
		if round.NonzeroMask&laneMask == 0 {
			if magnitude != 0 || round.NegativeMask&laneMask != 0 {
				panic("r51x5: zero asymmetric fixed-B digit has metadata")
			}
			continue
		}
		if magnitude < 1 || magnitude > len(table.points) {
			panic("r51x5: asymmetric fixed-B magnitude outside table")
		}
		if lookupMask&laneMask != 0 {
			setFixedBaseIFMACachedLaneX4(out, &table.points[magnitude-1], lane, round.NegativeMask&laneMask != 0)
		}
	}
}

// selectAsymmetricFixedBDenseAffine3CheckedX4 preserves the scalar selector's
// public-metadata validation and output atomicity while using the dense
// affine3 transpose ABI. The uint16 magnitude checks are local because widths
// 9 and 10 exceed RadixRoundX4's uint8 digit ABI.
func selectAsymmetricFixedBDenseAffine3CheckedX4(
	out *fixedBaseIFMACachedX4,
	table *asymmetricFixedBTableExperiment,
	round *asymmetricFixedBRoundX4,
	active uint8,
) *fixedBaseIFMACachedX4 {
	active &= 0x0f
	lookupMask := round.NonzeroMask & active
	p0 := &ifmaAffine3MicroAoSIdentityEntryExperiment
	p1, p2, p3 := p0, p0, p0
	for lane := 0; lane < X4Lanes; lane++ {
		laneMask := uint8(1 << lane)
		if active&laneMask == 0 {
			continue
		}
		magnitude := round.Magnitude[lane]
		nonzero := round.NonzeroMask&laneMask != 0
		negative := round.NegativeMask&laneMask != 0
		if !nonzero {
			if magnitude != 0 || negative {
				panic("r51x5: zero asymmetric fixed-B digit has metadata")
			}
			continue
		}
		if magnitude < 1 || int(magnitude) > len(table.densePoints) {
			panic("r51x5: asymmetric fixed-B magnitude outside dense table")
		}
		source := &table.densePoints[int(magnitude)-1]
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

	var selected fixedBaseIFMACachedX4
	ifmaAffine3MicroAoSTransposeSelectExperimentX4(&selected, p0, p1, p2, p3)
	conditionalNegateIFMAAffine3MicroAoSX4(&selected, round.NegativeMask&lookupMask)
	*out = selected
	return out
}

// selectAsymmetricFixedBDenseAffine3UncheckedX4 is the validated hot-loop
// counterpart. It selects four source pointers before the transpose and then
// applies the exact signed-digit negation to the cached affine representation.
func selectAsymmetricFixedBDenseAffine3UncheckedX4(
	out *fixedBaseIFMACachedX4,
	table *asymmetricFixedBTableExperiment,
	round *asymmetricFixedBRoundX4,
	active uint8,
) *fixedBaseIFMACachedX4 {
	lookupMask := round.NonzeroMask & active & 0x0f
	p0 := &ifmaAffine3MicroAoSIdentityEntryExperiment
	p1, p2, p3 := p0, p0, p0
	if lookupMask == 0x0f {
		p0 = &table.densePoints[int(round.Magnitude[0])-1]
		p1 = &table.densePoints[int(round.Magnitude[1])-1]
		p2 = &table.densePoints[int(round.Magnitude[2])-1]
		p3 = &table.densePoints[int(round.Magnitude[3])-1]
	} else {
		if lookupMask&0x01 != 0 {
			p0 = &table.densePoints[int(round.Magnitude[0])-1]
		}
		if lookupMask&0x02 != 0 {
			p1 = &table.densePoints[int(round.Magnitude[1])-1]
		}
		if lookupMask&0x04 != 0 {
			p2 = &table.densePoints[int(round.Magnitude[2])-1]
		}
		if lookupMask&0x08 != 0 {
			p3 = &table.densePoints[int(round.Magnitude[3])-1]
		}
	}
	ifmaAffine3MicroAoSTransposeSelectExperimentX4(out, p0, p1, p2, p3)
	conditionalNegateIFMAAffine3MicroAoSX4(out, round.NegativeMask&lookupMask)
	return out
}

// evaluateAsymmetricFixedBPreparedRadix64DSMX4 computes [s]B+[-k]A on one
// exact merged timeline. A remains the current radix-64 per-key micro-AoS
// path. B alone varies from width 6 through 10 and uses a shared scalar affine
// table. The event at exponent e is injected before lowering the accumulator
// to e-1, so the total number of doublings is max(42*6,(roundsB-1)*wB)=252.
func evaluateAsymmetricFixedBPreparedRadix64DSMX4(
	out *IFMAPointX4,
	aTables *[X4Lanes]ifmaMicroAoSPerKeyTableExperiment,
	bTable *asymmetricFixedBTableExperiment,
	scalars *FixedDSMScalarsX4,
	negativeMasks *[DSMTerms]uint8,
	active uint8,
) (uint8, error) {
	if !ExperimentalIFMAAvailable() {
		return 0, ErrIFMAUnavailable
	}
	active &= 0x0f
	var aDigits FixedRadixDigitsX4
	usable := RecodeCanonicalScalarsX4(&aDigits, &scalars[1], negativeMasks[1], active, 6)
	var bDigits asymmetricFixedBDigitsX4
	usable &= recodeAsymmetricFixedBScalarsX4(&bDigits, &scalars[0], negativeMasks[0], active, bTable.radixBits)
	acc := identityIFMAPointX4Value()
	if usable == 0 {
		*out = acc
		return 0, nil
	}

	const topExponent = 42 * 6
	for exponent := topExponent; exponent >= 0; exponent-- {
		if exponent != topExponent {
			if err := ifmaPointDoubleComposableStaticX4(&acc, &acc); err != nil {
				return 0, err
			}
		}
		if exponent%int(bTable.radixBits) == 0 {
			roundIndex := exponent / int(bTable.radixBits)
			if roundIndex < int(bDigits.count) {
				round := &bDigits.rounds[roundIndex]
				if round.NonzeroMask&usable != 0 {
					var selected fixedBaseIFMACachedX4
					selectAsymmetricFixedBIFMACachedX4(&selected, bTable, round, usable)
					if err := addFixedBaseIFMACachedX4(&acc, &acc, &selected); err != nil {
						return 0, err
					}
				}
			}
		}
		if exponent%6 == 0 {
			roundIndex := exponent / 6
			round := aDigits.Round(roundIndex)
			if round.NonzeroMask&usable != 0 {
				var selected IFMAPointX4
				selectIFMAMicroAoSUncheckedExperimentX4(&selected, aTables, round, usable)
				if err := ifmaPointAddComposableStaticX4(&acc, &acc, &selected); err != nil {
					return 0, err
				}
			}
		}
	}
	*out = acc
	return usable, nil
}

// evaluateAsymmetricFixedBDensePreparedRadix64DSMX4 is the dense-affine-B
// candidate. It intentionally mirrors evaluateAsymmetricFixedBPreparedRadix64DSMX4
// so the existing scalar-affine implementation remains an unmodified control.
func evaluateAsymmetricFixedBDensePreparedRadix64DSMX4(
	out *IFMAPointX4,
	aTables *[X4Lanes]ifmaMicroAoSPerKeyTableExperiment,
	bTable *asymmetricFixedBTableExperiment,
	scalars *FixedDSMScalarsX4,
	negativeMasks *[DSMTerms]uint8,
	active uint8,
) (uint8, error) {
	if !ExperimentalIFMAAvailable() {
		return 0, ErrIFMAUnavailable
	}
	active &= 0x0f
	var aDigits FixedRadixDigitsX4
	usable := RecodeCanonicalScalarsX4(&aDigits, &scalars[1], negativeMasks[1], active, 6)
	var bDigits asymmetricFixedBDigitsX4
	usable &= recodeAsymmetricFixedBScalarsX4(&bDigits, &scalars[0], negativeMasks[0], active, bTable.radixBits)
	acc := identityIFMAPointX4Value()
	if usable == 0 {
		*out = acc
		return 0, nil
	}

	const topExponent = 42 * 6
	for exponent := topExponent; exponent >= 0; exponent-- {
		if exponent != topExponent {
			if err := ifmaPointDoubleComposableStaticX4(&acc, &acc); err != nil {
				return 0, err
			}
		}
		if exponent%int(bTable.radixBits) == 0 {
			roundIndex := exponent / int(bTable.radixBits)
			if roundIndex < int(bDigits.count) {
				round := &bDigits.rounds[roundIndex]
				if round.NonzeroMask&usable != 0 {
					var selected fixedBaseIFMACachedX4
					selectAsymmetricFixedBDenseAffine3UncheckedX4(&selected, bTable, round, usable)
					if err := addFixedBaseIFMACachedX4(&acc, &acc, &selected); err != nil {
						return 0, err
					}
				}
			}
		}
		if exponent%6 == 0 {
			roundIndex := exponent / 6
			round := aDigits.Round(roundIndex)
			if round.NonzeroMask&usable != 0 {
				var selected IFMAPointX4
				selectIFMAMicroAoSUncheckedExperimentX4(&selected, aTables, round, usable)
				if err := ifmaPointAddComposableStaticX4(&acc, &acc, &selected); err != nil {
					return 0, err
				}
			}
		}
	}
	*out = acc
	return usable, nil
}
