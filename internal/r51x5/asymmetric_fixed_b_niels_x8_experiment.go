package r51x5

// IFMAAsymmetricFixedB10TableX8 is a one-row, process-shared signed table for
// a public fixed point. Unlike the separate two-row radix-256 comb,
// it uses the 250 doublings already required by the radix-32 variable-base
// term. Width ten therefore needs only 26 fixed-base additions and no
// separate fixed-base doubling chain or final point addition.
//
// Regime tag: complete 200-, 1,232-, and 4,096-byte cold-verifier A/B gates on
// AMD family 1Ah (Zen 5) measured a consistent win over the separate comb.
// Registered dispatch enables this table only under that measured CPU policy;
// Zen 4 and unknown IFMA CPUs retain the separate-comb control.
type IFMAAsymmetricFixedB10TableX8 struct {
	points [512]fixedBaseIFMASignedAffineCached
}

type asymmetricFixedB10RoundX8 struct {
	Magnitude    [X8Lanes]uint16
	NonzeroMask  uint8
	NegativeMask uint8
}

type asymmetricFixedB10DigitsX8 struct {
	rounds [26]asymmetricFixedB10RoundX8
}

// BuildIFMAAsymmetricFixedB10TableX8 prepares both public signs
// of multiples 1..512 of base. The resulting 120-KiB table is immutable and
// safe for concurrent evaluation after construction.
func BuildIFMAAsymmetricFixedB10TableX8(base *Point) *IFMAAsymmetricFixedB10TableX8 {
	table := new(IFMAAsymmetricFixedB10TableX8)
	multiple := *base
	for entry := range table.points {
		var cached fixedBaseAffineCached
		fixedBaseCacheAffine(&cached, &multiple)
		storeFixedBaseIFMASignedAffineCached(&table.points[entry], &cached)
		if entry+1 < len(table.points) {
			fixedBasePointAdd(&multiple, &multiple, base)
		}
	}
	return table
}

func recodeAsymmetricFixedB10ScalarsX8(
	out *asymmetricFixedB10DigitsX8,
	scalars *[X8Lanes][32]byte,
	active uint8,
) uint8 {
	*out = asymmetricFixedB10DigitsX8{}
	var usable uint8
	for lane := 0; lane < X8Lanes; lane++ {
		laneMask := uint8(1 << lane)
		if active&laneMask == 0 || !canonicalScalarBytes(&scalars[lane]) {
			continue
		}
		usable |= laneMask
		words := asymmetricFixedBScalarWords(&scalars[lane])
		carry := int32(0)
		for round := range out.rounds {
			digit := int32(asymmetricFixedBScalarWordBits(&words, round*10, 10)) + carry
			carry = (digit + 512) >> 10
			digit -= carry << 10
			negative := digit < 0
			if negative {
				digit = -digit
			}
			out.rounds[round].Magnitude[lane] = uint16(digit)
			if digit != 0 {
				out.rounds[round].NonzeroMask |= laneMask
			}
			if negative {
				out.rounds[round].NegativeMask |= laneMask
			}
		}
		if carry != 0 {
			panic("r51x5: canonical scalar exceeded x8 asymmetric B10 schedule")
		}
	}
	return usable
}

func selectAsymmetricFixedB10SignedX8(
	out *fixedBaseIFMACachedX8,
	table *IFMAAsymmetricFixedB10TableX8,
	round *asymmetricFixedB10RoundX8,
	active uint8,
) {
	lookupMask := round.NonzeroMask & active
	p0 := &ifmaAffine3MicroAoSIdentityEntryExperiment
	p1, p2, p3, p4, p5, p6, p7 := p0, p0, p0, p0, p0, p0, p0
	pointers := [X8Lanes]**ifmaAffine3MicroAoSEntryExperiment{&p0, &p1, &p2, &p3, &p4, &p5, &p6, &p7}
	for lane := 0; lane < X8Lanes; lane++ {
		laneMask := uint8(1 << lane)
		if lookupMask&laneMask == 0 {
			continue
		}
		magnitude := round.Magnitude[lane]
		if magnitude == 0 || magnitude > uint16(len(table.points)) {
			panic("r51x5: x8 asymmetric B10 digit outside table")
		}
		sign := fixedBasePublicSign(round.NegativeMask, laneMask)
		*pointers[lane] = &table.points[int(magnitude)-1][sign]
	}
	ifmaAffine3MicroAoSTransposeSelectExperimentX8(out, p0, p1, p2, p3, p4, p5, p6, p7)
}

// IFMAAsymmetricFixedB10EvaluateX8 computes [s]B-[k]A on one
// shared 250-doubling chain. variable must already be prepared for A at radix
// 32. B is fixed and public; s and k retain independent per-lane verdicts.
// Each five-doubling block uses the same dedicated-square P3 -> P2 -> P3
// schedule as the registered standalone A term: T is omitted from the first
// four results and restored before either A or B can consume the point.
func IFMAAsymmetricFixedB10EvaluateX8(
	out *IFMAPointX8,
	variable *ExperimentalIFMAProjectiveNielsPreSignedMicroAoSVariableBaseWorkspaceX8,
	fixed *IFMAAsymmetricFixedB10TableX8,
	s, k *[X8Lanes][32]byte,
	active uint8,
) (uint8, error) {
	if !ExperimentalIFMAAvailable() {
		return 0, ErrIFMAUnavailable
	}
	usable := recodeCanonicalScalarsRadix32X8(&variable.digits, k, active, active)
	var bDigits asymmetricFixedB10DigitsX8
	usable &= recodeAsymmetricFixedB10ScalarsX8(&bDigits, s, active)
	acc := identityIFMAPointX8Value()
	if usable == 0 {
		*out = acc
		return 0, nil
	}

	var doubleWorkspace ifmaPointDoubleWorkspaceX8
	var projective ifmaProjectivePointX8
	var aAddWorkspace ifmaPointAddProjectiveNielsScratchX8
	var bAddWorkspace fixedBaseIFMAAddScratchX8
	for block := 25; block >= 0; block-- {
		bRound := &bDigits.rounds[block]
		if bRound.NonzeroMask&usable != 0 {
			var selected fixedBaseIFMACachedX8
			selectAsymmetricFixedB10SignedX8(&selected, fixed, bRound, usable)
			if err := addFixedBaseIFMACachedWorkspaceX8(&acc, &acc, &selected, &bAddWorkspace); err != nil {
				return 0, err
			}
		}
		aEven := variable.digits.Round(block * 2)
		if aEven.NonzeroMask&usable != 0 {
			var selected IFMAProjectiveNielsX8
			selectIFMAProjectiveNielsPreSignedMicroAoSX8(&selected, &variable.table, aEven, usable)
			if err := ifmaPointAddProjectiveNielsWorkspaceX8(&acc, &acc, &selected, &aAddWorkspace); err != nil {
				return 0, err
			}
		}
		if block == 0 {
			break
		}
		ifmaPointDoubleRawSquareP3ToP2ExperimentX8(&projective, &acc, &doubleWorkspace)
		for doubling := 1; doubling < 4; doubling++ {
			ifmaPointDoubleRawSquareP2ToP2ExperimentX8(&projective, &projective, &doubleWorkspace)
		}
		ifmaPointDoubleRawSquareP2ToP3ExperimentX8(&acc, &projective, &doubleWorkspace)
		aOdd := variable.digits.Round(block*2 - 1)
		if aOdd.NonzeroMask&usable != 0 {
			var selected IFMAProjectiveNielsX8
			selectIFMAProjectiveNielsPreSignedMicroAoSX8(&selected, &variable.table, aOdd, usable)
			if err := ifmaPointAddProjectiveNielsWorkspaceX8(&acc, &acc, &selected, &aAddWorkspace); err != nil {
				return 0, err
			}
		}
		ifmaPointDoubleRawSquareP3ToP2ExperimentX8(&projective, &acc, &doubleWorkspace)
		for doubling := 1; doubling < 4; doubling++ {
			ifmaPointDoubleRawSquareP2ToP2ExperimentX8(&projective, &projective, &doubleWorkspace)
		}
		ifmaPointDoubleRawSquareP2ToP3ExperimentX8(&acc, &projective, &doubleWorkspace)
	}
	*out = acc
	return usable, nil
}
