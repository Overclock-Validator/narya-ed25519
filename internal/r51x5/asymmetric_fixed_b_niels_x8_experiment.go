package r51x5

// ExperimentalIFMAAsymmetricFixedB10TableX8 is a one-row, process-shared
// signed table for a public fixed point. Unlike the production two-row comb,
// it uses the 250 doublings already required by the radix-32 variable-base
// term. Width ten therefore needs only 26 fixed-base additions and no
// separate fixed-base doubling chain or final point addition.
//
// Regime tag: this is an x8 cold-verification experiment. A 2026-07-29 Zen 5
// arithmetic-core gate measured about 3.4% over the separate radix-256 comb.
// It is not reachable from registered dispatch pending a complete-verifier
// gate and broader differential coverage.
type ExperimentalIFMAAsymmetricFixedB10TableX8 struct {
	points [512]fixedBaseIFMASignedAffineCached
}

type asymmetricFixedBRoundX8Experiment struct {
	Magnitude    [X8Lanes]uint16
	NonzeroMask  uint8
	NegativeMask uint8
}

type asymmetricFixedBDigitsX8Experiment struct {
	rounds [26]asymmetricFixedBRoundX8Experiment
}

// BuildExperimentalIFMAAsymmetricFixedB10TableX8 prepares both public signs
// of multiples 1..512 of base. The resulting 120-KiB table is immutable and
// safe for concurrent evaluation after construction.
func BuildExperimentalIFMAAsymmetricFixedB10TableX8(base *Point) *ExperimentalIFMAAsymmetricFixedB10TableX8 {
	table := new(ExperimentalIFMAAsymmetricFixedB10TableX8)
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

func recodeAsymmetricFixedB10ScalarsX8Experiment(
	out *asymmetricFixedBDigitsX8Experiment,
	scalars *[X8Lanes][32]byte,
	active uint8,
) uint8 {
	*out = asymmetricFixedBDigitsX8Experiment{}
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

func selectAsymmetricFixedB10SignedX8Experiment(
	out *fixedBaseIFMACachedX8,
	table *ExperimentalIFMAAsymmetricFixedB10TableX8,
	round *asymmetricFixedBRoundX8Experiment,
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

// ExperimentalIFMAAsymmetricFixedB10EvaluateX8 computes [s]B-[k]A on one
// shared 250-doubling chain. variable must already be prepared for A at radix
// 32. B is fixed and public; s and k retain independent per-lane verdicts.
func ExperimentalIFMAAsymmetricFixedB10EvaluateX8(
	out *IFMAPointX8,
	variable *ExperimentalIFMAProjectiveNielsPreSignedMicroAoSVariableBaseWorkspaceX8,
	fixed *ExperimentalIFMAAsymmetricFixedB10TableX8,
	s, k *[X8Lanes][32]byte,
	active uint8,
) (uint8, error) {
	if !ExperimentalIFMAAvailable() {
		return 0, ErrIFMAUnavailable
	}
	usable := RecodeCanonicalScalarsX8(&variable.digits, k, active, active, 5)
	var bDigits asymmetricFixedBDigitsX8Experiment
	usable &= recodeAsymmetricFixedB10ScalarsX8Experiment(&bDigits, s, active)
	acc := identityIFMAPointX8Value()
	if usable == 0 {
		*out = acc
		return 0, nil
	}

	var doubleWorkspace ifmaPointDoubleWorkspaceX8
	var aAddWorkspace ifmaPointAddProjectiveNielsScratchX8
	var bAddWorkspace fixedBaseIFMAAddScratchX8
	for block := 25; block >= 0; block-- {
		bRound := &bDigits.rounds[block]
		if bRound.NonzeroMask&usable != 0 {
			var selected fixedBaseIFMACachedX8
			selectAsymmetricFixedB10SignedX8Experiment(&selected, fixed, bRound, usable)
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
		for range 5 {
			if err := ifmaPointDoubleComposableWorkspaceStaticX8(&acc, &acc, &doubleWorkspace); err != nil {
				return 0, err
			}
		}
		aOdd := variable.digits.Round(block*2 - 1)
		if aOdd.NonzeroMask&usable != 0 {
			var selected IFMAProjectiveNielsX8
			selectIFMAProjectiveNielsPreSignedMicroAoSX8(&selected, &variable.table, aOdd, usable)
			if err := ifmaPointAddProjectiveNielsWorkspaceX8(&acc, &acc, &selected, &aAddWorkspace); err != nil {
				return 0, err
			}
		}
		for range 5 {
			if err := ifmaPointDoubleComposableWorkspaceStaticX8(&acc, &acc, &doubleWorkspace); err != nil {
				return 0, err
			}
		}
	}
	*out = acc
	return usable, nil
}
