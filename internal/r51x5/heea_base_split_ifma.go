package r51x5

import "math/bits"

// ExperimentalHEEASignedCoefficient is a fixed-storage exact signed integer
// for the HEEA research path. Magnitude is a little-endian absolute value;
// Negative is an integer sign, not scalar negation modulo L.
//
// The IFMA base-split workspace admits magnitudes below L. Current modulo-8L
// HEEA selectors produce at most 136-bit rho and tau values, so this gate does
// not narrow an admitted candidate. A larger value is an explicit baseline
// fallback and is never reduced before multiplying A or R.
type ExperimentalHEEASignedCoefficient struct {
	Magnitude [32]byte
	Negative  bool
}

// ExperimentalHEEABaseSplitCoefficientsX4 owns the four fixed scalar
// schedules for
//
//	[lambda0]B + [lambda1]([2^128]B) - [tau]R - [epsilon*rho]A.
//
// Its fields are private so callers cannot accidentally replace an exact
// signed A/R coefficient with a modulo-L representative. Prepare with
// ExperimentalPrepareHEEABaseSplitCoefficientsX4.
type ExperimentalHEEABaseSplitCoefficientsX4 struct {
	scalars       [QSMTerms][X4Lanes][32]byte
	negativeMasks [QSMTerms]uint8
	validMask     uint8
}

// ExperimentalHEEABaseSplitCoefficientsX8 is the eight-lane counterpart of
// ExperimentalHEEABaseSplitCoefficientsX4.
type ExperimentalHEEABaseSplitCoefficientsX8 struct {
	scalars       [QSMTerms][X8Lanes][32]byte
	negativeMasks [QSMTerms]uint8
	validMask     uint8
}

// ValidMask reports the lanes admitted by coefficient preparation.
func (c *ExperimentalHEEABaseSplitCoefficientsX4) ValidMask() uint8 {
	return c.validMask & 0x0f
}

// ValidMask reports the lanes admitted by coefficient preparation.
func (c *ExperimentalHEEABaseSplitCoefficientsX8) ValidMask() uint8 {
	return c.validMask
}

// FallbackMask reports active lanes that coefficient preparation rejected.
func (c *ExperimentalHEEABaseSplitCoefficientsX4) FallbackMask(active uint8) uint8 {
	active &= 0x0f
	return active &^ c.ValidMask()
}

// FallbackMask reports active lanes that coefficient preparation rejected.
func (c *ExperimentalHEEABaseSplitCoefficientsX8) FallbackMask(active uint8) uint8 {
	return active &^ c.ValidMask()
}

// ExperimentalPrepareHEEABaseSplitCoefficientsX4 computes tau*s modulo L,
// splits its canonical encoding at bit 128, and retains exact signed
// magnitudes for -tau and -epsilon*rho. s must be a canonical Ed25519 scalar;
// abs(tau) and abs(rho) must be below L, and tau must be nonzero and odd. The
// tau gate is a local defense against a malformed zero/even candidate. It is
// not complete selector admission: active must already exclude UseCandidate
// false, fallback, and selected-width failures. These are
// representation/admission gates, not modular reductions of the
// variable-point coefficients. The selector-to-QSM adapter also remains
// responsible for proving rho = epsilon*tau*k (mod 8L).
//
// The returned masks partition active (after restricting it to four lanes).
// Rejected lanes are baseline fallbacks. out is fully replaced and the helper
// uses only fixed caller-owned storage.
func ExperimentalPrepareHEEABaseSplitCoefficientsX4(out *ExperimentalHEEABaseSplitCoefficientsX4, s *[X4Lanes][32]byte, tau, rho *[X4Lanes]ExperimentalHEEASignedCoefficient, epsilon *[X4Lanes]int8, active uint8) (usable, fallback uint8) {
	*out = ExperimentalHEEABaseSplitCoefficientsX4{}
	active &= 0x0f
	usable = active
	for lane := 0; lane < X4Lanes; lane++ {
		laneMask := uint8(1 << lane)
		if active&laneMask == 0 {
			continue
		}
		if epsilon[lane] != -1 && epsilon[lane] != 1 ||
			!canonicalScalarBytes(&s[lane]) ||
			!canonicalScalarBytes(&tau[lane].Magnitude) ||
			!canonicalScalarBytes(&rho[lane].Magnitude) ||
			!heeaAdmissibleTau(&tau[lane]) {
			usable &^= laneMask
			continue
		}
		if !prepareHEEABaseSplitLane(
			&out.scalars[0][lane], &out.scalars[1][lane],
			&out.scalars[2][lane], &out.scalars[3][lane],
			&out.negativeMasks, &s[lane], &tau[lane], &rho[lane], epsilon[lane], lane,
		) {
			usable &^= laneMask
		}
	}
	out.validMask = usable
	return usable, active &^ usable
}

// ExperimentalPrepareHEEABaseSplitCoefficientsX8 is the eight-lane
// counterpart of ExperimentalPrepareHEEABaseSplitCoefficientsX4.
func ExperimentalPrepareHEEABaseSplitCoefficientsX8(out *ExperimentalHEEABaseSplitCoefficientsX8, s *[X8Lanes][32]byte, tau, rho *[X8Lanes]ExperimentalHEEASignedCoefficient, epsilon *[X8Lanes]int8, active uint8) (usable, fallback uint8) {
	*out = ExperimentalHEEABaseSplitCoefficientsX8{}
	usable = active
	for lane := 0; lane < X8Lanes; lane++ {
		laneMask := uint8(1 << lane)
		if active&laneMask == 0 {
			continue
		}
		if epsilon[lane] != -1 && epsilon[lane] != 1 ||
			!canonicalScalarBytes(&s[lane]) ||
			!canonicalScalarBytes(&tau[lane].Magnitude) ||
			!canonicalScalarBytes(&rho[lane].Magnitude) ||
			!heeaAdmissibleTau(&tau[lane]) {
			usable &^= laneMask
			continue
		}
		if !prepareHEEABaseSplitLane(
			&out.scalars[0][lane], &out.scalars[1][lane],
			&out.scalars[2][lane], &out.scalars[3][lane],
			&out.negativeMasks, &s[lane], &tau[lane], &rho[lane], epsilon[lane], lane,
		) {
			usable &^= laneMask
		}
	}
	out.validMask = usable
	return usable, active &^ usable
}

func prepareHEEABaseSplitLane(lambda0, lambda1, tauMagnitude, rhoMagnitude *[32]byte, negativeMasks *[QSMTerms]uint8, s *[32]byte, tau, rho *ExperimentalHEEASignedCoefficient, epsilon int8, lane int) bool {
	sValue := heeaSignedMagnitudeView(s[:], false)
	tauValue := heeaSignedMagnitudeView(tau.Magnitude[:], tau.Negative)
	var reduced [32]byte
	if !heeaReduceSignedProduct(&reduced, tauValue, sValue) {
		return false
	}
	copy(lambda0[:16], reduced[:16])
	copy(lambda1[:16], reduced[16:])
	*tauMagnitude = tau.Magnitude
	*rhoMagnitude = rho.Magnitude

	laneMask := uint8(1 << lane)
	if !fixedScalarIsZero(&tau.Magnitude) && !tau.Negative {
		// The R coefficient is -tau.
		negativeMasks[2] |= laneMask
	}
	if !fixedScalarIsZero(&rho.Magnitude) {
		// The A coefficient is -epsilon*rho. For epsilon=+1 the
		// coefficient sign is flipped; for epsilon=-1 it is unchanged.
		aNegative := rho.Negative
		if epsilon == 1 {
			aNegative = !aNegative
		}
		if aNegative {
			negativeMasks[3] |= laneMask
		}
	}
	return true
}

// ExperimentalSplitHEEABaseSplitCoefficientsX8 copies one x8 coefficient
// record into two independent x4 records without changing any signed integer.
// It is the handoff used to compare one x8 QSM with two x4 QSMs.
func ExperimentalSplitHEEABaseSplitCoefficientsX8(out *[2]ExperimentalHEEABaseSplitCoefficientsX4, in *ExperimentalHEEABaseSplitCoefficientsX8) {
	*out = [2]ExperimentalHEEABaseSplitCoefficientsX4{}
	for half := 0; half < 2; half++ {
		for term := 0; term < QSMTerms; term++ {
			copy(out[half].scalars[term][:], in.scalars[term][half*X4Lanes:(half+1)*X4Lanes])
			out[half].negativeMasks[term] = (in.negativeMasks[term] >> (half * X4Lanes)) & 0x0f
		}
		out[half].validMask = (in.validMask >> (half * X4Lanes)) & 0x0f
	}
}

func fixedScalarIsZero(x *[32]byte) bool {
	var nonzero byte
	for _, value := range x {
		nonzero |= value
	}
	return nonzero == 0
}

func heeaAdmissibleTau(tau *ExperimentalHEEASignedCoefficient) bool {
	return tau.Magnitude[0]&1 == 1
}

// heeaFixedRadixDigitsX4 is a fixed-storage, variable-round signed schedule.
// Unlike FixedRadixDigitsX4, it stops at the actual public coefficient width,
// preserving HEEA's approximately half-length doubling chain.
type heeaFixedRadixDigitsX4 struct {
	rounds    [maxFixedScalarRounds]RadixRoundX4
	count     uint8
	radixBits uint8
}

// heeaFixedRadixDigitsX8 is the eight-lane counterpart.
type heeaFixedRadixDigitsX8 struct {
	rounds    [maxFixedScalarRounds]RadixRoundX8
	count     uint8
	radixBits uint8
}

func recodeHEEAFixedScalarsX4(out *heeaFixedRadixDigitsX4, scalars *[X4Lanes][32]byte, negativeMask, active uint8, radixBits uint) uint8 {
	*out = heeaFixedRadixDigitsX4{radixBits: uint8(radixBits)}
	fixedScalarRoundCount(radixBits)
	active &= 0x0f
	valid := active
	for lane := 0; lane < X4Lanes; lane++ {
		laneMask := uint8(1 << lane)
		if active&laneMask == 0 {
			continue
		}
		if !canonicalScalarBytes(&scalars[lane]) || !recodeHEEAFixedScalarX4(out, lane, &scalars[lane], negativeMask&laneMask != 0) {
			valid &^= laneMask
		}
	}
	return valid
}

func recodeHEEAFixedScalarsX8(out *heeaFixedRadixDigitsX8, scalars *[X8Lanes][32]byte, negativeMask, active uint8, radixBits uint) uint8 {
	*out = heeaFixedRadixDigitsX8{radixBits: uint8(radixBits)}
	fixedScalarRoundCount(radixBits)
	valid := active
	for lane := 0; lane < X8Lanes; lane++ {
		laneMask := uint8(1 << lane)
		if active&laneMask == 0 {
			continue
		}
		if !canonicalScalarBytes(&scalars[lane]) || !recodeHEEAFixedScalarX8(out, lane, &scalars[lane], negativeMask&laneMask != 0) {
			valid &^= laneMask
		}
	}
	return valid
}

func recodeHEEAFixedScalarX4(out *heeaFixedRadixDigitsX4, lane int, scalar *[32]byte, negative bool) bool {
	bitLen := fixedScalarBitLen(scalar)
	if bitLen == 0 {
		return true
	}
	count := (bitLen + int(out.radixBits) - 1) / int(out.radixBits)
	carry := int16(0)
	radix := int16(1 << out.radixBits)
	half := radix >> 1
	for round := 0; round < count; round++ {
		digit := int16(fixedScalarBits(scalar, round*int(out.radixBits), uint(out.radixBits))) + carry
		carry = (digit + half) / radix
		digit -= carry * radix
		if negative {
			digit = -digit
		}
		setRadixRoundDigitX4(&out.rounds[round], lane, int8(digit))
	}
	if carry != 0 {
		if count == len(out.rounds) {
			return false
		}
		digit := int8(carry)
		if negative {
			digit = -digit
		}
		setRadixRoundDigitX4(&out.rounds[count], lane, digit)
		count++
	}
	if count > int(out.count) {
		out.count = uint8(count)
	}
	return true
}

func recodeHEEAFixedScalarX8(out *heeaFixedRadixDigitsX8, lane int, scalar *[32]byte, negative bool) bool {
	bitLen := fixedScalarBitLen(scalar)
	if bitLen == 0 {
		return true
	}
	count := (bitLen + int(out.radixBits) - 1) / int(out.radixBits)
	carry := int16(0)
	radix := int16(1 << out.radixBits)
	half := radix >> 1
	for round := 0; round < count; round++ {
		digit := int16(fixedScalarBits(scalar, round*int(out.radixBits), uint(out.radixBits))) + carry
		carry = (digit + half) / radix
		digit -= carry * radix
		if negative {
			digit = -digit
		}
		setRadixRoundDigitX8(&out.rounds[round], lane, int8(digit))
	}
	if carry != 0 {
		if count == len(out.rounds) {
			return false
		}
		digit := int8(carry)
		if negative {
			digit = -digit
		}
		setRadixRoundDigitX8(&out.rounds[count], lane, digit)
		count++
	}
	if count > int(out.count) {
		out.count = uint8(count)
	}
	return true
}

func fixedScalarBitLen(x *[32]byte) int {
	for i := len(x) - 1; i >= 0; i-- {
		if x[i] != 0 {
			return i*8 + bits.Len8(x[i])
		}
	}
	return 0
}

// ExperimentalIFMAHEEABaseSplitWorkspaceX4 owns four composable tables and
// four fixed, short scalar schedules. B and [2^128]B are prepared once;
// PrepareVariableBases replaces only the cold R and A tables. The workspace
// is caller-owned, reusable, not concurrent-safe, and unreachable from
// production dispatch.
type experimentalIFMAHEEABaseSplitWorkspaceX4[Storage ifmaFullTableStorageX4] struct {
	tables                [QSMTerms]ifmaFullTableX4[Storage]
	digits                [QSMTerms]heeaFixedRadixDigitsX4
	radixBits             uint8
	variableValidMask     uint8
	fixedBasesPrepared    bool
	variableBasesPrepared bool
}

// ExperimentalIFMAHEEABaseSplitWorkspaceX8 is the eight-lane counterpart.
type experimentalIFMAHEEABaseSplitWorkspaceX8[Storage ifmaFullTableStorageX8] struct {
	tables                [QSMTerms]ifmaFullTableX8[Storage]
	digits                [QSMTerms]heeaFixedRadixDigitsX8
	radixBits             uint8
	variableValidMask     uint8
	fixedBasesPrepared    bool
	variableBasesPrepared bool
}

type ExperimentalIFMAHEEABaseSplitWorkspaceRadix16X4 = experimentalIFMAHEEABaseSplitWorkspaceX4[ifmaFullTableStorageRadix16X4]
type ExperimentalIFMAHEEABaseSplitWorkspaceRadix16X8 = experimentalIFMAHEEABaseSplitWorkspaceX8[ifmaFullTableStorageRadix16X8]

type ExperimentalIFMAHEEABaseSplitWorkspaceX4 = experimentalIFMAHEEABaseSplitWorkspaceX4[ifmaFullTableStorageRadix32X4]
type ExperimentalIFMAHEEABaseSplitWorkspaceX8 = experimentalIFMAHEEABaseSplitWorkspaceX8[ifmaFullTableStorageRadix32X8]

type ExperimentalIFMAHEEABaseSplitWorkspaceRadix64X4 = experimentalIFMAHEEABaseSplitWorkspaceX4[ifmaFullTableStorageRadix64X4]
type ExperimentalIFMAHEEABaseSplitWorkspaceRadix64X8 = experimentalIFMAHEEABaseSplitWorkspaceX8[ifmaFullTableStorageRadix64X8]

// PrepareFixedBase builds and retains the B and [2^128]B tables. The second
// base is derived lane-wise here so callers cannot supply a mismatched table.
func (w *experimentalIFMAHEEABaseSplitWorkspaceX4[Storage]) PrepareFixedBase(B *PointX4, radixBits uint) error {
	fixedScalarRoundCount(radixBits)
	if !ExperimentalIFMAAvailable() {
		return ErrIFMAUnavailable
	}
	w.fixedBasesPrepared = false
	w.variableBasesPrepared = false
	w.variableValidMask = 0
	var B128 PointX4
	ExperimentalHEEABaseSplitB128X4(&B128, B)
	if err := buildIFMAFullTableX4Into(&w.tables[0], B, radixBits); err != nil {
		return err
	}
	if err := buildIFMAFullTableX4Into(&w.tables[1], &B128, radixBits); err != nil {
		return err
	}
	w.radixBits = uint8(radixBits)
	w.fixedBasesPrepared = true
	return nil
}

// PrepareFixedBase is the x8 counterpart of
// ExperimentalIFMAHEEABaseSplitWorkspaceX4.PrepareFixedBase.
func (w *experimentalIFMAHEEABaseSplitWorkspaceX8[Storage]) PrepareFixedBase(B *PointX8, radixBits uint) error {
	fixedScalarRoundCount(radixBits)
	if !ExperimentalIFMAAvailable() {
		return ErrIFMAUnavailable
	}
	w.fixedBasesPrepared = false
	w.variableBasesPrepared = false
	w.variableValidMask = 0
	var B128 PointX8
	ExperimentalHEEABaseSplitB128X8(&B128, B)
	if err := buildIFMAFullTableX8Into(&w.tables[0], B, radixBits); err != nil {
		return err
	}
	if err := buildIFMAFullTableX8Into(&w.tables[1], &B128, radixBits); err != nil {
		return err
	}
	w.radixBits = uint8(radixBits)
	w.fixedBasesPrepared = true
	return nil
}

// PrepareVariableBases rebuilds the cold R and A tables while retaining both
// fixed basepoint tables.
func (w *experimentalIFMAHEEABaseSplitWorkspaceX4[Storage]) PrepareVariableBases(R, A *PointX4) error {
	if !w.fixedBasesPrepared {
		panic("r51x5: experimental IFMA HEEA x4 fixed bases are not prepared")
	}
	if !ExperimentalIFMAAvailable() {
		return ErrIFMAUnavailable
	}
	w.variableBasesPrepared = false
	if err := buildIFMAFullTableX4Into(&w.tables[2], R, uint(w.radixBits)); err != nil {
		return err
	}
	if err := buildIFMAFullTableX4Into(&w.tables[3], A, uint(w.radixBits)); err != nil {
		return err
	}
	w.variableValidMask = 0x0f
	w.variableBasesPrepared = true
	return nil
}

// PrepareVariableBases is the x8 counterpart of
// ExperimentalIFMAHEEABaseSplitWorkspaceX4.PrepareVariableBases.
func (w *experimentalIFMAHEEABaseSplitWorkspaceX8[Storage]) PrepareVariableBases(R, A *PointX8) error {
	if !w.fixedBasesPrepared {
		panic("r51x5: experimental IFMA HEEA x8 fixed bases are not prepared")
	}
	if !ExperimentalIFMAAvailable() {
		return ErrIFMAUnavailable
	}
	w.variableBasesPrepared = false
	if err := buildIFMAFullTableX8Into(&w.tables[2], R, uint(w.radixBits)); err != nil {
		return err
	}
	if err := buildIFMAFullTableX8Into(&w.tables[3], A, uint(w.radixBits)); err != nil {
		return err
	}
	w.variableValidMask = 0xff
	w.variableBasesPrepared = true
	return nil
}

// PrepareVariableBasesAffineR rebuilds the cold R and A tables directly from
// Decode2NoTX4's compact affine R and full A outputs. decodedValid must be the
// caller's complete decode-admission mask (normally aValid & rValid, further
// intersected with strict byte prechecks). It is retained by the workspace and
// independently gates Evaluate, so forgetting to reapply it cannot turn an
// invalid compact R lane into an identity-equation candidate.
//
// Valid R lanes are imported with Z=1 and T=X*Y. Invalid lanes are represented
// as identity only to keep every table lane well-formed; they remain explicit
// fallbacks. Reconstructing T costs one composable IFMA multiplication and is
// part of the cold-table benchmark.
func (w *experimentalIFMAHEEABaseSplitWorkspaceX4[Storage]) PrepareVariableBasesAffineR(R *AffinePointX4, A *PointX4, decodedValid uint8) error {
	if !w.fixedBasesPrepared {
		panic("r51x5: experimental IFMA HEEA x4 fixed bases are not prepared")
	}
	if !ExperimentalIFMAAvailable() {
		return ErrIFMAUnavailable
	}
	w.variableBasesPrepared = false
	w.variableValidMask = 0
	decodedValid &= 0x0f
	var composableR IFMAPointX4
	if err := heeaIFMAPointFromAffineX4(&composableR, R, decodedValid); err != nil {
		return err
	}
	if err := buildIFMAFullTableFromComposableX4Into(&w.tables[2], &composableR, uint(w.radixBits)); err != nil {
		return err
	}
	if err := buildIFMAFullTableX4Into(&w.tables[3], A, uint(w.radixBits)); err != nil {
		return err
	}
	w.variableValidMask = decodedValid
	w.variableBasesPrepared = true
	return nil
}

// PrepareVariableBasesAffineR is the x8 counterpart of
// ExperimentalIFMAHEEABaseSplitWorkspaceX4.PrepareVariableBasesAffineR.
func (w *experimentalIFMAHEEABaseSplitWorkspaceX8[Storage]) PrepareVariableBasesAffineR(R *AffinePointX8, A *PointX8, decodedValid uint8) error {
	if !w.fixedBasesPrepared {
		panic("r51x5: experimental IFMA HEEA x8 fixed bases are not prepared")
	}
	if !ExperimentalIFMAAvailable() {
		return ErrIFMAUnavailable
	}
	w.variableBasesPrepared = false
	w.variableValidMask = 0
	var composableR IFMAPointX8
	if err := heeaIFMAPointFromAffineX8(&composableR, R, decodedValid); err != nil {
		return err
	}
	if err := buildIFMAFullTableFromComposableX8Into(&w.tables[2], &composableR, uint(w.radixBits)); err != nil {
		return err
	}
	if err := buildIFMAFullTableX8Into(&w.tables[3], A, uint(w.radixBits)); err != nil {
		return err
	}
	w.variableValidMask = decodedValid
	w.variableBasesPrepared = true
	return nil
}

func heeaIFMAPointFromAffineX4(out *IFMAPointX4, affine *AffinePointX4, valid uint8) error {
	valid &= 0x0f
	zero := ElementX4{}
	one := broadcastX4(new(Element).One())
	var x, y ElementX4
	decodeSelectX4(&x, &zero, &affine.X, valid)
	decodeSelectX4(&y, &one, &affine.Y, valid)
	var point IFMAPointX4
	point.X.SetReduced(&x)
	point.Y.SetReduced(&y)
	point.Z.SetReduced(&one)
	if err := ifmaMultiplyComposableUncheckedX4(&point.T, &point.X, &point.Y); err != nil {
		return err
	}
	*out = point
	return nil
}

func heeaIFMAPointFromAffineX8(out *IFMAPointX8, affine *AffinePointX8, valid uint8) error {
	zero := ElementX8{}
	one := broadcastX8(new(Element).One())
	var x, y ElementX8
	decodeSelectX8(&x, &zero, &affine.X, valid)
	decodeSelectX8(&y, &one, &affine.Y, valid)
	var point IFMAPointX8
	point.X.SetReduced(&x)
	point.Y.SetReduced(&y)
	point.Z.SetReduced(&one)
	if err := ifmaMultiplyComposableUncheckedX8(&point.T, &point.X, &point.Y); err != nil {
		return err
	}
	*out = point
	return nil
}

func buildIFMAFullTableFromComposableX4Into[Storage ifmaFullTableStorageX4](table *ifmaFullTableX4[Storage], base *IFMAPointX4, radixBits uint) error {
	validateIFMAFullTableStorage(len(table.points), radixBits)
	table.entries = regularRadixEntries(radixBits)
	table.radixBits = radixBits
	table.points[0] = *base
	for entry := 1; entry < table.entries; entry++ {
		if err := ifmaPointAddComposableStaticX4(&table.points[entry], &table.points[entry-1], base); err != nil {
			return err
		}
	}
	return nil
}

func buildIFMAFullTableFromComposableX8Into[Storage ifmaFullTableStorageX8](table *ifmaFullTableX8[Storage], base *IFMAPointX8, radixBits uint) error {
	validateIFMAFullTableStorage(len(table.points), radixBits)
	table.entries = regularRadixEntries(radixBits)
	table.radixBits = radixBits
	table.points[0] = *base
	for entry := 1; entry < table.entries; entry++ {
		if err := ifmaPointAddComposableStaticX8(&table.points[entry], &table.points[entry-1], base); err != nil {
			return err
		}
	}
	return nil
}

// PrepareAll is an explicitly full-cold convenience helper. Target
// verification benchmarks should normally prepare B once and time only
// PrepareVariableBases plus Evaluate.
func (w *experimentalIFMAHEEABaseSplitWorkspaceX4[Storage]) PrepareAll(B, R, A *PointX4, radixBits uint) error {
	if err := w.PrepareFixedBase(B, radixBits); err != nil {
		return err
	}
	return w.PrepareVariableBases(R, A)
}

// PrepareAll is the x8 counterpart of
// ExperimentalIFMAHEEABaseSplitWorkspaceX4.PrepareAll.
func (w *experimentalIFMAHEEABaseSplitWorkspaceX8[Storage]) PrepareAll(B, R, A *PointX8, radixBits uint) error {
	if err := w.PrepareFixedBase(B, radixBits); err != nil {
		return err
	}
	return w.PrepareVariableBases(R, A)
}

// Evaluate runs one four-term shared-doubling QSM. The returned masks
// partition active: usable lanes contain a computed result and fallback lanes
// must run the ordinary verifier. Inactive and fallback outputs are identity.
// On an IFMA error, out is unchanged and every active lane is a fallback.
func (w *experimentalIFMAHEEABaseSplitWorkspaceX4[Storage]) Evaluate(out *IFMAPointX4, coefficients *ExperimentalHEEABaseSplitCoefficientsX4, active uint8) (usable, fallback uint8, err error) {
	if !w.fixedBasesPrepared || !w.variableBasesPrepared {
		panic("r51x5: experimental IFMA HEEA x4 workspace is not prepared")
	}
	active &= 0x0f
	if !ExperimentalIFMAAvailable() {
		return 0, active, ErrIFMAUnavailable
	}
	usable = active & coefficients.validMask & w.variableValidMask
	for term := 0; term < QSMTerms; term++ {
		usable &= recodeHEEAFixedScalarsX4(&w.digits[term], &coefficients.scalars[term], coefficients.negativeMasks[term], usable, uint(w.radixBits))
	}
	fallback = active &^ usable
	acc := identityIFMAPointX4Value()
	if usable == 0 {
		*out = acc
		return 0, fallback, nil
	}
	maxRounds := 0
	for term := range w.digits {
		if int(w.digits[term].count) > maxRounds {
			maxRounds = int(w.digits[term].count)
		}
	}
	for round := maxRounds - 1; round >= 0; round-- {
		if round != maxRounds-1 {
			for doubling := uint8(0); doubling < w.radixBits; doubling++ {
				if err := ifmaPointDoubleComposableStaticX4(&acc, &acc); err != nil {
					return 0, active, err
				}
			}
		}
		for term := 0; term < QSMTerms; term++ {
			if round >= int(w.digits[term].count) {
				continue
			}
			digit := &w.digits[term].rounds[round]
			if digit.NonzeroMask&usable == 0 {
				continue
			}
			var selected IFMAPointX4
			SelectIFMAFullTableX4Public(&selected, &w.tables[term], digit, usable)
			if err := ifmaPointAddComposableStaticX4(&acc, &acc, &selected); err != nil {
				return 0, active, err
			}
		}
	}
	*out = acc
	return usable, fallback, nil
}

// Evaluate is the x8 counterpart of
// ExperimentalIFMAHEEABaseSplitWorkspaceX4.Evaluate.
func (w *experimentalIFMAHEEABaseSplitWorkspaceX8[Storage]) Evaluate(out *IFMAPointX8, coefficients *ExperimentalHEEABaseSplitCoefficientsX8, active uint8) (usable, fallback uint8, err error) {
	if !w.fixedBasesPrepared || !w.variableBasesPrepared {
		panic("r51x5: experimental IFMA HEEA x8 workspace is not prepared")
	}
	if !ExperimentalIFMAAvailable() {
		return 0, active, ErrIFMAUnavailable
	}
	usable = active & coefficients.validMask & w.variableValidMask
	for term := 0; term < QSMTerms; term++ {
		usable &= recodeHEEAFixedScalarsX8(&w.digits[term], &coefficients.scalars[term], coefficients.negativeMasks[term], usable, uint(w.radixBits))
	}
	fallback = active &^ usable
	acc := identityIFMAPointX8Value()
	if usable == 0 {
		*out = acc
		return 0, fallback, nil
	}
	maxRounds := 0
	for term := range w.digits {
		if int(w.digits[term].count) > maxRounds {
			maxRounds = int(w.digits[term].count)
		}
	}
	for round := maxRounds - 1; round >= 0; round-- {
		if round != maxRounds-1 {
			for doubling := uint8(0); doubling < w.radixBits; doubling++ {
				if err := ifmaPointDoubleComposableStaticX8(&acc, &acc); err != nil {
					return 0, active, err
				}
			}
		}
		for term := 0; term < QSMTerms; term++ {
			if round >= int(w.digits[term].count) {
				continue
			}
			digit := &w.digits[term].rounds[round]
			if digit.NonzeroMask&usable == 0 {
				continue
			}
			var selected IFMAPointX8
			selectIFMAFullTableX8PublicUncheckedNoAlias(&selected, &w.tables[term], digit, usable)
			if err := ifmaPointAddComposableStaticX8(&acc, &acc, &selected); err != nil {
				return 0, active, err
			}
		}
	}
	*out = acc
	return usable, fallback, nil
}
