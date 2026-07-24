package r51x5

// ExperimentalIFMAScalarMultLoopX4 evaluates a prebuilt, pre-recoded shared
// scalar loop through the checked YMM IFMA point bridge. Recoding and direct
// SoA table selection are shared with ScalarMultLoopX4, while point calls are
// statically bound so a function-value abstraction cannot force every round
// onto the heap. This function is not used by production dispatch.
//
// Table selection is variable-time in public verification scalars. out is
// unchanged if an IFMA point operation returns an error.
func ExperimentalIFMAScalarMultLoopX4(out *PointX4, table *FullTableX4, recoded *RadixDigitsX4, active uint8) error {
	if table.radixBits != recoded.RadixBits {
		panic("r51x5: x4 table/recoding radix mismatch")
	}
	active &= 0x0f
	acc := identityPointX4Value()
	if active == 0 {
		*out = acc
		return nil
	}
	for round := len(recoded.Rounds) - 1; round >= 0; round-- {
		if round != len(recoded.Rounds)-1 {
			for doubling := uint(0); doubling < recoded.RadixBits; doubling++ {
				if err := ExperimentalIFMAPointDoubleX4(&acc, &acc); err != nil {
					return err
				}
			}
		}
		var selected PointX4
		SelectFullTableX4Public(&selected, table, &recoded.Rounds[round], active)
		if err := ExperimentalIFMAPointAddX4(&acc, &acc, &selected); err != nil {
			return err
		}
	}
	*out = acc
	return nil
}

// ExperimentalIFMAScalarMultLoopX8 is the statically bound ZMM counterpart
// of ExperimentalIFMAScalarMultLoopX4. It is not used by production dispatch.
func ExperimentalIFMAScalarMultLoopX8(out *PointX8, table *FullTableX8, recoded *RadixDigitsX8, active uint8) error {
	if table.radixBits != recoded.RadixBits {
		panic("r51x5: x8 table/recoding radix mismatch")
	}
	acc := identityPointX8Value()
	if active == 0 {
		*out = acc
		return nil
	}
	for round := len(recoded.Rounds) - 1; round >= 0; round-- {
		if round != len(recoded.Rounds)-1 {
			for doubling := uint(0); doubling < recoded.RadixBits; doubling++ {
				if err := ExperimentalIFMAPointDoubleX8(&acc, &acc); err != nil {
					return err
				}
			}
		}
		var selected PointX8
		SelectFullTableX8Public(&selected, table, &recoded.Rounds[round], active)
		if err := ExperimentalIFMAPointAddX8(&acc, &acc, &selected); err != nil {
			return err
		}
	}
	*out = acc
	return nil
}

// ExperimentalIFMAComposableScalarMultLoopX4 keeps the accumulator and table
// selections in the u52 composable domain for the entire loop. It is the
// throughput-oriented successor to the canonical bridge above, but remains
// explicit and unreachable from production dispatch pending Zen 4 gates.
func ExperimentalIFMAComposableScalarMultLoopX4[Storage ifmaFullTableStorageX4](out *IFMAPointX4, table *ifmaFullTableX4[Storage], recoded *RadixDigitsX4, active uint8) error {
	if table.radixBits != recoded.RadixBits {
		panic("r51x5: composable x4 table/recoding radix mismatch")
	}
	active &= 0x0f
	acc := identityIFMAPointX4Value()
	if active == 0 {
		*out = acc
		return nil
	}
	if !ExperimentalIFMAAvailable() {
		return ErrIFMAUnavailable
	}
	for round := len(recoded.Rounds) - 1; round >= 0; round-- {
		if round != len(recoded.Rounds)-1 {
			for doubling := uint(0); doubling < recoded.RadixBits; doubling++ {
				if err := ifmaPointDoubleComposableStaticX4(&acc, &acc); err != nil {
					return err
				}
			}
		}
		var selected IFMAPointX4
		SelectIFMAFullTableX4Public(&selected, table, &recoded.Rounds[round], active)
		if err := ifmaPointAddComposableStaticX4(&acc, &acc, &selected); err != nil {
			return err
		}
	}
	*out = acc
	return nil
}

// ExperimentalIFMAComposableScalarMultLoopX8 is the eight-lane counterpart
// of ExperimentalIFMAComposableScalarMultLoopX4.
func ExperimentalIFMAComposableScalarMultLoopX8[Storage ifmaFullTableStorageX8](out *IFMAPointX8, table *ifmaFullTableX8[Storage], recoded *RadixDigitsX8, active uint8) error {
	if table.radixBits != recoded.RadixBits {
		panic("r51x5: composable x8 table/recoding radix mismatch")
	}
	acc := identityIFMAPointX8Value()
	if active == 0 {
		*out = acc
		return nil
	}
	if !ExperimentalIFMAAvailable() {
		return ErrIFMAUnavailable
	}
	for round := len(recoded.Rounds) - 1; round >= 0; round-- {
		if round != len(recoded.Rounds)-1 {
			for doubling := uint(0); doubling < recoded.RadixBits; doubling++ {
				if err := ifmaPointDoubleComposableStaticX8(&acc, &acc); err != nil {
					return err
				}
			}
		}
		var selected IFMAPointX8
		SelectIFMAFullTableX8Public(&selected, table, &recoded.Rounds[round], active)
		if err := ifmaPointAddComposableStaticX8(&acc, &acc, &selected); err != nil {
			return err
		}
	}
	*out = acc
	return nil
}
