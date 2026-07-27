// Command narya-decode-fixtures emits deterministic permissive-decoder vectors
// for external implementations of Narya's pinned byte semantics.
//
// It deliberately uses the scalar r51 Point decoder rather than any IFMA path.
// Output coordinates are canonical radix-2^51 limbs. Invalid inputs are paired
// with the identity, matching the fail-closed lane representation used by the
// standalone assembly port.
package main

import (
	"encoding/hex"
	"flag"
	"fmt"

	"github.com/Overclock-Validator/narya-ed25519/internal/r51x5"
)

func main() {
	count := flag.Int("count", 128, "number of vectors")
	flag.Parse()
	if *count < 1 {
		panic("count must be positive")
	}

	vectors := edgeVectors()
	state := uint64(0xd1b54a32d192ed03)
	for len(vectors) < *count {
		var encoded [32]byte
		for i := range encoded {
			state ^= state >> 12
			state ^= state << 25
			state ^= state >> 27
			state *= 0x2545f4914f6cdd1d
			encoded[i] = byte(state >> 56)
		}
		vectors = append(vectors, encoded)
	}

	fmt.Println("# narya-permissive-decode-v1")
	fmt.Println("# input_hex valid X[5] Y[5] Z[5] T[5]; limbs are 13-digit hex")
	for _, encoded := range vectors[:*count] {
		point := new(r51x5.Point)
		valid := 1
		if _, err := point.SetBytes(encoded[:]); err != nil {
			valid = 0
			point = r51x5.NewIdentityPoint()
		}
		fmt.Printf("%s %d", hex.EncodeToString(encoded[:]), valid)
		printLimbs(point.X.Limbs())
		printLimbs(point.Y.Limbs())
		printLimbs(point.Z.Limbs())
		printLimbs(point.T.Limbs())
		fmt.Println()
	}
}

func printLimbs(limbs r51x5.Limbs) {
	for _, limb := range limbs {
		fmt.Printf(" %013x", limb)
	}
}

func edgeVectors() [][32]byte {
	var out [][32]byte
	appendSignPair := func(value [32]byte) {
		value[31] &= 0x7f
		out = append(out, value)
		value[31] |= 0x80
		out = append(out, value)
	}

	var base [32]byte
	base[0] = 0x58
	for i := 1; i < 32; i++ {
		base[i] = 0x66
	}
	appendSignPair(base)

	for low := uint8(0); low <= 18; low++ {
		var canonical [32]byte
		canonical[0] = low
		appendSignPair(canonical)

		// p+low = 2^255-19+low, the complete noncanonical-y interval.
		var alias [32]byte
		alias[0] = 0xed + low
		for i := 1; i < 31; i++ {
			alias[i] = 0xff
		}
		alias[31] = 0x7f
		appendSignPair(alias)
	}

	// Mutations around identity, order-two, and the first invalid small y.
	for _, low := range []byte{1, 2, 0xec, 0xed, 0xee, 0xff} {
		var encoded [32]byte
		encoded[0] = low
		appendSignPair(encoded)
	}
	return out
}
