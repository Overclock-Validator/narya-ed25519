package sigprep

// The encoding predicates below decide acceptance from bytes alone, with no
// curve arithmetic. They were previously duplicated across ed25519/profile.go
// and the r51 backend; they are moved here verbatim so every backend and every
// predicate consults one implementation.

// The permissive Edwards25519 decoder ignores the sign bit and reduces the
// encoded y-coordinate modulo p. Its small-order points therefore have exactly
// these seven low-255-bit encodings: 0, 1, p-1, p, p+1, and the two y values
// of the order-eight points. The sign bit is immaterial for all seven values.
var (
	smallOrderAlpha = [32]byte{
		0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f,
		0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
		0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6,
		0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a,
	}
	smallOrderNegAlpha = [32]byte{
		0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0,
		0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
		0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39,
		0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05,
	}
)

// SmallOrderEncoding reports whether b is one of the encodings the permissive
// decoder maps to a small-order point. All other encodings, including ones that
// do not decode at all, are left for the equation to reject.
func SmallOrderEncoding(b []byte) bool {
	if len(b) != 32 {
		return false
	}

	// The seven values have distinct first bytes, so almost every input exits
	// after this switch without a full 255-bit comparison.
	switch b[0] {
	case 0x00, 0x01:
		return low255TailEqual(b, 0x00, 0x00)
	case 0x26:
		return low255Equal(b, &smallOrderNegAlpha)
	case 0xc7:
		return low255Equal(b, &smallOrderAlpha)
	case 0xec, 0xed, 0xee:
		return low255TailEqual(b, 0xff, 0x7f)
	default:
		return false
	}
}

func low255TailEqual(b []byte, middle, last byte) bool {
	diff := (b[31] & 0x7f) ^ last
	for i := 1; i < 31; i++ {
		diff |= b[i] ^ middle
	}
	return diff == 0
}

func low255Equal(b []byte, want *[32]byte) bool {
	diff := (b[31] & 0x7f) ^ want[31]
	for i := 0; i < 31; i++ {
		diff |= b[i] ^ want[i]
	}
	return diff == 0
}

// CanonicalREncoding reports whether r satisfies the decoder-specific byte
// canonicality condition used by strict verification. It is independent of
// small-order rejection: besides requiring low255(r) < p, it rejects the two
// sign-bit-one encodings whose decoded x coordinate is zero (y=1 and y=-1).
//
// Point decoding remains a separate requirement. A reduced byte string that
// is not on the curve can pass this helper and must still fail decoding.
func CanonicalREncoding(r []byte) bool {
	if len(r) != 32 {
		return false
	}
	if !low255LessThanP(r) {
		return false
	}
	if r[31]&0x80 == 0 {
		return true
	}
	// On Edwards25519, x=0 iff y=1 or y=-1. Their sign-bit-one forms decode
	// permissively but are not canonical compressed encodings.
	if r[0] == 0x01 && low255TailEqual(r, 0x00, 0x00) {
		return false
	}
	if r[0] == 0xec && low255TailEqual(r, 0xff, 0x7f) {
		return false
	}
	return true
}

// low255LessThanP compares the encoded little-endian y-coordinate with
// p=2^255-19 while ignoring the compressed x-sign bit.
func low255LessThanP(encoded []byte) bool {
	if len(encoded) != 32 {
		return false
	}
	if encoded[31]&0x7f != 0x7f {
		return true
	}
	for index := 30; index > 0; index-- {
		if encoded[index] != 0xff {
			return true
		}
	}
	return encoded[0] < 0xed
}

// ScalarOrderEncoding is the little-endian encoding of the prime subgroup
// order l. Ed25519 signatures require the original S encoding to be strictly
// less than l; reducing a noncanonical encoding would change the verification
// predicate.
var ScalarOrderEncoding = [32]byte{
	0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
	0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
}

// CanonicalScalarEncoding reports whether s is the canonical 32-byte
// little-endian encoding of an integer in [0,l). Signature inputs are public,
// so the early exits do not expose secret data. This direct predicate also
// avoids allocating the error returned by SetCanonicalBytes on invalid input.
//
// Every Ed25519 predicate in use requires this, including the cofactored one,
// so it is unconditional rather than a Rules field.
func CanonicalScalarEncoding(s []byte) bool {
	if len(s) != len(ScalarOrderEncoding) {
		return false
	}
	for index := len(s) - 1; index >= 0; index-- {
		if s[index] < ScalarOrderEncoding[index] {
			return true
		}
		if s[index] > ScalarOrderEncoding[index] {
			return false
		}
	}
	return false
}
