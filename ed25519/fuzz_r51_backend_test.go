package ed25519

import (
	stded25519 "crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/Overclock-Validator/narya-ed25519/internal/edwards25519"
)

// fuzzR51MaxBatch covers every dispatch width the r51 backend distinguishes:
// singletons, the packed strict pair, x4 and x8 groups with tails, and more
// than one full x8 group.
const fuzzR51MaxBatch = 65

// fuzzR51Keys is a small fixed key set so lanes repeat signers the way real
// batches do, which also exercises any per-batch key sharing.
var fuzzR51Keys = func() []stded25519.PrivateKey {
	keys := make([]stded25519.PrivateKey, 5)
	for i := range keys {
		var seed [stded25519.SeedSize]byte
		seed[0] = byte(i + 1)
		seed[31] = 0x5a
		keys[i] = stded25519.NewKeyFromSeed(seed[:])
	}
	return keys
}()

// FuzzR51BackendDifferential drives the live r51 batch entry point that
// Mithril reaches through VerifyBatchStrict, at every width from 1 to 65, and
// requires each lane's verdict to equal the independent DalekStrict oracle
// (crypto/ed25519 plus a decoded [8]P small-order check). It also requires
// that the backend never takes its internal-fault fallback to the generic
// verifier, which would otherwise hide an r51 arithmetic fault.
//
// The fuzzer input chooses the width and, per lane, one of the shapes that
// historically split Ed25519 verifiers: honest signatures, corrupted
// messages and signatures, small-order and non-canonical R and A encodings,
// non-canonical s, mixed-order public keys (A = aB + T) whose verdict depends
// on the challenge modulo the torsion order, nil keys, raw fuzzer bytes, and
// repeated lanes. It skips on CPUs without the r51 IFMA pipeline; CI runs its
// seed corpus under Intel SDE.
func FuzzR51BackendDifferential(f *testing.F) {
	f.Add([]byte{1, 0}, []byte("seed"), []byte{})
	f.Add([]byte{2, 0, 3}, []byte("pair"), []byte{})
	f.Add([]byte{8, 0, 1, 2, 3, 4, 5, 6, 7}, []byte("group"), []byte{})
	f.Add([]byte{9, 8, 0, 0, 0, 0, 0, 0, 0, 9}, []byte("tail"), []byte{})
	f.Add([]byte{17, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5}, []byte("mixed"), []byte{})
	f.Add([]byte{64, 10}, []byte("wide"), []byte{})
	f.Add([]byte{65, 7, 3, 1, 8, 2, 6, 4, 9, 10, 11}, []byte("all"), make([]byte, 96))

	b := requireR51Backend(f)
	edges := make([][32]byte, len(edgePoints))
	for i, encoded := range edgePoints {
		decoded, err := hex.DecodeString(encoded)
		if err != nil || len(decoded) != 32 {
			f.Fatalf("invalid edge point %q", encoded)
		}
		copy(edges[i][:], decoded)
	}

	f.Fuzz(func(t *testing.T, plan, message, raw []byte) {
		if len(message) > 1232 || len(plan) == 0 {
			return
		}
		n := 1 + int(plan[0])%fuzzR51MaxBatch
		pubs := make([]*[32]byte, n)
		msgs := make([][]byte, n)
		sigs := make([][]byte, n)
		want := make([]bool, n)
		for lane := 0; lane < n; lane++ {
			op := byte(lane)
			if 1+lane < len(plan) {
				op = plan[1+lane]
			}
			pubs[lane], msgs[lane], sigs[lane] = fuzzR51Lane(t, lane, op, message, raw, edges, pubs, msgs, sigs)
			want[lane] = pubs[lane] != nil && referenceVerifyProfile(DalekStrict, pubs[lane], msgs[lane], sigs[lane])
		}

		faults := b.faults.Load()
		ok := make([]bool, n)
		all, err := b.verifyBatchRawErr(DalekStrict, pubs, msgs, sigs, ok)
		if err != nil {
			t.Fatalf("n=%d: r51 batch returned an internal error: %v", n, err)
		}
		if got := b.faults.Load(); got != faults {
			t.Fatalf("n=%d: r51 took the internal-fault fallback", n)
		}
		allWant := true
		for lane := range want {
			allWant = allWant && want[lane]
			if ok[lane] != want[lane] {
				t.Fatalf("n=%d lane=%d: r51=%v want=%v\npub %x\nmsg %x\nsig %x",
					n, lane, ok[lane], want[lane], pubOrNil(pubs[lane]), msgs[lane], sigs[lane])
			}
		}
		if all != allWant {
			t.Fatalf("n=%d: r51 batch result=%v want=%v", n, all, allWant)
		}
		if n == 1 && pubs[0] != nil {
			if got := b.verifyStrictRaw(pubs[0], msgs[0], sigs[0]); got != want[0] {
				t.Fatalf("singleton: r51=%v want=%v", got, want[0])
			}
		}
	})
}

func pubOrNil(pub *[32]byte) []byte {
	if pub == nil {
		return nil
	}
	return pub[:]
}

// fuzzR51Lane builds one lane. op selects the shape; its high bits choose the
// key, edge point, or byte position so the same op covers many variants.
func fuzzR51Lane(
	t *testing.T,
	lane int,
	op byte,
	message, raw []byte,
	edges [][32]byte,
	pubs []*[32]byte,
	msgs, sigs [][]byte,
) (*[32]byte, []byte, []byte) {
	key := fuzzR51Keys[int(op>>4)%len(fuzzR51Keys)]
	var pub [32]byte
	copy(pub[:], key.Public().(stded25519.PublicKey))
	msg := make([]byte, 0, len(message)+2)
	msg = append(msg, message...)
	msg = binary.LittleEndian.AppendUint16(msg, uint16(lane))
	sig := stded25519.Sign(key, msg)
	position := int(op>>4) % 64
	edge := edges[int(op>>4)%len(edges)]

	switch op % 12 {
	case 0: // honest
	case 1: // message changed after signing
		msg[len(msg)-1] ^= 0x80
	case 2: // one signature bit flipped
		sig[position] ^= 1 << (op >> 5 % 8)
	case 3: // R replaced by a small-order or non-canonical edge encoding
		copy(sig[:32], edge[:])
	case 4: // A replaced by an edge encoding
		pub = edge
	case 5: // mixed-order A = aB + T, signed honestly over that A
		return fuzzR51MixedOrderLane(t, op, msg, edges)
	case 6: // non-canonical s: s + L, still 32 bytes when it fits
		if s, carry := addGroupOrder(sig[32:]); !carry {
			copy(sig[32:], s[:])
		}
	case 7: // repeat an earlier lane exactly
		if lane > 0 {
			prior := int(op>>4) % lane
			return pubs[prior], msgs[prior], sigs[prior]
		}
	case 8: // nil public key
		return nil, msg, sig
	case 9: // raw fuzzer bytes as the public key and signature
		if len(raw) >= 96 {
			copy(pub[:], raw[:32])
			sig = append([]byte(nil), raw[32:96]...)
		}
	case 10: // wrong length signature
		sig = sig[:63]
	case 11: // signature from a different key in the set
		other := fuzzR51Keys[(int(op>>4)+1)%len(fuzzR51Keys)]
		sig = stded25519.Sign(other, msg)
	}
	return &pub, msg, sig
}

// fuzzR51MixedOrderLane signs over A = aB + T for a small-order T taken from
// the edge points. The cofactorless strict predicate then accepts exactly when
// the challenge k kills T, so the verdict depends on k modulo T's order: the
// case an implementation that reduces -k modulo L instead of keeping its
// exact integer value gets wrong.
func fuzzR51MixedOrderLane(t *testing.T, op byte, msg []byte, edges [][32]byte) (*[32]byte, []byte, []byte) {
	t.Helper()
	var torsion *edwards25519.Point
	for i := 0; i < len(edges); i++ {
		candidate := edges[(int(op>>4)+i)%len(edges)]
		point, err := new(edwards25519.Point).SetBytes(candidate[:])
		if err == nil && referenceSmallOrderEncoding(candidate[:]) &&
			point.Equal(edwards25519.NewIdentityPoint()) == 0 {
			torsion = point
			break
		}
	}
	if torsion == nil {
		t.Fatal("no non-identity small-order edge point")
	}
	a := scalarFromUint64(t, 3+uint64(op))
	r := scalarFromUint64(t, 11+uint64(op))
	A := new(edwards25519.Point).Add(new(edwards25519.Point).ScalarBaseMult(a), torsion)
	R := new(edwards25519.Point).ScalarBaseMult(r)
	var pub [32]byte
	copy(pub[:], A.Bytes())
	k := strictChallenge(t, R.Bytes(), pub[:], msg)
	s := new(edwards25519.Scalar).Multiply(k, a)
	s.Add(s, r)
	sigArray := assembleStrictTestSignature(R, s)
	return &pub, msg, append([]byte(nil), sigArray[:]...)
}

// addGroupOrder returns s + L for a little-endian 32-byte s and whether the sum
// overflowed 256 bits.
func addGroupOrder(s []byte) ([32]byte, bool) {
	order := [32]byte{
		0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
		0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
	}
	var sum [32]byte
	carry := 0
	for i := range sum {
		v := int(s[i]) + int(order[i]) + carry
		sum[i] = byte(v)
		carry = v >> 8
	}
	return sum, carry != 0
}
