package ed25519

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/Overclock-Validator/narya/internal/edwards25519"
	"github.com/Overclock-Validator/narya/internal/r43x6"
)

// verifyR43Reference is a complete verification pipeline over the pure-Go
// r43x6 correctness model. It is intentionally test-only and is not an IFMA
// backend: future assembly must first agree with this result before it is
// registered under the explicit "ifma" selector.
func verifyR43Reference(profile Profile, pub *[32]byte, message, sig []byte) bool {
	if len(sig) != 64 || rejectedByProfile(profile, pub, sig) {
		return false
	}

	var a r43x6.Point
	if _, err := a.SetBytes(pub[:]); err != nil {
		return false
	}
	var s r43x6.Scalar
	if _, err := s.SetCanonicalBytes(sig[32:]); err != nil {
		return false
	}

	h := sha512.New()
	h.Write(sig[:32])
	h.Write(pub[:])
	h.Write(message)
	var digest [sha512.Size]byte
	h.Sum(digest[:0])
	reducedK, err := edwards25519.NewScalar().SetUniformBytes(digest[:])
	if err != nil {
		return false
	}
	var k r43x6.Scalar
	if _, err := k.SetCanonicalBytes(reducedK.Bytes()); err != nil {
		return false
	}

	q := new(r43x6.Point).VarTimeVerifyMult(&s, &k, &a)
	encodedQ := q.Bytes()
	return bytes.Equal(encodedQ[:], sig[:32])
}

func TestR43ReferenceVerifierMatchesCorpora(t *testing.T) {
	type vector struct {
		name string
		pub  string
		msg  string
		sig  string
	}
	vectors := make([]vector, 0, len(cctvVectors)+len(wycheproofVectors))
	for _, v := range cctvVectors {
		vectors = append(vectors, vector{fmt.Sprintf("cctv/%d", v.tcID), v.pub, v.msg, v.sig})
	}
	for _, v := range wycheproofVectors {
		vectors = append(vectors, vector{fmt.Sprintf("wycheproof/%d", v.tcID), v.pub, v.msg, v.sig})
	}

	for _, v := range vectors {
		pubBytes, err := hex.DecodeString(v.pub)
		if err != nil || len(pubBytes) != 32 {
			t.Fatalf("%s: bad public key fixture", v.name)
		}
		msg, err := hex.DecodeString(v.msg)
		if err != nil {
			t.Fatalf("%s: bad message fixture", v.name)
		}
		sig, err := hex.DecodeString(v.sig)
		if err != nil {
			t.Fatalf("%s: bad signature fixture", v.name)
		}
		var pub [32]byte
		copy(pub[:], pubBytes)

		for _, profile := range []Profile{StdlibCompat, DalekStrict} {
			got := verifyR43Reference(profile, &pub, msg, sig)
			want := referenceVerifyProfile(profile, &pub, msg, sig)
			if got != want {
				t.Fatalf("%s profile=%d: r43ref=%v reference=%v", v.name, profile, got, want)
			}
			pipeline := false
			if !rejectedByProfile(profile, &pub, sig) {
				pipeline = verifyR43Pipeline(profile, &pub, msg, sig)
			}
			if pipeline != want {
				t.Fatalf("%s profile=%d: r43-pipeline=%v reference=%v", v.name, profile, pipeline, want)
			}
		}
	}
}

func BenchmarkR43ReferenceVerify(b *testing.B) {
	for _, size := range benchMsgSizes {
		f := makeFixture(b, size)
		b.Run(fmt.Sprintf("msg=%d", size), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if !verifyR43Reference(DalekStrict, &f.pub, f.msg, f.sig) {
					b.Fatal("r43 reference rejected valid signature")
				}
			}
		})
	}
}
