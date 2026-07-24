package ed25519

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/Overclock-Validator/narya/internal/edwards25519"
	"github.com/Overclock-Validator/narya/internal/r43x6"
)

// verifyR43PairedStrict is the complete correctness-first paired-decompression
// experiment. It remains test-only until an IFMA implementation beats the
// complete-pipeline gate on the target Zen 4 host.
func verifyR43PairedStrict(pub *[32]byte, message, sig []byte) bool {
	if len(sig) != 64 || sig[63]&224 != 0 || rejectedByStrict(pub, sig) {
		return false
	}
	if !canonicalRAfterSmallOrderCheck(sig[:32]) {
		return false
	}

	a, r, aErr, rErr := r43x6.Decode2NoT(pub[:], sig[:32])
	if aErr != nil || rErr != nil {
		return false
	}
	var s r43x6.Scalar
	if _, err := s.SetCanonicalBytes(sig[32:]); err != nil {
		return false
	}

	h := sha512.New()
	_, _ = h.Write(sig[:32])
	_, _ = h.Write(pub[:])
	_, _ = h.Write(message)
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
	return q.EqualAffineNoT(&r) == 1
}

func TestR43Decode2MatchesIndependentDecodersOnCorpora(t *testing.T) {
	type encodedPair struct {
		name string
		a    string
		r    string
	}
	pairs := make([]encodedPair, 0, len(cctvVectors)+len(wycheproofVectors))
	for _, v := range cctvVectors {
		pairs = append(pairs, encodedPair{fmt.Sprintf("cctv/%d", v.tcID), v.pub, v.sig[:64]})
	}
	for _, v := range wycheproofVectors {
		pairs = append(pairs, encodedPair{fmt.Sprintf("wycheproof/%d", v.tcID), v.pub, v.sig[:64]})
	}

	for _, pair := range pairs {
		aBytes, err := hex.DecodeString(pair.a)
		if err != nil || len(aBytes) != 32 {
			t.Fatalf("%s: invalid A fixture", pair.name)
		}
		rBytes, err := hex.DecodeString(pair.r)
		if err != nil || len(rBytes) != 32 {
			t.Fatalf("%s: invalid R fixture", pair.name)
		}

		var wantA, wantR r43x6.Point
		_, wantAErr := wantA.SetBytes(aBytes)
		_, wantRErr := wantR.SetBytes(rBytes)
		gotA, gotR, gotAErr, gotRErr := r43x6.Decode2NoT(aBytes, rBytes)
		if (gotAErr != nil) != (wantAErr != nil) || (gotRErr != nil) != (wantRErr != nil) {
			t.Fatalf("%s: paired errors A=%v/%v R=%v/%v", pair.name, gotAErr, wantAErr, gotRErr, wantRErr)
		}
		if wantAErr == nil && gotA.Equal(&wantA) != 1 {
			t.Fatalf("%s: paired A differs", pair.name)
		}
		if wantRErr == nil {
			wantBytes := wantR.Bytes()
			gotBytes := gotR.Bytes()
			if gotBytes != wantBytes {
				t.Fatalf("%s: paired R differs: got=%x want=%x", pair.name, gotBytes, wantBytes)
			}
		}
	}
}

func TestR43PairedStrictMatchesReferenceCorpora(t *testing.T) {
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
			t.Fatalf("%s: invalid public key fixture", v.name)
		}
		message, err := hex.DecodeString(v.msg)
		if err != nil {
			t.Fatalf("%s: invalid message fixture", v.name)
		}
		sig, err := hex.DecodeString(v.sig)
		if err != nil || len(sig) != 64 {
			t.Fatalf("%s: invalid signature fixture", v.name)
		}
		var pub [32]byte
		copy(pub[:], pubBytes)

		got := verifyR43PairedStrict(&pub, message, sig)
		want := referenceVerifyProfile(DalekStrict, &pub, message, sig)
		if got != want {
			t.Fatalf("%s: paired strict=%v reference=%v", v.name, got, want)
		}
	}
}

func BenchmarkR43PairedStrictPipeline(b *testing.B) {
	for _, size := range benchMsgSizes {
		f := makeFixture(b, size)
		b.Run(fmt.Sprintf("reference-decodeA-encodeQ/msg=%d", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if !verifyR43Reference(DalekStrict, &f.pub, f.msg, f.sig) {
					b.Fatal("reference rejected valid signature")
				}
			}
		})
		b.Run(fmt.Sprintf("paired-decode-projective/msg=%d", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if !verifyR43PairedStrict(&f.pub, f.msg, f.sig) {
					b.Fatal("paired pipeline rejected valid signature")
				}
			}
		})
	}
}
