package ed25519

import (
	"bytes"
	stded25519 "crypto/ed25519"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/Overclock-Validator/narya/internal/r51x5"
)

// These seeds are the minimized inputs retained by Firedancer's
// fuzz_ed25519_sigverify corpus. That target derives a keypair from the first
// 32 bytes, signs the remaining message, and verifies the result. The inputs
// caught three failures directly relevant to Narya's Firedancer-derived
// arithmetic:
//
//   - projective equality compared redundant limbs instead of values modulo p;
//   - paired decode returned an insufficiently folded point; and
//   - w-NAF recoding overflowed while combining adjacent digits.
//
// Sources and fixes:
//
//   - https://github.com/firedancer-io/firedancer/commit/432463091c6c981fd99e29aa95b4863017c381ea
//   - https://github.com/firedancer-io/firedancer/commit/af4f2ef8f47c47b4bc25fe120b1411cc6bd836fa
//   - https://github.com/firedancer-io/firedancer/commit/d5b5bfd52e0a1138d07ab3cc5cfbf9f9605ead87
//
// Public keys and signatures are pinned as KATs instead of being generated as
// the sole expectation. The test also regenerates them with crypto/ed25519 to
// prove that the corpus parser and the copied constants have not drifted.
var firedancerFuzzSeedRegressions = []struct {
	name      string
	seed      string
	message   string
	publicKey string
	signature string
}{
	{
		name:      "projective-equality-mod-p",
		seed:      "0a4d4d4dadb64d4d4d004d4d4d4d4d4d4d2a2a2a2a2a2a4d4d4d4d4d4d4d4dfe",
		message:   "ffffff4d4d4d4d4d4d4d",
		publicKey: "97af288eac6130df4f60497d08e80e587c53a982cb549d20010eba96fa7e1dfe",
		signature: "073af4081a4860a33de307b7d3f4a4a2ca9a2a705d02c9fc18dbde2586f722ec7977eeeff944fce1fd02ed115a71a8c08f53d839f23cea37bf35b07b6f91ed03",
	},
	{
		name:      "paired-decode-canonicalization",
		seed:      "26010000000030000000d3d2d26dfff7ff000000012d2d2d00007bdaa74c6aac",
		message:   "",
		publicKey: "933d3225bb99c5537bab8b6f6e18e8ca5bc1396f448e155d705489b1a76cae0d",
		signature: "7f8f0229cd60bf97db3b3948c604d66b8cb202aaf72f038257d37467b7ea1352d2e0c03e0a06b82d09acd8b78220b3178b7b298356d9b8229fdb3ffd49a8af08",
	},
	{
		name:      "wnaf-overflow-1",
		seed:      "1c72eed200000011000000040000000000000000000000000000000000000000",
		message:   "",
		publicKey: "00d9d56a78bcdb68b28dc54eee5430e2428324823313dc353659dbb3f9df4df5",
		signature: "85477ea2501968bc4e29f475667930672e15e966edc0f49700f9c4b4a48138609122b543913b15edc63d7df7150000249686917a96913bbb40f6edf2a3d8fd00",
	},
	{
		name:      "wnaf-overflow-2",
		seed:      "ffa70aef0500d0d00000006b7a00006b7a0000a1d2c0616b7a0000d2c07a0000",
		message:   "",
		publicKey: "82fdd54f122e6e67044cf20b004316b3e3eff86e34cf463acbe48f6624ffc5eb",
		signature: "af6ad56f5cfdbb8656807d1f92d213eeace030de49e25d4f6af4e9047348cf84f2fe20c4a6019b194d99675cc1060000e8b577d52ff810127be9160305b9d904",
	},
}

func firedancerFuzzRegressionVectors(t *testing.T) []r51ReferenceVector {
	t.Helper()
	vectors := make([]r51ReferenceVector, len(firedancerFuzzSeedRegressions))
	for index, fixture := range firedancerFuzzSeedRegressions {
		seed, err := hex.DecodeString(fixture.seed)
		if err != nil || len(seed) != stded25519.SeedSize {
			t.Fatalf("%s: malformed Firedancer seed", fixture.name)
		}
		vector := decodeR51Vector(t, "firedancer/"+fixture.name, fixture.publicKey, fixture.message, fixture.signature)
		privateKey := stded25519.NewKeyFromSeed(seed)
		if publicKey := privateKey.Public().(stded25519.PublicKey); !bytes.Equal(publicKey, vector.pub[:]) {
			t.Fatalf("%s: derived public key=%x want=%x", fixture.name, publicKey, vector.pub)
		}
		if signature := stded25519.Sign(privateKey, vector.msg); !bytes.Equal(signature, vector.sig) {
			t.Fatalf("%s: derived signature=%x want=%x", fixture.name, signature, vector.sig)
		}
		vectors[index] = vector
	}
	return vectors
}

func repeatFiredancerFuzzRegressionVectors(t *testing.T, count int) []r51ReferenceVector {
	t.Helper()
	base := firedancerFuzzRegressionVectors(t)
	vectors := make([]r51ReferenceVector, count)
	for index := range vectors {
		vectors[index] = base[index%len(base)]
		vectors[index].name = fmt.Sprintf("%s/lane=%d", vectors[index].name, index)
		vectors[index].msg = append([]byte(nil), vectors[index].msg...)
		vectors[index].sig = append([]byte(nil), vectors[index].sig...)
	}
	return vectors
}

func TestFiredancerFuzzRegressionVectors(t *testing.T) {
	vectors := firedancerFuzzRegressionVectors(t)
	for _, vector := range vectors {
		vector := vector
		t.Run(vector.name, func(t *testing.T) {
			for _, profile := range []Profile{StdlibCompat, DalekStrict} {
				if !referenceVerifyProfile(profile, &vector.pub, vector.msg, vector.sig) {
					t.Fatalf("profile=%d: reference rejected a valid regression vector", profile)
				}
				if !verifyR43Reference(profile, &vector.pub, vector.msg, vector.sig) {
					t.Fatalf("profile=%d: r43 reference rejected a valid regression vector", profile)
				}
				if !verifyR43Pipeline(profile, &vector.pub, vector.msg, vector.sig) {
					t.Fatalf("profile=%d: r43 pipeline rejected a valid regression vector", profile)
				}
			}

			withProfile(StdlibCompat, func() {
				check(t, &Cache{}, &vector.pub, vector.msg, vector.sig)
			})
			if !VerifyStrict(vector.pub[:], vector.msg, vector.sig) {
				t.Fatal("VerifyStrict rejected a valid regression vector")
			}
		})
	}

	// Repeating the four inputs through 17 positions crosses x4/x8, two-x4,
	// and multi-group tail boundaries. Every historical input occupies several
	// distinct lane positions.
	expanded := repeatFiredancerFuzzRegressionVectors(t, 17)
	for _, profile := range []Profile{StdlibCompat, DalekStrict} {
		for _, width := range []int{r51x5.X4Lanes, r51x5.X8Lanes} {
			for _, radixBits := range []uint{4, 5} {
				assertR51ReferenceVectors(t, expanded, profile, width, radixBits)
			}
		}
	}
}
