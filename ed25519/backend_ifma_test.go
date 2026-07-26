package ed25519

import (
	stded25519 "crypto/ed25519"
	"encoding/hex"
	"fmt"
	mrand "math/rand"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"testing"

	"github.com/Overclock-Validator/narya-ed25519/internal/r43x6"
)

func requireIFMABackend(t testing.TB) ifmaBackend {
	t.Helper()
	if !r43x6.ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	b := ifmaBackend{}
	if err := b.activate(); err != nil {
		t.Fatalf("activate IFMA backend: %v", err)
	}
	return b
}

// enterIsolatedIFMABackendTest runs activation-dependent hardware tests in a
// same-binary subprocess. IFMA field dispatch is intentionally one-way, so
// enabling it in the package test process would silently turn later r43x6
// reference tests into hardware tests. The child returns true and executes
// the test body; the parent waits for it and returns false.
func enterIsolatedIFMABackendTest(t *testing.T) bool {
	t.Helper()
	const childEnv = "NARYA_IFMA_BACKEND_TEST_CHILD"
	if os.Getenv(childEnv) == t.Name() {
		return true
	}
	if !r43x6.ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	if r43x6.ExperimentalIFMAEnabled() {
		t.Fatal("IFMA field dispatch was enabled before the isolated backend test")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^"+regexp.QuoteMeta(t.Name())+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), childEnv+"="+t.Name())
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("isolated IFMA backend test: %v\n%s", err, output)
	}
	if r43x6.ExperimentalIFMAEnabled() {
		t.Fatal("isolated IFMA backend test changed parent-process field dispatch")
	}
	return false
}

func TestIFMABackendUnsupportedGate(t *testing.T) {
	if _, ok := registry["ifma"]; !ok {
		t.Fatal("forced-only IFMA backend is not registered")
	}
	if r43x6.ExperimentalIFMAAvailable() {
		t.Skip("CPU supports IFMA; hardware tests cover the successful gate")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("explicit IFMA selection did not reject an unsupported CPU")
		}
		if r43x6.ExperimentalIFMAEnabled() {
			t.Fatal("failed selection enabled IFMA field dispatch")
		}
	}()
	_ = pick("ifma")
}

func TestIFMABackendMatchesCorpora(t *testing.T) {
	if !enterIsolatedIFMABackendTest(t) {
		return
	}
	b := requireIFMABackend(t)
	type vector struct {
		name, pub, msg, sig string
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
			got := verifyOne(b, profile, &pub, msg, sig, nil)
			want := referenceVerifyProfile(profile, &pub, msg, sig)
			if got != want {
				t.Fatalf("%s profile=%d: ifma=%v reference=%v", v.name, profile, got, want)
			}
		}
	}
}

func TestIFMABackendFiredancerFuzzRegressions(t *testing.T) {
	if !enterIsolatedIFMABackendTest(t) {
		return
	}
	b := requireIFMABackend(t)
	// Firedancer keeps these minimized signing inputs because they exposed
	// concrete r43x6 failures. Exercise the derived fixed signatures through
	// the actual hardware-selected backend as well as the pure-Go references.
	for _, v := range firedancerFuzzRegressionVectors(t) {
		for _, profile := range []Profile{StdlibCompat, DalekStrict} {
			got := verifyOne(b, profile, &v.pub, v.msg, v.sig, nil)
			want := referenceVerifyProfile(profile, &v.pub, v.msg, v.sig)
			if got != want {
				t.Fatalf("%s profile=%d: ifma=%v reference=%v", v.name, profile, got, want)
			}
		}
	}
}

func TestIFMABackendRandomDifferential(t *testing.T) {
	if !enterIsolatedIFMABackendTest(t) {
		return
	}
	b := requireIFMABackend(t)
	rng := mrand.New(mrand.NewSource(0x431f4a))
	for round := 0; round < 256; round++ {
		pubBytes, priv, err := stded25519.GenerateKey(rng)
		if err != nil {
			t.Fatal(err)
		}
		var pub [32]byte
		copy(pub[:], pubBytes)
		msg := make([]byte, rng.Intn(1233))
		_, _ = rng.Read(msg)
		sig := stded25519.Sign(priv, msg)

		candidates := [][]byte{sig, append([]byte(nil), sig...)}
		candidates[1][rng.Intn(len(candidates[1]))] ^= byte(1 << rng.Intn(8))
		for _, candidate := range candidates {
			for _, profile := range []Profile{StdlibCompat, DalekStrict} {
				got := verifyOne(b, profile, &pub, msg, candidate, nil)
				want := referenceVerifyProfile(profile, &pub, msg, candidate)
				if got != want {
					t.Fatalf("round=%d profile=%d ifma=%v reference=%v\npub=%x\nmsg=%x\nsig=%x",
						round, profile, got, want, pub, msg, candidate)
				}
			}
		}
	}
}

func TestIFMABackendBatchLaneMapping(t *testing.T) {
	if !enterIsolatedIFMABackendTest(t) {
		return
	}
	b := requireIFMABackend(t)
	for _, n := range []int{1, 4, 8, 9, 16, 17, 32, 64} {
		bf := makeBatchFixture(t, n, 200)
		for badLane := range bf.sigs {
			caseMsgs := append([][]byte(nil), bf.msgs...)
			bad := append([]byte(nil), caseMsgs[badLane]...)
			bad[0] ^= 1
			caseMsgs[badLane] = bad

			items := makeItems(bf.pubs, caseMsgs, bf.sigs, make([]bool, n))
			applyProfile(DalekStrict, items)
			b.verifyBatch(DalekStrict, items)
			for lane := range items {
				want := referenceVerifyProfile(DalekStrict, bf.pubs[lane], caseMsgs[lane], bf.sigs[lane])
				if items[lane].ok != want {
					t.Fatalf("n=%d bad-lane=%d lane=%d: got=%v want=%v", n, badLane, lane, items[lane].ok, want)
				}
			}
		}
	}
}

// This subprocess test exercises the public selector without contaminating
// the package test process, whose automatic backend is deliberately generic.
func TestIFMAExplicitSelection(t *testing.T) {
	if os.Getenv("NARYA_IFMA_SELECTION_CHILD") == "1" {
		if got := ActiveBackend(); got != "ifma" {
			t.Fatalf("explicit backend selected %q, want ifma", got)
		}
		f := makeFixture(t, 200)
		if !VerifyStrict(f.pub[:], f.msg, f.sig) {
			t.Fatal("forced public IFMA verification rejected a valid signature")
		}
		return
	}
	if !r43x6.ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestIFMAExplicitSelection$")
	cmd.Env = append(os.Environ(),
		"NARYA_IFMA_SELECTION_CHILD=1",
		"OVERCLOCK_ED25519_BACKEND=ifma",
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("forced IFMA subprocess: %v\n%s", err, output)
	}
}

func BenchmarkIFMABackendVerify(b *testing.B) {
	backend := requireIFMABackend(b)
	for _, size := range benchMsgSizes {
		f := makeFixture(b, size)
		b.Run(fmt.Sprintf("profile=strict/msg=%d", size), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if !verifyOne(backend, DalekStrict, &f.pub, f.msg, f.sig, nil) {
					b.Fatal("verify failed")
				}
			}
		})
		b.Run(fmt.Sprintf("profile=compat/msg=%d", size), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if !verifyOne(backend, StdlibCompat, &f.pub, f.msg, f.sig, nil) {
					b.Fatal("verify failed")
				}
			}
		})
	}
}

func BenchmarkIFMABackendBatch(b *testing.B) {
	backend := requireIFMABackend(b)
	for _, n := range []int{1, 4, 8, 16, 32, 64} {
		bf := makeBatchFixture(b, n, 200)
		items := makeItems(bf.pubs, bf.msgs, bf.sigs, bf.ok)
		applyProfile(DalekStrict, items)
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				backend.verifyBatch(DalekStrict, items)
			}
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*n)/1000, "us/sig")
		})
	}
}
