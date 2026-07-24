package r43x6

import (
	"errors"
	"math/big"
	"math/bits"
	"math/rand"
	"os"
	"os/exec"
	"runtime"
	"testing"
)

func ifmaRawModel(x, y Limbs) Limbs {
	var coefficients [12]uint64
	const mask52 = uint64(1<<52) - 1
	for i := 0; i < 6; i++ {
		for j := 0; j < 6; j++ {
			hi, lo := bits.Mul64(x[i], y[j])
			coefficients[i+j] += lo & mask52
			coefficients[i+j+1] += (lo>>52 | hi<<12) << 9
		}
	}
	var folded Limbs
	for i := range folded {
		folded[i] = coefficients[i] + 152*coefficients[i+6]
	}
	return Limbs{
		folded[0]&limbMask + 19*(folded[5]>>TopLimbBits),
		folded[1]&limbMask + (folded[0] >> LimbBits),
		folded[2]&limbMask + (folded[1] >> LimbBits),
		folded[3]&limbMask + (folded[2] >> LimbBits),
		folded[4]&limbMask + (folded[3] >> LimbBits),
		folded[5]&topMask + (folded[4] >> LimbBits),
	}
}

func reduceLooseForTest(loose Limbs) Element {
	var accum [6]uint128
	for i := range loose {
		accum[i].lo = loose[i]
	}
	return Element{limbs: reduceAccumulators(&accum)}
}

func TestIFMARawContractModel(t *testing.T) {
	rng := rand.New(rand.NewSource(0x52))
	for i := 0; i < 8192; i++ {
		x, _ := randomElement(t, rng)
		y, _ := randomElement(t, rng)
		loose := ifmaRawModel(x.Limbs(), y.Limbs())
		if !IsUnreduced(loose) {
			t.Fatalf("model output %d is outside u47: %#v", i, loose)
		}
		var want Element
		want.multiplyReference(&x, &y)
		got := reduceLooseForTest(loose)
		if got.Equal(&want) != 1 {
			t.Fatalf("model output %d represents wrong element: got %x want %x", i, got.Bytes(), want.Bytes())
		}
	}
}

func TestExperimentalIFMAGate(t *testing.T) {
	if ExperimentalIFMAAvailable() {
		return
	}
	var x, y, out Element
	x.One()
	y.One()
	out.One()
	want := out.Bytes()
	if err := ExperimentalIFMAMultiply(&out, &x, &y); !errors.Is(err, ErrIFMAUnavailable) {
		t.Fatalf("multiply error=%v want %v", err, ErrIFMAUnavailable)
	}
	if got := out.Bytes(); got != want {
		t.Fatalf("unavailable multiply changed output: got %x want %x", got, want)
	}
	if err := ExperimentalIFMASquare(&out, &x); !errors.Is(err, ErrIFMAUnavailable) {
		t.Fatalf("square error=%v want %v", err, ErrIFMAUnavailable)
	}
	if err := EnableExperimentalIFMA(); !errors.Is(err, ErrIFMAUnavailable) {
		t.Fatalf("enable error=%v want %v", err, ErrIFMAUnavailable)
	}
	if ExperimentalIFMAEnabled() {
		t.Fatal("unsupported enable changed the one-way dispatch switch")
	}
}

func TestExperimentalIFMAMultiply(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	boundary := []*big.Int{
		big.NewInt(0),
		big.NewInt(1),
		big.NewInt(2),
		big.NewInt(19),
		new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 43), big.NewInt(1)),
		new(big.Int).Lsh(big.NewInt(1), 43),
		new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 215), big.NewInt(1)),
		new(big.Int).Lsh(big.NewInt(1), 215),
		new(big.Int).Sub(new(big.Int).Set(testModulus), big.NewInt(2)),
		new(big.Int).Sub(new(big.Int).Set(testModulus), big.NewInt(1)),
	}

	check := func(label string, x, y *Element) {
		t.Helper()
		var want, got Element
		want.multiplyReference(x, y)
		if err := ExperimentalIFMAMultiply(&got, x, y); err != nil {
			t.Fatalf("%s: multiply failed: %v", label, err)
		}
		if got.Equal(&want) != 1 {
			t.Fatalf("%s: multiply mismatch\ngot  %x\nwant %x\nx=%#v\ny=%#v", label, got.Bytes(), want.Bytes(), x.Limbs(), y.Limbs())
		}

		// Inspect the assembly contract before wrapper canonicalization.
		xl, yl := x.Limbs(), y.Limbs()
		var loose Limbs
		ifmaMulRaw(&loose, &xl, &yl)
		if model := ifmaRawModel(xl, yl); loose != model {
			t.Fatalf("%s: raw assembly/model mismatch\nassembly=%#v\nmodel=%#v", label, loose, model)
		}
		if !IsUnreduced(loose) {
			t.Fatalf("%s: raw output is outside u47: %#v", label, loose)
		}
		if reduced := reduceLooseForTest(loose); reduced.Equal(&want) != 1 {
			t.Fatalf("%s: raw output represents wrong field element: %#v", label, loose)
		}

		aliasX := *x
		if err := ExperimentalIFMAMultiply(&aliasX, &aliasX, y); err != nil || aliasX.Equal(&want) != 1 {
			t.Fatalf("%s: x-alias mismatch: err=%v", label, err)
		}
		aliasY := *y
		if err := ExperimentalIFMAMultiply(&aliasY, x, &aliasY); err != nil || aliasY.Equal(&want) != 1 {
			t.Fatalf("%s: y-alias mismatch: err=%v", label, err)
		}
	}

	for _, xb := range boundary {
		x := elementFromBig(t, xb)
		for _, yb := range boundary {
			y := elementFromBig(t, yb)
			check("boundary", &x, &y)
		}
	}

	rng := rand.New(rand.NewSource(0x1f4a))
	for i := 0; i < 4096; i++ {
		x, _ := randomElement(t, rng)
		y, _ := randomElement(t, rng)
		check("random", &x, &y)

		var want, got Element
		want.multiplyReference(&x, &x)
		if err := ExperimentalIFMASquare(&got, &x); err != nil {
			t.Fatalf("square %d failed: %v", i, err)
		}
		if got.Equal(&want) != 1 {
			t.Fatalf("square %d mismatch: got %x want %x", i, got.Bytes(), want.Bytes())
		}
		alias := x
		if err := ExperimentalIFMASquare(&alias, &alias); err != nil || alias.Equal(&want) != 1 {
			t.Fatalf("aliased square %d mismatch: err=%v", i, err)
		}
	}
}

func TestIFMAOneWayFieldDispatch(t *testing.T) {
	const childEnv = "NARYA_R43_IFMA_DISPATCH_TEST_CHILD"
	if !ExperimentalIFMAAvailable() {
		t.Skipf("AVX-512 IFMA unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	if os.Getenv(childEnv) != "1" {
		if ExperimentalIFMAEnabled() {
			t.Fatal("IFMA dispatch was enabled before the isolated dispatch test")
		}
		cmd := exec.Command(os.Args[0], "-test.run=^TestIFMAOneWayFieldDispatch$", "-test.count=1")
		cmd.Env = append(os.Environ(), childEnv+"=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("isolated IFMA dispatch test: %v\n%s", err, output)
		}
		if ExperimentalIFMAEnabled() {
			t.Fatal("isolated IFMA dispatch test changed parent-process dispatch")
		}
		return
	}
	if err := EnableExperimentalIFMA(); err != nil {
		t.Fatal(err)
	}
	if !ExperimentalIFMAEnabled() {
		t.Fatal("successful enable left scalar dispatch active")
	}
	// Enabling twice is intentionally idempotent; disabling is not exposed.
	if err := EnableExperimentalIFMA(); err != nil {
		t.Fatalf("second enable: %v", err)
	}

	rng := rand.New(rand.NewSource(0x1f4a43))
	for i := 0; i < 4096; i++ {
		x, _ := randomElement(t, rng)
		y, _ := randomElement(t, rng)
		var want, got Element
		want.multiplyReference(&x, &y)
		got.Multiply(&x, &y)
		if got.Equal(&want) != 1 {
			t.Fatalf("dispatched multiply %d mismatch: got %x want %x", i, got.Bytes(), want.Bytes())
		}
	}
}
