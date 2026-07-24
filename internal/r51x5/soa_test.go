package r51x5

import (
	"bytes"
	"math/rand"
	"testing"

	edwardsfield "github.com/Overclock-Validator/narya/internal/edwards25519/field"
)

func TestElementX8LayoutAndArithmetic(t *testing.T) {
	rng := rand.New(rand.NewSource(0x8_51_05))
	for round := 0; round < 256; round++ {
		var x, y [8]Element
		for lane := range x {
			x[lane], _ = randomElement(t, rng)
			y[lane], _ = randomElement(t, rng)
		}

		var vx, vy ElementX8
		vx.SetElements(&x)
		vy.SetElements(&y)
		if !IsReducedX8(vx.Limbs()) || !IsReducedX8(vy.Limbs()) {
			t.Fatal("packed x8 value is not reduced")
		}
		assertX8Layout(t, &vx, &x)
		if got := vx.Elements(); got != x {
			t.Fatalf("round %d: x8 unpack mismatch", round)
		}

		var got ElementX8
		got.Add(&vx, &vy)
		assertX8Operation(t, "add", &got, &x, &y)
		got.Subtract(&vx, &vy)
		assertX8Operation(t, "subtract", &got, &x, &y)
		got.Negate(&vx)
		assertX8Operation(t, "negate", &got, &x, &y)
		got.Multiply(&vx, &vy)
		assertX8Operation(t, "multiply", &got, &x, &y)
		got.Square(&vx)
		assertX8Operation(t, "square", &got, &x, &y)

		alias := vx
		alias.Multiply(&alias, &vy)
		assertX8Operation(t, "multiply", &alias, &x, &y)
	}
}

func TestElementX4LayoutAndArithmetic(t *testing.T) {
	rng := rand.New(rand.NewSource(0x4_51_05))
	for round := 0; round < 256; round++ {
		var x, y [4]Element
		for lane := range x {
			x[lane], _ = randomElement(t, rng)
			y[lane], _ = randomElement(t, rng)
		}

		var vx, vy ElementX4
		vx.SetElements(&x)
		vy.SetElements(&y)
		if !IsReducedX4(vx.Limbs()) || !IsReducedX4(vy.Limbs()) {
			t.Fatal("packed x4 value is not reduced")
		}
		assertX4Layout(t, &vx, &x)
		if got := vx.Elements(); got != x {
			t.Fatalf("round %d: x4 unpack mismatch", round)
		}

		var got ElementX4
		got.Add(&vx, &vy)
		assertX4Operation(t, "add", &got, &x, &y)
		got.Subtract(&vx, &vy)
		assertX4Operation(t, "subtract", &got, &x, &y)
		got.Negate(&vx)
		assertX4Operation(t, "negate", &got, &x, &y)
		got.Multiply(&vx, &vy)
		assertX4Operation(t, "multiply", &got, &x, &y)
		got.Square(&vx)
		assertX4Operation(t, "square", &got, &x, &y)

		alias := vx
		alias.Add(&alias, &vy)
		assertX4Operation(t, "add", &alias, &x, &y)
	}
}

func TestSoAInversionAndLaneIndependence(t *testing.T) {
	rng := rand.New(rand.NewSource(0x1_8_51))
	var x8 [8]Element
	for lane := range x8 {
		x8[lane], _ = randomElement(t, rng)
	}
	x8[3].Zero()
	var vx8, got8 ElementX8
	vx8.SetElements(&x8)
	got8.Invert(&vx8)
	for lane := range x8 {
		var want Element
		want.Invert(&x8[lane])
		if got := got8.Lane(lane); got != want {
			t.Fatalf("x8 lane %d: inversion mismatch", lane)
		}
	}

	var x4 [4]Element
	copy(x4[:], x8[:4])
	var vx4, got4 ElementX4
	vx4.SetElements(&x4)
	got4.Invert(&vx4)
	for lane := range x4 {
		var want Element
		want.Invert(&x4[lane])
		if got := got4.Lane(lane); got != want {
			t.Fatalf("x4 lane %d: inversion mismatch", lane)
		}
	}

	// Altering one packed input lane must not change any other output lane.
	mutated := x8
	mutated[5].One()
	var vm, outOriginal, outMutated ElementX8
	vm.SetElements(&mutated)
	outOriginal.Square(&vx8)
	outMutated.Square(&vm)
	for lane := range x8 {
		if lane == 5 {
			continue
		}
		if outOriginal.Lane(lane) != outMutated.Lane(lane) {
			t.Fatalf("changing lane 5 affected lane %d", lane)
		}
	}
}

func TestSoARangeAndLaneChecks(t *testing.T) {
	var x8 ElementX8
	raw8 := x8.Limbs()
	raw8[2][7] = 1 << LimbBits
	if IsReducedX8(raw8) {
		t.Fatal("x8 accepted overwide lane")
	}
	var x4 ElementX4
	raw4 := x4.Limbs()
	for limb := range modulusLimbs {
		raw4[limb][2] = modulusLimbs[limb]
	}
	if IsReducedX4(raw4) {
		t.Fatal("x4 accepted p lane")
	}

	for _, test := range []struct {
		name string
		fn   func()
	}{
		{"x4 negative", func() { _ = x4.Lane(-1) }},
		{"x4 high", func() { _ = x4.Lane(4) }},
		{"x8 negative", func() { _ = x8.Lane(-1) }},
		{"x8 high", func() { _ = x8.Lane(8) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("invalid lane did not panic")
				}
			}()
			test.fn()
		})
	}
}

func assertX8Layout(t *testing.T, got *ElementX8, want *[8]Element) {
	t.Helper()
	raw := got.Limbs()
	for lane := range want {
		limbs := want[lane].Limbs()
		for limb := range limbs {
			if raw[limb][lane] != limbs[limb] {
				t.Fatalf("x8 limb %d lane %d: got %x want %x", limb, lane, raw[limb][lane], limbs[limb])
			}
		}
	}
}

func assertX4Layout(t *testing.T, got *ElementX4, want *[4]Element) {
	t.Helper()
	raw := got.Limbs()
	for lane := range want {
		limbs := want[lane].Limbs()
		for limb := range limbs {
			if raw[limb][lane] != limbs[limb] {
				t.Fatalf("x4 limb %d lane %d: got %x want %x", limb, lane, raw[limb][lane], limbs[limb])
			}
		}
	}
}

func assertX8Operation(t *testing.T, operation string, got *ElementX8, x, y *[8]Element) {
	t.Helper()
	if !IsReducedX8(got.Limbs()) {
		t.Fatalf("%s: x8 output is not reduced", operation)
	}
	for lane := range x {
		assertLaneOperation(t, operation, lane, got.Lane(lane), &x[lane], &y[lane])
	}
}

func assertX4Operation(t *testing.T, operation string, got *ElementX4, x, y *[4]Element) {
	t.Helper()
	if !IsReducedX4(got.Limbs()) {
		t.Fatalf("%s: x4 output is not reduced", operation)
	}
	for lane := range x {
		assertLaneOperation(t, operation, lane, got.Lane(lane), &x[lane], &y[lane])
	}
}

func assertLaneOperation(t *testing.T, operation string, lane int, got Element, x, y *Element) {
	t.Helper()
	var want Element
	var fx, fy, fw edwardsfield.Element
	xBytes, yBytes := x.Bytes(), y.Bytes()
	_, _ = fx.SetBytes(xBytes[:])
	_, _ = fy.SetBytes(yBytes[:])
	switch operation {
	case "add":
		want.Add(x, y)
		fw.Add(&fx, &fy)
	case "subtract":
		want.Subtract(x, y)
		fw.Subtract(&fx, &fy)
	case "negate":
		want.Negate(x)
		fw.Negate(&fx)
	case "multiply":
		want.Multiply(x, y)
		fw.Multiply(&fx, &fy)
	case "square":
		want.Square(x)
		fw.Square(&fx)
	default:
		t.Fatalf("unknown operation %q", operation)
	}
	if got != want {
		t.Fatalf("%s lane %d: scalar mismatch got %#v want %#v", operation, lane, got.Limbs(), want.Limbs())
	}
	encoded := got.Bytes()
	if !bytes.Equal(encoded[:], fw.Bytes()) {
		t.Fatalf("%s lane %d: Edwards mismatch got %x want %x", operation, lane, encoded, fw.Bytes())
	}
}
