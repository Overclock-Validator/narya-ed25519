package edwards25519

import (
	"bytes"
	"testing"
)

func TestMultiScalarMultInitializesZeroReceiver(t *testing.T) {
	var scalarBytes [32]byte
	scalarBytes[0] = 7
	scalar, err := NewScalar().SetCanonicalBytes(scalarBytes[:])
	if err != nil {
		t.Fatal(err)
	}

	var got Point
	got.MultiScalarMult([]*Scalar{scalar}, []*Point{NewGeneratorPoint()})
	want := new(Point).ScalarBaseMult(scalar)
	if !bytes.Equal(got.Bytes(), want.Bytes()) {
		t.Fatalf("zero-receiver MultiScalarMult mismatch\ngot  %x\nwant %x", got.Bytes(), want.Bytes())
	}
}

func TestMultiScalarMultReceiverMayAliasInput(t *testing.T) {
	var scalarBytes [32]byte
	scalarBytes[0] = 11
	scalar, err := NewScalar().SetCanonicalBytes(scalarBytes[:])
	if err != nil {
		t.Fatal(err)
	}

	got := NewGeneratorPoint()
	got.MultiScalarMult([]*Scalar{scalar}, []*Point{got})
	want := new(Point).ScalarBaseMult(scalar)
	if !bytes.Equal(got.Bytes(), want.Bytes()) {
		t.Fatalf("aliased-receiver MultiScalarMult mismatch\ngot  %x\nwant %x", got.Bytes(), want.Bytes())
	}
}
