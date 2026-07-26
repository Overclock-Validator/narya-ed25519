package r51x5

import (
	"bytes"
	"math/rand"
	"testing"
	"unsafe"
)

func TestExperimentalQuadTwoChainNAFVerifyX8(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("AVX-512 IFMA is unavailable")
	}
	fixture := newQuadDSMFixtureX4(t)
	ops := quadDSMOperationsX4{hardware: true}
	var aTable quadNAFTable5X4
	var bTable quadNAFTable8X4
	if err := buildQuadNAFTable5X4(&aTable, &fixture.a, ops); err != nil {
		t.Fatal(err)
	}
	if err := buildQuadNAFTable8X4(&bTable, &fixture.b, ops); err != nil {
		t.Fatal(err)
	}

	var scalarPairs [258][2][32]byte
	scalarPairs[1][0] = scalarOrderBytes
	scalarPairs[1][1] = scalarOrderBytes
	decrementLittleEndianX4Test(&scalarPairs[1][0])
	decrementLittleEndianX4Test(&scalarPairs[1][1])
	rng := rand.New(rand.NewSource(0x514e325a))
	for index := 2; index < len(scalarPairs); index++ {
		_, _ = rng.Read(scalarPairs[index][0][:])
		_, _ = rng.Read(scalarPairs[index][1][:])
		scalarPairs[index][0][31] &= 0x0f
		scalarPairs[index][1][31] &= 0x0f
	}

	for index := range scalarPairs {
		var want quadPackedPointX4
		wantValid, err := evaluateQuadNAFVerifyX4(
			&want, &aTable, &bTable,
			&scalarPairs[index][0], &scalarPairs[index][1], ops,
		)
		if err != nil || !wantValid {
			t.Fatalf("case %d x4=(%v,%v)", index, wantValid, err)
		}

		var got quadPackedPointX4
		gotValid, err := evaluateQuadTwoChainNAFVerifyX8Experiment(
			&got, &aTable, &bTable,
			&scalarPairs[index][0], &scalarPairs[index][1],
		)
		if err != nil || !gotValid {
			t.Fatalf("case %d x8=(%v,%v)", index, gotValid, err)
		}
		wantPoint := want.reduced()
		gotPoint := got.reduced()
		wantEncoding := wantPoint.Bytes()
		gotEncoding := gotPoint.Bytes()
		if !bytes.Equal(gotEncoding[:], wantEncoding[:]) {
			t.Fatalf("case %d two-chain/shared mismatch\ngot  %x\nwant %x", index, gotEncoding, wantEncoding)
		}
	}

	invalid := scalarOrderBytes
	var out quadPackedPointX4
	valid, err := evaluateQuadTwoChainNAFVerifyX8Experiment(
		&out, &aTable, &bTable, &invalid, &scalarPairs[0][1],
	)
	if err != nil || valid {
		t.Fatalf("noncanonical s=(%v,%v), want (false,nil)", valid, err)
	}
	if out != quadPackedIdentityValueX4() {
		t.Fatal("noncanonical scalar did not fail closed to identity")
	}
}

func TestExperimentalQuadTwoChainNAFVerifyX8ZeroAllocations(t *testing.T) {
	if !ExperimentalIFMAAvailable() {
		t.Skip("AVX-512 IFMA is unavailable")
	}
	fixture := newQuadDSMFixtureX4(t)
	ops := quadDSMOperationsX4{hardware: true}
	var aTable quadNAFTable5X4
	var bTable quadNAFTable8X4
	if err := buildQuadNAFTable5X4(&aTable, &fixture.a, ops); err != nil {
		t.Fatal(err)
	}
	if err := buildQuadNAFTable8X4(&bTable, &fixture.b, ops); err != nil {
		t.Fatal(err)
	}
	s := fixture.scalars[0][0]
	k := fixture.scalars[1][0]
	var out quadPackedPointX4
	if allocs := testing.AllocsPerRun(100, func() {
		valid, err := evaluateQuadTwoChainNAFVerifyX8Experiment(&out, &aTable, &bTable, &s, &k)
		if err != nil {
			panic(err)
		}
		if !valid {
			panic("r51x5: canonical two-chain scalar rejected")
		}
	}); allocs != 0 {
		t.Fatalf("allocations=%v want 0", allocs)
	}
	benchmarkQuadNAFPointSink = out
}

func BenchmarkExperimentalQuadTwoChainNAFVerifyX8(b *testing.B) {
	if !ExperimentalIFMAAvailable() {
		b.Skip("AVX-512 IFMA is unavailable")
	}
	fixture := newQuadDSMFixtureX4(b)
	ops := quadDSMOperationsX4{hardware: true}
	var aTable quadNAFTable5X4
	var bTable quadNAFTable8X4
	if err := buildQuadNAFTable5X4(&aTable, &fixture.a, ops); err != nil {
		b.Fatal(err)
	}
	if err := buildQuadNAFTable8X4(&bTable, &fixture.b, ops); err != nil {
		b.Fatal(err)
	}
	s := fixture.scalars[0][0]
	k := fixture.scalars[1][0]

	b.Run("stage=prepared/path=shared-x4", func(b *testing.B) {
		var out quadPackedPointX4
		b.ReportAllocs()
		b.ReportMetric(float64(unsafe.Sizeof(aTable)), "A-table-B")
		b.ResetTimer()
		for iteration := 0; iteration < b.N; iteration++ {
			valid, err := evaluateQuadNAFVerifyX4(&out, &aTable, &bTable, &s, &k, ops)
			if err != nil {
				b.Fatal(err)
			}
			if !valid {
				b.Fatal("canonical shared scalar rejected")
			}
		}
		benchmarkQuadNAFPointSink = out
	})

	b.Run("stage=prepared/path=two-chain-zmm", func(b *testing.B) {
		var out quadPackedPointX4
		b.ReportAllocs()
		b.ReportMetric(float64(unsafe.Sizeof(aTable)), "A-table-B")
		b.ResetTimer()
		for iteration := 0; iteration < b.N; iteration++ {
			valid, err := evaluateQuadTwoChainNAFVerifyX8Experiment(&out, &aTable, &bTable, &s, &k)
			if err != nil {
				b.Fatal(err)
			}
			if !valid {
				b.Fatal("canonical two-chain scalar rejected")
			}
		}
		benchmarkQuadNAFPointSink = out
	})
}
