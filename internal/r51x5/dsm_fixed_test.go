package r51x5

import (
	"fmt"
	"math/rand"
	"testing"
)

func TestFixedDSMMatchesSignedMagnitudeReference(t *testing.T) {
	rng := rand.New(rand.NewSource(0x51f1d5b))
	torsion := referenceTorsionPoints(t)
	refs, bases8 := scalarWindowQSMBasesX8(t, rng, &torsion)
	_ = refs

	var bases [DSMTerms]PointX8
	for term := 0; term < DSMTerms; term++ {
		bases[term] = bases8[term]
	}
	for _, radixBits := range []uint{4, 5, 6} {
		var workspace FixedDSMWorkspaceX8
		workspace.Prepare(&bases, radixBits)
		for round := 0; round < 128; round++ {
			var fixed FixedDSMScalarsX8
			var signed DSMScalarsX8
			var negative [DSMTerms]uint8
			for term := 0; term < DSMTerms; term++ {
				negative[term] = uint8(rng.Uint32())
				for lane := 0; lane < X8Lanes; lane++ {
					for {
						_, _ = rng.Read(fixed[term][lane][:])
						fixed[term][lane][31] &= 0x1f
						if canonicalScalarBytes(&fixed[term][lane]) {
							break
						}
					}
					signed[term][lane] = NewSignedMagnitude(fixed[term][lane][:], negative[term]&(1<<lane) != 0)
				}
			}
			active := uint8(rng.Uint32())
			var got, want PointX8
			if usable := workspace.Evaluate(&got, &fixed, &negative, active); usable != active {
				t.Fatalf("radix %d round %d usable=%02x active=%02x", 1<<radixBits, round, usable, active)
			}
			DSMX8(&want, &bases, &signed, radixBits, active)
			if mask := got.Equal(&want); mask != 0xff {
				t.Fatalf("radix %d round %d equality=%02x", 1<<radixBits, round, mask)
			}
		}
	}
}

func TestFixedDSMMasksNoncanonicalScalarLanes(t *testing.T) {
	_, bases8, _, _ := scalarWindowBenchmarkFixtures(t)
	bases := [DSMTerms]PointX8{bases8, bases8}
	var scalars FixedDSMScalarsX8
	for term := range scalars {
		for lane := range scalars[term] {
			scalars[term][lane][0] = byte(lane + term + 1)
		}
	}
	scalars[0][2] = scalarOrderBytes
	scalars[1][5] = scalarOrderBytes
	negative := [DSMTerms]uint8{0xaa, 0x55}
	var workspace FixedDSMWorkspaceX8
	workspace.Prepare(&bases, 5)
	var got PointX8
	if usable := workspace.Evaluate(&got, &scalars, &negative, 0xff); usable != 0xdb {
		t.Fatalf("usable=%02x want=db", usable)
	}
	for _, lane := range []int{2, 5} {
		point := got.Lane(lane)
		if point.IsIdentity() != 1 {
			t.Fatalf("invalid lane %d is not identity", lane)
		}
	}
}

func TestFixedDSMX4MatchesX8Halves(t *testing.T) {
	rng := rand.New(rand.NewSource(0x51f1_04a8))
	torsion := referenceTorsionPoints(t)
	_, fixture := scalarWindowQSMBasesX8(t, rng, &torsion)
	bases8 := [DSMTerms]PointX8{fixture[0], fixture[1]}
	for _, radixBits := range []uint{4, 5, 6} {
		var workspace8 FixedDSMWorkspaceX8
		workspace8.Prepare(&bases8, radixBits)
		var workspaces4 [2]FixedDSMWorkspaceX4
		var bases4 [2][DSMTerms]PointX4
		for half := 0; half < 2; half++ {
			for term := 0; term < DSMTerms; term++ {
				bases4[half][term] = pointX4Half(&bases8[term], half)
			}
			workspaces4[half].Prepare(&bases4[half], radixBits)
		}

		for iteration := 0; iteration < 64; iteration++ {
			var scalars8 FixedDSMScalarsX8
			var signs8 [DSMTerms]uint8
			for term := 0; term < DSMTerms; term++ {
				signs8[term] = uint8(rng.Uint32())
				for lane := 0; lane < X8Lanes; lane++ {
					for {
						_, _ = rng.Read(scalars8[term][lane][:])
						scalars8[term][lane][31] &= 0x1f
						if canonicalScalarBytes(&scalars8[term][lane]) {
							break
						}
					}
				}
			}
			active8 := uint8(rng.Uint32())
			var want8 PointX8
			usable8 := workspace8.Evaluate(&want8, &scalars8, &signs8, active8)
			var joined PointX8
			var joinedUsable uint8
			for half := 0; half < 2; half++ {
				var scalars4 FixedDSMScalarsX4
				var signs4 [DSMTerms]uint8
				for term := 0; term < DSMTerms; term++ {
					copy(scalars4[term][:], scalars8[term][half*X4Lanes:(half+1)*X4Lanes])
					signs4[term] = (signs8[term] >> (half * X4Lanes)) & 0x0f
				}
				active4 := (active8 >> (half * X4Lanes)) & 0x0f
				var got4 PointX4
				usable4 := workspaces4[half].Evaluate(&got4, &scalars4, &signs4, active4)
				joinedUsable |= usable4 << (half * X4Lanes)
				for lane := 0; lane < X4Lanes; lane++ {
					point := got4.Lane(lane)
					joined.SetLane(half*X4Lanes+lane, &point)
				}
			}
			if joinedUsable != usable8 {
				t.Fatalf("radix %d iteration %d x4 usable=%02x x8=%02x", 1<<radixBits, iteration, joinedUsable, usable8)
			}
			if mask := joined.Equal(&want8); mask != 0xff {
				t.Fatalf("radix %d iteration %d x4/x8 equality=%02x", 1<<radixBits, iteration, mask)
			}
		}
	}
}

func TestFixedDSMAllInvalidReturnsIdentity(t *testing.T) {
	_, bases8, _, _ := scalarWindowBenchmarkFixtures(t)
	bases := [DSMTerms]PointX8{bases8, bases8}
	var scalars FixedDSMScalarsX8
	for term := range scalars {
		for lane := range scalars[term] {
			scalars[term][lane] = scalarOrderBytes
		}
	}
	var workspace FixedDSMWorkspaceX8
	workspace.Prepare(&bases, 5)
	var out PointX8
	if usable := workspace.Evaluate(&out, &scalars, &[DSMTerms]uint8{}, 0xff); usable != 0 {
		t.Fatalf("usable=%02x want=00", usable)
	}
	if mask := out.IsIdentity(); mask != 0xff {
		t.Fatalf("identity mask=%02x", mask)
	}
}

func TestFixedDSMRequiresPreparation(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("unprepared workspace did not panic")
		}
	}()
	var workspace FixedDSMWorkspaceX4
	var out PointX4
	var scalars FixedDSMScalarsX4
	var signs [DSMTerms]uint8
	workspace.Evaluate(&out, &scalars, &signs, 0x0f)
}

var benchmarkFixedDSMPointX8 PointX8

func BenchmarkFixedDSMWorkspaceX8(b *testing.B) {
	_, bases8, _, _ := scalarWindowBenchmarkFixtures(b)
	bases := [DSMTerms]PointX8{bases8, bases8}
	var scalars FixedDSMScalarsX8
	for term := range scalars {
		for lane := range scalars[term] {
			scalars[term][lane][0] = byte(1 + term + lane)
			scalars[term][lane][31] = 0x0f
		}
	}
	signs := [DSMTerms]uint8{0, 0xff}
	for _, radixBits := range []uint{4, 5, 6} {
		b.Run(fmt.Sprintf("radix=%d", 1<<radixBits), func(b *testing.B) {
			var workspace FixedDSMWorkspaceX8
			workspace.Prepare(&bases, radixBits)
			b.Run("prepared", func(b *testing.B) {
				b.ReportAllocs()
				var out PointX8
				for i := 0; i < b.N; i++ {
					workspace.Evaluate(&out, &scalars, &signs, 0xff)
				}
				benchmarkFixedDSMPointX8 = out
			})
			b.Run("cold", func(b *testing.B) {
				b.ReportAllocs()
				var out PointX8
				for i := 0; i < b.N; i++ {
					workspace.Prepare(&bases, radixBits)
					workspace.Evaluate(&out, &scalars, &signs, 0xff)
				}
				benchmarkFixedDSMPointX8 = out
			})
		})
	}
}
