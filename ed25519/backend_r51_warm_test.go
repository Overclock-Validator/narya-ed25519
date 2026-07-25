package ed25519

import (
	"fmt"
	"testing"
	"unsafe"

	"github.com/Overclock-Validator/narya/internal/r51x5"
)

func buildR51WarmGroupForTest(
	tb testing.TB,
	backend *r51Backend,
	pubs []*[32]byte,
) [r51x5.X4Lanes]*PrecomputedKey {
	tb.Helper()
	if len(pubs) != r51x5.X4Lanes {
		tb.Fatalf("warm test group width=%d", len(pubs))
	}
	var pubGroup [r51x5.X4Lanes]*[32]byte
	var decoded [r51x5.X4Lanes]*PrecomputedKey
	for lane := 0; lane < r51x5.X4Lanes; lane++ {
		pubGroup[lane] = pubs[lane]
		pre, err := backend.buildPrecomp(pubs[lane])
		if err != nil {
			tb.Fatal(err)
		}
		decoded[lane] = pre
	}
	warm, err := backend.buildWarmPrecompGroup(&pubGroup, &decoded)
	if err != nil {
		tb.Fatal(err)
	}
	return warm
}

func TestR51WarmPrecomputeShapeAndStrictDifferential(t *testing.T) {
	backend := requireR51Backend(t)
	if got, want := int64(unsafe.Sizeof(r51WarmTable{})), int64(r51WarmTableBytes); got != want {
		t.Fatalf("r51 warm table bytes=%d accounting=%d", got, want)
	}
	fixture := makeBatchFixture(t, 8, 1232)
	first := buildR51WarmGroupForTest(t, backend, fixture.pubs[:4])
	var pre [8]*PrecomputedKey
	copy(pre[:4], first[:])
	for lane := 4; lane < len(pre); lane++ {
		decoded, err := backend.buildPrecomp(fixture.pubs[lane])
		if err != nil {
			t.Fatal(err)
		}
		pre[lane] = decoded
	}

	verdicts := make([]bool, len(fixture.pubs))
	all, err := backend.verifyBatchRawPrecomputedErr(
		DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, verdicts, pre[:],
	)
	if err != nil {
		t.Fatal(err)
	}
	if !all {
		t.Fatalf("mixed warm/decoded verdicts=%v", verdicts)
	}
	for lane := range pre[:4] {
		if pre[lane].size != r51WarmTableBytes || pre[lane].raw != *fixture.pubs[lane] {
			t.Fatalf("lane=%d warm metadata size=%d raw=%x", lane, pre[lane].size, pre[lane].raw)
		}
		if _, ok := pre[lane].table.(*r51WarmTable); !ok {
			t.Fatalf("lane=%d warm table type %T", lane, pre[lane].table)
		}
	}

	mutated := append([][]byte(nil), fixture.sigs...)
	mutated[2] = append([]byte(nil), mutated[2]...)
	mutated[2][11] ^= 0x40
	all, err = backend.verifyBatchRawPrecomputedErr(
		DalekStrict, fixture.pubs, fixture.msgs, mutated, verdicts, pre[:],
	)
	if err != nil {
		t.Fatal(err)
	}
	if all {
		t.Fatal("warm group accepted an invalid equation")
	}
	for lane := range verdicts {
		want := referenceVerifyProfile(DalekStrict, fixture.pubs[lane], fixture.msgs[lane], mutated[lane])
		if verdicts[lane] != want {
			t.Fatalf("lane=%d got=%v want=%v", lane, verdicts[lane], want)
		}
	}
}

func TestR51WarmPrecomputedGroupZeroAllocations(t *testing.T) {
	backend := requireR51Backend(t)
	fixture := makeBatchFixture(t, r51x5.X4Lanes, 1232)
	pre := buildR51WarmGroupForTest(t, backend, fixture.pubs)
	verdicts := make([]bool, r51x5.X4Lanes)
	if all, err := backend.verifyBatchRawPrecomputedErr(
		DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, verdicts, pre[:],
	); err != nil || !all {
		t.Fatalf("warmup all=%v err=%v verdicts=%v", all, err, verdicts)
	}
	allocations := testing.AllocsPerRun(100, func() {
		all, err := backend.verifyBatchRawPrecomputedErr(
			DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, verdicts, pre[:],
		)
		if err != nil || !all {
			panic("r51 warm group verification failed")
		}
	})
	if allocations != 0 {
		t.Fatalf("r51 warm group allocations=%v want=0", allocations)
	}
}

func BenchmarkR51WarmPrecomputedGroup(b *testing.B) {
	backend := requireR51Backend(b)
	for _, messageSize := range []int{64, 200, 1232} {
		fixture := makeBatchFixture(b, r51x5.X4Lanes, messageSize)
		pre := buildR51WarmGroupForTest(b, backend, fixture.pubs)
		b.Run(fmt.Sprintf("n=4/msg=%d", messageSize), func(b *testing.B) {
			if all, err := backend.verifyBatchRawPrecomputedErr(
				DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok, pre[:],
			); err != nil || !all {
				b.Fatalf("warmup all=%v err=%v", all, err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				all, err := backend.verifyBatchRawPrecomputedErr(
					DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok, pre[:],
				)
				if err != nil || !all {
					b.Fatalf("verify all=%v err=%v", all, err)
				}
			}
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*r51x5.X4Lanes)/1000, "us/sig")
		})
	}
}
