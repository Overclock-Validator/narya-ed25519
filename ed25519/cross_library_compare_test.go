//go:build oasis_compare

package ed25519

import (
	stded25519 "crypto/ed25519"
	"crypto/rand"
	"fmt"
	"testing"

	oasised25519 "github.com/oasisprotocol/curve25519-voi/primitives/ed25519"
)

// This matrix deliberately uses ordinary, per-signature verification for the
// comparison libraries. curve25519-voi's aggregate BatchVerifier cannot
// implement the cofactorless DalekStrict predicate, so including it here would
// compare a different acceptance equation. Every candidate writes one verdict
// per input and the harness consumes those verdicts after the timed loop.

var crossLibraryComparisonResult bool

func makeCrossLibrarySameMessageFixture(tb testing.TB, count, messageSize int) batchFixture {
	tb.Helper()

	message := make([]byte, messageSize)
	if _, err := rand.Read(message); err != nil {
		tb.Fatal(err)
	}
	fixture := batchFixture{
		fs:   make([]sigFixture, count),
		pubs: make([]*[32]byte, count),
		msgs: make([][]byte, count),
		sigs: make([][]byte, count),
		ok:   make([]bool, count),
	}
	for index := range fixture.fs {
		publicKey, privateKey, err := stded25519.GenerateKey(rand.Reader)
		if err != nil {
			tb.Fatal(err)
		}
		entry := &fixture.fs[index]
		entry.pubk = publicKey
		copy(entry.pub[:], publicKey)
		entry.msg = message
		entry.sig = stded25519.Sign(privateKey, message)
		fixture.pubs[index] = &entry.pub
		fixture.msgs[index] = entry.msg
		fixture.sigs[index] = entry.sig
	}
	return fixture
}

func benchmarkCrossLibraryCandidate(
	b *testing.B,
	count int,
	verdicts []bool,
	verify func() (bool, error),
) {
	b.Helper()

	assertVerdicts := func(all bool, err error) {
		b.Helper()
		if err != nil {
			b.Fatal(err)
		}
		if !all {
			b.Fatal("candidate rejected an honest comparison fixture")
		}
		for lane, accepted := range verdicts {
			if !accepted {
				b.Fatalf("candidate rejected honest lane %d", lane)
			}
		}
	}

	// Check the candidate and ensure every per-lane result is materialized
	// before measuring it. ResetTimer excludes this preflight from both time
	// and allocation accounting.
	assertVerdicts(verify())
	b.ReportAllocs()
	b.ResetTimer()
	var result bool
	var err error
	for iteration := 0; iteration < b.N; iteration++ {
		result, err = verify()
		if err != nil {
			break
		}
	}
	b.StopTimer()
	assertVerdicts(result, err)
	crossLibraryComparisonResult = result && verdicts[len(verdicts)-1]
	elapsed := b.Elapsed()
	b.ReportMetric(float64(elapsed.Nanoseconds())/float64(b.N*count)/1000, "µs/sig")
	b.ReportMetric(float64(b.N*count)/elapsed.Seconds(), "sig/s")
}

func benchmarkCrossLibraryFixture(b *testing.B, mode string, fixture *batchFixture) {
	b.Helper()

	count := len(fixture.pubs)
	expanded := prepareOasisExpandedPublicKeys(fixture.pubs)
	for lane, key := range expanded {
		if key == nil {
			b.Fatalf("expand honest Oasis public key at lane %d", lane)
		}
	}

	run := func(implementation string, verify func() (bool, error)) {
		b.Run(fmt.Sprintf("mode=%s/impl=%s/n=%d/msg=%d", mode, implementation, count, len(fixture.msgs[0])), func(b *testing.B) {
			benchmarkCrossLibraryCandidate(b, count, fixture.ok, verify)
		})
	}

	if r51IFMAPipelineAvailable(r51IFMATwoX4) {
		// Cold arbitrary-key Narya candidate. This is the exact private
		// pipeline whose complete-path measurements currently establish the
		// r51 headline; it is intentionally separate from public automatic
		// backend selection.
		r51Cold := requireR51IFMABatchQPipeline(b)
		run("narya-r51-cold", func() (bool, error) {
			return r51Cold.VerifyBatch(DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok)
		})

		// Prepared-A is a recurrence upper bound analogous to an expanded
		// public key: exact-key point decoding happens before timing, while
		// challenge hashing and the complete variable-base table/DSM remain
		// paid.
		decodedStorage, decodedEntries := makeR51DecodedAEntries(b, fixture.pubs, func(int) bool { return true })
		_ = decodedStorage // Entries retain pointers into this storage.
		r51Prepared := requireR51IFMABatchQPipeline(b)
		run("narya-r51-prepared-A", func() (bool, error) {
			return r51Prepared.verifyBatchWithDecodedA(
				DalekStrict,
				fixture.pubs,
				fixture.msgs,
				fixture.sigs,
				fixture.ok,
				decodedEntries,
			)
		})
	}

	generic := genericBackend{}
	run("narya-generic-strict", func() (bool, error) {
		return verifyBatch(generic, DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok, nil), nil
	})

	run("go-stdlib-loop", func() (bool, error) {
		all := true
		for lane := range fixture.pubs {
			accepted := stded25519.Verify(fixture.pubs[lane][:], fixture.msgs[lane], fixture.sigs[lane])
			fixture.ok[lane] = accepted
			all = all && accepted
		}
		return all, nil
	})

	run("oasis-strict-cold-loop", func() (bool, error) {
		all := true
		for lane := range fixture.pubs {
			accepted := oasised25519.VerifyWithOptions(
				fixture.pubs[lane][:],
				fixture.msgs[lane],
				fixture.sigs[lane],
				oasisDalekStrictOptions,
			)
			fixture.ok[lane] = accepted
			all = all && accepted
		}
		return all, nil
	})

	run("oasis-strict-expanded-loop", func() (bool, error) {
		all := true
		for lane := range fixture.pubs {
			accepted := oasised25519.VerifyExpandedWithOptions(
				expanded[lane],
				fixture.msgs[lane],
				fixture.sigs[lane],
				oasisDalekStrictOptions,
			)
			fixture.ok[lane] = accepted
			all = all && accepted
		}
		return all, nil
	})
}

// BenchmarkEd25519CrossLibrary compares complete verification using honest,
// canonical signatures and distinct public keys. "independent" models a
// queue spanning transactions. "same-message" models multiple signers on one
// transaction; it is also the only workload shape accepted by Firedancer's
// specialized batch API, so these rows are the bridge to its C benchmark.
//
// All rows are serial and should be run pinned with GOMAXPROCS=1. The n=1 row
// intentionally exposes r51 lane underfill rather than hiding it behind a
// dispatcher. n=17 exposes the first post-16 chunk/tail boundary.
func BenchmarkEd25519CrossLibrary(b *testing.B) {
	// Keep the dense singleton-to-first-full-group region: the r51 x4
	// dispatch crossover against serial implementations lies between n=1
	// and n=4. The later values expose x4 fill, common transaction signature
	// counts, and the first post-16 tail.
	counts := []int{1, 2, 3, 4, 5, 8, 9, 12, 16, 17, 32, 64}
	for _, messageSize := range []int{64, 200, 1232} {
		for _, count := range counts {
			fixture := makeBatchFixture(b, count, messageSize)
			benchmarkCrossLibraryFixture(b, "independent", &fixture)
		}
	}

	for _, count := range counts {
		fixture := makeCrossLibrarySameMessageFixture(b, count, 200)
		benchmarkCrossLibraryFixture(b, "same-message", &fixture)
	}
}

func makeCrossLibraryGenericPrecomputed(
	tb testing.TB,
	pubs []*[32]byte,
	build func(*[32]byte) (*PrecomputedKey, error),
) ([]*PrecomputedKey, int64) {
	tb.Helper()
	precomputed := make([]*PrecomputedKey, len(pubs))
	var tableBytes int64
	for lane, pub := range pubs {
		var err error
		precomputed[lane], err = build(pub)
		if err != nil {
			tb.Fatalf("precompute honest public key at lane %d: %v", lane, err)
		}
		if precomputed[lane] == nil {
			tb.Fatalf("precompute honest public key at lane %d returned nil", lane)
		}
		if lane == 0 {
			tableBytes = precomputed[lane].size
		} else if precomputed[lane].size != tableBytes {
			tb.Fatalf("precomputed table size at lane %d is %d, want %d", lane, precomputed[lane].size, tableBytes)
		}
	}
	return precomputed, tableBytes
}

func verifyCrossLibraryGenericLoop(
	backend genericBackend,
	fixture *batchFixture,
	precomputed []*PrecomputedKey,
) bool {
	all := true
	for lane := range fixture.pubs {
		var pre *PrecomputedKey
		if precomputed != nil {
			pre = precomputed[lane]
		}
		accepted := verifyOne(
			backend,
			DalekStrict,
			fixture.pubs[lane],
			fixture.msgs[lane],
			fixture.sigs[lane],
			pre,
		)
		fixture.ok[lane] = accepted
		all = all && accepted
	}
	return all
}

func benchmarkCrossLibraryPreparedFixture(b *testing.B, fixture *batchFixture) {
	b.Helper()

	count := len(fixture.pubs)
	generic := genericBackend{}
	compact, compactBytes := makeCrossLibraryGenericPrecomputed(b, fixture.pubs, generic.buildCompactPrecomp)
	hot, hotBytes := makeCrossLibraryGenericPrecomputed(b, fixture.pubs, generic.buildPrecomp)
	expanded := prepareOasisExpandedPublicKeys(fixture.pubs)
	for lane, key := range expanded {
		if key == nil {
			b.Fatalf("expand honest Oasis public key at lane %d", lane)
		}
	}

	run := func(implementation string, tableBytes int64, verify func() (bool, error)) {
		b.Run(fmt.Sprintf("mode=independent/impl=%s/n=%d/msg=200", implementation, count), func(b *testing.B) {
			benchmarkCrossLibraryCandidate(b, count, fixture.ok, verify)
			if tableBytes >= 0 {
				b.ReportMetric(float64(tableBytes), "table-bytes/key")
			}
		})
	}

	if r51IFMAPipelineAvailable(r51IFMATwoX4) {
		r51Cold := requireR51IFMABatchQPipeline(b)
		run("narya-r51-cold", 0, func() (bool, error) {
			return r51Cold.VerifyBatch(DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok)
		})

		decodedStorage, decodedEntries := makeR51DecodedAEntries(b, fixture.pubs, func(int) bool { return true })
		_ = decodedStorage
		r51Prepared := requireR51IFMABatchQPipeline(b)
		run("narya-r51-prepared-A", -1, func() (bool, error) {
			return r51Prepared.verifyBatchWithDecodedA(
				DalekStrict,
				fixture.pubs,
				fixture.msgs,
				fixture.sigs,
				fixture.ok,
				decodedEntries,
			)
		})
	}

	run("narya-generic-cold-loop", 0, func() (bool, error) {
		return verifyCrossLibraryGenericLoop(generic, fixture, nil), nil
	})
	run("narya-generic-compact-naf-loop", compactBytes, func() (bool, error) {
		return verifyCrossLibraryGenericLoop(generic, fixture, compact), nil
	})
	run("narya-generic-hot-comb-loop", hotBytes, func() (bool, error) {
		return verifyCrossLibraryGenericLoop(generic, fixture, hot), nil
	})
	run("go-stdlib-loop", 0, func() (bool, error) {
		all := true
		for lane := range fixture.pubs {
			accepted := stded25519.Verify(fixture.pubs[lane][:], fixture.msgs[lane], fixture.sigs[lane])
			fixture.ok[lane] = accepted
			all = all && accepted
		}
		return all, nil
	})
	run("oasis-strict-cold-loop", 0, func() (bool, error) {
		all := true
		for lane := range fixture.pubs {
			accepted := oasised25519.VerifyWithOptions(
				fixture.pubs[lane][:],
				fixture.msgs[lane],
				fixture.sigs[lane],
				oasisDalekStrictOptions,
			)
			fixture.ok[lane] = accepted
			all = all && accepted
		}
		return all, nil
	})
	run("oasis-strict-expanded-loop", -1, func() (bool, error) {
		all := true
		for lane := range fixture.pubs {
			accepted := oasised25519.VerifyExpandedWithOptions(
				expanded[lane],
				fixture.msgs[lane],
				fixture.sigs[lane],
				oasisDalekStrictOptions,
			)
			fixture.ok[lane] = accepted
			all = all && accepted
		}
		return all, nil
	})
}

// BenchmarkEd25519CrossLibraryPreparedTiers bounds the warm-key comparison
// to the transaction-shaped 200-byte message and representative widths around
// the singleton-to-full-x4 dispatch crossover plus the n=8/64 throughput cases.
// Every expansion/table build happens before the sub-benchmark timer starts.
// table-bytes/key is the complete Narya PrecomputedKey payload size. The metric
// is omitted for prepared representations whose complete transitive footprint
// is not exposed by their API, rather than reporting a misleading shallow size.
func BenchmarkEd25519CrossLibraryPreparedTiers(b *testing.B) {
	for _, count := range []int{1, 2, 3, 4, 8, 64} {
		fixture := makeBatchFixture(b, count, 200)
		benchmarkCrossLibraryPreparedFixture(b, &fixture)
	}
}

var crossLibraryScalarOrder = [32]byte{
	0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
	0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
}

func makeCrossLibraryInvalidFixture(tb testing.TB, count int, invalidKind string) batchFixture {
	tb.Helper()
	fixture := makeBatchFixture(tb, count, 200)
	for lane := range fixture.pubs {
		switch invalidKind {
		case "noncanonical-S-early":
			signature := append([]byte(nil), fixture.sigs[lane]...)
			copy(signature[32:], crossLibraryScalarOrder[:])
			fixture.sigs[lane] = signature
		case "bad-message-late":
			message := append([]byte(nil), fixture.msgs[lane]...)
			message[0] ^= 0x80
			fixture.msgs[lane] = message
		default:
			tb.Fatalf("unknown invalid comparison fixture %q", invalidKind)
		}
	}
	return fixture
}

func benchmarkCrossLibraryRejectCandidate(
	b *testing.B,
	count int,
	verdicts []bool,
	verify func() (bool, error),
) {
	b.Helper()

	assertRejected := func(all bool, err error) {
		b.Helper()
		if err != nil {
			b.Fatal(err)
		}
		if all {
			b.Fatal("candidate accepted an all-invalid comparison fixture")
		}
		for lane, accepted := range verdicts {
			if accepted {
				b.Fatalf("candidate accepted invalid lane %d", lane)
			}
		}
	}

	assertRejected(verify())
	b.ReportAllocs()
	b.ResetTimer()
	var result bool
	var err error
	for iteration := 0; iteration < b.N; iteration++ {
		// No common-contract candidate may stop after observing an earlier
		// rejected lane. Each closure below invokes its verifier for every
		// lane, or uses Narya's per-lane batch API which writes the full mask.
		result, err = verify()
		if err != nil {
			break
		}
	}
	b.StopTimer()
	assertRejected(result, err)
	crossLibraryComparisonResult = !result && !verdicts[len(verdicts)-1]
	elapsed := b.Elapsed()
	b.ReportMetric(float64(elapsed.Nanoseconds())/float64(b.N*count)/1000, "µs/sig")
	b.ReportMetric(float64(b.N*count)/elapsed.Seconds(), "sig/s")
}

func benchmarkCrossLibraryInvalidFixture(b *testing.B, invalidKind string, fixture *batchFixture) {
	b.Helper()

	count := len(fixture.pubs)
	generic := genericBackend{}
	compact, compactBytes := makeCrossLibraryGenericPrecomputed(b, fixture.pubs, generic.buildCompactPrecomp)
	hot, hotBytes := makeCrossLibraryGenericPrecomputed(b, fixture.pubs, generic.buildPrecomp)
	expanded := prepareOasisExpandedPublicKeys(fixture.pubs)
	for lane, key := range expanded {
		if key == nil {
			b.Fatalf("expand honest Oasis public key at lane %d", lane)
		}
	}

	run := func(implementation string, tableBytes int64, verify func() (bool, error)) {
		b.Run(fmt.Sprintf("invalid=%s/impl=%s/n=%d/msg=200", invalidKind, implementation, count), func(b *testing.B) {
			benchmarkCrossLibraryRejectCandidate(b, count, fixture.ok, verify)
			if tableBytes >= 0 {
				b.ReportMetric(float64(tableBytes), "table-bytes/key")
			}
		})
	}

	if r51IFMAPipelineAvailable(r51IFMATwoX4) {
		r51Cold := requireR51IFMABatchQPipeline(b)
		run("narya-r51-cold", 0, func() (bool, error) {
			return r51Cold.VerifyBatch(DalekStrict, fixture.pubs, fixture.msgs, fixture.sigs, fixture.ok)
		})

		decodedStorage, decodedEntries := makeR51DecodedAEntries(b, fixture.pubs, func(int) bool { return true })
		_ = decodedStorage
		r51Prepared := requireR51IFMABatchQPipeline(b)
		run("narya-r51-prepared-A", -1, func() (bool, error) {
			return r51Prepared.verifyBatchWithDecodedA(
				DalekStrict,
				fixture.pubs,
				fixture.msgs,
				fixture.sigs,
				fixture.ok,
				decodedEntries,
			)
		})
	}

	run("narya-generic-cold-loop", 0, func() (bool, error) {
		return verifyCrossLibraryGenericLoop(generic, fixture, nil), nil
	})
	run("narya-generic-compact-naf-loop", compactBytes, func() (bool, error) {
		return verifyCrossLibraryGenericLoop(generic, fixture, compact), nil
	})
	run("narya-generic-hot-comb-loop", hotBytes, func() (bool, error) {
		return verifyCrossLibraryGenericLoop(generic, fixture, hot), nil
	})
	run("go-stdlib-loop", 0, func() (bool, error) {
		all := true
		for lane := range fixture.pubs {
			accepted := stded25519.Verify(fixture.pubs[lane][:], fixture.msgs[lane], fixture.sigs[lane])
			fixture.ok[lane] = accepted
			all = all && accepted
		}
		return all, nil
	})
	run("oasis-strict-cold-loop", 0, func() (bool, error) {
		all := true
		for lane := range fixture.pubs {
			accepted := oasised25519.VerifyWithOptions(
				fixture.pubs[lane][:],
				fixture.msgs[lane],
				fixture.sigs[lane],
				oasisDalekStrictOptions,
			)
			fixture.ok[lane] = accepted
			all = all && accepted
		}
		return all, nil
	})
	run("oasis-strict-expanded-loop", -1, func() (bool, error) {
		all := true
		for lane := range fixture.pubs {
			accepted := oasised25519.VerifyExpandedWithOptions(
				expanded[lane],
				fixture.msgs[lane],
				fixture.sigs[lane],
				oasisDalekStrictOptions,
			)
			fixture.ok[lane] = accepted
			all = all && accepted
		}
		return all, nil
	})
}

// BenchmarkEd25519CrossLibraryInvalid covers two universally rejected input
// classes without relying on incompatible edge-case semantics: S==L fails the
// canonical scalar gate, while a message mutation reaches the full equation.
// Unlike native aggregate/early-break APIs, every comparison row materializes
// a verdict for every lane, so invalid position cannot shorten the batch.
func BenchmarkEd25519CrossLibraryInvalid(b *testing.B) {
	for _, invalidKind := range []string{"noncanonical-S-early", "bad-message-late"} {
		for _, count := range []int{1, 8, 64} {
			fixture := makeCrossLibraryInvalidFixture(b, count, invalidKind)
			benchmarkCrossLibraryInvalidFixture(b, invalidKind, &fixture)
		}
	}
}
