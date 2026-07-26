package r51x5

import "testing"

// The per-key A tables are populated only for lanes that survive their caller's
// pre-checks. A lane carrying a malformed signature is skipped and keeps its nil
// zero value, so any code that reads the group's spec from lane 0
// unconditionally dereferences nil whenever lane 0 is the skipped one. That
// position is attacker-chosen: it is just the batch index, modulo the group
// width.
//
// This test needs no IFMA, so it runs on every host rather than only where the
// vector kernels are available.
func TestLiveHeterogeneousPartialCombSpecSkipsNilLanes(t *testing.T) {
	// Distinct specs per lane so the result identifies which lane it came from.
	specs := [X4Lanes]heterogeneousPartialCombSpecExperiment{
		{width: 4, passes: 1},
		{width: 5, passes: 2},
		{width: 6, passes: 3},
		{width: 7, passes: 4},
	}

	build := func(present [X4Lanes]bool) [X4Lanes]*heterogeneousPartialCombTableExperiment {
		var tables [X4Lanes]*heterogeneousPartialCombTableExperiment
		for lane := 0; lane < X4Lanes; lane++ {
			if present[lane] {
				tables[lane] = &heterogeneousPartialCombTableExperiment{spec: specs[lane]}
			}
		}
		return tables
	}

	// One live lane at each position, every other lane nil. Lane 0 is the case
	// that used to crash.
	for lane := 0; lane < X4Lanes; lane++ {
		var present [X4Lanes]bool
		present[lane] = true
		tables := build(present)
		got, ok := liveHeterogeneousPartialCombSpec(&tables, 1<<uint(lane))
		if !ok {
			t.Fatalf("lane %d live: ok=false", lane)
		}
		if got != specs[lane] {
			t.Fatalf("lane %d live: spec=%+v want %+v", lane, got, specs[lane])
		}
	}

	// Lanes 1..3 live with lane 0 nil: the spec must come from lane 1, and
	// reaching for lane 0 would fault.
	tables := build([X4Lanes]bool{false, true, true, true})
	got, ok := liveHeterogeneousPartialCombSpec(&tables, 0b1110)
	if !ok || got != specs[1] {
		t.Fatalf("lanes 1-3 live: spec=%+v ok=%v, want %+v", got, ok, specs[1])
	}

	// A lane that is present but not active must not be consulted: it is not
	// part of this group's verdict.
	tables = build([X4Lanes]bool{true, true, true, true})
	got, ok = liveHeterogeneousPartialCombSpec(&tables, 0b0100)
	if !ok || got != specs[2] {
		t.Fatalf("only lane 2 active: spec=%+v ok=%v, want %+v", got, ok, specs[2])
	}

	// Nothing active is an empty group, not a fault.
	tables = build([X4Lanes]bool{true, true, true, true})
	if _, ok := liveHeterogeneousPartialCombSpec(&tables, 0); ok {
		t.Fatal("empty active mask must report no spec")
	}

	// An active mask naming only nil lanes must fail closed rather than fault.
	// The production caller cannot produce this, since it sets the live bit and
	// the table together, but failing closed keeps the helper safe for any
	// future caller that separates the two.
	tables = build([X4Lanes]bool{false, false, true, false})
	if _, ok := liveHeterogeneousPartialCombSpec(&tables, 0b0011); ok {
		t.Fatal("active mask naming only nil lanes must report no spec")
	}
}
