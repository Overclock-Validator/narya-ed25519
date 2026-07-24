package ed25519

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

// cacheProbeBackend makes cache policy observable without depending on the
// process-wide backend selection. Its verifier deliberately rejects malformed
// signatures after cache lookup, matching the ordering of Cache.Verify.
type cacheProbeBackend struct {
	supported bool
	tableSize int64
	builds    atomic.Int64
	build     func(*[32]byte) (*PrecomputedKey, error)
}

func (*cacheProbeBackend) name() string { return "cache-probe" }

func (b *cacheProbeBackend) supportsPrecomp() bool { return b.supported }

func (*cacheProbeBackend) verify(_ Profile, _ *[32]byte, _ []byte, sig []byte, _ *PrecomputedKey) bool {
	return len(sig) == 64
}

func (b *cacheProbeBackend) verifyBatch(profile Profile, items []batchItem) {
	for i := range items {
		if !items[i].skip {
			items[i].ok = b.verify(profile, items[i].pub, items[i].msg, items[i].sig, items[i].pre)
		}
	}
}

func (b *cacheProbeBackend) buildPrecomp(pub *[32]byte) (*PrecomputedKey, error) {
	b.builds.Add(1)
	if b.build != nil {
		return b.build(pub)
	}
	return &PrecomputedKey{raw: *pub, table: new(byte), size: b.tableSize}, nil
}

func probeVerify(c *Cache, b backend, pub *[32]byte, msg, sig []byte) bool {
	pre := c.lookup(pub)
	ok := b.verify(StdlibCompat, pub, msg, sig, pre)
	if ok && pre == nil {
		c.admit(b, pub)
	}
	return ok
}

func probeVerifyBatch(c *Cache, b backend, pubs []*[32]byte, msgs, sigs [][]byte, ok []bool) bool {
	all := verifyBatch(b, StdlibCompat, pubs, msgs, sigs, ok, c.lookup)
	for i := range ok {
		if ok[i] {
			c.admit(b, pubs[i])
		}
	}
	return all
}

func TestCacheInvalidSignaturesDoNotEarnAdmission(t *testing.T) {
	b := &cacheProbeBackend{supported: true, tableSize: 64}
	c := &Cache{MaxTableBytes: 64}
	pub := &[32]byte{0x42}
	msg := []byte("malformed")
	badSig := []byte{0x01} // wrong length, rejected by the backend
	goodSig := make([]byte, 64)

	for i := 0; i < 4*buildThreshold; i++ {
		if probeVerify(c, b, pub, msg, badSig) {
			t.Fatalf("malformed signature accepted at attempt %d", i+1)
		}
	}
	if got := c.Stats(); got.Tables != 0 || got.TableBytes != 0 || got.Misses != 4*buildThreshold {
		t.Fatalf("invalid attempts affected admission: %+v", got)
	}
	if got := c.seenCount.Load(); got != 0 {
		t.Fatalf("invalid attempts created %d admission entries", got)
	}
	if got := b.builds.Load(); got != 0 {
		t.Fatalf("invalid attempts triggered %d builds", got)
	}

	for i := 1; i < buildThreshold; i++ {
		if !probeVerify(c, b, pub, msg, goodSig) {
			t.Fatalf("valid signature rejected at sighting %d", i)
		}
	}
	// An invalid attempt between successful sightings must not cross the
	// threshold.
	if probeVerify(c, b, pub, msg, badSig) {
		t.Fatal("interleaved malformed signature accepted")
	}
	if got := b.builds.Load(); got != 0 {
		t.Fatalf("interleaved invalid attempt triggered %d builds", got)
	}
	if !probeVerify(c, b, pub, msg, goodSig) {
		t.Fatal("threshold signature rejected")
	}
	if got := c.Stats(); got.Tables != 1 || got.TableBytes != 64 {
		t.Fatalf("successful threshold admission = %+v", got)
	}
	if got := b.builds.Load(); got != 1 {
		t.Fatalf("successful threshold builds = %d, want 1", got)
	}

	// Existing tables are still looked up before verification, even when the
	// signature is then rejected.
	if probeVerify(c, b, pub, msg, badSig) {
		t.Fatal("malformed signature accepted on table hit")
	}
	if got := c.Stats(); got.Hits != 1 {
		t.Fatalf("invalid verification did not observe existing table: %+v", got)
	}
}

func TestCachePublicAPIsAdmitOnlyValidEquations(t *testing.T) {
	f := makeFixture(t, 64)
	c := &Cache{}
	badMsg := append([]byte(nil), f.msg...)
	badMsg[0] ^= 1 // structurally valid inputs, wrong verification equation

	for i := 0; i < 2*buildThreshold; i++ {
		if c.Verify(&f.pub, badMsg, f.sig) {
			t.Fatalf("single invalid equation accepted at attempt %d", i+1)
		}
		ok := []bool{true}
		if c.VerifyBatch([]*[32]byte{&f.pub}, [][]byte{badMsg}, [][]byte{f.sig}, ok) || ok[0] {
			t.Fatalf("batch invalid equation accepted at attempt %d", i+1)
		}
	}
	if got := c.seenCount.Load(); got != 0 {
		t.Fatalf("public invalid-equation paths created %d admission entries", got)
	}
	if got := c.Stats(); got.Tables != 0 || got.TableBytes != 0 {
		t.Fatalf("public invalid-equation paths affected admission: %+v", got)
	}

	for i := 1; i <= buildThreshold; i++ {
		if !c.Verify(&f.pub, f.msg, f.sig) {
			t.Fatalf("valid signature rejected at sighting %d", i)
		}
	}
	if got := c.Stats(); got.Tables != 1 || got.TableBytes != genericTableBytes {
		t.Fatalf("public successful threshold admission = %+v", got)
	}
}

func TestCacheBatchAdmitsOnlySuccessfulItems(t *testing.T) {
	b := &cacheProbeBackend{supported: true, tableSize: 64}
	c := &Cache{MaxTableBytes: 64}
	pub := &[32]byte{0x43}
	pubs := make([]*[32]byte, buildThreshold)
	msgs := make([][]byte, buildThreshold)
	sigs := make([][]byte, buildThreshold)
	ok := make([]bool, buildThreshold)
	for i := range pubs {
		pubs[i] = pub
		msgs[i] = []byte("batch")
		sigs[i] = []byte{byte(i)}
	}
	if probeVerifyBatch(c, b, pubs, msgs, sigs, ok) {
		t.Fatal("all-invalid batch reported success")
	}
	if got := c.seenCount.Load(); got != 0 {
		t.Fatalf("invalid batch created %d admission entries", got)
	}
	if got := b.builds.Load(); got != 0 {
		t.Fatalf("invalid batch triggered %d builds", got)
	}

	for i := range sigs {
		sigs[i] = make([]byte, 64)
	}
	if !probeVerifyBatch(c, b, pubs, msgs, sigs, ok) {
		t.Fatal("all-valid batch reported failure")
	}
	if got := c.Stats(); got.Tables != 1 || got.TableBytes != 64 {
		t.Fatalf("valid batch admission = %+v", got)
	}
	if got := b.builds.Load(); got != 1 {
		t.Fatalf("valid batch builds = %d, want 1", got)
	}
}

func TestCacheNoTableBackendNeverBuilds(t *testing.T) {
	b := &cacheProbeBackend{supported: false, tableSize: 64}
	c := &Cache{}
	pub := &[32]byte{0x44}
	sig := make([]byte, 64)

	for i := 0; i < 4*buildThreshold; i++ {
		if !probeVerify(c, b, pub, nil, sig) {
			t.Fatal("probe verifier rejected a well-formed signature")
		}
	}
	if got := b.builds.Load(); got != 0 {
		t.Fatalf("no-table backend buildPrecomp calls = %d, want 0", got)
	}
	if got := c.Stats(); got.Tables != 0 || got.TableBytes != 0 || got.Misses != 4*buildThreshold {
		t.Fatalf("no-table stats = %+v", got)
	}
}

func TestCacheMalformedKeyBuildFailureIsRemembered(t *testing.T) {
	b := &cacheProbeBackend{
		supported: true,
		tableSize: 64,
		build: func(*[32]byte) (*PrecomputedKey, error) {
			return nil, errors.New("invalid compressed point")
		},
	}
	c := &Cache{}
	pub := &[32]byte{0x45}
	sig := make([]byte, 64)

	for i := 0; i < 4*buildThreshold; i++ {
		if !probeVerify(c, b, pub, nil, sig) {
			t.Fatal("probe verifier rejected a well-formed signature")
		}
	}
	if got := b.builds.Load(); got != 1 {
		t.Fatalf("malformed-key build attempts = %d, want 1", got)
	}
	if got := c.Stats(); got.Tables != 0 || got.TableBytes != 0 {
		t.Fatalf("malformed-key stats = %+v", got)
	}
}

func TestCacheMaxTableBytesStrictUnderConcurrency(t *testing.T) {
	const (
		keys      = 24
		tableSize = int64(64)
		maxTables = int64(5)
	)
	var builders sync.WaitGroup
	builders.Add(keys)
	release := make(chan struct{})
	b := &cacheProbeBackend{
		supported: true,
		tableSize: tableSize,
		build: func(pub *[32]byte) (*PrecomputedKey, error) {
			builders.Done()
			<-release
			return &PrecomputedKey{raw: *pub, table: new(byte), size: tableSize}, nil
		},
	}
	max := maxTables*tableSize + tableSize/2
	c := &Cache{MaxTableBytes: max}
	pubs := make([][32]byte, keys)
	for i := range pubs {
		pubs[i][0] = byte(i + 1)
		pubs[i][31] = 0x11
		for sighting := 1; sighting < buildThreshold; sighting++ {
			c.admit(b, &pubs[i])
		}
	}

	var calls sync.WaitGroup
	calls.Add(keys)
	for i := range pubs {
		go func(pub *[32]byte) {
			defer calls.Done()
			c.admit(b, pub)
		}(&pubs[i])
	}
	builders.Wait() // make every build pass the old racy pre-build budget check
	close(release)
	calls.Wait()

	got := c.Stats()
	if got.TableBytes > max {
		t.Fatalf("table bytes %d exceeded MaxTableBytes %d", got.TableBytes, max)
	}
	if got.Tables != maxTables || got.TableBytes != maxTables*tableSize {
		t.Fatalf("concurrent admission = %+v, want %d tables/%d bytes", got, maxTables, maxTables*tableSize)
	}
	if builds := b.builds.Load(); builds != keys {
		t.Fatalf("builds = %d, want %d concurrent candidates", builds, keys)
	}
}

func TestCacheRejectsTableLargerThanBudget(t *testing.T) {
	b := &cacheProbeBackend{supported: true, tableSize: 65}
	c := &Cache{MaxTableBytes: 64}
	pub := &[32]byte{0x46}
	for i := 0; i < buildThreshold+4; i++ {
		c.admit(b, pub)
	}
	if got := c.Stats(); got.Tables != 0 || got.TableBytes != 0 {
		t.Fatalf("oversized table admitted: %+v", got)
	}
	if got := b.builds.Load(); got != 1 {
		t.Fatalf("oversized table builds = %d, want 1", got)
	}
}

func TestCacheAdmissionEntryLimitPreservesExistingState(t *testing.T) {
	c := &Cache{}
	disabledPub := &[32]byte{0x47}
	disabled := new(atomic.Int32)
	disabled.Store(admissionDisabled)
	c.seen.Store(*disabledPub, disabled)
	c.seenCount.Store(admissionEntryLimit)

	if got, ok := c.admissionCounter(disabledPub); !ok || got != disabled {
		t.Fatal("entry limit detached an existing disabled counter")
	}
	if claimAdmissionBuild(disabled) {
		t.Fatal("disabled counter granted a build")
	}
	if _, ok := c.admissionCounter(&[32]byte{0x48}); ok {
		t.Fatal("entry limit admitted a previously unseen key")
	}
	if got := c.seenCount.Load(); got != admissionEntryLimit {
		t.Fatalf("admission entry count = %d, want %d", got, admissionEntryLimit)
	}
	if got, ok := c.seen.Load(*disabledPub); !ok || got != disabled {
		t.Fatal("entry limit erased existing disabled state")
	}
}

func TestCacheSingleBuilderPerKey(t *testing.T) {
	const goroutines = 32
	started := make(chan struct{})
	release := make(chan struct{})
	b := &cacheProbeBackend{
		supported: true,
		tableSize: 64,
		build: func(pub *[32]byte) (*PrecomputedKey, error) {
			close(started)
			<-release
			return &PrecomputedKey{raw: *pub, table: new(byte), size: 64}, nil
		},
	}
	c := &Cache{MaxTableBytes: 64}
	pub := &[32]byte{0x49}
	for i := 1; i < buildThreshold; i++ {
		c.admit(b, pub)
	}

	var calls sync.WaitGroup
	calls.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer calls.Done()
			c.admit(b, pub)
		}()
	}
	<-started
	close(release)
	calls.Wait()

	if got := b.builds.Load(); got != 1 {
		t.Fatalf("concurrent same-key builds = %d, want 1", got)
	}
	if got := c.Stats(); got.Tables != 1 || got.TableBytes != 64 {
		t.Fatalf("concurrent same-key admission = %+v", got)
	}
}
