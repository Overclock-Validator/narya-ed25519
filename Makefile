# Narya — test and benchmark targets.
#
# Benchmarks are ordinary Go benchmarks, so they run independently of any
# consuming node and every implementation appears side by side in one run
# (stdlib vs narya-compat vs narya-strict vs narya-cached). See
# docs/performance/BENCHMARKING.md for how to read them and A/B with benchstat.

GO ?= go
BENCHTIME ?= 2s
COUNT ?= 1
PKG ?= ./...

.PHONY: test
test:
	$(GO) test $(PKG)

# The independent curve25519-voi oracle is intentionally absent from the
# library's main module graph. Its pinned comparison module is opt-in.
.PHONY: test-oasis
test-oasis:
	$(GO) test -modfile=go.oasis.mod -tags oasis_compare ./ed25519

.PHONY: fuzz
fuzz:
	$(GO) test -run x -fuzz FuzzVerifyDifferential -fuzztime 60s ./ed25519

# Full benchmark sweep. Redirect to a file to feed benchstat:
#   make bench > new.txt ; benchstat old.txt new.txt
.PHONY: bench
bench:
	$(GO) test -run '^$$' -bench . -benchmem -benchtime $(BENCHTIME) -count $(COUNT) ./...

.PHONY: bench-verify
bench-verify:
	$(GO) test -run '^$$' -bench 'BenchmarkVerify$$' -benchtime $(BENCHTIME) ./ed25519

.PHONY: bench-batch
bench-batch:
	$(GO) test -run '^$$' -bench BenchmarkVerifyBatch -benchtime $(BENCHTIME) ./ed25519

.PHONY: bench-hash
bench-hash:
	$(GO) test -run '^$$' -bench BenchmarkHash -benchtime $(BENCHTIME) ./sha512mb

.PHONY: bench-r51
bench-r51:
	$(GO) test -run '^$$' -bench . -benchmem -benchtime $(BENCHTIME) -count $(COUNT) ./internal/r51x5

.PHONY: bench-r51-pipeline
bench-r51-pipeline:
	$(GO) test -run '^$$' -bench 'BenchmarkR51IFMAPipeline/stage=cold-A/path=(stdlib|generic-strict)/n=(8|64)/msg=(64|200|1232)' -benchmem -benchtime $(BENCHTIME) -count $(COUNT) ./ed25519
	$(GO) test -run '^$$' -bench 'BenchmarkR51IFMAPipeline/stage=cold-A/path=(two-x4|x8)/radixA=(16|32|64)/fixedB=(shared|comb16|comb32|comb256)/n=(8|64)/msg=(64|200|1232)' -benchmem -benchtime $(BENCHTIME) -count $(COUNT) ./ed25519

.PHONY: bench-r51-pipeline-full
bench-r51-pipeline-full:
	$(GO) test -run '^$$' -bench '^BenchmarkR51IFMAPipeline$$' -benchmem -benchtime $(BENCHTIME) -count $(COUNT) ./ed25519

.PHONY: bench-r51-invalid
bench-r51-invalid:
	$(GO) test -run '^$$' -bench '^BenchmarkR51IFMAPipelineInvalid(Mix|Lane)$$' -benchmem -benchtime $(BENCHTIME) -count $(COUNT) ./ed25519

.PHONY: bench-heea
bench-heea:
	$(GO) test -run '^$$' -bench . -benchmem -benchtime $(BENCHTIME) -count $(COUNT) ./internal/heea8l

.PHONY: bench-heea-pipeline
bench-heea-pipeline:
	$(GO) test -run '^$$' -bench '^BenchmarkR51HEEACompletePipeline(Parallel|SelectorFallback)?$$' -benchmem -benchtime $(BENCHTIME) -count $(COUNT) ./ed25519

# Which backend the ifma benchmarks would exercise on this host.
.PHONY: backend
backend:
	@$(GO) test -run TestBackendSelection -v ./ed25519 2>/dev/null | grep -i backend || \
	 $(GO) run ./... 2>/dev/null || true

# Serialized exact-input cache diagnostic. Production-quality evidence also
# needs TRACEBENCH_ARGS='-output ... -representative -pinned-core-attested'
# plus external fixed-core execution; see docs/performance/BENCHMARKING.md.
TRACE ?=
TRACEBENCH_ARGS ?=
.PHONY: tracebench
tracebench:
	@test -n "$(TRACE)" || (echo 'set TRACE=/path/to/mithril-sigverify-v3.jsonl' >&2; exit 2)
	$(GO) run ./cmd/sigverifytracebench -input "$(TRACE)" $(TRACEBENCH_ARGS)
