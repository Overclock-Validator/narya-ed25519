# Narya — test and benchmark targets.
#
# Benchmarks are ordinary Go benchmarks, so they run independently of any
# consuming node and every implementation appears side by side in one run
# (stdlib vs narya-compat vs narya-strict vs narya-cached). See
# docs/BENCHMARKING.md for how to read them and how to A/B with benchstat.

GO ?= go
BENCHTIME ?= 2s
COUNT ?= 1
PKG ?= ./...

.PHONY: test
test:
	$(GO) test $(PKG)

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

# Which backend the ifma benchmarks would exercise on this host.
.PHONY: backend
backend:
	@$(GO) test -run TestBackendSelection -v ./ed25519 2>/dev/null | grep -i backend || \
	 $(GO) run ./... 2>/dev/null || true
