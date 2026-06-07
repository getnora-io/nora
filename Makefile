# NORA — build & quality pipeline
# Usage: make check   — run all quality checks
#        make test    — unit tests only
#        make build   — release build
#        make release — tagged release (runs checks first)
#        make kani    — run Kani bounded-model-checking proofs (needs `cargo kani`)

CARGO := cargo

.PHONY: check test build release fmt clippy coherence lock-audit version-check install-hooks verify-changelog kani

check: version-check fmt clippy test coherence lock-audit verify-changelog
	@echo ""
	@echo "=== All checks passed ==="

fmt:
	$(CARGO) fmt --check

clippy:
	$(CARGO) clippy -- -D warnings

test:
	$(CARGO) test --lib --bin nora

coherence:
	@if [ -x scripts/coherence-check.sh ]; then scripts/coherence-check.sh; fi

lock-audit:
	@if [ -x scripts/lock-audit.sh ]; then scripts/lock-audit.sh; fi

verify-changelog:
	@if [ -x scripts/verify-changelog.sh ]; then scripts/verify-changelog.sh; fi

# Kani proofs are NOT part of `check`: they need the Kani toolchain (`cargo kani`)
# and run CBMC, which is far heavier than the unit suite. Run on demand / in the
# dedicated `kani` CI workflow. Harnesses are `#[cfg(kani)]` — invisible to the
# normal build, clippy, and tests.
kani:
	$(CARGO) kani --package nora-registry

build:
	$(CARGO) build --release

version-check:
	@scripts/pre-commit-check.sh

install-hooks:
	@scripts/install-hooks.sh

release:
ifndef VERSION
	$(error VERSION is required. Usage: make release VERSION=0.7.3)
endif
	@scripts/pre-commit-check.sh "v$(VERSION)"
	$(MAKE) check
	git tag -a "v$(VERSION)" -m "Release v$(VERSION)"
	@echo "Ready to push: git push origin v$(VERSION)"
