# NORA — build & quality pipeline
# Usage: make check   — run all quality checks
#        make test    — unit tests only
#        make build   — release build
#        make release — tagged release (runs checks first)

CARGO := cargo

.PHONY: check test build release fmt clippy coherence lock-audit version-check install-hooks verify-changelog

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
