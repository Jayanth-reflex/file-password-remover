# File Password Remover -- developer entry points.
#
# Every target here is exactly what CI runs, so a green `make check` locally
# means a green pipeline. If that stops being true, the Makefile is the bug.

PYTHON  ?= python3
VENV    ?= .venv
BIN     := $(VENV)/bin
ARTIFACTS := artifacts

.DEFAULT_GOAL := help
.PHONY: help venv install lint format typecheck test test-all test-slow security audit \
        check build bundle checksums clean docs-check evidence

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

venv: ## Create the virtualenv
	$(PYTHON) -m venv $(VENV)

install: ## Install the package and all developer tooling
	$(BIN)/python -m pip install --upgrade pip
	$(BIN)/python -m pip install -e ".[dev,sevenzip,build]"

lint: ## ruff check + format check
	$(BIN)/ruff check .
	$(BIN)/ruff format --check .

format: ## Apply ruff's formatter and safe fixes
	$(BIN)/ruff check --fix .
	$(BIN)/ruff format .

typecheck: ## mypy --strict over src/
	$(BIN)/mypy

test: ## Fast test suite (no slow performance tests)
	$(BIN)/python -m pytest -q -m "not slow"

test-all: ## Everything, with coverage
	mkdir -p $(ARTIFACTS)
	$(BIN)/python -m pytest -q --cov=fpr --cov=fpr_gui \
	  --cov-report=term:skip-covered \
	  --cov-report=xml:$(ARTIFACTS)/coverage.xml \
	  --cov-report=html:$(ARTIFACTS)/htmlcov

test-slow: ## Only the performance tests
	$(BIN)/python -m pytest -q -m slow

security: ## bandit static analysis
	mkdir -p $(ARTIFACTS)
	$(BIN)/bandit -q -c pyproject.toml -r src -f json -o $(ARTIFACTS)/bandit.json
	$(BIN)/bandit -q -c pyproject.toml -r src

audit: ## Dependency vulnerability audit
	mkdir -p $(ARTIFACTS)
	$(BIN)/pip-audit --progress-spinner off

evidence: ## Refresh dependency licence/advisory evidence (needs network)
	$(BIN)/python scripts/audit_dependencies.py

check: lint typecheck test-all security audit ## Everything CI runs
	@echo "all gates passed"

build: ## Build the wheel and sdist
	$(BIN)/python -m pip install --quiet build
	$(BIN)/python -m build --outdir dist

bundle: ## Build the standalone desktop/CLI bundle for this platform
	bash scripts/build_desktop.sh

checksums: ## SHA-256 for everything in dist/
	bash scripts/checksums.sh

docs-check: ## Verify the docs' internal links resolve
	$(BIN)/python scripts/check_docs.py

clean:
	rm -rf build dist $(ARTIFACTS) .pytest_cache .mypy_cache .ruff_cache \
	       .coverage htmlcov src/*.egg-info
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
