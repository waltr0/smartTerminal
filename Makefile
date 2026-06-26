.PHONY: install install-bash install-zsh uninstall test bench doctor smoke \
        lint typecheck coverage check build publish-check clean

PYTHON ?= python3

install:
	bash install.sh

install-bash:
	bash install.sh --shell bash

install-zsh:
	bash install.sh --shell zsh

uninstall:
	bash uninstall.sh

test:
	PYTHONPATH=src $(PYTHON) -m unittest discover -s tests -v

bench:
	PYTHONPATH=src $(PYTHON) -m cybershell bench-eval --fail-on-miss

doctor:
	PYTHONPATH=src $(PYTHON) -m cybershell doctor

lint:
	ruff check src tests tools

typecheck:
	mypy

coverage:
	PYTHONPATH=src coverage run --source=src/cybershell -m unittest discover -s tests
	coverage report --fail-under=80

# Full local gate: mirrors CI (lint, types, tests, benchmark, drift, coverage).
check: lint typecheck test bench
	PYTHONPATH=src $(PYTHON) tools/baseline_snapshot.py --check
	$(MAKE) coverage

build:
	rm -rf dist build src/*.egg-info
	$(PYTHON) -m build

# Verify the built distribution before you `twine upload dist/*` yourself.
publish-check: build
	twine check dist/*

smoke: test bench
	PYTHONPATH=src $(PYTHON) -m cybershell policies
	PYTHONPATH=src $(PYTHON) -m cybershell backends
	PYTHONPATH=src $(PYTHON) -m cybershell suggest --partial "journal" --cwd .
	PYTHONPATH=src $(PYTHON) -m cybershell risk -- "cat ~/.ssh/id_rsa"

clean:
	find . -type d -name '__pycache__' -prune -exec rm -rf {} +
	find . -type d -name '*.egg-info' -prune -exec rm -rf {} +
	rm -rf build dist .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage
