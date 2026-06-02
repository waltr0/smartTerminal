.PHONY: install install-bash install-zsh uninstall test bench doctor smoke clean

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

smoke: test bench
	PYTHONPATH=src $(PYTHON) -m cybershell policies
	PYTHONPATH=src $(PYTHON) -m cybershell backends
	PYTHONPATH=src $(PYTHON) -m cybershell suggest --partial "journal" --cwd .
	PYTHONPATH=src $(PYTHON) -m cybershell risk -- "cat ~/.ssh/id_rsa"

clean:
	find . -type d -name '__pycache__' -prune -exec rm -rf {} +
	find . -type d -name '*.egg-info' -prune -exec rm -rf {} +
	rm -rf build dist .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage
