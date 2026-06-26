# Release Checklist

## 1. Quality gate (mirrors CI)

```bash
make check        # ruff + mypy + tests + benchmark + drift + coverage
# or individually:
ruff check src tests tools
mypy
python -m unittest discover -s tests -v
cybershell bench-eval --fail-on-miss
python tools/baseline_snapshot.py --check
coverage run --source=src/cybershell -m unittest discover -s tests && coverage report --fail-under=80
```

## 2. Version and changelog

- Bump `__version__` in `src/cybershell/__init__.py` (semantic versioning). The
  packaged metadata and `cybershell --version` read from it automatically.
- Add a dated section to `CHANGELOG.md` describing Added / Changed / Fixed.

## 3. Build and verify the distribution

```bash
make publish-check         # build sdist+wheel, then twine check
# verify a clean install:
python -m venv /tmp/verify && /tmp/verify/bin/pip install dist/*.whl
/tmp/verify/bin/cybershell --version
/tmp/verify/bin/cybershell doctor
/tmp/verify/bin/cybershell bench-eval --fail-on-miss
```

Confirm the wheel ships the packaged data (`cybershell/data/*.json`,
`cybershell/data/cybershell_bench.jsonl`).

## 4. Repository hygiene

- no `__pycache__`, `.venv`, `*.egg-info`, `dist/`, or `build/` committed
- no secrets in docs/tests/benchmarks
- `LICENSE`, `SECURITY.md`, `THREAT_MODEL.md`, `CHANGELOG.md` present
- README installation path and benchmark numbers are accurate
- GitHub Actions (test matrix, quality, package) passing

## 5. Tag and publish

```bash
git tag -a v0.2.0 -m "CyberShell Copilot v0.2.0"
git push origin v0.2.0
```

Publishing to PyPI is a manual, credentialed step performed by the maintainer:

```bash
twine upload dist/*        # requires your PyPI API token
```

Consider validating on TestPyPI first (`twine upload --repository testpypi dist/*`).
