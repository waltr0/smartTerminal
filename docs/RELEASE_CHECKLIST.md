# Release Checklist

Before tagging a GitHub release:

```bash
python -m unittest discover -s tests -v
python -m cybershell bench-eval --fail-on-miss
python -m compileall src tests
bash -n scripts/cybershell.bash
```

Optional if available:

```bash
zsh -n scripts/cybershell.zsh
bash install.sh
cybershell doctor
bash uninstall.sh
```

Check repository hygiene:

- no `__pycache__`
- no `.venv`
- no `*.egg-info`
- no secrets in docs/tests/benchmarks
- `LICENSE` exists
- `SECURITY.md` exists
- README installation path is correct
- GitHub Actions passing

Tag:

```bash
git tag -a v0.1.0 -m "CyberShell Copilot v0.1.0"
git push origin v0.1.0
```
