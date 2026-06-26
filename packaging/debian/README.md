# Building a Debian package (notes)

CyberShell Copilot is a pure-Python, stdlib-only package. A native `.deb` is
optional — `pipx install cybershell-copilot` is the recommended install on Debian
and Ubuntu. If you do want a `.deb`, two pragmatic routes:

## Option A — `fpm` (quickest)

```bash
# On a Debian/Ubuntu host, after building the wheel:
python -m build --wheel
pipx install fpm 2>/dev/null || gem install --user-install fpm
fpm -s python -t deb \
    --python-bin python3 \
    --python-package-name-prefix python3 \
    dist/cybershell_copilot-*.whl
```

## Option B — `dh-virtualenv` (self-contained venv)

Use `dh-virtualenv` to bundle a virtualenv into the package. This is heavier but
isolates dependencies. See the dh-virtualenv documentation for the `debian/rules`
setup.

## Must be tested on-target

Whichever route, build and install the resulting `.deb` on a clean Debian/Ubuntu
system and confirm `cybershell --version`, `cybershell doctor`, and
`cybershell bench-eval --fail-on-miss` before publishing it anywhere.
