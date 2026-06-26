# Packaging

> **Status:** the primary, fully-supported install paths are `pipx` / `pip` and
> the `Containerfile`. The Homebrew and Debian artifacts below are **untested
> scaffolds** — they require the published release and per-platform testing before
> they can be called supported. See `HANDOFF.md`.

## Recommended install (works everywhere Python runs)

```bash
pipx install cybershell-copilot     # isolated, recommended
# or
pip install cybershell-copilot
```

CyberShell is a pure-Python, standard-library package, so `pipx`/`pip` is the
simplest and most portable distribution method.

## Container

A `Containerfile` is provided at the repo root. See its header for build/run usage.

## Homebrew (macOS) — template

`homebrew/cybershell-copilot.rb` is a formula **template**. Before use:

1. Publish the sdist to PyPI.
2. Fill in the `url` and `sha256` for the published sdist.
3. Test via a personal tap (`brew install --build-from-source ...`) on macOS.

Note the platform caveats in `docs/PLATFORM_SUPPORT.md`: on macOS the engine runs
and the universal-danger rules apply, but Linux-specific coverage does not.

## Debian / .deb — notes

See `debian/README.md`. Because this is a pure-Python package, the pragmatic paths
to a `.deb` are `fpm` or `dh-virtualenv`; building and testing must happen on a
Debian/Ubuntu host.
