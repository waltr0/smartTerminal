# Changelog

All notable changes to CyberShell Copilot are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-06-26

A substantial hardening release. The guardrail engine was taken from prototype to
a state with a regression safety net, evasion resistance, broader coverage, and an
honest, categorized benchmark.

### Added
- **Regression safety net**: a locked invariant corpus, a behavior snapshot, and a
  drift checker (`tools/baseline_snapshot.py`) that fails the build if any locked
  decision changes. Mirrored by `tests/test_baseline_regression.py`.
- **Evasion-resistant analysis**: the engine now re-scans decoded and de-obfuscated
  views of a command and analyzes every sub-command of a pipeline or chain. It
  catches base64-encoded payloads, `\xHH` hex escapes, quote/backslash keyword
  splitting, simple variable indirection, and dangerous commands hidden behind
  command chaining.
- **THREAT_MODEL.md**: an honest description of what the guardrails detect and the
  documented limitations (multi-layer encodings, `$(...)` substitution,
  `cd`-tracking, full shell parsing, advisory-not-enforcing).
- **Expanded coverage**: guardrail rules grew to 31 (broader MITRE ATT&CK coverage
  across Defense Evasion, Credential Access, Exfiltration, and Privilege
  Escalation); the command knowledge base grew to 114 curated defensive /
  blue-team / DevOps commands across incident response, network inspection,
  file integrity, forensics, process triage, persistence audit, account review,
  container and Kubernetes security, cloud posture, and host hardening.
- **Knowledge-base quality gate** (`tests/test_kb_quality.py`): every command is
  validated for schema, unique id/command, and MITRE format, and -- critically --
  is checked to ensure the guardrail engine would never block it. A suggestion the
  tool would refuse to display can no longer be shipped.
- **Rebuilt benchmark** (`tools/build_benchmark.py`, 143 categorized cases) with a
  reported per-category accuracy, a false-positive rate over a dedicated benign
  set, block detection recall, and a suggestion-contract accuracy. Documented
  limitations are surfaced as expected misses rather than hidden.
- A `dev` optional-dependency group (ruff, mypy, build, twine, coverage) and a
  single-sourced package version exposed via `cybershell --version`.
- **Global-readiness documentation**: an honest cross-platform support assessment
  (`docs/PLATFORM_SUPPORT.md`), a privacy/data-handling document
  (`PRIVACY.md`) reflecting the offline, opt-in, locally-stored design, and a
  maintainer handoff checklist (`HANDOFF.md`) of the human-only release tasks.
- **Packaging scaffolds**: a non-root `Containerfile`, and clearly-labelled
  Homebrew and Debian packaging templates under `packaging/` (untested, pending the
  published release), alongside `pipx`/`pip` as the supported install path.
- **i18n scaffold** (`cybershell.i18n` + `locale/en.json` + `docs/I18N.md`): a
  tested message-catalog mechanism with safe fallback, with the codebase strings
  not yet migrated (documented honestly as a deferred, post-1.0 effort).

### Changed
- `rm` is scored by its resolved target: catastrophic paths (root, system
  directories, whole home directories, critical files) block, while routine
  project cleanup such as `rm -rf node_modules` is allowed. `sudo`/`doas`
  prefixes are stripped before this analysis so privilege-wrapped commands cannot
  bypass it.
- Tightened several rules to remove false positives: archiving a user's own
  project directory no longer trips the mass-exfil rule, and the `.env` secret
  rule matches real path segments instead of substrings.
- `bench-eval` now reports the new structured metrics; `--fail-on-miss` trips only
  on unexpected regressions, not on documented limitations.
- Reverse-shell detection extended to `nc -e`, `ncat --exec`, and
  `socat exec:`/`system:`.

### Fixed
- `history-audit` now reports correct file line numbers.
- Audit-log records redact secret-like tokens (passwords, API keys) before writing.
- The prefix cache tolerates corrupt or non-object JSON.
- The "`/`-prefix" bug that treated every absolute path as sensitive.

### Quality
- Lint (ruff) and type-check (mypy) pass cleanly; line coverage is ~85%.
- CI runs the test matrix (Python 3.10-3.13), the benchmark and drift gates, lint,
  type-check, coverage, and a clean-environment install of the built wheel.

## [0.1.0]

- Initial release: offline, deterministic shell-command risk scoring with
  allow/warn/block decisions, MITRE ATT&CK mapping, safer-command suggestions,
  policy profiles, shell integration, and a baseline benchmark.

[0.2.0]: https://github.com/waltr0/smartTerminal/releases/tag/v0.2.0
[0.1.0]: https://github.com/waltr0/smartTerminal/releases/tag/v0.1.0
