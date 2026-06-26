# Maintainer Handoff Checklist

This is the honest list of things that remain — the items that require a human
decision, an account/credential, real-world validation, or a legal judgment, and
therefore cannot be completed inside the codebase itself. The engineering work
(correctness, evasion resistance, coverage, packaging, quality gates) is done and
green; what follows is the path from "ready" to "shipped and trusted."

## Before the first public release

- [ ] **Set the maintainer identity.** `pyproject.toml` currently lists a
      placeholder author (`Elite Taskforce`). Replace it with the real
      author/maintainer name and contact before publishing.
- [ ] **Confirm the license holder.** `LICENSE` is MIT; make sure the copyright
      line names the right person/entity.
- [ ] **Decide the canonical name.** The GitHub repo is `smartTerminal`, the
      distribution is `cybershell-copilot`, the import package is `cybershell`, and
      the product is "CyberShell Copilot." This works, but pick the public-facing
      name deliberately and align the README/links.
- [ ] **Regenerate or remove the PDFs.** `docs/CyberShell_Copilot_Project_Guide.pdf`
      and `docs/CyberShell_Copilot_User_Manual.pdf` predate v0.2.0 and contain
      outdated numbers. The Markdown docs are the source of truth; regenerate the
      PDFs from them or remove them.

## Publishing

- [ ] **PyPI.** Create the project/account, generate an API token, validate on
      **TestPyPI** first, then `twine upload dist/*`. See `docs/RELEASE_CHECKLIST.md`.
- [ ] **Tag and release.** `git tag -a v0.2.0` and create the GitHub release with
      the `CHANGELOG.md` entry.
- [ ] **Push the hardening work.** All Stage 0–5 commits are local; push the branch
      and open/merge the PR.

## Distribution channels (optional, each needs real testing)

- [ ] **Container** — `Containerfile` is provided and uses the same install flow
      verified in CI (clean wheel install). The image build itself has not been run
      in this environment; build and test it on your container host, then publish.
- [ ] **Homebrew** — `packaging/homebrew/cybershell-copilot.rb` is a *template*. It
      needs the published sdist URL + sha256 and must be tested via a tap on macOS
      before it can be called supported.
- [ ] **Debian/.deb** — `packaging/debian/` contains notes and a control skeleton.
      Building and testing a real `.deb` must be done on a Debian/Ubuntu host.

## Security and legal

- [ ] **External review.** Commission an independent security/code review and a
      pentest of the guardrail bypass surface. The in-repo `THREAT_MODEL.md` and
      benchmark document the known limitations honestly; an outside party should
      probe beyond them.
- [ ] **Trademark / naming.** Check that "CyberShell" / "CyberShell Copilot" is
      clear to use and does not collide with existing marks in your jurisdiction.
- [ ] **Bundled-data license.** Confirm the licensing of any data you add to the
      knowledge base or rules in future (the current rules/KB are authored in-repo).
- [ ] **Enable GitHub private vulnerability reporting** so `SECURITY.md`'s process
      has a real private channel.

## Operational

- [ ] **Real-world beta.** Run with a small group of consenting blue-team users on
      real systems and collect false-positive/false-negative feedback. The 0.0
      benchmark false-positive rate is measured on an authored corpus, not the wild.
- [ ] **Rule and KB curation cadence.** Attacker techniques evolve; decide who owns
      ongoing rule/KB updates and how new entries pass the quality gate
      (`tests/test_kb_quality.py`) and benchmark.
- [ ] **Triage process.** Define how reported bypasses become rule or decoding
      updates, and a rough SLA.

## Expectation-setting (state these plainly to users)

So adopters are not surprised, the product README/threat model already say, and you
should keep saying:

- CyberShell **does not execute commands**; it advises.
- It is **not** a sandbox, EDR, or kernel-level control — it is one advisory layer
  in defense-in-depth.
- **Rule coverage is finite** and pattern-based; treat `block` as a strong signal
  and `allow` as "no known-dangerous pattern matched," not proof of safety.
- The documented static-analysis limitations (command substitution, multi-layer
  encoding, cwd-tracking) are real and listed in `THREAT_MODEL.md`.
