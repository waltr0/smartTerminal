# Security Policy

CyberShell Copilot is a cybersecurity tool that analyzes and suggests terminal
commands. It never executes suggested commands by itself.

## Supported Versions

Security fixes are currently provided for the latest `main` branch and tagged
releases starting from `v0.1.0`.

## Reporting A Vulnerability

Please do not open a public issue for sensitive vulnerabilities.

Send a private report to the project maintainers using your preferred private
channel. If GitHub private vulnerability reporting is enabled for the repository,
use that first.

Include:

- affected version or commit
- operating system and shell
- reproduction steps
- expected vs actual behavior
- impact
- any logs or command examples, with secrets removed

## Scope

In scope:

- unsafe suggestion insertion
- guardrail bypass
- command-risk misclassification that could cause dangerous insertion
- audit/cache data leakage
- installer behavior that modifies unexpected files
- shell integration bugs that disrupt normal shell input

Out of scope:

- attacks requiring malicious local modification of CyberShell source code
- unsafe commands manually typed and executed by a user outside CyberShell
- third-party package vulnerabilities unless CyberShell directly exposes them

## Safety Model

CyberShell treats all generated or retrieved command suggestions as untrusted
until validated by the deterministic guardrail engine. Optional LLM/RAG backends
must never bypass this validation layer.

The detection engine is pattern-based and has **documented static-analysis
limitations** (command substitution, multi-layer encoding, working-directory
tracking) described in [THREAT_MODEL.md](THREAT_MODEL.md). These are known and
tracked in the benchmark as expected gaps — they are not treated as new
vulnerabilities. Reports of **novel** bypasses beyond those documented limitations
are very welcome and are exactly what private disclosure is for.

For how the tool handles your data, see [PRIVACY.md](PRIVACY.md): the core makes no
network connections, and the audit log and prefix cache are opt-in and local.

