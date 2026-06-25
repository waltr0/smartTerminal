# CyberShell Copilot — Threat Model

This document states, as plainly and honestly as possible, what CyberShell Copilot's
guardrails do and do not protect against. It is deliberately conservative: a security
tool that overstates its guarantees is worse than one that is clear about its limits.

## 1. What CyberShell Copilot is

CyberShell Copilot is an **advisory** guardrail and risk-scoring layer for shell
commands. Given a command string and some context (working directory, root flag,
environment indicators, recent history), it returns a decision — `allow`, `warn`,
or `block` — together with the matched rules, a risk score, MITRE ATT&CK tags, and
safer alternatives.

The guardrail engine is the deterministic final authority: decisions come from regex
rules plus contextual analysis, never from a model. The tool **does not execute
commands** and is intended to sit in front of a human or an assistant that does.

## 2. Trust boundaries and security model

- **Input**: an untrusted command string plus caller-supplied context.
- **Output**: an advisory decision. The caller (a shell integration, an assistant,
  or a CI gate) decides what to do with `block` / `warn`.
- **Authority**: detection is deterministic and decoupled from suggestion/retrieval.
  Every candidate suggestion is re-assessed before display.

CyberShell Copilot is **not** a sandbox, a seccomp/AppArmor profile, an EDR agent,
or a kernel-level control. It raises the cost of running a dangerous command by
surfacing intent; it cannot prevent a determined operator with a real shell from
running whatever they want directly.

## 3. What the guardrails detect

- **Destructive filesystem actions** — recursive/forced removal is scored by its
  *resolved target*: root, system directories (`/etc`, `/usr`, `/var`, …), whole
  home directories, and critical files (`/etc/passwd`, `/etc/shadow`, …) block;
  absolute non-system paths warn; routine project cleanup is allowed.
- **Device / data destruction** — `mkfs`, `dd` to a device, `wipefs`, `shred`.
- **Reverse shells & interactive network shells** — `/dev/tcp` and `/dev/udp`
  redirection, `bash -i`, `nc -e` / `ncat --exec`, `socat exec:`/`system:`.
- **Credential and secret exposure** — reads of private keys and `/etc/shadow`,
  secret-bearing environment dumps, Kubernetes secret access.
- **Persistence** — writes/appends to `authorized_keys`, cron, and systemd paths.
- **Remote code execution patterns** — `curl … | bash` and similar.
- **Natural-language abuse intent** — requests to build malware, steal credentials,
  or disable defenses.

### Evasion-resistance layer (Stage 2)

Before deciding, the engine re-scans **de-obfuscated and decoded views** of the
command and analyzes **each sub-command** of a pipeline or chain, not just the head.
This catches:

- **Base64-encoded payloads** (e.g. `echo <b64> | base64 -d | bash`) — one layer of
  base64 is decoded and re-scanned.
- **Hex-escaped text** (`$'\x72\x6d' …`).
- **Quote / backslash keyword splitting** (`r''m`, `r\m`, `rm -r''f`).
- **Simple variable indirection** (`a=rm; b=-rf; $a $b /etc`).
- **Command chaining** (`ls && rm -rf /etc`, `… ; nc -e …`) — each segment is
  assessed with the caller's context.

A finding is added from a decoded/de-obfuscated view only when a rule actually
matches that view, so commands that merely *contain* dangerous-looking text inside
quotes or arguments (`echo "rm -rf /"`, an incidental base64 argument) are not
escalated.

## 4. What it does NOT catch (known limitations)

Detection is pattern- and heuristic-based. It is **not exhaustive**, and the
following are known gaps. This list is intended to be honest, not complete.

- **Multi-layer / non-base64 encodings.** Only a single base64 layer and `\xHH`
  hex escapes are decoded. Double-encoded payloads, base32/uuencode/gzip+base64,
  ROT13, and similar are not unwound.
- **Runtime-only resolution.** Constructs whose meaning is only determined at
  execution time can evade static analysis: `$(...)` / backtick command
  substitution, `eval` of a string built at runtime, `IFS` manipulation,
  arithmetic/brace-expansion tricks, here-docs, and reading the payload from a file
  or the network.
- **Working-directory tracking across `cd`.** A relative target is judged against
  the caller-supplied cwd. `cd /etc && rm -rf .` is not recognized as deleting
  `/etc`, because the engine does not simulate `cd`.
- **Full shell-syntax parsing.** Segment splitting is operator-based, not a real
  shell parser; escaped or quoted separators (`\;`, `';'`) and exotic quoting can
  cause a sub-command to be under-analyzed.
- **Bounded scanning.** Decoding is limited (token length and count caps, ~16 KB
  view cap) to bound CPU; very large or pathological inputs are scanned only
  partially.
- **Finite rule/knowledge set.** Coverage is only as good as the shipped rules and
  command knowledge base, which must be maintained as techniques evolve.
- **Advisory, not enforcing.** `block` is a recommendation to the integrating
  caller. The tool cannot stop direct execution outside its path.

## 5. Residual risk and compensating controls

Because detection is advisory and not exhaustive, deploy CyberShell Copilot as **one
layer of defense in depth**, alongside:

- least-privilege accounts and `sudo` policy,
- real endpoint protection / EDR and kernel-level controls (seccomp, AppArmor,
  SELinux),
- centralized, tamper-resistant audit logging and review,
- change control for production systems.

Treat a `block` as a strong signal and an `allow` as "no known-dangerous pattern
matched," **not** as proof that a command is safe.

## 6. Reporting security issues

Responsible-disclosure instructions are provided in `SECURITY.md`. Please do not file
public issues for suspected bypasses; report them privately so a rule or decoding
update can be shipped first.
