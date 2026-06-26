# Privacy and Data Handling

CyberShell Copilot is designed to be privacy-preserving by default. This document
describes exactly what it does and does not do with your data, based on how the
code actually behaves.

## Summary

- **Fully offline.** The core tool makes no network connections and contains no
  telemetry or analytics. Nothing about your commands is sent anywhere.
- **Nothing is written to disk by default.** Both the audit log and the prefix
  cache are opt-in; if you do not enable them, CyberShell processes everything in
  memory and persists nothing.
- **Local-only and user-controlled.** When you do enable persistence, the data
  stays on your machine in your home directory, with secrets redacted, and you can
  delete it at any time.

## What is processed

To assess a command, CyberShell looks at the command string and lightweight
context: the working directory, the shell name, recent history (if you pass it),
and environment-variable *keys* (to detect secret-like names). This processing
happens in memory.

## What is stored, and only when you ask

### Audit log (opt-in: `--audit`)

When you pass `--audit`, one JSON line per evaluation is appended to:

```
~/.cybershell/audit.jsonl
```

Each record contains a UTC timestamp, the (redacted) partial command, the working
directory, the shell name, the decision/status/risk level/score, the matched rule
IDs, and the suggestion source/record id. **Secrets are redacted before writing** —
token/password/secret/API-key assignments and flags, and AWS access-key patterns
are masked. No raw environment values and no command arguments flagged as secrets
are stored.

### Prefix cache (opt-in: `--cache-file <path>`)

The prefix cache stores previously accepted command completions to speed up
suggestions. It is only written to disk if you explicitly pass `--cache-file`;
otherwise it lives in memory for the duration of the process. It contains command
patterns and acceptance counts — no secrets are intended to be stored, and you
should choose a path you control.

## What is never collected

- No remote transmission of any kind (no servers, no telemetry, no crash reporting).
- No user identifiers, accounts, or device fingerprints.
- No background data collection — CyberShell only acts when you run it.

## GDPR / data-protection posture

CyberShell is local software, so in data-protection terms **you (the operator) are
the data controller**; the tool is a local processor running entirely under your
control. Relevant properties:

- **Local processing** — data never leaves your machine.
- **Data minimization** — only the fields above are recorded, and secrets are
  redacted before being written.
- **Purpose limitation** — recorded data exists only to support local risk auditing.
- **Storage control and erasure** — you choose whether anything is stored and can
  erase it instantly (see below).
- **No third-party sharing** — there are no third parties.

If you deploy CyberShell in an organization, the audit log may contain command
metadata about operators; handle it under your own logging and retention policy.

## Inspecting and deleting your data

```bash
# See what (if anything) has been recorded
cat ~/.cybershell/audit.jsonl

# Delete the audit log and any local CyberShell state
rm -rf ~/.cybershell

# Uninstall and purge local data in one step
bash uninstall.sh --purge-data
```

## Honest caveats

- **Redaction is best-effort.** It matches common secret formats (named
  assignments, password/token flags, AWS keys). It cannot catch every possible
  secret embedded in a command, so avoid pasting raw credentials regardless.
- **Optional research backends.** The default app uses no network. The optional
  FAISS and local-GGUF backends also run locally. If you deliberately configure a
  *remote* model endpoint, that network behavior is introduced by your
  configuration, not by CyberShell's defaults.
