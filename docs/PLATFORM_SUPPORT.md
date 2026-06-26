# Platform Support

This document is deliberately precise about where CyberShell Copilot applies,
because a security tool that implies coverage it does not have is worse than one
that is clear about its boundaries.

## Two separate questions

There are two different things to keep apart:

1. **Does the tool run on this OS?** CyberShell is pure Python 3.10+ using only the
   standard library, so it runs anywhere CPython runs — Linux, macOS, Windows, WSL.
2. **Do the detection rules and command suggestions apply to this OS?** The
   guardrail rules and the command knowledge base are written for **Linux / POSIX
   shells**. This is the part that varies, and it is what the table below is about.

The distinction matters: you can `pip install` and run `cybershell` on macOS or
Windows, but what it *knows about* is Linux command behavior.

## Support matrix

| Target environment | Tool runs | Rule + KB relevance | Status |
| --- | --- | --- | --- |
| Linux (Kali, Debian, Ubuntu, RHEL, etc.) | Yes | Full | **Designed for this** |
| WSL (Linux distro on Windows) | Yes | Full (Linux semantics) | **Supported** |
| macOS (bash/zsh) | Yes | Partial | Works with caveats |
| Native Windows (PowerShell / cmd) | Yes | Minimal | **Out of scope** |

## macOS caveats

macOS is Unix-like, so a meaningful subset of the rules applies: destructive
filesystem actions (`rm -rf /`, removal of system directories), reverse-shell
patterns, credential-file reads, and archive/exfil patterns are still relevant.

However, several rule families and many knowledge-base commands are Linux-specific
and will not match or will not exist on macOS:

- **No `/proc`** — rules and commands that read procfs do not apply.
- **launchd, not systemd** — `systemctl` / `journalctl` persistence and service
  rules and KB entries are not meaningful; macOS uses `launchctl` and unified logs.
- **Different package manager** — `apt` / `dpkg` / `rpm` commands do not apply
  (`brew` is the norm).
- **SIP-protected paths** — `/usr` and others behave differently under System
  Integrity Protection.
- **`/dev/tcp`** is a bash feature; the default macOS shell is zsh.

Treat macOS as "the engine runs and the universal-danger rules apply, but
Linux-specific persistence/package/process coverage does not."

## Windows

The command model does not transfer to native Windows. PowerShell and cmd have
different syntax, path conventions (`C:\\`), no `/etc`, no `/dev/tcp`, and a
different persistence/credential model. The guardrails are built for POSIX shells
and should not be relied on to assess PowerShell commands.

If you are on Windows, run CyberShell under **WSL**, where it operates with full
Linux semantics.

## Recommendation

Use CyberShell on Linux (especially Kali for blue-team / lab work) or under WSL.
macOS is usable for the universal-danger checks but expect reduced rule and
knowledge-base relevance. Native Windows PowerShell support is not a goal of this
project and would require a separate rule set and command model.
