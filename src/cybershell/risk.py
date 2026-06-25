from __future__ import annotations

import base64
import re
import shlex
from dataclasses import dataclass
from pathlib import PurePosixPath

from cybershell.alternatives import safe_alternatives
from cybershell.data_loader import load_json_resource
from cybershell.models import Decision, RiskAssessment, RiskFinding, RiskLevel, ShellContext
from cybershell.policy import Policy, PolicyRegistry


@dataclass(slots=True)
class GuardrailRule:
    id: str
    pattern: re.Pattern[str]
    category: str
    weight: int
    severity: str
    message: str
    mitre_tactic: str | None = None
    mitre_technique: str | None = None


DEFAULT_POLICY = PolicyRegistry.packaged().get("soc")


class GuardrailEngine:
    """Deterministic final authority for command safety decisions."""

    SYSTEM_CRITICAL_DIRS = frozenset(
        {
            "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib32",
            "/lib64", "/opt", "/proc", "/root", "/run", "/sbin", "/srv",
            "/sys", "/usr", "/var",
        }
    )
    CRITICAL_FILES = frozenset(
        {"/etc/passwd", "/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/fstab"}
    )
    SENSITIVE_PREFIXES = (
        "/etc", "/boot", "/usr", "/bin", "/sbin", "/lib", "/lib64",
        "/var/log", "/root", "/sys", "/proc",
    )

    def __init__(self, rules: list[GuardrailRule]) -> None:
        self.rules = rules

    @classmethod
    def packaged(cls) -> "GuardrailEngine":
        raw = load_json_resource("guardrail_rules.json")
        rules = []
        for item in raw["rules"]:
            flags = re.IGNORECASE
            rules.append(
                GuardrailRule(
                    id=item["id"],
                    pattern=re.compile(item["pattern"], flags),
                    category=item["category"],
                    weight=int(item["weight"]),
                    severity=item.get("severity", "warn"),
                    message=item["message"],
                    mitre_tactic=item.get("mitre_tactic"),
                    mitre_technique=item.get("mitre_technique"),
                )
            )
        return cls(rules)

    def assess(
        self,
        command: str,
        context: ShellContext | None = None,
        policy: Policy | None = None,
    ) -> RiskAssessment:
        active_policy = policy or DEFAULT_POLICY
        normalized = command.strip()
        findings: list[RiskFinding] = []
        score = 0

        if not normalized:
            return RiskAssessment(
                command=command,
                score=0,
                level=RiskLevel.SAFE,
                decision=Decision.ALLOW,
                findings=[],
                safe_alternatives=[],
                summary="No command was provided.",
            )

        for rule in self.rules:
            match = rule.pattern.search(normalized)
            if not match:
                continue
            evidence = match.group(0)
            adjusted_weight = self._policy_weight(rule.weight, rule.category, active_policy)
            score += adjusted_weight
            findings.append(
                RiskFinding(
                    rule_id=rule.id,
                    category=rule.category,
                    weight=adjusted_weight,
                    severity=rule.severity,
                    message=rule.message,
                    evidence=evidence,
                    mitre_tactic=rule.mitre_tactic,
                    mitre_technique=rule.mitre_technique,
                )
            )

        syntax_finding = self._syntax_check(normalized)
        if syntax_finding:
            syntax_finding = self._with_policy_weight(syntax_finding, active_policy)
            score += syntax_finding.weight
            findings.append(syntax_finding)

        if context is not None:
            contextual_findings = self._contextual_checks(normalized, context)
            for finding in contextual_findings:
                finding = self._with_policy_weight(finding, active_policy)
                score += finding.weight
                findings.append(finding)

        # Evasion-resistant pass: re-scan decoded / de-obfuscated views of the
        # command so encoded or quote-mangled payloads cannot slip past the
        # surface-level rule match. Only findings for rules not already matched
        # are added, so non-obfuscated commands are unaffected.
        seen_rule_ids = {finding.rule_id for finding in findings}
        for finding in self._evasion_view_findings(normalized, seen_rule_ids):
            finding = self._with_policy_weight(finding, active_policy)
            score += finding.weight
            findings.append(finding)
            seen_rule_ids.add(finding.rule_id)

        if self._must_block(findings, active_policy) or score >= active_policy.block_threshold:
            level = RiskLevel.BLOCKED
            decision = Decision.BLOCK
        elif score >= active_policy.dangerous_threshold:
            level = RiskLevel.DANGEROUS
            decision = Decision.WARN
        elif score >= active_policy.caution_threshold:
            level = RiskLevel.CAUTION
            decision = Decision.WARN
        else:
            level = RiskLevel.SAFE
            decision = Decision.ALLOW

        alternatives = safe_alternatives(normalized, findings) if decision != Decision.ALLOW and findings else []
        summary = self._summary(level, findings)
        return RiskAssessment(
            command=normalized,
            score=score,
            level=level,
            decision=decision,
            findings=findings,
            safe_alternatives=alternatives,
            summary=summary,
        )

    def _syntax_check(self, command: str) -> RiskFinding | None:
        try:
            shlex.split(command, posix=True)
            return None
        except ValueError as exc:
            return RiskFinding(
                rule_id="syntax.unbalanced_shell",
                category="syntax",
                weight=18,
                severity="warn",
                message="The command has malformed shell quoting or escaping.",
                evidence=str(exc),
                mitre_tactic=None,
                mitre_technique=None,
            )

    def _contextual_checks(
        self, command: str, context: ShellContext
    ) -> list[RiskFinding]:
        home = self._home(context)
        cwd = (context.cwd or "").rstrip("/")
        segments = self._split_segments(command)
        seg_argvs = [self._effective_argv(self._split_command(seg)) for seg in segments]
        seg_heads = [argv[0] if argv else "" for argv in seg_argvs]
        mutating_heads = {"rm", "mv", "cp", "chmod", "chown", "dd", "mkfs", "wipefs", "shred"}

        collected: list[RiskFinding] = []

        for seg, argv, head in zip(segments, seg_argvs, seg_heads):
            if not argv:
                continue

            if context.is_root and head in mutating_heads:
                collected.append(
                    RiskFinding(
                        rule_id="context.root_mutation",
                        category="privilege_escalation",
                        weight=16,
                        severity="warn",
                        message="Mutating command is being prepared from a root shell context.",
                        evidence=context.user or "root",
                        mitre_tactic="Privilege Escalation",
                        mitre_technique="T1548",
                    )
                )

            # rm is assessed by resolved target so catastrophic paths block while
            # routine project cleanup (e.g. `rm -rf node_modules`) is allowed.
            if head == "rm":
                collected.extend(self._destructive_rm_findings(argv, cwd, home))

            if head in {"mv", "cp", "chmod", "chown"}:
                sensitive_targets = self._sensitive_targets(argv, cwd, home)
                if sensitive_targets:
                    collected.append(
                        RiskFinding(
                            rule_id="context.sensitive_target",
                            category="destructive_filesystem",
                            weight=20,
                            severity="warn",
                            message="The command targets a system-sensitive path.",
                            evidence=", ".join(sensitive_targets[:3]),
                            mitre_tactic="Impact",
                            mitre_technique="T1485",
                        )
                    )

            if context.last_exit_status not in (None, 0) and head in {"rm", "mv", "chmod", "chown"}:
                collected.append(
                    RiskFinding(
                        rule_id="context.failed_previous_command",
                        category="operational_safety",
                        weight=8,
                        severity="warn",
                        message="The previous command failed; destructive follow-up commands should be double-checked.",
                        evidence=str(context.last_exit_status),
                    )
                )

            if self._redirects_to_sensitive_path(argv, cwd, home):
                collected.append(
                    RiskFinding(
                        rule_id="context.sensitive_redirection",
                        category="persistence",
                        weight=28,
                        severity="warn",
                        message="Command redirects output into a sensitive or persistence-related path.",
                        evidence=seg,
                        mitre_tactic="Persistence",
                        mitre_technique="T1053",
                    )
                )

        if self._has_secret_env_indicator(context) and any(
            head in {"env", "printenv", "set", "export"} for head in seg_heads
        ):
            collected.append(
                RiskFinding(
                    rule_id="context.secret_env_dump",
                    category="secrets_access",
                    weight=22,
                    severity="warn",
                    message="The environment appears to contain secret-like variables; dumping it may expose credentials.",
                    evidence="secret-like environment key",
                    mitre_tactic="Credential Access",
                    mitre_technique="T1552",
                )
            )

        if self._is_kubernetes_context(context) and "secret" in command.lower():
            collected.append(
                RiskFinding(
                    rule_id="context.kubernetes_secret_context",
                    category="secrets_access",
                    weight=12,
                    severity="warn",
                    message="Kubernetes context is active while the command references secrets.",
                    evidence="KUBECONFIG/context",
                    mitre_tactic="Credential Access",
                    mitre_technique="T1552",
                )
            )

        # Collapse duplicate rule hits across segments to the highest-weight one
        # so a multi-segment command cannot inflate its own score.
        best: dict[str, RiskFinding] = {}
        for finding in collected:
            current = best.get(finding.rule_id)
            if current is None or finding.weight > current.weight:
                best[finding.rule_id] = finding
        return list(best.values())

    def _split_segments(self, command: str) -> list[str]:
        parts = re.split(r"\s*(?:\|\||&&|;|\n|\|)\s*", command)
        return [stripped for stripped in (part.strip() for part in parts) if stripped]

    def _effective_argv(self, argv: list[str]) -> list[str]:
        """Drop a leading sudo/doas (and its options) so the real command head is
        analyzed -- otherwise `sudo rm -rf ~` would escape target-aware scoring."""
        if not argv or argv[0] not in {"sudo", "doas"}:
            return argv
        index = 1
        while index < len(argv) and argv[index].startswith("-"):
            if argv[index] in {"-u", "-g", "--user", "--group"} and index + 1 < len(argv):
                index += 2
            else:
                index += 1
        return argv[index:]

    # -- Evasion-resistant decoding / de-obfuscation -----------------------------

    def _evasion_view_findings(
        self, command: str, seen_rule_ids: set[str]
    ) -> list[RiskFinding]:
        findings: list[RiskFinding] = []
        added: set[str] = set()
        decoded_hit = False
        obfuscated_hit = False

        for label, view in self._deobfuscated_views(command):
            for rule in self.rules:
                if rule.id in seen_rule_ids or rule.id in added:
                    continue
                match = rule.pattern.search(view)
                if not match:
                    continue
                findings.append(
                    RiskFinding(
                        rule_id=rule.id,
                        category=rule.category,
                        weight=rule.weight,
                        severity=rule.severity,
                        message=rule.message,
                        evidence=match.group(0)[:80],
                        mitre_tactic=rule.mitre_tactic,
                        mitre_technique=rule.mitre_technique,
                    )
                )
                added.add(rule.id)
                if label in {"base64", "hex"}:
                    decoded_hit = True
                else:
                    obfuscated_hit = True

        if findings and decoded_hit:
            findings.append(
                RiskFinding(
                    rule_id="evasion.encoded_payload",
                    category="defense_evasion",
                    weight=12,
                    severity="warn",
                    message="A dangerous command was hidden inside an encoded payload (base64/hex).",
                    evidence="decoded payload",
                    mitre_tactic="Defense Evasion",
                    mitre_technique="T1140",
                )
            )
        if findings and obfuscated_hit:
            findings.append(
                RiskFinding(
                    rule_id="evasion.obfuscated_command",
                    category="defense_evasion",
                    weight=10,
                    severity="warn",
                    message="A dangerous command was obscured with quoting, escaping, or variable indirection.",
                    evidence="obfuscated command",
                    mitre_tactic="Defense Evasion",
                    mitre_technique="T1027",
                )
            )
        return findings

    def _deobfuscated_views(self, command: str) -> list[tuple[str, str]]:
        views: list[tuple[str, str]] = []
        seen: set[str] = {command}

        def add(label: str, text: str) -> None:
            if text and text not in seen and len(text) <= 16384:
                seen.add(text)
                views.append((label, text))

        add("dequote", self._dequote(command))
        add("vars", self._inline_vars(command))
        add("hex", self._decode_hex(command))
        for chunk in self._decode_base64_chunks(command):
            add("base64", chunk)
        return views

    def _dequote(self, command: str) -> str:
        text = command
        for _ in range(3):
            previous = text
            text = text.replace("''", "").replace('""', "")
            text = re.sub(r"(\w)['\"\\](\w)", r"\1\2", text)
            if text == previous:
                break
        return text

    def _inline_vars(self, command: str) -> str:
        assignments = dict(
            re.findall(r"(?:^|[\s;&|(])([A-Za-z_]\w*)=([^\s'\";|&()]+)", command)
        )
        if not assignments:
            return command

        def replace(match: re.Match[str]) -> str:
            name = match.group(1) or match.group(2)
            return assignments.get(name, match.group(0))

        return re.sub(r"\$\{(\w+)\}|\$(\w+)", replace, command)

    def _decode_hex(self, command: str) -> str:
        if "\\x" not in command:
            return command
        return re.sub(
            r"\\x([0-9A-Fa-f]{2})",
            lambda match: chr(int(match.group(1), 16)),
            command,
        )

    def _decode_base64_chunks(self, command: str) -> list[str]:
        chunks: list[str] = []
        for token in re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", command):
            if len(token) > 8192:
                continue
            padded = token + "=" * ((-len(token)) % 4)
            try:
                raw = base64.b64decode(padded, validate=True)
            except Exception:
                continue
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                continue
            if not text:
                continue
            printable = sum(1 for char in text if 32 <= ord(char) < 127 or char in "\t\n")
            if printable / len(text) >= 0.85:
                chunks.append(text)
            if len(chunks) >= 8:
                break
        return chunks

    def _summary(self, level: RiskLevel, findings: list[RiskFinding]) -> str:
        if not findings:
            return "No guardrail patterns matched; command appears safe for display."
        if level == RiskLevel.SAFE:
            return "Low-scoring guardrail findings matched, but policy thresholds allow the command."
        top = sorted(findings, key=lambda item: item.weight, reverse=True)[:2]
        reasons = "; ".join(finding.message for finding in top)
        if level == RiskLevel.BLOCKED:
            return f"Blocked because high-risk guardrails matched: {reasons}"
        if level == RiskLevel.DANGEROUS:
            return f"Dangerous command; require explicit review: {reasons}"
        return f"Caution recommended: {reasons}"

    def _policy_weight(self, weight: int, category: str, policy: Policy) -> int:
        multiplier = policy.category_multipliers.get(category, 1.0)
        return max(1, int(round(weight * multiplier)))

    def _with_policy_weight(self, finding: RiskFinding, policy: Policy) -> RiskFinding:
        finding.weight = self._policy_weight(finding.weight, finding.category, policy)
        return finding

    def _must_block(self, findings: list[RiskFinding], policy: Policy) -> bool:
        for finding in findings:
            if finding.severity == "block":
                return True
            if policy.category_floor_decisions.get(finding.category) == "block":
                return True
        return False

    def _split_command(self, command: str) -> list[str]:
        try:
            return shlex.split(command, posix=True)
        except ValueError:
            return command.split()

    def _home(self, context: ShellContext | None) -> str | None:
        if context is None:
            return None
        env = context.env or {}
        home = env.get("HOME") or env.get("USERPROFILE")
        if home:
            return home.rstrip("/") or "/"
        if context.user == "root":
            return "/root"
        if context.user:
            return f"/home/{context.user}"
        return None

    def _resolve_target(self, token: str, cwd: str, home: str | None = None) -> str:
        if token in {"~", "~/"}:
            return (home or "/home/user").rstrip("/") or "/"
        if token.startswith("~/"):
            token = ((home or "/home/user").rstrip("/")) + token[1:]
        if token.startswith("/"):
            return str(PurePosixPath(token))
        base = cwd or "."
        if "\\" in base:
            return token
        return str(PurePosixPath(base) / token)

    def _rm_flags(self, argv: list[str]) -> tuple[bool, bool]:
        recursive = force = False
        for token in argv[1:]:
            if not token.startswith("-") or token == "-":
                continue
            if token.startswith("--"):
                if token == "--recursive":
                    recursive = True
                elif token == "--force":
                    force = True
                continue
            body = token[1:]
            if "r" in body or "R" in body:
                recursive = True
            if "f" in body:
                force = True
        return recursive, force

    def _rm_targets(self, argv: list[str]) -> list[str]:
        targets: list[str] = []
        for token in argv[1:]:
            if token in {"&&", "||", ";", "|"}:
                break
            if token.startswith("-") and token != "-":
                continue
            targets.append(token)
        return targets

    def _classify_rm_target(self, token: str, cwd: str, home: str | None) -> str:
        if token in {"/", "/*", "/.", "/.*", "~", "~/"}:
            return "critical"
        path = self._resolve_target(token, cwd, home)
        norm = path.rstrip("/") or "/"
        base = norm[:-2] if norm.endswith("/*") else norm
        base = base.rstrip("/") or "/"
        if base == "/":
            return "critical"
        if base in self.SYSTEM_CRITICAL_DIRS or base in self.CRITICAL_FILES:
            return "critical"
        if home and base == home.rstrip("/"):
            return "critical"
        if base.startswith("/home/") and base.count("/") == 2:
            return "critical"  # an entire user's home directory
        # "under a system directory" excludes the home trees (/home/<user>/... and
        # /root/...), which are user data, not system files.
        system_parents = self.SYSTEM_CRITICAL_DIRS - {"/home", "/root"}
        for parent in system_parents:
            if base.startswith(parent + "/"):
                return "system_child"
        # A relative target is routine project cleanup (e.g. `rm -rf node_modules`)
        # and is allowed regardless of where the working directory happens to be.
        if not (token.startswith("/") or token.startswith("~")):
            return "local"
        return "abs_other"

    def _destructive_rm_findings(
        self, argv: list[str], cwd: str, home: str | None
    ) -> list[RiskFinding]:
        targets = self._rm_targets(argv)
        if not targets:
            return []
        recursive, force = self._rm_flags(argv)
        tiers = [(token, self._classify_rm_target(token, cwd, home)) for token in targets]

        critical = [token for token, tier in tiers if tier == "critical"]
        if critical:
            return [
                RiskFinding(
                    rule_id="fs.destructive_critical_path",
                    category="destructive_filesystem",
                    weight=80,
                    severity="block",
                    message="Removal targets the filesystem root, a system directory or file, or a home directory.",
                    evidence=critical[0],
                    mitre_tactic="Impact",
                    mitre_technique="T1485",
                )
            ]
        if not (recursive or force):
            return []
        system_child = [token for token, tier in tiers if tier == "system_child"]
        if system_child:
            return [
                RiskFinding(
                    rule_id="fs.destructive_system_subpath",
                    category="destructive_filesystem",
                    weight=18,
                    severity="warn",
                    message="Recursive or forced removal targets a path inside a system or home directory.",
                    evidence=system_child[0],
                    mitre_tactic="Impact",
                    mitre_technique="T1485",
                )
            ]
        abs_other = [token for token, tier in tiers if tier == "abs_other"]
        if abs_other:
            return [
                RiskFinding(
                    rule_id="fs.destructive_abs_path",
                    category="destructive_filesystem",
                    weight=14,
                    severity="warn",
                    message="Recursive or forced removal targets an absolute path outside the working directory.",
                    evidence=abs_other[0],
                    mitre_tactic="Impact",
                    mitre_technique="T1485",
                )
            ]
        return []

    def _is_sensitive_path(self, path: str) -> bool:
        norm = path.rstrip("/") or "/"
        if norm == "/":
            return True
        if "/.ssh" in norm:
            return True
        for prefix in self.SENSITIVE_PREFIXES:
            if norm == prefix or norm.startswith(prefix + "/"):
                return True
        return False

    def _sensitive_targets(
        self, argv: list[str], cwd: str, home: str | None = None
    ) -> list[str]:
        targets: list[str] = []
        for token in argv[1:]:
            if token.startswith("-") or "=" in token:
                continue
            path = self._resolve_target(token, cwd, home)
            if self._is_sensitive_path(path):
                targets.append(path)
        if not targets and (
            cwd in {"", "/"}
            or any(cwd.startswith(prefix) for prefix in ("/etc", "/boot", "/usr", "/var/log", "/root"))
        ):
            targets.append(cwd or "/")
        return targets

    def _has_secret_env_indicator(self, context: ShellContext) -> bool:
        markers = ("TOKEN", "SECRET", "KEY", "PASS", "CREDENTIAL")
        return any(any(marker in key.upper() for marker in markers) for key in context.env)

    def _is_kubernetes_context(self, context: ShellContext) -> bool:
        env_keys = {key.upper() for key in context.env}
        return "KUBECONFIG" in env_keys or any("kubectl" in item for item in context.history[-5:])

    def _redirects_to_sensitive_path(
        self, argv: list[str], cwd: str, home: str | None = None
    ) -> bool:
        def is_sensitive(raw: str) -> bool:
            path = self._resolve_target(raw, cwd, home)
            if path.startswith(("/etc/cron", "/etc/systemd", "/etc/init", "/etc/profile", "/root")):
                return True
            return "/.ssh/" in path or path.endswith("/.ssh")

        for index, token in enumerate(argv):
            if token in {">", ">>"} and index + 1 < len(argv):
                if is_sensitive(argv[index + 1]):
                    return True
            if token.startswith((">", ">>")) and len(token) > 1:
                if is_sensitive(token.lstrip(">")):
                    return True
        return False
