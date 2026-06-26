from __future__ import annotations

import argparse
import json
import os
import sys
from importlib.resources import as_file, files
from pathlib import Path
from typing import Any

from cybershell.audit import AuditLog, default_audit_path
from cybershell.backends import optional_backend_status
from cybershell.benchmark import evaluate_benchmark
from cybershell.cache import PrefixCache
from cybershell.data_loader import load_json_resource
from cybershell.engine import SuggestionEngine
from cybershell.kb import CommandKnowledgeBase
from cybershell.models import (
    Decision,
    RiskAssessment,
    ShellContext,
    Suggestion,
    SuggestionResult,
    SuggestionStatus,
)
from cybershell.policy import PolicyRegistry
from cybershell.risk import GuardrailEngine

POLICY_NAMES = PolicyRegistry.packaged().names()


def _package_version() -> str:
    try:
        from importlib.metadata import version

        return version("cybershell-copilot")
    except Exception:  # pragma: no cover - source checkout without install metadata
        from cybershell import __version__

        return __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cybershell",
        description="Offline cybersecurity-aware terminal command assistant.",
    )
    parser.add_argument(
        "--version", action="version", version=f"cybershell {_package_version()}"
    )
    sub = parser.add_subparsers(dest="command_name", required=True)

    suggest = sub.add_parser("suggest", help="Generate a safe command suggestion.")
    add_context_args(suggest)
    suggest.add_argument("--mode", default="soc", choices=POLICY_NAMES)
    suggest.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    suggest.add_argument(
        "--completion-only",
        action="store_true",
        help="Print only the completion text for shell integration.",
    )
    suggest.add_argument(
        "--shell-insert",
        action="store_true",
        help="Print shell insertion action and text for Bash/Zsh integration.",
    )
    suggest.add_argument(
        "--safe-only",
        action="store_true",
        help="Suppress suggestions that require warning review.",
    )
    suggest.add_argument("--cache-file", type=Path, default=None)
    suggest.add_argument(
        "--audit",
        action="store_true",
        help="Write a local privacy-minimized audit event.",
    )
    suggest.add_argument("--audit-file", type=Path, default=default_audit_path())
    suggest.set_defaults(func=cmd_suggest)

    risk = sub.add_parser("risk", help="Assess a command without generating a suggestion.")
    risk.add_argument("command", nargs=argparse.REMAINDER)
    risk.add_argument("--json", action="store_true")
    risk.add_argument("--cwd", default=os.getcwd())
    risk.add_argument("--root", action="store_true")
    risk.add_argument("--mode", default="soc", choices=POLICY_NAMES)
    risk.set_defaults(func=cmd_risk)

    explain = sub.add_parser("explain", help="Explain cyber risk and safe alternatives.")
    explain.add_argument("command", nargs=argparse.REMAINDER)
    explain.add_argument("--cwd", default=os.getcwd())
    explain.add_argument("--mode", default="soc", choices=POLICY_NAMES)
    explain.set_defaults(func=cmd_explain)

    accept = sub.add_parser("accept", help="Persist an accepted suggestion in the prefix cache.")
    accept.add_argument("--partial", required=True)
    accept.add_argument("--suggested", required=True)
    accept.add_argument("--record-id", default=None)
    accept.add_argument("--cache-file", type=Path, required=True)
    accept.set_defaults(func=cmd_accept)

    doctor = sub.add_parser("doctor", help="Check packaged data and runtime readiness.")
    doctor.set_defaults(func=cmd_doctor)

    backends = sub.add_parser("backends", help="Show optional FAISS/LLM backend status.")
    backends.add_argument("--json", action="store_true")
    backends.set_defaults(func=cmd_backends)

    kb_search = sub.add_parser("kb-search", help="Search the packaged command knowledge base.")
    kb_search.add_argument("query", nargs="+", help="Search terms (multiple words allowed).")
    kb_search.add_argument("--top-k", type=int, default=5)
    kb_search.add_argument("--json", action="store_true")
    kb_search.set_defaults(func=cmd_kb_search)

    rules = sub.add_parser("rules", help="List packaged guardrail rules.")
    rules.add_argument("--json", action="store_true")
    rules.set_defaults(func=cmd_rules)

    policies = sub.add_parser("policies", help="List risk policy modes.")
    policies.add_argument("--json", action="store_true")
    policies.set_defaults(func=cmd_policies)

    bench_eval = sub.add_parser(
        "bench-eval", help="Evaluate the guardrail engine on a JSONL benchmark."
    )
    bench_eval.add_argument(
        "--dataset",
        type=Path,
        default=None,
        help="Path to CyberShell-Bench JSONL dataset.",
    )
    bench_eval.add_argument("--mode", default="soc", choices=POLICY_NAMES)
    bench_eval.add_argument("--json", action="store_true")
    bench_eval.add_argument(
        "--fail-on-miss",
        action="store_true",
        help="Exit nonzero when any benchmark case fails.",
    )
    bench_eval.set_defaults(func=cmd_bench_eval)

    history_audit = sub.add_parser(
        "history-audit", help="Assess shell history for risky command patterns."
    )
    history_audit.add_argument("--history-file", type=Path, required=True)
    history_audit.add_argument("--limit", type=int, default=2000)
    history_audit.add_argument("--mode", default="soc", choices=POLICY_NAMES)
    history_audit.add_argument("--json", action="store_true")
    history_audit.set_defaults(func=cmd_history_audit)

    playbook = sub.add_parser("playbook", help="Show built-in defensive playbooks.")
    playbook_sub = playbook.add_subparsers(dest="playbook_cmd", required=True)
    playbook_list = playbook_sub.add_parser("list", help="List playbooks.")
    playbook_list.set_defaults(func=cmd_playbook_list)
    playbook_show = playbook_sub.add_parser("show", help="Show one playbook.")
    playbook_show.add_argument("id")
    playbook_show.set_defaults(func=cmd_playbook_show)

    interactive = sub.add_parser("interactive", help="Run a small interactive suggestion loop.")
    interactive.add_argument("--mode", default="soc", choices=POLICY_NAMES)
    interactive.add_argument("--cache-file", type=Path, default=None)
    interactive.set_defaults(func=cmd_interactive)

    audit = sub.add_parser("audit-report", help="Summarize local CyberShell audit JSONL.")
    audit.add_argument("--audit-file", type=Path, default=default_audit_path())
    audit.add_argument("--json", action="store_true")
    audit.set_defaults(func=cmd_audit_report)

    return parser


def add_context_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--partial", required=True, help="Partial command currently typed.")
    parser.add_argument("--cwd", default=os.getcwd(), help="Current working directory.")
    parser.add_argument("--history", action="append", default=[], help="Recent command history item.")
    parser.add_argument("--history-file", type=Path, help="File containing recent history lines.")
    parser.add_argument("--env", action="append", default=[], help="Context env pair KEY=VALUE.")
    parser.add_argument("--last-status", type=int, default=None)
    parser.add_argument("--shell", default=os.environ.get("SHELL", "bash"))
    parser.add_argument("--root", action="store_true", help="Treat context as a root shell.")


def _should_emit_completion(
    result: SuggestionResult, args: argparse.Namespace, policy
) -> bool:
    """Decide whether a completion / shell-insert line should be emitted.

    Emit only when a suggestion exists and was not blocked. When safe-only mode is
    active (either via ``--safe-only`` or the active policy), restrict emission to
    suggestions the guardrails explicitly allow.
    """
    if result.suggestion is None:
        return False
    if result.risk.decision == Decision.BLOCK:
        return False
    safe_only = getattr(args, "safe_only", False) or policy.safe_only_suggestions
    return not (safe_only and result.risk.decision != Decision.ALLOW)


def cmd_suggest(args: argparse.Namespace) -> int:
    audit = AuditLog(args.audit_file) if args.audit else None
    cache = PrefixCache(path=args.cache_file) if args.cache_file else PrefixCache()
    engine = SuggestionEngine(cache=cache, audit_log=audit)
    context = context_from_args(args)
    result = engine.suggest(context, mode=args.mode)
    policy = engine.policies.get(args.mode)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
        return 0

    if args.completion_only or args.shell_insert:
        if _should_emit_completion(result, args, policy):
            assert result.suggestion is not None  # guaranteed when emitting a completion
            if args.shell_insert:
                if result.suggestion.completion:
                    print(f"append\t{result.suggestion.completion}", end="")
                else:
                    print(f"replace\t{result.suggestion.suggested_command}", end="")
            else:
                print(result.suggestion.completion, end="")
            return 0
        return 1

    print(format_suggestion_result(result))
    if result.risk.decision == Decision.BLOCK:
        return 2
    return 0 if result.status == SuggestionStatus.ANSWERED else 1


def cmd_risk(args: argparse.Namespace) -> int:
    command = command_from_remainder(args.command)
    context = ShellContext(partial_command=command, cwd=args.cwd, is_root=args.root)
    policy = PolicyRegistry.packaged().get(args.mode)
    assessment = GuardrailEngine.packaged().assess(command, context, policy)
    if args.json:
        print(json.dumps(assessment.to_dict(), indent=2))
    else:
        print(format_risk(assessment))
    return 0 if assessment.decision != Decision.BLOCK else 2


def cmd_explain(args: argparse.Namespace) -> int:
    command = command_from_remainder(args.command)
    context = ShellContext(partial_command=command, cwd=args.cwd)
    policy = PolicyRegistry.packaged().get(args.mode)
    assessment = GuardrailEngine.packaged().assess(command, context, policy)
    print(format_risk(assessment, verbose=True))
    return 0 if assessment.decision != Decision.BLOCK else 2


def cmd_accept(args: argparse.Namespace) -> int:
    cache = PrefixCache(path=args.cache_file)
    completion = (
        args.suggested[len(args.partial) :]
        if args.suggested.startswith(args.partial)
        else args.suggested
    )
    suggestion = Suggestion(
        suggested_command=args.suggested,
        completion=completion,
        source="manual-accept",
        confidence=0.95,
        explanation="Accepted by user.",
        retrieved_id=args.record_id,
    )
    cache.update(args.partial, suggestion)
    cache.save(args.cache_file)
    print(f"Cached accepted suggestion for prefix: {args.partial}")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    kb = CommandKnowledgeBase.packaged()
    guardrails = GuardrailEngine.packaged()
    print("CyberShell doctor")
    print(f"Python: {sys.version.split()[0]}")
    print(f"Command records: {len(kb.records)}")
    print(f"Guardrail rules: {len(guardrails.rules)}")
    print("Default audit path:", default_audit_path())
    print("Status: ready")
    return 0


def cmd_backends(args: argparse.Namespace) -> int:
    statuses = optional_backend_status()
    if args.json:
        print(json.dumps([status.to_dict() for status in statuses], indent=2))
        return 0
    print("Optional backend status")
    for status in statuses:
        state = "available" if status.available else "missing"
        print(f"{status.name}: {state} ({status.purpose})")
    return 0


def cmd_kb_search(args: argparse.Namespace) -> int:
    kb = CommandKnowledgeBase.packaged()
    context = ShellContext(partial_command=" ".join(args.query), cwd=os.getcwd())
    hits = kb.retrieve(context, top_k=args.top_k)
    if args.json:
        print(
            json.dumps(
                [
                    {
                        "score": hit.score,
                        "id": hit.record.id,
                        "command": hit.record.command,
                        "description": hit.record.description,
                        "domain": hit.record.domain,
                        "tags": hit.record.tags,
                        "risk_level": hit.record.risk_level,
                        "mitre_tactic": hit.record.mitre_tactic,
                        "mitre_technique": hit.record.mitre_technique,
                    }
                    for hit in hits
                ],
                indent=2,
            )
        )
        return 0
    for hit in hits:
        print(f"{hit.score:.1f}  {hit.record.id}")
        print(f"  {hit.record.command}")
        print(f"  {hit.record.description}")
    return 0


def cmd_rules(args: argparse.Namespace) -> int:
    guardrails = GuardrailEngine.packaged()
    if args.json:
        print(
            json.dumps(
                [
                    {
                        "id": rule.id,
                        "category": rule.category,
                        "weight": rule.weight,
                        "severity": rule.severity,
                        "message": rule.message,
                        "mitre_tactic": rule.mitre_tactic,
                        "mitre_technique": rule.mitre_technique,
                    }
                    for rule in guardrails.rules
                ],
                indent=2,
            )
        )
        return 0
    for rule in guardrails.rules:
        mitre = f" [{rule.mitre_tactic} {rule.mitre_technique}]" if rule.mitre_tactic else ""
        print(f"{rule.id}  {rule.category}  +{rule.weight}  {rule.severity}{mitre}")
        print(f"  {rule.message}")
    return 0


def cmd_policies(args: argparse.Namespace) -> int:
    registry = PolicyRegistry.packaged()
    policies = [registry.get(name) for name in registry.names()]
    if args.json:
        print(
            json.dumps(
                [
                    {
                        "name": policy.name,
                        "description": policy.description,
                        "caution_threshold": policy.caution_threshold,
                        "dangerous_threshold": policy.dangerous_threshold,
                        "block_threshold": policy.block_threshold,
                        "safe_only_suggestions": policy.safe_only_suggestions,
                        "lab_allows_recon": policy.lab_allows_recon,
                        "category_multipliers": policy.category_multipliers,
                        "category_floor_decisions": policy.category_floor_decisions,
                    }
                    for policy in policies
                ],
                indent=2,
            )
        )
        return 0
    for policy in policies:
        print(f"{policy.name}: {policy.description}")
        print(
            f"  thresholds caution/danger/block: "
            f"{policy.caution_threshold}/{policy.dangerous_threshold}/{policy.block_threshold}"
        )
    return 0


def cmd_bench_eval(args: argparse.Namespace) -> int:
    if args.dataset is None:
        resource = files("cybershell").joinpath("data").joinpath("cybershell_bench.jsonl")
        with as_file(resource) as dataset_path:
            report = evaluate_benchmark(dataset_path, default_mode=args.mode)
    else:
        report = evaluate_benchmark(args.dataset, default_mode=args.mode)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print("CyberShell-Bench evaluation")
        print(f"Dataset: {report['dataset']}")
        print(
            f"Cases: {report['cases']} "
            f"({report['guardrail_cases']} guardrail, {report['suggestion_cases']} suggestion)"
        )
        print(f"Core accuracy (excl. documented limitations): {report['core_accuracy']:.4f}")
        print(f"Guardrail decision accuracy: {report['guardrail_decision_accuracy']:.4f}")
        print(f"Suggestion-contract accuracy: {report['suggestion_status_accuracy']:.4f}")
        fpr = report["false_positive_rate"]
        print(
            f"False-positive rate: {fpr['rate']:.4f} "
            f"({fpr['false_alarms']}/{fpr['safe_cases']} safe commands)"
        )
        recall = report["detection_recall"]
        print(
            f"Block detection recall: {recall['recall']:.4f} "
            f"({recall['block_cases'] - recall['missed']}/{recall['block_cases']} dangerous commands)"
        )
        print(f"Avg latency: {report['avg_latency_ms']:.4f} ms")
        print("By category:")
        for name, stats in report["by_category"].items():
            print(f"  {name:22} {stats['passed']:>3}/{stats['cases']:<3} ({stats['accuracy']:.2f})")
        if report["known_limitations"]:
            print("Documented limitations (expected misses):")
            for row in report["known_limitations"]:
                print(f"  - {row['id']}: {row['command']}")
        if report["resolved_limitations"]:
            print("Limitations now resolved (update the dataset):")
            for row in report["resolved_limitations"]:
                print(f"  - {row['id']}: {row['command']}")
        if report["failures"]:
            print("UNEXPECTED failures:")
            for failure in report["failures"]:
                print(
                    f"  - [{failure['category']}] {failure['id']}: expected "
                    f"{failure['expected']} got {failure['actual']} | {failure['command']}"
                )
    return 1 if args.fail_on_miss and report["failures"] else 0


def cmd_history_audit(args: argparse.Namespace) -> int:
    if not args.history_file.exists():
        print(f"History file not found: {args.history_file}", file=sys.stderr)
        return 1
    guardrails = GuardrailEngine.packaged()
    policy = PolicyRegistry.packaged().get(args.mode)
    lines = args.history_file.read_text(encoding="utf-8", errors="ignore").splitlines()
    numbered = [
        (number, line.strip())
        for number, line in enumerate(lines, start=1)
        if line.strip()
    ]
    numbered = numbered[-args.limit :]
    commands = [command for _, command in numbered]
    risky: list[dict[str, Any]] = []
    for line_number, command in numbered:
        assessment = guardrails.assess(command, policy=policy)
        if assessment.decision != Decision.ALLOW:
            risky.append(
                {
                    "line": line_number,
                    "command": command,
                    "risk_level": assessment.level.value,
                    "decision": assessment.decision.value,
                    "score": assessment.score,
                    "rules": [finding.rule_id for finding in assessment.findings],
                    "mitre": [
                        {
                            "tactic": finding.mitre_tactic,
                            "technique": finding.mitre_technique,
                        }
                        for finding in assessment.findings
                        if finding.mitre_tactic
                    ],
                }
            )
    report = {"commands_scanned": len(commands), "risky_commands": risky}
    if args.json:
        print(json.dumps(report, indent=2))
        return 0
    print(f"Scanned commands: {len(commands)}")
    print(f"Risky commands: {len(risky)}")
    for item in risky[:25]:
        print(
            f"- line {item['line']}: {item['risk_level']} "
            f"score={item['score']} command={item['command']}"
        )
        print(f"  rules: {', '.join(item['rules'])}")
    if len(risky) > 25:
        print(f"... {len(risky) - 25} more risky commands omitted")
    return 0


def cmd_playbook_list(args: argparse.Namespace) -> int:
    playbooks = load_json_resource("playbooks.json")["playbooks"]
    for item in playbooks:
        print(f"{item['id']}  {item['title']}")
        print(f"  {item['summary']}")
    return 0


def cmd_playbook_show(args: argparse.Namespace) -> int:
    playbooks = load_json_resource("playbooks.json")["playbooks"]
    selected = next((item for item in playbooks if item["id"] == args.id), None)
    if selected is None:
        print(f"Unknown playbook: {args.id}", file=sys.stderr)
        return 1
    print(selected["title"])
    print(selected["summary"])
    print()
    for idx, step in enumerate(selected["steps"], start=1):
        print(f"{idx}. {step['name']}")
        print(f"   Goal: {step['goal']}")
        print(f"   Command: {step['command']}")
    return 0


def cmd_interactive(args: argparse.Namespace) -> int:
    engine = SuggestionEngine.packaged(cache_path=args.cache_file)
    print("CyberShell interactive mode. Type a partial command, or 'exit'.")
    while True:
        try:
            partial = input("cshell> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if partial in {"exit", "quit"}:
            return 0
        context = ShellContext(partial_command=partial, cwd=os.getcwd())
        result = engine.suggest(context, mode=args.mode)
        print(format_suggestion_result(result))


def cmd_audit_report(args: argparse.Namespace) -> int:
    report = AuditLog(args.audit_file).summarize()
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print("CyberShell audit report")
        print(f"Events: {report['events']}")
        print("By decision:")
        for key, value in sorted(report["by_decision"].items()):
            print(f"  {key}: {value}")
        print("Top rules:")
        for key, value in sorted(
            report["by_rule"].items(), key=lambda item: item[1], reverse=True
        )[:10]:
            print(f"  {key}: {value}")
    return 0


def context_from_args(args: argparse.Namespace) -> ShellContext:
    history = list(args.history or [])
    if args.history_file and args.history_file.exists():
        file_lines = args.history_file.read_text(encoding="utf-8", errors="ignore").splitlines()
        history.extend(line.strip() for line in file_lines if line.strip())

    env = parse_env(args.env)
    user = os.environ.get("USER") or os.environ.get("USERNAME")
    is_root = bool(args.root)
    if hasattr(os, "geteuid"):
        is_root = is_root or os.geteuid() == 0
    elif user:
        is_root = is_root or user.lower() == "root"

    return ShellContext(
        partial_command=args.partial,
        cwd=args.cwd,
        history=history[-7:],
        env=env,
        last_exit_status=args.last_status,
        shell=args.shell,
        user=user,
        is_root=is_root,
    )


def parse_env(items: list[str]) -> dict[str, str]:
    env: dict[str, str] = {}
    for item in items:
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        env[key] = value
    return env


def command_from_remainder(parts: list[str]) -> str:
    if parts and parts[0] == "--":
        parts = parts[1:]
    return " ".join(parts).strip()


def format_suggestion_result(result) -> str:
    lines: list[str] = []
    if result.suggestion:
        lines.append(f"Suggestion: {result.suggestion.suggested_command}")
        lines.append(f"Completion: {result.suggestion.completion or '<full command>'}")
        lines.append(f"Source: {result.suggestion.source} ({result.suggestion.confidence:.2f})")
        lines.append(f"Why: {result.suggestion.explanation}")
    else:
        if result.status == SuggestionStatus.CLARIFY:
            lines.append("Suggestion: <needs clarification>")
        elif result.status == SuggestionStatus.UNSUPPORTED:
            lines.append("Suggestion: <unsupported>")
        else:
            lines.append("Suggestion: <suppressed>")
    lines.append(f"Status: {result.status.value}")
    if result.message:
        lines.append(f"Message: {result.message}")
    lines.append("")
    lines.append(format_risk(result.risk))
    return "\n".join(lines)


def format_risk(assessment: RiskAssessment, verbose: bool = False) -> str:
    lines = [
        f"Risk: {assessment.level.value} / decision={assessment.decision.value} / score={assessment.score}",
        f"Summary: {assessment.summary}",
    ]
    if assessment.findings:
        lines.append("Findings:")
        for finding in assessment.findings:
            mitre = ""
            if finding.mitre_tactic:
                mitre = f" [{finding.mitre_tactic} {finding.mitre_technique or ''}]"
            lines.append(
                f"  - {finding.rule_id}: {finding.message} "
                f"(+{finding.weight}, evidence={finding.evidence!r}){mitre}"
            )
    if assessment.safe_alternatives:
        lines.append("Safer alternatives:")
        for item in assessment.safe_alternatives:
            lines.append(f"  - {item}")
    if verbose and not assessment.findings:
        lines.append("No MITRE-style guardrail tags matched this command.")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
