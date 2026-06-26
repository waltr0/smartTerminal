import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from cybershell.cli import main


class CliTests(unittest.TestCase):
    def invoke(self, *args: str) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(list(args))
        return code, stdout.getvalue(), stderr.getvalue()

    def test_doctor(self) -> None:
        code, out, err = self.invoke("doctor")
        self.assertEqual(code, 0, err)
        self.assertIn("Status: ready", out)

    def test_suggest_json(self) -> None:
        code, out, err = self.invoke("suggest", "--partial", "journal", "--cwd", ".","--json")
        self.assertEqual(code, 0, err)
        payload = json.loads(out)
        self.assertIsNotNone(payload["suggestion"])
        self.assertEqual(payload["risk"]["decision"], "allow")

    def test_suggest_completion_only(self) -> None:
        code, out, err = self.invoke("suggest", "--partial", "ss", "--cwd", ".", "--completion-only")
        self.assertEqual(code, 0, err)
        self.assertTrue(out)

    def test_shell_insert_appends_prefix_completion(self) -> None:
        code, out, err = self.invoke("suggest", "--partial", "ss", "--cwd", ".", "--shell-insert")
        self.assertEqual(code, 0, err)
        self.assertTrue(out.startswith("append\t"), out)
        completion = out.split("\t", 1)[1].strip()
        self.assertTrue(completion, "expected a non-empty prefix completion")

    def test_shell_insert_replaces_natural_language_intent(self) -> None:
        code, out, err = self.invoke(
            "suggest",
            "--partial",
            "show ssh failed logins",
            "--cwd",
            ".",
            "--shell-insert",
        )
        self.assertEqual(code, 0, err)
        self.assertTrue(out.startswith("replace\t"), out)
        self.assertIn("failed password", out.lower())

    def test_suggest_suppresses_blocked_partial(self) -> None:
        code, out, err = self.invoke("suggest", "--partial", "rm -rf /", "--cwd", "/")
        self.assertEqual(code, 2, err)
        self.assertIn("Suggestion: <suppressed>", out)
        self.assertIn("Status: blocked", out)
        self.assertIn("decision=block", out)

    def test_suggest_clarifies_vague_query(self) -> None:
        code, out, err = self.invoke("suggest", "--partial", "scan", "--cwd", ".")
        self.assertEqual(code, 1, err)
        self.assertIn("Suggestion: <needs clarification>", out)
        self.assertIn("Status: clarify", out)
        self.assertIn("target", out.lower())

    def test_suggest_marks_unrelated_query_unsupported(self) -> None:
        code, out, err = self.invoke("suggest", "--partial", "make me coffee", "--cwd", ".")
        self.assertEqual(code, 1, err)
        self.assertIn("Suggestion: <unsupported>", out)
        self.assertIn("Status: unsupported", out)

    def test_suggest_blocks_harmful_natural_language_intent(self) -> None:
        code, out, err = self.invoke(
            "suggest",
            "--partial",
            "make a reverse shell payload",
            "--cwd",
            ".",
        )
        self.assertEqual(code, 2, err)
        self.assertIn("Status: blocked", out)
        self.assertIn("intent.reverse_shell_or_payload", out)

    def test_risk_json(self) -> None:
        code, out, err = self.invoke("risk", "--json", "--", "cat", "~/.ssh/id_rsa")
        self.assertEqual(code, 0, err)
        payload = json.loads(out)
        self.assertEqual(payload["decision"], "warn")
        self.assertGreater(payload["score"], 0)

    def test_explain(self) -> None:
        code, out, err = self.invoke("explain", "--", "nmap", "-sV", "--top-ports", "100", "127.0.0.1")
        self.assertEqual(code, 0, err)
        self.assertIn("network scanning", out.lower())

    def test_accept_and_cache_lookup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cache_file = Path(tmp) / "cache.json"
            code, out, err = self.invoke(
                "accept",
                "--partial",
                "jctl",
                "--suggested",
                "journalctl -u ssh --since \"1 hour ago\"",
                "--cache-file",
                str(cache_file),
            )
            self.assertEqual(code, 0, err)
            self.assertTrue(cache_file.exists())

            code, out, err = self.invoke(
                "suggest",
                "--partial",
                "jctl",
                "--cwd",
                ".",
                "--cache-file",
                str(cache_file),
                "--json",
            )
            self.assertEqual(code, 0, err)
            payload = json.loads(out)
            self.assertEqual(payload["suggestion"]["source"], "prefix-cache")

    def test_kb_search_json(self) -> None:
        code, out, err = self.invoke("kb-search", "ssh", "--json")
        self.assertEqual(code, 0, err)
        payload = json.loads(out)
        self.assertTrue(payload)
        self.assertIn("ssh", json.dumps(payload).lower())

    def test_kb_search_accepts_multi_word_query(self) -> None:
        # Regression: a multi-word query must not be rejected as extra arguments.
        code, out, err = self.invoke("kb-search", "failed", "ssh", "logins")
        self.assertEqual(code, 0, err)
        self.assertTrue(out.strip())

    def test_rules_json(self) -> None:
        code, out, err = self.invoke("rules", "--json")
        self.assertEqual(code, 0, err)
        payload = json.loads(out)
        self.assertTrue(any(item["id"] == "fs.rm_recursive_force" for item in payload))

    def test_policies_json(self) -> None:
        code, out, err = self.invoke("policies", "--json")
        self.assertEqual(code, 0, err)
        payload = json.loads(out)
        names = {item["name"] for item in payload}
        self.assertIn("strict", names)
        self.assertIn("lab", names)

    def test_backends_json(self) -> None:
        code, out, err = self.invoke("backends", "--json")
        self.assertEqual(code, 0, err)
        payload = json.loads(out)
        self.assertTrue(any(item["name"] == "faiss" for item in payload))

    def test_bench_eval(self) -> None:
        code, out, err = self.invoke(
            "bench-eval", "--dataset", "benchmarks/cybershell_bench.jsonl", "--json"
        )
        self.assertEqual(code, 0, err)
        payload = json.loads(out)
        # A substantive dataset, not a token one.
        self.assertGreaterEqual(payload["cases"], 100)
        # The credibility guarantees: no benign command is misclassified, and
        # everything we claim to handle passes. Documented limitations are shown
        # honestly rather than hidden, and there are no unexpected regressions.
        self.assertEqual(payload["false_positive_rate"]["rate"], 0.0)
        self.assertEqual(payload["core_accuracy"], 1.0)
        self.assertEqual(payload["suggestion_status_accuracy"], 1.0)
        self.assertEqual(payload["failures"], [])
        self.assertGreater(len(payload["known_limitations"]), 0)

    def test_bench_eval_packaged_default(self) -> None:
        code, out, err = self.invoke("bench-eval", "--json")
        self.assertEqual(code, 0, err)
        payload = json.loads(out)
        self.assertGreaterEqual(payload["cases"], 100)
        self.assertEqual(payload["false_positive_rate"]["rate"], 0.0)
        self.assertEqual(payload["core_accuracy"], 1.0)
        self.assertEqual(payload["failures"], [])

    def test_bench_eval_fail_on_miss_passes_when_no_unexpected_failures(self) -> None:
        # --fail-on-miss must NOT trip on documented limitations, only on
        # unexpected regressions.
        code, _out, err = self.invoke("bench-eval", "--json", "--fail-on-miss")
        self.assertEqual(code, 0, err)

    def test_history_audit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            history = Path(tmp) / "history.txt"
            history.write_text("ss -tulpn\nrm -rf /\ncat ~/.ssh/id_rsa\n", encoding="utf-8")
            code, out, err = self.invoke(
                "history-audit", "--history-file", str(history), "--json"
            )
            self.assertEqual(code, 0, err)
            payload = json.loads(out)
            self.assertEqual(payload["commands_scanned"], 3)
            self.assertEqual(len(payload["risky_commands"]), 2)

    def test_playbooks(self) -> None:
        code, out, err = self.invoke("playbook", "list")
        self.assertEqual(code, 0, err)
        self.assertIn("ssh-bruteforce-triage", out)

        code, out, err = self.invoke("playbook", "show", "ssh-bruteforce-triage")
        self.assertEqual(code, 0, err)
        self.assertIn("SSH Brute-Force Triage", out)

    def test_audit_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            audit_file = Path(tmp) / "audit.jsonl"
            code, out, err = self.invoke(
                "suggest",
                "--partial",
                "ss",
                "--cwd",
                ".",
                "--audit",
                "--audit-file",
                str(audit_file),
            )
            self.assertEqual(code, 0, err)
            self.assertTrue(audit_file.exists())

            code, out, err = self.invoke(
                "audit-report", "--audit-file", str(audit_file), "--json"
            )
            self.assertEqual(code, 0, err)
            payload = json.loads(out)
            self.assertEqual(payload["events"], 1)


if __name__ == "__main__":
    unittest.main()
