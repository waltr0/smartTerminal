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

    def test_suggest_suppresses_blocked_partial(self) -> None:
        code, out, err = self.invoke("suggest", "--partial", "rm -rf /", "--cwd", "/")
        self.assertEqual(code, 2, err)
        self.assertIn("Suggestion: <suppressed>", out)
        self.assertIn("decision=block", out)

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
        self.assertEqual(payload["cases"], 25)
        self.assertEqual(payload["failures"], [])

    def test_bench_eval_packaged_default(self) -> None:
        code, out, err = self.invoke("bench-eval", "--json")
        self.assertEqual(code, 0, err)
        payload = json.loads(out)
        self.assertEqual(payload["cases"], 25)
        self.assertEqual(payload["failures"], [])

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
