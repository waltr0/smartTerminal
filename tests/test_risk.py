import unittest

from cybershell.models import Decision, RiskLevel, ShellContext
from cybershell.policy import PolicyRegistry
from cybershell.risk import GuardrailEngine


class RiskEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = GuardrailEngine.packaged()

    def test_blocks_recursive_root_delete(self) -> None:
        result = self.engine.assess("rm -rf /")
        self.assertEqual(result.decision, Decision.BLOCK)
        self.assertEqual(result.level, RiskLevel.BLOCKED)
        self.assertTrue(any(f.rule_id == "fs.rm_recursive_force" for f in result.findings))

    def test_warns_on_private_key_read(self) -> None:
        result = self.engine.assess("cat ~/.ssh/id_rsa")
        self.assertEqual(result.decision, Decision.WARN)
        self.assertTrue(any(f.category == "secrets_access" for f in result.findings))

    def test_allows_read_only_network_inspection(self) -> None:
        result = self.engine.assess("ss -tulpn")
        self.assertEqual(result.decision, Decision.ALLOW)
        self.assertEqual(result.level, RiskLevel.SAFE)

    def test_warns_on_scoped_network_scan(self) -> None:
        result = self.engine.assess("nmap -sV --top-ports 100 127.0.0.1")
        self.assertEqual(result.decision, Decision.WARN)
        self.assertTrue(any(f.mitre_tactic == "Discovery" for f in result.findings))

    def test_lab_policy_allows_low_scoring_recon(self) -> None:
        policy = PolicyRegistry.packaged().get("lab")
        result = self.engine.assess("nmap -sV --top-ports 100 127.0.0.1", policy=policy)
        self.assertEqual(result.decision, Decision.ALLOW)
        self.assertEqual(result.level, RiskLevel.SAFE)

    def test_context_detects_secret_environment_dump(self) -> None:
        ctx = ShellContext(
            partial_command="env",
            cwd="/tmp",
            env={"AWS_SECRET_ACCESS_KEY": "example"},
        )
        result = self.engine.assess("env", ctx)
        self.assertEqual(result.decision, Decision.WARN)
        self.assertTrue(any(f.rule_id == "context.secret_env_dump" for f in result.findings))

    def test_context_increases_root_mutation_risk(self) -> None:
        ctx = ShellContext(partial_command="chmod 777 config.yml", cwd="/etc", is_root=True)
        result = self.engine.assess("chmod 777 config.yml", ctx)
        self.assertGreaterEqual(result.score, 35)
        self.assertTrue(any(f.rule_id == "context.root_mutation" for f in result.findings))


if __name__ == "__main__":
    unittest.main()
