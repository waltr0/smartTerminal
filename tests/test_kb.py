import unittest

from cybershell.kb import CommandKnowledgeBase
from cybershell.models import ShellContext


class KnowledgeBaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.kb = CommandKnowledgeBase.packaged()

    def test_retrieves_journalctl_for_ssh_logs(self) -> None:
        ctx = ShellContext(
            partial_command="journal",
            cwd="/var/log",
            history=["ssh user@example.com", "systemctl status ssh"],
        )
        hits = self.kb.retrieve(ctx)
        self.assertTrue(hits)
        self.assertIn("journalctl", hits[0].record.command)

    def test_retrieves_docker_inventory(self) -> None:
        ctx = ShellContext(partial_command="docker ps", cwd="/srv/app")
        hits = self.kb.retrieve(ctx)
        self.assertTrue(hits)
        self.assertIn("docker", hits[0].record.command)


if __name__ == "__main__":
    unittest.main()

