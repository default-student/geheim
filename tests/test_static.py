import ast
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class StaticSecurityTests(unittest.TestCase):
    def test_source_parses(self):
        ast.parse((ROOT / "geheim.py").read_text())

    def test_no_eval(self):
        tree = ast.parse((ROOT / "geheim.py").read_text())
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
        names = {node.func.id for node in calls if isinstance(node.func, ast.Name)}
        self.assertNotIn("eval", names)
        self.assertNotIn("exec", names)

    def test_version_is_pinned(self):
        source = (ROOT / "geheim.py").read_text()
        installer = (ROOT / "scripts" / "install.sh").read_text()
        self.assertIn('BW_VERSION = "2026.4.2"', source)
        self.assertIn("BW_VERSION=2026.4.2", installer)
        self.assertNotIn("/latest/", installer)

    def test_server_is_fixed(self):
        self.assertIn(
            'SERVER = "https://vaultwarden.example.com/"',
            (ROOT / "geheim.py").read_text(),
        )


if __name__ == "__main__":
    unittest.main()
