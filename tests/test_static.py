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
        self.assertIn('BW_VERSION = "2026.7.0"', source)
        self.assertIn("BW_VERSION=2026.7.0", installer)
        self.assertNotIn("/latest/", installer)

    def test_private_defaults_are_not_recorded(self):
        private_fragments = ("ta" + "yra", ".ts" + ".net")
        files = [path for path in ROOT.rglob("*") if path.is_file() and ".git" not in path.parts and "__pycache__" not in path.parts]
        for path in files:
            text = path.read_text(errors="ignore")
            for fragment in private_fragments:
                self.assertNotIn(fragment, text, str(path.relative_to(ROOT)))

    def test_setup_has_no_default_server(self):
        source = (ROOT / "geheim.py").read_text()
        self.assertNotIn("DEFAULT_SERVER", source)

    def test_skill_bootstraps_missing_cli(self):
        skill = (ROOT / "skills" / "geheim-credentials" / "SKILL.md").read_text()
        agent = (ROOT / "skills" / "geheim-credentials" / "agents" / "openai.yaml").read_text()
        plugin = (ROOT / ".codex-plugin" / "plugin.json").read_text()
        self.assertIn("command -v geheim", skill)
        self.assertIn("scripts/install.sh", skill)
        self.assertIn("outside the Codex filesystem sandbox", skill)
        self.assertIn("install the local geheim command if missing", agent)
        self.assertIn("$geheim-credentials", plugin)


if __name__ == "__main__":
    unittest.main()
